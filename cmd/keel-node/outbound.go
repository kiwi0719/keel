package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
)

const (
	dialTimeout = 10 * time.Second
	udpTimeout  = 3 * time.Minute
)

// outbound is one way for traffic to leave the node.
type outbound interface {
	dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	listenUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error)
}

// router picks an outbound per connection. It is replaced as a whole on
// reload; connections keep the router they started with.
type router struct {
	rules    []routeRule
	final    []string
	outbound map[string]outbound
	// health tracks every outbound but direct; entries are carried over a
	// reload when the outbound's settings did not change.
	health      map[string]*outboundHealth
	healthCheck healthCheck
}

type routeRule struct {
	name     string
	list     *ruleList
	outbound []string // fallback order
}

var currentRouter atomic.Pointer[router]

func newRouter(c *Config, previous *router) (*router, error) {
	direct := &directOutbound{ipv4Only: c.Route.IPv4Only}
	r := &router{
		final:       c.Route.Final,
		outbound:    map[string]outbound{"direct": direct},
		health:      make(map[string]*outboundHealth),
		healthCheck: newHealthCheck(c.Route.HealthCheck),
	}
	if len(r.final) == 0 {
		r.final = []string{"direct"}
	}
	for _, o := range c.Outbounds {
		if previous != nil && previous.health[o.Tag] != nil && previous.health[o.Tag].config == o {
			r.health[o.Tag] = previous.health[o.Tag]
		} else {
			r.health[o.Tag] = newOutboundHealth(o)
		}
		switch o.Type {
		case "socks":
			r.outbound[o.Tag] = &socksOutbound{socks.NewClient(direct, M.ParseSocksaddr(o.Server), socks.Version5, "", "")}
		case "ss2022":
			method := o.Method
			if method == "" {
				method = "2022-blake3-aes-128-gcm"
			}
			ss, err := shadowaead_2022.NewWithPassword(method, o.Password, time.Now)
			if err != nil {
				return nil, fmt.Errorf("outbound %s: %w", o.Tag, err)
			}
			r.outbound[o.Tag] = &ssOutbound{method: ss, server: M.ParseSocksaddr(o.Server), direct: direct, udpOverTCP: o.UDPOverTCP}
		}
	}
	for i, rc := range c.Route.Rules {
		name := rc.Name
		if name == "" {
			name = fmt.Sprint("rule", i+1)
		}
		var list *ruleList
		if previous != nil {
			for _, old := range previous.rules {
				if old.list.sameSource(rc.File, rc.Domains) {
					list = old.list
					break
				}
			}
		}
		if list == nil {
			list = newRuleList(rc.File, rc.Domains)
		}
		r.rules = append(r.rules, routeRule{name: name, list: list, outbound: rc.Outbound})
	}
	return r, nil
}

// pick returns the outbound for destination, its tag and a label for logs.
func (r *router) pick(destination M.Socksaddr) (outbound, string, string) {
	for _, rule := range r.rules {
		if rule.list.match(destination) {
			tag := r.firstAlive(rule.outbound)
			return r.outbound[tag], tag, rule.name + "->" + tag
		}
	}
	tag := r.firstAlive(r.final)
	return r.outbound[tag], tag, tag
}

// firstAlive returns the first outbound of list that is not known to be
// dead. When all are dead it returns the first, so traffic still tries.
func (r *router) firstAlive(list []string) string {
	for _, tag := range list {
		if h := r.health[tag]; h == nil || h.isAlive() {
			return tag
		}
	}
	return list[0]
}

// dialFailed asks for an early health check after a dial to the outbound's
// server failed.
func (r *router) dialFailed(tag string) {
	if h := r.health[tag]; h != nil {
		h.suspect()
	}
}

func (r *router) relayTCP(ctx context.Context, user string, conn net.Conn, destination M.Socksaddr) {
	out, tag, label := r.pick(destination)
	if verbose {
		log.Print("[", user, "] tcp ", destination, " via ", label)
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	remote, err := out.dialTCP(dialCtx, destination)
	cancel()
	if err != nil {
		r.dialFailed(tag)
		N.ReportHandshakeFailure(conn, err)
		if verbose {
			log.Print("[", user, "] tcp ", destination, ": ", err)
		}
		return
	}
	N.ReportHandshakeSuccess(conn)
	bufio.CopyConn(ctx, conn, remote)
}

// relayUDP forwards a UDP session. stream is the carrying TCP connection for
// UDP-over-TCP (to report the handshake result), or nil. The session is
// routed by its first destination.
func (r *router) relayUDP(ctx context.Context, user string, packetConn N.PacketConn, stream net.Conn, destination M.Socksaddr) {
	out, tag, label := r.pick(destination)
	if verbose {
		log.Print("[", user, "] udp ", destination, " via ", label)
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	remote, err := out.listenUDP(dialCtx, destination)
	cancel()
	if err != nil {
		r.dialFailed(tag)
	}
	if stream != nil {
		if err != nil {
			N.ReportHandshakeFailure(stream, err)
		} else {
			N.ReportHandshakeSuccess(stream)
		}
	}
	if err != nil {
		if verbose {
			log.Print("[", user, "] udp ", destination, ": ", err)
		}
		return
	}
	bufio.CopyPacketConn(ctx, packetConn, remote)
}

// directOutbound dials from this machine. It also implements N.Dialer so the
// other outbounds reach their servers through it (and honor ipv4_only).
type directOutbound struct {
	ipv4Only bool
}

func (d *directOutbound) network(name string) string {
	if d.ipv4Only {
		return name + "4"
	}
	return name
}

func (d *directOutbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, d.network("tcp"), destination.String())
}

func (d *directOutbound) listenUDP(context.Context, M.Socksaddr) (N.PacketConn, error) {
	udpConn, err := net.ListenUDP(d.network("udp"), nil)
	if err != nil {
		return nil, err
	}
	return &udpOutbound{UDPConn: udpConn, ipv4Only: d.ipv4Only, resolved: make(map[string]netip.Addr)}, nil
}

func (d *directOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, d.network(N.NetworkName(network)), destination.String())
}

func (d *directOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP(d.network("udp"), nil)
}

// socksOutbound sends traffic through a SOCKS5 proxy, e.g. a local sslocal
// pointing at a residential landing.
type socksOutbound struct {
	client *socks.Client
}

func (s *socksOutbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return s.client.DialContext(ctx, N.NetworkTCP, destination)
}

func (s *socksOutbound) listenUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	conn, err := s.client.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return conn.(N.PacketConn), nil
}

// ssOutbound is a Shadowsocks 2022 client, used by entry nodes to reach exits.
type ssOutbound struct {
	method     shadowsocks.Method
	server     M.Socksaddr
	direct     *directOutbound
	udpOverTCP bool
}

func (s *ssOutbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.direct.dialTCP(ctx, s.server)
	if err != nil {
		return nil, err
	}
	ssConn, err := s.method.DialConn(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssConn, nil
}

func (s *ssOutbound) listenUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	if s.udpOverTCP {
		client := uot.Client{Dialer: ssDialer{s}, Version: uot.Version}
		conn, err := client.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return conn.(N.PacketConn), nil
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, s.direct.network("udp"), s.server.String())
	if err != nil {
		return nil, err
	}
	return s.method.DialPacketConn(&idleConn{conn}), nil
}

// ssDialer lets the UDP-over-TCP client open its stream through the SS server.
type ssDialer struct{ s *ssOutbound }

func (d ssDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("ss2022 outbound: unsupported network ", network)
	}
	return d.s.dialTCP(ctx, destination)
}

func (d ssDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("ss2022 outbound: ListenPacket unsupported")
}

// idleConn ends a UDP session to the SS server after udpTimeout without
// replies. It wraps the socket under the SS packet conn, so the SS conn's
// header room is still visible to sing's copy.
type idleConn struct {
	net.Conn
}

func (c *idleConn) Read(p []byte) (int, error) {
	c.SetReadDeadline(time.Now().Add(udpTimeout))
	return c.Conn.Read(p)
}

// udpOutbound adapts a UDP socket to N.PacketConn, resolving domain
// destinations and expiring after udpTimeout of inactivity.
type udpOutbound struct {
	*net.UDPConn
	ipv4Only bool
	resolved map[string]netip.Addr
}

func (c *udpOutbound) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.SetReadDeadline(time.Now().Add(udpTimeout))
	n, addr, err := c.ReadFromUDPAddrPort(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNetIP(addr).Unwrap(), nil
}

func (c *udpOutbound) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	addr := destination.Unwrap().Addr
	if destination.IsFqdn() {
		ip, ok := c.resolved[destination.Fqdn]
		if !ok {
			network := "ip"
			if c.ipv4Only {
				network = "ip4"
			}
			ips, err := net.DefaultResolver.LookupNetIP(context.Background(), network, destination.Fqdn)
			if err != nil || len(ips) == 0 {
				return nil // drop packet, keep session alive
			}
			ip = ips[0]
			for _, candidate := range ips {
				if candidate.Is4() {
					ip = candidate
					break
				}
			}
			c.resolved[destination.Fqdn] = ip.Unmap()
		}
		addr = ip
	}
	if c.ipv4Only && !addr.Unmap().Is4() {
		return nil // drop IPv6 destinations, keep session alive
	}
	_, err := c.WriteToUDPAddrPort(buffer.Bytes(), netip.AddrPortFrom(addr, destination.Port))
	return err
}
