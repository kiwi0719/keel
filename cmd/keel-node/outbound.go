package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
)

const (
	dialTimeout = 10 * time.Second
	udpTimeout  = 3 * time.Minute
)

// outbound is how traffic leaves the node. It is replaced as a whole on
// reload; connections keep the outbound they started with.
type outbound struct {
	ipv4Only bool
	// upstream, when set, carries outbound TCP/UDP through a SOCKS5 proxy
	// (e.g. a local sslocal pointing at a residential landing).
	upstream *socks.Client
	// upstreamDomains limits the upstream to listed domains; directDomains
	// always bypasses it (see route.go).
	upstreamDomains *domainList
	directDomains   *domainList
}

var currentOutbound atomic.Pointer[outbound]

func newOutbound(c OutboundConfig, previous *outbound) *outbound {
	o := &outbound{ipv4Only: c.IPv4Only}
	if c.Socks == "" {
		return o
	}
	o.upstream = socks.NewClient(N.SystemDialer, M.ParseSocksaddr(c.Socks), socks.Version5, "", "")
	o.upstreamDomains = reuseDomainList(c.SocksDomains, previous, func(p *outbound) *domainList { return p.upstreamDomains })
	o.directDomains = reuseDomainList(c.DirectDomains, previous, func(p *outbound) *domainList { return p.directDomains })
	return o
}

// reuseDomainList keeps an already loaded list when its path is unchanged;
// the list reloads itself when the file changes.
func reuseDomainList(path string, previous *outbound, get func(*outbound) *domainList) *domainList {
	if path == "" {
		return nil
	}
	if previous != nil {
		if l := get(previous); l != nil && l.path == path {
			return l
		}
	}
	return newDomainList(path)
}

// network picks the IPv4-only variant of a Go network name when needed.
func (o *outbound) network(name string) string {
	if o.ipv4Only {
		return name + "4"
	}
	return name
}

var errUserInactive = errors.New("user removed, expired or over quota")

// user returns the authenticated user if it may still use the node. Checked
// per connection, so a multiplexed session (AnyTLS, XUDP) cannot open new
// streams after its user is blocked.
func (h *handler) user(ctx context.Context) *userState {
	name, ok := auth.UserFromContext[string](ctx)
	if !ok {
		return nil
	}
	return h.users.lookup(name)
}

// handler receives every proxied connection from every inbound. The inbound
// has already authenticated the user and put the name in the context.
type handler struct {
	users *registry
}

func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user := h.user(ctx)
	if user == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errUserInactive)
		return
	}
	untrack := user.track(conn)
	defer untrack()
	defer N.CloseOnHandshakeFailure(conn, onClose, nil)
	defer conn.Close()
	conn = bufio.NewInt64CounterConn(conn, []*atomic.Int64{&user.up}, []*atomic.Int64{&user.down})

	o := currentOutbound.Load()
	destination = destination.Unwrap()
	switch destination.Fqdn {
	case uot.MagicAddress:
		request, err := uot.ReadRequest(conn)
		if err != nil {
			N.ReportHandshakeFailure(conn, err)
			return
		}
		o.relayUDP(ctx, user.name, uot.NewConn(conn, *request), conn, request.Destination)
	case uot.LegacyMagicAddress:
		o.relayUDP(ctx, user.name, uot.NewConn(conn, uot.Request{}), conn, M.Socksaddr{})
	default:
		o.relayTCP(ctx, user.name, conn, destination)
	}
}

func (h *handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user := h.user(ctx)
	if user == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errUserInactive)
		return
	}
	untrack := user.track(conn)
	defer untrack()
	defer N.CloseOnHandshakeFailure(conn, onClose, nil)
	defer conn.Close()
	conn = bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&user.up}, nil, []*atomic.Int64{&user.down}, nil)
	currentOutbound.Load().relayUDP(ctx, user.name, conn, nil, destination.Unwrap())
}

func (o *outbound) relayTCP(ctx context.Context, user string, conn net.Conn, destination M.Socksaddr) {
	viaUpstream := o.viaUpstream(destination)
	if verbose {
		log.Print("[", user, "] tcp ", destination, " via-upstream=", viaUpstream)
	}
	var remote net.Conn
	var err error
	if viaUpstream {
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		remote, err = o.upstream.DialContext(dialCtx, N.NetworkTCP, destination)
		cancel()
	} else {
		dialer := net.Dialer{Timeout: dialTimeout}
		remote, err = dialer.DialContext(ctx, o.network("tcp"), destination.String())
	}
	if err != nil {
		N.ReportHandshakeFailure(conn, err)
		return
	}
	N.ReportHandshakeSuccess(conn)
	bufio.CopyConn(ctx, conn, remote)
}

// relayUDP forwards a UDP session. stream is the carrying TCP connection for
// UDP-over-TCP (to report the handshake result), or nil.
func (o *outbound) relayUDP(ctx context.Context, user string, packetConn N.PacketConn, stream net.Conn, destination M.Socksaddr) {
	viaUpstream := o.viaUpstream(destination)
	if verbose {
		log.Print("[", user, "] udp ", destination, " via-upstream=", viaUpstream)
	}
	report := func(err error) {
		if stream == nil {
			return
		}
		if err != nil {
			N.ReportHandshakeFailure(stream, err)
		} else {
			N.ReportHandshakeSuccess(stream)
		}
	}
	if viaUpstream {
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		associated, err := o.upstream.ListenPacket(dialCtx, destination)
		cancel()
		report(err)
		if err != nil {
			return
		}
		bufio.CopyPacketConn(ctx, packetConn, associated.(N.PacketConn))
		return
	}
	udpConn, err := net.ListenUDP(o.network("udp"), nil)
	report(err)
	if err != nil {
		return
	}
	bufio.CopyPacketConn(ctx, packetConn, &udpOutbound{UDPConn: udpConn, ipv4Only: o.ipv4Only, resolved: make(map[string]netip.Addr)})
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
