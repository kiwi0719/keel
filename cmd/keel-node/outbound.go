package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
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
	// allowPrivate mirrors route.allow_private; without it an IP literal
	// that is not public is refused whichever outbound would carry it.
	allowPrivate bool
}

// refused reports a destination no outbound may carry: the direct dialer
// checks resolved names itself, but socks, vless and third-party servers
// would otherwise take a private IP literal straight to their own LAN.
func (r *router) refused(destination M.Socksaddr) bool {
	return !r.allowPrivate && destination.IsIP() && !isPublic(destination.Addr)
}

type routeRule struct {
	name     string
	list     *ruleList
	outbound []string // fallback order
}

var currentRouter atomic.Pointer[router]

func newRouter(c *Config, previous *router) (*router, error) {
	direct := &directOutbound{ipv4Only: c.Route.IPv4Only, allowPrivate: c.Route.AllowPrivate}
	r := &router{
		final:        c.Route.Final,
		outbound:     map[string]outbound{"direct": direct},
		health:       make(map[string]*outboundHealth),
		healthCheck:  newHealthCheck(c.Route.HealthCheck),
		allowPrivate: c.Route.AllowPrivate,
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
			r.outbound[o.Tag] = &socksOutbound{socks.NewClient(socksDialer{direct}, M.ParseSocksaddr(o.Server), socks.Version5, "", "")}
		case "ss2022":
			method := o.Method
			if method == "" {
				method = "2022-blake3-aes-128-gcm"
			}
			var ss shadowsocks.Method
			var err error
			if strings.HasPrefix(method, "2022-") {
				ss, err = shadowaead_2022.NewWithPassword(method, o.Password, time.Now)
			} else {
				// Classic AEAD methods, for imported third-party servers.
				ss, err = shadowaead.New(method, nil, o.Password)
			}
			if err != nil {
				return nil, fmt.Errorf("outbound %s: %w", o.Tag, err)
			}
			r.outbound[o.Tag] = &ssOutbound{method: ss, server: M.ParseSocksaddr(o.Server), direct: direct, udpOverTCP: o.UDPOverTCP}
		case "vless":
			v, err := newVLESSOutbound(o, direct)
			if err != nil {
				return nil, fmt.Errorf("outbound %s: %w", o.Tag, err)
			}
			r.outbound[o.Tag] = v
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
	if r.refused(destination) {
		N.ReportHandshakeFailure(conn, errPrivateDestination)
		return
	}
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
	if r.refused(destination) {
		if stream != nil {
			N.ReportHandshakeFailure(stream, errPrivateDestination)
		}
		return
	}
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
	mux := newUDPRoutes(ctx, r, user, tag, remote)
	defer mux.Close()
	bufio.CopyPacketConn(ctx, packetConn, mux)
}

// udpRoutes is the remote side of one UDP session, routing each packet by
// its own destination: a later packet to a host the rules send elsewhere
// (or one that is private) must not ride the outbound the first packet
// picked. Remotes are opened per outbound on first use, in the background,
// so a slow outbound does not hold up the session's other packets; the
// session ends when every remote has idled out.
type udpRoutes struct {
	ctx     context.Context
	r       *router
	user    string
	mu      sync.Mutex
	remotes map[string]N.PacketConn
	opening map[string][]udpPacket // outbounds being opened, with the packets waiting for them
	failed  map[string]time.Time   // outbounds that failed to open: skipped until then
	in      chan udpPacket
	done    chan struct{}
	once    sync.Once
}

// udpPacket is a packet with the address it came from or goes to.
type udpPacket struct {
	buffer *buf.Buffer
	addr   M.Socksaddr
}

const (
	// udpPendingMax packets may wait for an outbound being opened; later
	// ones are dropped.
	udpPendingMax = 16
	// udpOpenBackoff is how long an outbound that failed to open is skipped.
	udpOpenBackoff = 2 * time.Second
)

func newUDPRoutes(ctx context.Context, r *router, user, tag string, first N.PacketConn) *udpRoutes {
	u := &udpRoutes{
		ctx: ctx, r: r, user: user,
		remotes: map[string]N.PacketConn{tag: first},
		opening: make(map[string][]udpPacket),
		failed:  make(map[string]time.Time),
		in:      make(chan udpPacket, 64),
		done:    make(chan struct{}),
	}
	go u.read(tag, first)
	return u
}

// read forwards one remote's packets until it fails or idles out.
func (u *udpRoutes) read(tag string, remote N.PacketConn) {
	defer func() {
		remote.Close()
		u.mu.Lock()
		if u.remotes[tag] == remote {
			delete(u.remotes, tag)
		}
		idle := len(u.remotes) == 0 && len(u.opening) == 0
		u.mu.Unlock()
		if idle {
			u.Close()
		}
	}()
	for {
		buffer := buf.NewPacket()
		from, err := remote.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		select {
		case u.in <- udpPacket{buffer, from}:
		case <-u.done:
			buffer.Release()
			return
		}
	}
}

func (u *udpRoutes) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case p := <-u.in:
		_, err := buffer.Write(p.buffer.Bytes())
		p.buffer.Release()
		return p.addr, err
	case <-u.done:
		return M.Socksaddr{}, net.ErrClosed
	}
}

func (u *udpRoutes) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	destination = destination.Unwrap()
	if u.r.refused(destination) {
		buffer.Release()
		return nil // drop, keep the session
	}
	out, tag, label := u.r.pick(destination)
	u.mu.Lock()
	if remote := u.remotes[tag]; remote != nil {
		u.mu.Unlock()
		return remote.WritePacket(buffer, destination)
	}
	if pending, ok := u.opening[tag]; ok {
		if len(pending) < udpPendingMax {
			u.opening[tag] = append(pending, udpPacket{buffer, destination})
		} else {
			buffer.Release()
		}
		u.mu.Unlock()
		return nil
	}
	if time.Now().Before(u.failed[tag]) {
		u.mu.Unlock()
		buffer.Release()
		return nil
	}
	u.opening[tag] = []udpPacket{{buffer, destination}}
	u.mu.Unlock()
	if verbose {
		log.Print("[", u.user, "] udp ", destination, " via ", label)
	}
	go u.open(out, tag, destination)
	return nil
}

// open opens the outbound for tag, sends the packets that waited for it in
// order, and only then lets later packets go to it directly.
func (u *udpRoutes) open(out outbound, tag string, destination M.Socksaddr) {
	defer recoverConn("udp", u)
	dialCtx, cancel := context.WithTimeout(u.ctx, dialTimeout)
	remote, err := out.listenUDP(dialCtx, destination)
	cancel()
	if err != nil {
		u.r.dialFailed(tag)
		if verbose {
			log.Print("[", u.user, "] udp ", destination, ": ", err)
		}
	}
	for {
		u.mu.Lock()
		pending := u.opening[tag]
		closed := u.closed()
		if err == nil && !closed && len(pending) > 0 {
			u.opening[tag] = nil
			u.mu.Unlock()
			for _, p := range pending {
				if werr := remote.WritePacket(p.buffer, p.addr); werr != nil && verbose {
					log.Print("[", u.user, "] udp ", p.addr, ": ", werr)
				}
			}
			continue
		}
		delete(u.opening, tag)
		if err != nil {
			u.failed[tag] = time.Now().Add(udpOpenBackoff)
		} else if !closed {
			u.remotes[tag] = remote
		}
		u.mu.Unlock()
		for _, p := range pending {
			p.buffer.Release()
		}
		switch {
		case err != nil:
		case closed:
			remote.Close()
		default:
			go u.read(tag, remote)
		}
		return
	}
}

func (u *udpRoutes) closed() bool {
	select {
	case <-u.done:
		return true
	default:
		return false
	}
}

// LazyHeadroom: which outbound a packet takes, and so the header room it
// needs, is only known per packet; callers leave sing's default room.
func (u *udpRoutes) LazyHeadroom() bool { return true }

func (u *udpRoutes) Close() error {
	u.once.Do(func() {
		close(u.done)
		u.mu.Lock()
		for _, remote := range u.remotes {
			remote.Close()
		}
		u.mu.Unlock()
		for {
			select {
			case p := <-u.in:
				p.buffer.Release()
			default:
				return
			}
		}
	})
	return nil
}

func (u *udpRoutes) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (u *udpRoutes) SetDeadline(time.Time) error      { return nil }
func (u *udpRoutes) SetReadDeadline(time.Time) error  { return nil }
func (u *udpRoutes) SetWriteDeadline(time.Time) error { return nil }

// directOutbound dials from this machine. It also implements N.Dialer so the
// other outbounds reach their servers through it (and honor ipv4_only).
//
// Proxied traffic (dialTCP, listenUDP) may only reach public addresses unless
// allowPrivate is set: a user must not get at this machine's own services
// (a panel on 127.0.0.1, cloud metadata) or the LAN behind it. Outbound
// servers (dialServer, DialContext) may be anywhere, e.g. a local sslocal.
type directOutbound struct {
	ipv4Only     bool
	allowPrivate bool
}

// maxResolved caps the names one direct UDP session keeps resolved.
const maxResolved = 256

// udpResolveWait is the longest a UDP packet to a name waits for its lookup.
const udpResolveWait = 200 * time.Millisecond

var errPrivateDestination = errors.New("destination is a private or local address")

// notGlobal lists IANA special-purpose ranges that are not reachable on the
// public internet but that netip still calls global unicast, plus platform
// endpoints that sit in public space (Azure WireServer, which its agent's
// firewall opens only to root, as keel-node runs).
var notGlobal = func() []netip.Prefix {
	var list []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"168.63.129.16/32",
		"::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
		"3fff::/20", "5f00::/16", "fec0::/10",
	} {
		list = append(list, netip.MustParsePrefix(s))
	}
	return list
}()

var (
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	siitMapped = netip.MustParsePrefix("::ffff:0:0:0/96")
	ipv4Compat = netip.MustParsePrefix("::/96")
)

// embeddedIPv4 returns the IPv4 address an IPv6 translation prefix carries.
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	b := a.As16()
	switch {
	case nat64.Contains(a), siitMapped.Contains(a), ipv4Compat.Contains(a):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// isPublic reports whether proxied traffic may go to a.
func isPublic(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if v4, ok := embeddedIPv4(a); ok && !isPublic(v4) {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range notGlobal {
		if p.Contains(a) {
			return false
		}
	}
	return !isLocal(a)
}

// The node's own addresses count as private: Linux delivers a connection to
// them over lo, past firewalls that only filter the outside interface.
// The list is read without locking (UDP checks every packet) and refreshed
// every 10 s by one caller while the others keep using the previous one.
var local struct {
	refresh sync.Mutex
	current atomic.Pointer[localSet]
}

type localSet struct {
	at    time.Time
	addrs map[netip.Addr]bool
}

func isLocal(a netip.Addr) bool {
	set := local.current.Load()
	if set == nil || time.Since(set.at) > 10*time.Second {
		set = refreshLocal(set)
	}
	return set.addrs[a]
}

func refreshLocal(stale *localSet) *localSet {
	if stale == nil {
		local.refresh.Lock() // nothing to fall back on: wait for the first list
	} else if !local.refresh.TryLock() {
		return stale
	}
	defer local.refresh.Unlock()
	if set := local.current.Load(); set != stale {
		return set
	}
	set := &localSet{at: time.Now(), addrs: localAddrs()}
	local.current.Store(set)
	return set
}

// localAddrs lists the interface addresses and each IPv4 network's
// directed broadcast address.
func localAddrs() map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return m
	}
	for _, ia := range ifaddrs {
		n, ok := ia.(*net.IPNet)
		if !ok {
			continue
		}
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		a = a.Unmap()
		m[a] = true
		if ones, bits := n.Mask.Size(); a.Is4() && bits == 32 && ones < 31 {
			b := a.As4()
			for i := range b {
				b[i] |= ^n.Mask[len(n.Mask)-4+i]
			}
			m[netip.AddrFrom4(b)] = true
		}
	}
	return m
}

func (d *directOutbound) userDialer() *net.Dialer {
	if d.allowPrivate {
		return &net.Dialer{}
	}
	// Checked on the address actually dialed, after DNS, so a domain that
	// resolves to 127.0.0.1 is refused too.
	return &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !isPublic(ap.Addr()) {
			return errPrivateDestination
		}
		return nil
	}}
}

func (d *directOutbound) network(name string) string {
	if d.ipv4Only {
		return name + "4"
	}
	return name
}

func (d *directOutbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsFqdn() {
		return d.userDialer().DialContext(ctx, d.network("tcp"), destination.String())
	}
	addrs, err := resolver.resolve(ctx, destination.Fqdn, d.ipv4Only, dnsTimeout)
	if err != nil {
		return nil, err
	}
	return dialAddrs(ctx, d.userDialer(), d.network("tcp"), addrs, destination.Port)
}

// dialServer reaches an outbound's own server, which may be private.
func (d *directOutbound) dialServer(ctx context.Context, server M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, d.network("tcp"), server.String())
}

func (d *directOutbound) listenUDP(context.Context, M.Socksaddr) (N.PacketConn, error) {
	udpConn, err := net.ListenUDP(d.network("udp"), nil)
	if err != nil {
		return nil, err
	}
	return &udpOutbound{UDPConn: udpConn, ipv4Only: d.ipv4Only, allowPrivate: d.allowPrivate, resolved: make(map[string]netip.Addr)}, nil
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
	return socksHandshake(ctx, func(ctx context.Context) (net.Conn, error) {
		return s.client.DialContext(ctx, N.NetworkTCP, destination)
	})
}

func (s *socksOutbound) listenUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	conn, err := socksHandshake(ctx, func(ctx context.Context) (net.PacketConn, error) {
		return s.client.ListenPacket(ctx, destination)
	})
	if err != nil {
		return nil, err
	}
	return conn.(N.PacketConn), nil
}

// The SOCKS client ignores the context once connected, so a server that
// never answers would hold the relay forever. socksDialer hands the raw
// connection to socksHandshake, which closes it if the context ends first.
type socksDialer struct{ N.Dialer }

type socksConnKey struct{}

type socksConnSlot struct {
	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

func (d socksDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if slot, ok := ctx.Value(socksConnKey{}).(*socksConnSlot); ok && err == nil {
		slot.mu.Lock()
		slot.conn = conn
		if slot.closed {
			conn.Close()
		}
		slot.mu.Unlock()
	}
	return conn, err
}

func socksHandshake[T any](ctx context.Context, handshake func(context.Context) (T, error)) (T, error) {
	slot := &socksConnSlot{}
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := handshake(context.WithValue(ctx, socksConnKey{}, slot))
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		slot.mu.Lock()
		slot.closed = true
		if slot.conn != nil {
			slot.conn.Close()
		}
		slot.mu.Unlock()
		var zero T
		return zero, ctx.Err()
	}
}

// ssOutbound is a Shadowsocks client: SS 2022 to reach keel exits, or a
// classic AEAD method for an imported third-party server.
type ssOutbound struct {
	method     shadowsocks.Method
	server     M.Socksaddr
	direct     *directOutbound
	udpOverTCP bool
}

func (s *ssOutbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.direct.dialServer(ctx, s.server)
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
	ipv4Only     bool
	allowPrivate bool
	resolved     map[string]netip.Addr
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
			if len(c.resolved) >= maxResolved {
				clear(c.resolved) // bounded: a session may name endless hosts
			}
			// A slow name costs this packet at most udpResolveWait; the
			// lookup goes on in the background and later packets find
			// the answer (or the failure) cached.
			ips, err := resolver.resolve(context.Background(), destination.Fqdn, c.ipv4Only, udpResolveWait)
			if err != nil {
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
	if !c.allowPrivate && !isPublic(addr) {
		return nil // drop, as dialTCP refuses these
	}
	_, err := c.WriteToUDPAddrPort(buffer.Bytes(), netip.AddrPortFrom(addr, destination.Port))
	return err
}
