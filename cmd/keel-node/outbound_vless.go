package main

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// vlessOutbound is a VLESS client for third-party upstreams such as bought
// residential lines, over TLS when the link asks for it (else plain TCP,
// which shows the UUID, destinations and payload to anyone on the path).
// UDP goes as XUDP, so one session can reach several destinations.
type vlessOutbound struct {
	client *vless.Client
	server M.Socksaddr
	direct *directOutbound
	tls    *tls.Config // nil: plain TCP
}

func newVLESSOutbound(o OutboundConfig, direct *directOutbound) (*vlessOutbound, error) {
	client, err := vless.NewClient(o.UUID, "", nil)
	if err != nil {
		return nil, err
	}
	v := &vlessOutbound{client: client, server: M.ParseSocksaddr(o.Server), direct: direct}
	if o.TLS != nil {
		v.tls = &tls.Config{ServerName: o.TLS.ServerName, MinVersion: tls.VersionTLS12}
	}
	return v, nil
}

// dial reaches the server, completing TLS (with certificate checks) first
// when configured.
func (v *vlessOutbound) dial(ctx context.Context) (net.Conn, error) {
	conn, err := v.direct.dialServer(ctx, v.server)
	if err != nil || v.tls == nil {
		return conn, err
	}
	tlsConn := tls.Client(conn, v.tls)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (v *vlessOutbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := v.dial(ctx)
	if err != nil {
		return nil, err
	}
	// The request header goes out with the first payload.
	remote, err := v.client.DialEarlyConn(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return remote, nil
}

func (v *vlessOutbound) listenUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	conn, err := v.dial(ctx)
	if err != nil {
		return nil, err
	}
	remote, err := v.client.DialEarlyXUDPPacketConn(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return remote, nil
}
