package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// vlessOutbound is a VLESS client for third-party upstreams such as bought
// residential lines: over REALITY or TLS when the link asks for it, else
// plain TCP (which shows the UUID, destinations and payload to anyone on
// the path). Vision (flow) needs REALITY or TLS.
// UDP goes as XUDP, so one session can reach several destinations.
type vlessOutbound struct {
	client  *vless.Client
	server  M.Socksaddr
	direct  *directOutbound
	tls     *tls.Config    // nil: plain TCP (unless reality)
	reality *realityClient // VLESS behind REALITY
}

func newVLESSOutbound(o OutboundConfig, direct *directOutbound) (*vlessOutbound, error) {
	if o.TLS != nil && o.Reality != nil {
		return nil, errors.New("tls and reality are mutually exclusive")
	}
	if o.Flow != "" && o.TLS == nil && o.Reality == nil {
		return nil, errors.New("flow needs tls or reality")
	}
	// Vision logs through the logger, so it must not be nil.
	client, err := vless.NewClient(o.UUID, o.Flow, logger.NOP())
	if err != nil {
		return nil, err
	}
	v := &vlessOutbound{client: client, server: M.ParseSocksaddr(o.Server), direct: direct}
	if o.TLS != nil {
		v.tls = &tls.Config{ServerName: o.TLS.ServerName, MinVersion: tls.VersionTLS12}
	}
	if o.Reality != nil {
		if v.reality, err = newRealityClient(o.Reality); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// dial reaches the server, completing TLS (with certificate checks) first
// when configured.
func (v *vlessOutbound) dial(ctx context.Context) (net.Conn, error) {
	conn, err := v.direct.dialServer(ctx, v.server)
	if err != nil {
		return nil, err
	}
	if v.reality != nil {
		uConn, err := v.reality.handshake(ctx, conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return uConn, nil
	}
	if v.tls == nil {
		return conn, nil
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
