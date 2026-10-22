package main

import (
	"context"
	"net"

	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// vlessOutbound is a plain VLESS client (TCP, no TLS) for third-party
// upstreams such as bought residential lines. UDP goes as XUDP, so one
// session can reach several destinations.
type vlessOutbound struct {
	client *vless.Client
	server M.Socksaddr
	direct *directOutbound
}

func newVLESSOutbound(o OutboundConfig, direct *directOutbound) (*vlessOutbound, error) {
	client, err := vless.NewClient(o.UUID, "", nil)
	if err != nil {
		return nil, err
	}
	return &vlessOutbound{client: client, server: M.ParseSocksaddr(o.Server), direct: direct}, nil
}

func (v *vlessOutbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := v.direct.dialTCP(ctx, v.server)
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
	conn, err := v.direct.dialTCP(ctx, v.server)
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
