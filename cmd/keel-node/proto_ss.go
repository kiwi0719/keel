//go:build ss

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func init() {
	protocols["ss2022"] = newSSInbound
}

// ssInbound serves Shadowsocks 2022 with one key per user (EIH), over TCP and
// native UDP. Clients use "<server password>:<user key>" as their password.
type ssInbound struct {
	listener net.Listener
	udpConn  *net.UDPConn
	service  *shadowaead_2022.MultiService[string]
}

func newSSInbound(config InboundConfig, h *handler) (inbound, error) {
	method := config.Method
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	service, err := shadowaead_2022.NewMultiServiceWithPassword[string](method, config.Password, int64(udpTimeout.Seconds()), ssHandler{h}, time.Now)
	if err != nil {
		return nil, err
	}
	in := &ssInbound{service: service}
	if config.Network != "udp" {
		if in.listener, err = net.Listen("tcp", config.Listen); err != nil {
			return nil, err
		}
		go acceptLoop(in.listener, in.serve)
	}
	if config.Network != "tcp" {
		addr, err := net.ResolveUDPAddr("udp", config.Listen)
		if err == nil {
			in.udpConn, err = net.ListenUDP("udp", addr)
		}
		if err != nil {
			in.close()
			return nil, err
		}
		go in.loopUDP()
	}
	return in, nil
}

func (in *ssInbound) serve(conn net.Conn) {
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	if err := in.service.NewConnection(context.Background(), conn, M.Metadata{Source: source}); err != nil {
		conn.Close()
		if verbose {
			log.Print("ss2022: connection from ", source, ": ", err)
		}
	}
}

func (in *ssInbound) loopUDP() {
	writer := bufio.NewPacketConn(in.udpConn)
	for {
		// The service keeps the buffer, so each packet gets a new one.
		buffer := buf.NewPacket()
		n, addr, err := in.udpConn.ReadFromUDPAddrPort(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			if !errors.Is(err, net.ErrClosed) {
				log.Print("ss2022: udp: ", err)
			}
			return
		}
		if !allowed(addr.Addr()) {
			buffer.Release()
			continue
		}
		buffer.Truncate(n)
		source := M.SocksaddrFromNetIP(addr).Unwrap()
		if err = in.service.NewPacket(context.Background(), writer, buffer, M.Metadata{Source: source}); err != nil && verbose {
			log.Print("ss2022: packet from ", source, ": ", err)
		}
	}
}

func (in *ssInbound) updateUsers(users []UserConfig) error {
	var names, keys []string
	for _, u := range users {
		if u.SSKey != "" {
			names = append(names, u.Name)
			keys = append(keys, u.SSKey)
		}
	}
	return in.service.UpdateUsersWithPasswords(names, keys)
}

func (in *ssInbound) close() error {
	if in.listener != nil {
		in.listener.Close()
	}
	if in.udpConn != nil {
		in.udpConn.Close()
	}
	return nil
}

// ssHandler adapts the shared handler to sing-shadowsocks' older interface.
type ssHandler struct{ *handler }

//nolint:staticcheck
func (h ssHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.NewConnectionEx(ctx, conn, metadata.Source, metadata.Destination, nil)
	return nil
}

//nolint:staticcheck
func (h ssHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	h.NewPacketConnectionEx(ctx, conn, metadata.Source, metadata.Destination, nil)
	return nil
}

func (h ssHandler) NewError(ctx context.Context, err error) {
	if verbose {
		log.Print("ss2022: ", err)
	}
}
