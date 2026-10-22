//go:build anytls

package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	M "github.com/sagernet/sing/common/metadata"
)

func init() {
	protocols["anytls"] = newAnyTLSInbound
}

type anytlsInbound struct {
	listener  net.Listener
	service   *anytls.Service
	tlsConfig *tls.Config
}

func newAnyTLSInbound(config InboundConfig, h *handler) (inbound, error) {
	cert, err := loadOrCreateCert(config.Cert, config.Key)
	if err != nil {
		return nil, err
	}
	service, err := anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: padding.DefaultPaddingScheme,
		Handler:       h,
		Logger:        stdLogger{},
	})
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}
	in := &anytlsInbound{
		listener:  listener,
		service:   service,
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go acceptLoop(listener, in.serve)
	return in, nil
}

func (in *anytlsInbound) serve(conn net.Conn) {
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	tlsConn := tls.Server(conn, in.tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		conn.Close()
		if verbose {
			log.Print("anytls: tls handshake from ", source, ": ", err)
		}
		return
	}
	if err = in.service.NewConnection(context.Background(), tlsConn, source, nil); err != nil {
		tlsConn.Close()
		log.Print("anytls: connection from ", source, ": ", err)
	}
}

func (in *anytlsInbound) updateUsers(users []UserConfig) error {
	list := make([]anytls.User, 0, len(users))
	for _, u := range users {
		if u.AnyTLSPassword != "" {
			list = append(list, anytls.User{Name: u.Name, Password: u.AnyTLSPassword})
		}
	}
	in.service.UpdateUsers(list)
	return nil
}

func (in *anytlsInbound) close() error {
	return in.listener.Close()
}
