//go:build anytls

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"

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
	acme      *certManager // nil unless the certificate comes from ACME
}

func newAnyTLSInbound(config InboundConfig, h *handler) (inbound, error) {
	scheme := padding.DefaultPaddingScheme
	if len(config.PaddingScheme) > 0 {
		scheme = []byte(strings.Join(config.PaddingScheme, "\n"))
		if padding.NewPaddingFactory(scheme) == nil {
			return nil, errors.New("anytls: invalid padding_scheme (needs a stop=N line)")
		}
	}
	service, err := anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: scheme,
		Handler:       h,
		Logger:        stdLogger{},
	})
	if err != nil {
		return nil, err
	}
	in := &anytlsInbound{service: service}
	if config.ACME != nil {
		if in.acme, err = newCertManager(config.ServerName, config.Listen, *config.ACME); err != nil {
			return nil, err
		}
		in.tlsConfig = in.acme.tlsConfig()
	} else {
		cert, err := anytlsCert(config)
		if err != nil {
			return nil, err
		}
		in.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	if in.listener, err = net.Listen("tcp", config.Listen); err != nil {
		if in.acme != nil {
			in.acme.close()
		}
		return nil, err
	}
	go acceptLoop(in.listener, in.serve)
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
	if tlsConn.ConnectionState().NegotiatedProtocol == acmeTLSALPN {
		tlsConn.Close() // the CA's tls-alpn-01 check is done with the handshake
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
	if in.acme != nil {
		in.acme.close()
	}
	return in.listener.Close()
}
