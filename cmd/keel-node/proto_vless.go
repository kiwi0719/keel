//go:build vless

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func init() {
	protocols["vless"] = newVLESSInbound
}

// vlessInbound serves VLESS (optionally with the xtls-rprx-vision flow) over
// Reality. Clients that fail Reality authentication are passed through to the
// real dest site by utls, so probes see that site's certificate.
type vlessInbound struct {
	listener net.Listener
	reality  *utls.RealityConfig
	handler  *handler
	// service is replaced as a whole on user updates: sing-vmess swaps its
	// user maps without locking, so a fresh service per update avoids races.
	service atomic.Pointer[vless.Service[string]]
}

func newVLESSInbound(config InboundConfig, h *handler) (inbound, error) {
	reality, err := newRealityConfig(config.Reality)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}
	in := &vlessInbound{listener: listener, reality: reality, handler: h}
	in.service.Store(vless.NewService[string](stdLogger{}, h))
	go acceptLoop(listener, in.serve)
	return in, nil
}

func newRealityConfig(c *RealityConfig) (*utls.RealityConfig, error) {
	if c == nil {
		return nil, errors.New("vless inbound needs reality settings")
	}
	if len(c.ServerNames) == 0 || c.ServerNames[0] == "" {
		return nil, errors.New("reality: server_names is required")
	}
	dest := c.Dest
	if dest == "" {
		dest = c.ServerNames[0]
	}
	if _, _, err := net.SplitHostPort(dest); err != nil {
		dest = net.JoinHostPort(dest, "443")
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(c.PrivateKey)
	if err != nil || len(privateKey) != 32 {
		return nil, fmt.Errorf("reality: invalid private_key")
	}
	config := &utls.RealityConfig{
		Type:        "tcp",
		Dest:        dest,
		ServerNames: make(map[string]bool),
		PrivateKey:  privateKey,
		MaxTimeDiff: time.Duration(c.MaxTimeDiff),
		ShortIds:    make(map[[8]byte]bool),
	}
	config.SessionTicketsDisabled = true
	if verbose {
		config.Log = func(format string, v ...any) { log.Printf("reality: "+format, v...) }
	} else {
		config.Log = func(string, ...any) {}
	}
	dialer := net.Dialer{Timeout: dialTimeout}
	config.DialContext = dialer.DialContext
	for _, name := range c.ServerNames {
		config.ServerNames[name] = true
	}
	if len(c.ShortIDs) == 0 {
		config.ShortIds[[8]byte{}] = true
	}
	for _, s := range c.ShortIDs {
		var id [8]byte
		if len(s) > 16 {
			return nil, fmt.Errorf("reality: short id %q longer than 16 hex digits", s)
		}
		if _, err = hex.Decode(id[:], []byte(s)); err != nil {
			return nil, fmt.Errorf("reality: short id %q: %w", s, err)
		}
		config.ShortIds[id] = true
	}
	return config, nil
}

func (in *vlessInbound) serve(conn net.Conn) {
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	tlsConn, err := utls.RealityServer(ctx, conn, in.reality)
	cancel()
	if err != nil {
		conn.Close()
		if verbose {
			log.Print("vless: reality handshake from ", source, ": ", err)
		}
		return
	}
	wrapped := &realityConn{Conn: tlsConn}
	if err = in.service.Load().NewConnection(context.Background(), wrapped, source, nil); err != nil {
		wrapped.Close()
		if verbose {
			log.Print("vless: connection from ", source, ": ", err)
		}
	}
}

func (in *vlessInbound) updateUsers(users []UserConfig) error {
	var names, uuids, flows []string
	for _, u := range users {
		if u.UUID != "" {
			names = append(names, u.Name)
			uuids = append(uuids, u.UUID)
			flows = append(flows, u.Flow)
		}
	}
	service := vless.NewService[string](stdLogger{}, in.handler)
	service.UpdateUsers(names, uuids, flows)
	in.service.Store(service)
	return nil
}

func (in *vlessInbound) close() error {
	return in.listener.Close()
}

// realityConn mirrors sing-box's wrapper: Vision finds the *utls.Conn through
// Upstream, and half-close is turned into a full close because the Reality
// server leaks memory on half-closed connections.
type realityConn struct {
	*utls.Conn
}

func (c *realityConn) Upstream() any           { return c.Conn }
func (c *realityConn) CloseWrite() error       { return c.Close() }
func (c *realityConn) ReaderReplaceable() bool { return true }
func (c *realityConn) WriterReplaceable() bool { return true }

var _ N.ReaderWithUpstream = (*realityConn)(nil)
