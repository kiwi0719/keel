package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// fakePacketConn hands out queued packets and records what is written.
type fakePacketConn struct {
	mu      sync.Mutex
	in      chan M.Socksaddr
	written []M.Socksaddr
	closed  chan struct{}
	once    sync.Once
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{in: make(chan M.Socksaddr, 8), closed: make(chan struct{})}
}

func (c *fakePacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	select {
	case d := <-c.in:
		b.WriteString("x")
		return d, nil
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	}
}

func (c *fakePacketConn) WritePacket(b *buf.Buffer, d M.Socksaddr) error {
	b.Release()
	c.mu.Lock()
	c.written = append(c.written, d)
	c.mu.Unlock()
	return nil
}

func (c *fakePacketConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *fakePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakePacketConn) sent() []M.Socksaddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]M.Socksaddr(nil), c.written...)
}

type fakeOutbound struct{ conn *fakePacketConn }

func (o fakeOutbound) dialTCP(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (o fakeOutbound) listenUDP(context.Context, M.Socksaddr) (N.PacketConn, error) {
	return o.conn, nil
}

func TestUDPRoutedPerPacket(t *testing.T) {
	viaA, viaB := newFakePacketConn(), newFakePacketConn()
	r := &router{
		rules:    []routeRule{{name: "a", list: newRuleList("", []string{"a.test"}), outbound: []string{"A"}}},
		final:    []string{"B"},
		outbound: map[string]outbound{"A": fakeOutbound{viaA}, "B": fakeOutbound{viaB}},
		health:   map[string]*outboundHealth{},
	}
	client := newFakePacketConn()
	first := M.ParseSocksaddrHostPort("b.test", 53)
	client.in <- M.ParseSocksaddrHostPort("a.test", 53)   // must not ride B
	client.in <- M.ParseSocksaddrHostPort("10.0.0.1", 53) // private: dropped
	client.in <- M.ParseSocksaddrHostPort("b.test", 443)
	done := make(chan struct{})
	go func() { r.relayUDP(context.Background(), "u", client, nil, first); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (len(viaA.sent()) < 1 || len(viaB.sent()) < 1) {
		time.Sleep(10 * time.Millisecond)
	}
	client.Close()
	<-done
	if got := viaA.sent(); len(got) != 1 || got[0].Fqdn != "a.test" {
		t.Errorf("via A: %v", got)
	}
	for _, d := range viaB.sent() {
		if d.Fqdn == "a.test" || d.IsIP() {
			t.Errorf("via B carried %v", d)
		}
	}
}
