package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAllowList(t *testing.T) {
	list, err := parseAllowList([]string{"192.0.2.7", "198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	currentAllow.Store(list)
	defer currentAllow.Store(nil)
	for addr, want := range map[string]bool{
		"192.0.2.7": true, "::ffff:192.0.2.7": true, "192.0.2.8": false,
		"198.51.100.200": true, "203.0.113.1": false,
	} {
		if got := allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("allowed(%s) = %v, want %v", addr, got, want)
		}
	}
	if _, err := parseAllowList([]string{"example.com"}); err == nil {
		t.Error("a domain should be rejected")
	}
}

func TestAcceptLoopDropsOthers(t *testing.T) {
	list, _ := parseAllowList([]string{"192.0.2.7"})
	currentAllow.Store(list)
	defer currentAllow.Store(nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan struct{}, 1)
	go acceptLoop(ln, func(c net.Conn) { served <- struct{}{}; c.Close() })
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("expected the connection to be closed")
	}
	select {
	case <-served:
		t.Error("connection from a source outside allow_from was served")
	default:
	}
}
