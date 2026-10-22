package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1":          true,
		"2606:4700::1111":  true,
		"127.0.0.1":        false,
		"10.1.2.3":         false,
		"172.16.0.1":       false,
		"192.168.1.1":      false,
		"100.64.0.1":       false,
		"169.254.169.254":  false,
		"0.1.2.3":          false,
		"0.0.0.0":          false,
		"224.0.0.1":        false,
		"::1":              false,
		"::":               false,
		"fe80::1":          false,
		"fd00::1":          false,
		"::ffff:127.0.0.1": false,
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestDirectRefusesLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	dest := M.ParseSocksaddr(ln.Addr().String())

	d := &directOutbound{}
	if _, err := d.dialTCP(context.Background(), dest); !errors.Is(err, errPrivateDestination) {
		t.Fatalf("dialTCP to %s: err = %v, want errPrivateDestination", dest, err)
	}
	// "localhost" resolves to a loopback address and is refused the same way.
	if _, err := d.dialTCP(context.Background(), M.ParseSocksaddrHostPort("localhost", dest.Port)); err == nil {
		t.Fatal("dialTCP to localhost succeeded")
	}
	// Outbound servers may be local (an sslocal on 127.0.0.1).
	c, err := d.dialServer(context.Background(), dest)
	if err != nil {
		t.Fatalf("dialServer: %v", err)
	}
	c.Close()

	open := &directOutbound{allowPrivate: true}
	c, err = open.dialTCP(context.Background(), dest)
	if err != nil {
		t.Fatalf("dialTCP with allow_private: %v", err)
	}
	c.Close()
}
