//go:build vless

package main

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestCheckAddons(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"empty", nil, true},
		{"flow", append([]byte{0x0a, 16}, "xtls-rprx-vision"...), true},
		{"flow length past the block", []byte{0x0a, 0x7f, 'x'}, false},
		{"huge flow length", []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, false},
		{"truncated varint", []byte{0x0a, 0xff}, false},
		{"not length-delimited", []byte{0x08, 0x01}, false},
	}
	for _, c := range cases {
		if err := checkAddons(c.in); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestCheckVLESSRequestReplaysPrefix(t *testing.T) {
	addons := append([]byte{0x0a, 16}, "xtls-rprx-vision"...)
	req := append([]byte{0}, make([]byte, 16)...)
	req = append(req, byte(len(addons)))
	req = append(req, addons...)
	rest := []byte{1, 0, 80, 1, 1, 2, 3, 4}
	client, server := net.Pipe()
	go func() { client.Write(append(append([]byte{}, req...), rest...)); client.Close() }()
	prefix, err := checkVLESSRequest(server)
	if err != nil {
		t.Fatal(err)
	}
	conn := &realityConn{prefix: prefix}
	got := make([]byte, len(req))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, req) {
		t.Fatalf("replayed %x, %v; want %x", got, err, req)
	}
}
