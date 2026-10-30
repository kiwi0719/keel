//go:build vless

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestVLESSOutboundVerifiesTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	v, err := newVLESSOutbound(OutboundConfig{Server: addr, UUID: "0f8b7a52-1111-4222-8333-444455556666", TLS: &OutboundTLSConfig{ServerName: "example.com"}}, &directOutbound{allowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := v.dialTCP(ctx, M.ParseSocksaddrHostPort("example.org", 80)); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a server with an untrusted certificate was accepted: %v", err)
	}
}
