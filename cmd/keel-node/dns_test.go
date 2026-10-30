package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLookup struct {
	calls   atomic.Int32
	release chan struct{} // nil: answer at once
	addrs   []netip.Addr
	err     error
}

func (f *fakeLookup) lookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	if f.release != nil {
		<-f.release
	}
	return append([]netip.Addr(nil), f.addrs...), f.err
}

func newTestCache(f *fakeLookup) *dnsCache {
	return &dnsCache{lookup: f.lookup, entries: make(map[dnsKey]*dnsEntry)}
}

func TestDNSCacheSharesLookupsAndKeepsAnswers(t *testing.T) {
	f := &fakeLookup{release: make(chan struct{}), addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	c := newTestCache(f)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := c.resolve(context.Background(), "Example.COM.", false, 5*time.Second)
			if err != nil || len(addrs) != 1 {
				t.Errorf("resolve: %v %v", addrs, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(f.release)
	wg.Wait()
	if _, err := c.resolve(context.Background(), "example.com", false, time.Second); err != nil {
		t.Fatal(err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d lookups for one name, want 1", n)
	}
	if _, ok := c.cached("example.com", true); ok {
		t.Fatal("an IPv4-only lookup must not reuse the dual-stack answer")
	}
}

func TestDNSCacheKeepsFailuresAndWaitsBriefly(t *testing.T) {
	f := &fakeLookup{release: make(chan struct{}), err: errors.New("no such host")}
	c := newTestCache(f)
	start := time.Now()
	if _, err := c.resolve(context.Background(), "slow.test", false, 50*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a slow lookup: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("waited past the limit")
	}
	if _, ok := c.cached("slow.test", false); ok {
		t.Fatal("cached while still in flight")
	}
	close(f.release)
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if _, err := c.resolve(context.Background(), "slow.test", false, time.Second); err == nil {
			t.Fatal("a failure turned into an answer")
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("a cached failure was looked up again (%d calls)", n)
	}
}

func TestDNSCacheStaysBounded(t *testing.T) {
	f := &fakeLookup{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	c := newTestCache(f)
	for i := 0; i < dnsMaxEntries+500; i++ {
		c.resolve(context.Background(), "h"+itoa(i)+".test", false, time.Second)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > dnsMaxEntries {
		t.Fatalf("%d entries, cap %d", n, dnsMaxEntries)
	}
}

func itoa(i int) string {
	return netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}).String()
}

// The preferred family failing at once must not cost the fallback delay,
// and a dead first address must not keep the second from answering.
func TestDialAddrsFallsBack(t *testing.T) {
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
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(closed.Addr().(*net.TCPAddr).Port)
	closed.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// IPv6 loopback refuses (nothing listens there), IPv4 answers.
	addrs := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}
	start := time.Now()
	conn, err := dialAddrs(ctx, &net.Dialer{}, "tcp", addrs, port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if d := time.Since(start); d > fallbackDelay {
		t.Fatalf("fell back after %v; a refused first family should not wait", d)
	}
	if _, err := dialAddrs(ctx, &net.Dialer{}, "tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, closedPort); err == nil {
		t.Fatal("dialed a closed port")
	}
}
