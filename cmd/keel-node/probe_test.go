package main

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// A dest candidate is a name from the master; one that resolves to a
// private address is never dialed.
func TestDestProbeSkipsPrivateAddresses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()
	defer func(old time.Duration) { probeSpacing = old }(probeSpacing)
	probeSpacing = time.Millisecond
	host := "localhost:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	r := tcping(context.Background(), destTargets([]string{host})[0], true)
	if r.LossPct != 100 || r.Name != host {
		t.Fatalf("probe of %s: %+v", host, r)
	}
	select {
	case <-accepted:
		t.Fatal("dialed a private address")
	case <-time.After(50 * time.Millisecond):
	}
}

// A dest round goes out in one report, and again once on a new connection:
// rounds are minutes apart.
func TestReportCarriesDestRoundOnce(t *testing.T) {
	n := &node{users: newRegistry(""), running: make(map[string]*runningInbound), prober: newProber(), destProber: newProber()}
	if err := n.reload(&Config{DestProbes: []string{"www.example.com:443"}}); err != nil {
		t.Fatal(err)
	}
	n.destProber.results["www.example.com:443"] = ProbeResult{Name: "www.example.com:443", Host: "www.example.com:443", LatencyMs: 12, At: 100}
	m := &masterClient{node: n}
	if r := m.report(); len(r.DestProbes) != 1 || r.DestProbes[0].LatencyMs != 12 {
		t.Fatalf("first report: %+v", r.DestProbes)
	}
	if r := m.report(); len(r.DestProbes) != 0 {
		t.Fatalf("sent twice: %+v", r.DestProbes)
	}
	m.destSent = 0 // what a new session does
	if r := m.report(); len(r.DestProbes) != 1 {
		t.Fatal("not sent again on a new connection")
	}
}
