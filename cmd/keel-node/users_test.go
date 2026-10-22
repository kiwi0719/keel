package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestQuotaPeriodAndRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "usage.json")
	r := newRegistry(state)
	r.apply([]UserConfig{{Name: "a", QuotaBytes: 100, Period: "p1"}, {Name: "b"}})

	a := r.lookup("a")
	a.down.Add(60)
	if r.check(time.Now()) || r.lookup("a") == nil {
		t.Fatal("a blocked before reaching quota")
	}
	a.up.Add(40)
	if !r.check(time.Now()) || r.lookup("a") != nil {
		t.Fatal("a not blocked at quota")
	}
	if got := len(r.active()); got != 1 {
		t.Fatalf("active users = %d, want 1", got)
	}

	// Counters survive a restart within the same period.
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	r2 := newRegistry(state)
	r2.apply([]UserConfig{{Name: "a", QuotaBytes: 100, Period: "p1"}})
	if r2.lookup("a") != nil {
		t.Fatal("a unblocked after restart")
	}

	// A new period starts from zero.
	r2.apply([]UserConfig{{Name: "a", QuotaBytes: 100, Period: "p2"}})
	if r2.lookup("a") == nil {
		t.Fatal("a still blocked in new period")
	}
}

func TestExpiryAndRemoval(t *testing.T) {
	r := newRegistry("")
	r.apply([]UserConfig{{Name: "a", ExpireAt: time.Now().Add(time.Hour).Unix()}})
	if r.lookup("a") == nil {
		t.Fatal("a blocked before expiry")
	}
	r.check(time.Now().Add(2 * time.Hour))
	if r.lookup("a") != nil {
		t.Fatal("a not blocked after expiry")
	}

	conn := &fakeConn{}
	r.apply([]UserConfig{{Name: "b"}})
	r.lookup("b").track(conn)
	r.apply(nil)
	if !conn.closed {
		t.Fatal("removing b did not close its connection")
	}
}

type fakeConn struct{ closed bool }

func (c *fakeConn) Close() error { c.closed = true; return nil }
