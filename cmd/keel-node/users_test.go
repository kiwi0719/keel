package main

import (
	"io"
	"os"
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

func TestUsageSurvivesRemovalAndCrash(t *testing.T) {
	r := newRegistry("")
	r.apply([]UserConfig{{Name: "u1", Period: "p"}})
	r.users["u1"].up.Store(500)
	// Taken off the node and put back in the same period: counters come back.
	r.apply(nil)
	r.apply([]UserConfig{{Name: "u1", Period: "p"}})
	if got := r.users["u1"].used(); got != 500 {
		t.Fatalf("after re-adding, used = %d, want 500", got)
	}
	// A restarted node that lost counters is lifted to what the master has.
	r2 := newRegistry("")
	r2.apply([]UserConfig{{Name: "u1", Period: "p", UsedSelf: 800}})
	if got := r2.users["u1"].used(); got != 800 {
		t.Fatalf("with used_self 800, used = %d", got)
	}
	// A new period starts from zero.
	r.apply([]UserConfig{{Name: "u1", Period: "q"}})
	if got := r.users["u1"].used(); got != 0 {
		t.Fatalf("new period, used = %d", got)
	}
}

func TestUserConnectionCap(t *testing.T) {
	old := maxUserConns
	maxUserConns = 2
	defer func() { maxUserConns = old }()
	u := &userState{conns: make(map[io.Closer]struct{})}
	a, b := nopCloser{1}, nopCloser{2}
	u.track(a)
	if u.full() {
		t.Fatal("full after one connection")
	}
	untrack := u.track(b)
	if !u.full() {
		t.Fatal("not full at the cap")
	}
	untrack()
	if u.full() {
		t.Fatal("still full after a connection closed")
	}
}

type nopCloser struct{ id int }

func (nopCloser) Close() error { return nil }

func TestSaveSkipsUnchangedCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	r := newRegistry(path)
	r.apply([]UserConfig{{Name: "a", Period: "p"}})
	r.lookup("a").up.Add(100)
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("an unchanged save rewrote the file")
	}
	r.lookup("a").down.Add(1)
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	reloaded := newRegistry(path)
	if s := reloaded.saved["a"]; s.Up != 100 || s.Down != 1 {
		t.Fatalf("saved after a change: %+v", s)
	}
}

func TestUsageMessages(t *testing.T) {
	state := filepath.Join(t.TempDir(), "usage.json")
	cached := func(rev int64) *Config {
		return &Config{Rev: rev, Users: []UserConfig{{Name: "a", QuotaBytes: 100, Period: "p", UsedBase: 10}}}
	}
	r := newRegistry(state)
	r.apply(cached(7).Users)
	if r.applyUsage(7, usageUpdate{rev: 6, users: map[string][2]int64{"a": {200, 0}}}) {
		t.Fatal("took a usage message for another config")
	}
	if !r.applyUsage(7, usageUpdate{rev: 7, users: map[string][2]int64{"a": {95, 3}, "x": {1, 1}}}) {
		t.Fatal("dropped a usage message for the running config")
	}
	a := r.lookup("a")
	if a.up.Load()+a.down.Load() != 3 || a.used() != 98 {
		t.Fatalf("counted %d+%d, used %d; want 3 and 98", a.up.Load(), a.down.Load(), a.used())
	}
	if r.applyUsage(7, usageUpdate{rev: 7, users: map[string][2]int64{"a": {97, 1}}}); a.up.Load()+a.down.Load() != 3 {
		t.Fatal("a lower used_self took counters back")
	}
	if !r.check(time.Now()) || r.lookup("a") != nil {
		t.Fatal("not blocked once used_base reached the quota")
	}
	if err := r.save(); err != nil {
		t.Fatal(err)
	}

	// A restart with the cached config keeps the newer figures; another
	// config does not take them.
	r2 := newRegistry(state)
	c := cached(7)
	r2.restoreUsage(c)
	if c.Users[0].UsedBase != 97 {
		t.Fatalf("restored used_base %d, want 97", c.Users[0].UsedBase)
	}
	r2.apply(c.Users)
	if r2.lookup("a") != nil {
		t.Fatal("unblocked by a restart")
	}
	other := cached(8)
	r2.restoreUsage(other)
	if other.Users[0].UsedBase != 10 {
		t.Fatal("figures for rev 7 applied to rev 8")
	}

	// A config fresh from the master replaces them for good.
	r2.forgetUsage()
	if err := r2.save(); err != nil {
		t.Fatal(err)
	}
	c = cached(7)
	newRegistry(state).restoreUsage(c)
	if c.Users[0].UsedBase != 10 {
		t.Fatal("figures survived a config from the master")
	}
}
