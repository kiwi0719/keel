package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// dnsCache resolves names for the direct outbound. Go's own resolver keeps
// nothing, so every proxied connection to a name waited for a DNS round
// trip, and a UDP session to a name that did not resolve waited 5 s on every
// packet.
//
// Answers are kept for dnsHit (failures for dnsMiss): Go does not expose the
// TTL, so these are fixed upper bounds. Concurrent lookups of one name share
// one query. The private-address checks still apply to every address an
// answer yields, where it is dialed or sent to.
type dnsCache struct {
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)

	mu      sync.Mutex
	entries map[dnsKey]*dnsEntry
}

type dnsKey struct {
	name string
	ipv4 bool
}

type dnsEntry struct {
	done    chan struct{} // closed once addrs and err are set
	addrs   []netip.Addr
	err     error
	expires time.Time
}

const (
	dnsHit        = 30 * time.Second
	dnsMiss       = 10 * time.Second
	dnsTimeout    = 5 * time.Second
	dnsMaxEntries = 4096
)

var errNoAddress = errors.New("no address for the name")

var resolver = &dnsCache{lookup: net.DefaultResolver.LookupNetIP, entries: make(map[dnsKey]*dnsEntry)}

// resolve returns name's addresses, preferred first. It waits at most wait
// (and no longer than ctx) for a lookup to finish; one that is still going
// keeps going in the background and fills the cache.
func (c *dnsCache) resolve(ctx context.Context, name string, ipv4 bool, wait time.Duration) ([]netip.Addr, error) {
	e := c.entry(dnsKey{strings.ToLower(strings.TrimSuffix(name, ".")), ipv4})
	select {
	case <-e.done:
		return e.addrs, e.err
	default:
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-e.done:
		return e.addrs, e.err
	case <-timer.C:
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// cached returns name's addresses only if they are already known, starting
// a lookup otherwise.
func (c *dnsCache) cached(name string, ipv4 bool) ([]netip.Addr, bool) {
	e := c.entry(dnsKey{strings.ToLower(strings.TrimSuffix(name, ".")), ipv4})
	select {
	case <-e.done:
		return e.addrs, e.err == nil
	default:
		return nil, false
	}
}

// entry returns the live entry for key, starting a lookup when there is none.
func (c *dnsCache) entry(key dnsKey) *dnsEntry {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil {
		select {
		case <-e.done:
			if now.Before(e.expires) {
				return e
			}
		default:
			return e // in flight
		}
	}
	if len(c.entries) >= dnsMaxEntries {
		c.evictLocked(now)
	}
	e := &dnsEntry{done: make(chan struct{})}
	c.entries[key] = e
	go c.run(key, e)
	return e
}

func (c *dnsCache) run(key dnsKey, e *dnsEntry) {
	network := "ip"
	if key.ipv4 {
		network = "ip4"
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	addrs, err := c.lookup(ctx, network, key.name)
	cancel()
	if err == nil && len(addrs) == 0 {
		err = errNoAddress
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	c.mu.Lock()
	e.addrs, e.err = addrs, err
	if err != nil {
		e.expires = time.Now().Add(dnsMiss)
	} else {
		e.expires = time.Now().Add(dnsHit)
	}
	close(e.done)
	c.mu.Unlock()
}

// evictLocked drops expired entries, then, if still full, an eighth of the
// finished ones: a user naming endless hosts must not grow the cache.
func (c *dnsCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		select {
		case <-e.done:
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		default:
		}
	}
	drop := len(c.entries) - dnsMaxEntries + dnsMaxEntries/8
	for k, e := range c.entries {
		if drop <= 0 {
			break
		}
		select {
		case <-e.done:
			delete(c.entries, k)
			drop--
		default:
		}
	}
}

// fallbackDelay is how long the preferred address family gets before the
// other one is tried too, as Go's dialer does (RFC 6555).
const fallbackDelay = 300 * time.Millisecond

// dialAddrs connects to the first of addrs that answers: the addresses of the
// preferred (first) family in turn, and after fallbackDelay the other family
// in parallel.
func dialAddrs(ctx context.Context, dialer *net.Dialer, network string, addrs []netip.Addr, port uint16) (net.Conn, error) {
	var primary, fallback []netip.Addr
	for _, a := range addrs {
		if a.Is4() == addrs[0].Is4() {
			primary = append(primary, a)
		} else {
			fallback = append(fallback, a)
		}
	}
	if len(fallback) == 0 {
		return dialSerial(ctx, dialer, network, primary, port)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 2)
	race := func(list []netip.Addr) {
		conn, err := dialSerial(ctx, dialer, network, list, port)
		results <- result{conn, err}
	}
	go race(primary)
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	running, fellBack := 1, false
	var firstErr error
	for {
		select {
		case <-timer.C:
			if !fellBack {
				fellBack, running = true, running+1
				go race(fallback)
			}
		case r := <-results:
			running--
			if r.err == nil {
				go func(n int) { // the other race may still connect
					for ; n > 0; n-- {
						if late := <-results; late.conn != nil {
							late.conn.Close()
						}
					}
				}(running)
				return r.conn, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
			if !fellBack {
				fellBack, running = true, running+1
				go race(fallback)
			} else if running == 0 {
				return nil, firstErr
			}
		}
	}
}

// dialSerial tries addrs in turn, giving each a fair share of the time left,
// as Go's dialer does.
func dialSerial(ctx context.Context, dialer *net.Dialer, network string, addrs []netip.Addr, port uint16) (net.Conn, error) {
	var firstErr error
	for i, a := range addrs {
		attempt := ctx
		if deadline, ok := ctx.Deadline(); ok {
			share := time.Until(deadline) / time.Duration(len(addrs)-i)
			if share < 2*time.Second {
				share = 2 * time.Second
			}
			if d := time.Now().Add(share); d.Before(deadline) {
				var cancel context.CancelFunc
				attempt, cancel = context.WithDeadline(ctx, d)
				defer cancel()
			}
		}
		conn, err := dialer.DialContext(attempt, network, netip.AddrPortFrom(a, port).String())
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}
