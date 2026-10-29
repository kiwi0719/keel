package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"sort"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	defaultHealthURL      = "http://www.gstatic.com/generate_204"
	defaultHealthInterval = 15 * time.Second
	healthTimeout         = 5 * time.Second
	// A first failure (or, while dead, a first success) is confirmed this
	// soon instead of waiting a whole interval.
	healthConfirm = 2 * time.Second
)

type healthCheck struct {
	url      *url.URL
	interval time.Duration
}

func newHealthCheck(c HealthCheckConfig) healthCheck {
	h := healthCheck{interval: defaultHealthInterval}
	if d := time.Duration(c.Interval); d >= 5*time.Second {
		h.interval = d
	}
	raw := c.URL
	if raw == "" {
		raw = defaultHealthURL
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" { // validated with the config
		h.url = parsed
	} else {
		h.url, _ = url.Parse(defaultHealthURL)
	}
	return h
}

// outboundHealth says whether an outbound currently works. An outbound
// starts alive; two failed checks in a row mark it dead and two successful
// ones alive again.
type outboundHealth struct {
	config OutboundConfig

	mu        sync.Mutex
	alive     bool
	streak    int // consecutive results disagreeing with alive
	latencyMs float64
	checkedAt int64
	lastError string
	next      time.Time
	running   bool
}

func newOutboundHealth(c OutboundConfig) *outboundHealth {
	return &outboundHealth{config: c, alive: true}
}

func (h *outboundHealth) isAlive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.alive
}

func (h *outboundHealth) suspect() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.alive && h.streak == 0 {
		h.next = time.Time{}
	}
}

// due reports whether a check should start now and marks it running.
func (h *outboundHealth) due(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running || now.Before(h.next) {
		return false
	}
	h.running = true
	return true
}

func (h *outboundHealth) record(tag string, ok bool, latency time.Duration, err error, interval time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	h.checkedAt = time.Now().Unix()
	if ok {
		h.latencyMs = float64(latency.Microseconds()) / 1000
		h.lastError = ""
	} else {
		h.lastError = err.Error()
		if len(h.lastError) > 200 {
			h.lastError = h.lastError[:200]
		}
	}
	if ok == h.alive {
		h.streak = 0
		h.next = time.Now().Add(interval)
		return
	}
	h.streak++
	if h.streak < 2 {
		h.next = time.Now().Add(healthConfirm)
		return
	}
	h.alive, h.streak = ok, 0
	h.next = time.Now().Add(interval)
	if ok {
		log.Printf("outbound %s is alive again (%.0f ms)", tag, h.latencyMs)
	} else {
		log.Printf("outbound %s is dead: %v", tag, err)
	}
}

// OutboundStatus is one outbound's health as reported to the master.
type OutboundStatus struct {
	Tag       string  `json:"tag"`
	Alive     bool    `json:"alive"`
	LatencyMs float64 `json:"latency_ms"` // last successful check
	CheckedAt int64   `json:"checked_at"` // unix seconds, 0 before the first check
	Error     string  `json:"error,omitempty"`
}

func (r *router) outboundStatus() []OutboundStatus {
	list := make([]OutboundStatus, 0, len(r.health))
	for tag, h := range r.health {
		h.mu.Lock()
		list = append(list, OutboundStatus{Tag: tag, Alive: h.alive, LatencyMs: h.latencyMs, CheckedAt: h.checkedAt, Error: h.lastError})
		h.mu.Unlock()
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Tag < list[j].Tag })
	return list
}

// runHealthChecks checks the current router's outbounds as they fall due.
func runHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(time.Second / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r := currentRouter.Load()
			if r == nil {
				continue
			}
			for tag, h := range r.health {
				if h.due(now) {
					go func() {
						latency, err := checkOutbound(ctx, r.outbound[tag], r.healthCheck.url)
						h.record(tag, err == nil, latency, err, r.healthCheck.interval)
					}()
				}
			}
		}
	}
}

// checkOutbound fetches target through out and expects any HTTP response.
func checkOutbound(ctx context.Context, out outbound, target *url.URL) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	port := target.Port()
	if port == "" {
		port = "80"
	}
	start := time.Now()
	conn, err := out.dialTCP(ctx, M.ParseSocksaddrHostPortStr(target.Hostname(), port))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	path := target.RequestURI()
	if _, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", path, target.Host); err != nil {
		return 0, err
	}
	// The far end of the outbound picks what comes back: read at most a
	// short status line, and quote at most a little of it.
	line, err := bufio.NewReaderSize(io.LimitReader(conn, 256), 256).ReadSlice('\n')
	if !bytes.HasPrefix(line, []byte("HTTP/1.")) {
		if len(line) == 0 && err != nil {
			return 0, fmt.Errorf("no response: %w", err)
		}
		return 0, fmt.Errorf("unexpected response %q", bytes.TrimSpace(line[:min(len(line), 64)]))
	}
	return time.Since(start), nil
}
