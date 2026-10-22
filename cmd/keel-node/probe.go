package main

import (
	"context"
	"math"
	"net"
	"sync"
	"time"
)

// ProbeTarget is a host the node measures its route to, e.g. a China
// Telecom, Unicom or Mobile address.
type ProbeTarget struct {
	Name string `json:"name"` // e.g. "ct", "cu", "cm"
	Host string `json:"host"` // ip:port reachable over TCP
}

// ProbeResult summarizes one round of TCP connects to a target.
type ProbeResult struct {
	Name      string  `json:"name"`
	Host      string  `json:"host"`
	LatencyMs float64 `json:"latency_ms"` // mean connect time of successful attempts
	JitterMs  float64 `json:"jitter_ms"`  // mean difference between consecutive successful attempts
	LossPct   float64 `json:"loss_pct"`   // timeouts plus connects that took a SYN retransmit (>= 1 s)
	Samples   int     `json:"samples"`
	At        int64   `json:"at"` // unix seconds when the round finished; same for all targets of a round
}

const (
	defaultProbeInterval = 30 * time.Second
	probeSamples         = 10
	// A connect this slow needed a retransmitted SYN (initial RTO is 1 s),
	// so it counts as a lost packet rather than a latency sample.
	probeRetransmitted = time.Second
	probeTimeout       = 2 * time.Second
)

var probeSpacing = 500 * time.Millisecond // a var so tests can shorten it

// prober runs a TCPing round against every target each probeInterval and
// keeps the latest result per target.
type prober struct {
	mu       sync.Mutex
	targets  []ProbeTarget
	results  map[string]ProbeResult
	ipv4     bool
	interval time.Duration
	wake     chan struct{} // starts a round early when the targets change
}

func newProber() *prober {
	return &prober{results: make(map[string]ProbeResult), interval: defaultProbeInterval, wake: make(chan struct{}, 1)}
}

func (p *prober) setTargets(targets []ProbeTarget, ipv4Only bool, interval time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = targets
	p.ipv4 = ipv4Only
	p.interval = defaultProbeInterval
	if interval >= 5*time.Second {
		p.interval = interval
	}
	keep := make(map[string]ProbeResult)
	changed := len(targets) != len(p.results)
	for _, t := range targets {
		if r, ok := p.results[t.Name]; ok && r.Host == t.Host {
			keep[t.Name] = r
		} else {
			changed = true
		}
	}
	p.results = keep
	if changed && len(targets) > 0 {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
}

func (p *prober) latest() []ProbeResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := make([]ProbeResult, 0, len(p.targets))
	for _, t := range p.targets {
		if r, ok := p.results[t.Name]; ok {
			list = append(list, r)
		}
	}
	return list
}

func (p *prober) run(ctx context.Context) {
	for {
		start := time.Now()
		p.round(ctx)
		p.mu.Lock()
		next := p.interval - time.Since(start)
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(max(next, time.Second)):
		case <-p.wake:
		}
	}
}

func (p *prober) round(ctx context.Context) {
	p.mu.Lock()
	targets, ipv4 := p.targets, p.ipv4
	p.mu.Unlock()
	results := make([]ProbeResult, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = tcping(ctx, target, ipv4)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	// Publish the round at once with one timestamp, so a report never
	// carries half a round.
	at := time.Now().Unix()
	p.mu.Lock()
	for _, r := range results {
		r.At = at
		p.results[r.Name] = r
	}
	p.mu.Unlock()
}

func tcping(ctx context.Context, target ProbeTarget, ipv4 bool) ProbeResult {
	network := "tcp"
	if ipv4 {
		network = "tcp4"
	}
	dialer := net.Dialer{Timeout: probeTimeout}
	var times []float64
	for i := range probeSamples {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ProbeResult{Name: target.Name, Host: target.Host}
			case <-time.After(probeSpacing):
			}
		}
		start := time.Now()
		conn, err := dialer.DialContext(ctx, network, target.Host)
		if err != nil {
			continue
		}
		elapsed := time.Since(start)
		conn.Close()
		if elapsed < probeRetransmitted {
			times = append(times, float64(elapsed.Microseconds())/1000)
		}
	}
	return summarizeProbe(target, times, probeSamples)
}

func summarizeProbe(target ProbeTarget, times []float64, samples int) ProbeResult {
	r := ProbeResult{Name: target.Name, Host: target.Host, Samples: samples}
	r.LossPct = 100 * float64(samples-len(times)) / float64(samples)
	if len(times) == 0 {
		return r
	}
	var sum, diff float64
	for i, t := range times {
		sum += t
		if i > 0 {
			diff += math.Abs(t - times[i-1])
		}
	}
	r.LatencyMs = round2(sum / float64(len(times)))
	if len(times) > 1 {
		r.JitterMs = round2(diff / float64(len(times)-1))
	}
	return r
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
