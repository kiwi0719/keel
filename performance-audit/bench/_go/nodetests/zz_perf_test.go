package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func BenchmarkIsPublicSerial(b *testing.B) {
	addr := netip.MustParseAddr("93.184.216.34")
	isPublic(addr)
	for b.Loop() {
		isPublic(addr)
	}
}

func BenchmarkIsPublicParallel(b *testing.B) {
	addr := netip.MustParseAddr("93.184.216.34")
	isPublic(addr)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			isPublic(addr)
		}
	})
}

func benchRouter(b *testing.B) *router {
	var rules []RuleConfig
	for _, name := range []string{"ai", "youtube", "streaming", "telegram", "games", "google"} {
		rules = append(rules, RuleConfig{Name: name, File: filepath.Join("..", "..", "rules", name+".list"), Outbound: OutboundList{"direct"}})
	}
	r, err := newRouter(&Config{Route: RouteConfig{Rules: rules}}, nil)
	if err != nil {
		b.Fatal(err)
	}
	return r
}

func BenchmarkPickMissDomain(b *testing.B) {
	r := benchRouter(b)
	d := M.ParseSocksaddr("static.cdn.example-site.com:443")
	for b.Loop() {
		r.pick(d)
	}
}

func BenchmarkPickMissDomainParallel(b *testing.B) {
	r := benchRouter(b)
	d := M.ParseSocksaddr("static.cdn.example-site.com:443")
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.pick(d)
		}
	})
}

func BenchmarkPickMissIP(b *testing.B) {
	r := benchRouter(b)
	d := M.ParseSocksaddr("93.184.216.34:443")
	for b.Loop() {
		r.pick(d)
	}
}

func makeRegistry(b testing.TB, n int, path string) *registry {
	r := newRegistry(path)
	users := make([]UserConfig, n)
	for i := range users {
		users[i] = UserConfig{Name: fmt.Sprint("u", 1000+i), AnyTLSPassword: "x", Period: "2026-10", QuotaBytes: 100 << 30}
	}
	r.apply(users)
	i := 0
	for _, u := range r.users {
		u.up.Store(int64(123456789 + i*7919))
		u.down.Store(int64(9876543210 + i*104729))
		i++
	}
	return r
}

func BenchmarkUsageSave(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := makeRegistry(b, n, filepath.Join(b.TempDir(), "usage.json"))
			for b.Loop() {
				if err := r.save(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUsageSnapshot(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := makeRegistry(b, n, "")
			for b.Loop() {
				r.usage()
			}
		})
	}
}

func BenchmarkQuotaCheck(b *testing.B) {
	for _, n := range []int{1000, 5000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := makeRegistry(b, n, "")
			for b.Loop() {
				r.check(time.Now())
			}
		})
	}
}

// TestPerfSizes prints the size of a report and of a pushed config for N users.
func TestPerfSizes(t *testing.T) {
	for _, n := range []int{10, 100, 1000, 5000} {
		r := makeRegistry(t, n, "")
		report := reportMessage{Type: "report", TS: 1761100000, ConfigRev: 13, Users: r.usage(), System: SystemStats{CPUPct: 3.2, MemTotal: 1 << 30}}
		rep, _ := json.Marshal(report)
		users := make([]UserConfig, n)
		for i := range users {
			users[i] = UserConfig{Name: fmt.Sprint("u", 1000+i), AnyTLSPassword: "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF", UUID: "80cc6a3a-1514-4342-af5b-78008172e101",
				Flow: "xtls-rprx-vision", SSKey: "Dx4NiV8victJxIdnEHdBVA==", Period: "2026-10", QuotaBytes: 107374182400, ExpireAt: 1798732800,
				UsedBase: 5368709120, UsedSelf: 123456789012}
		}
		cfg, _ := json.Marshal(map[string]any{"type": "config", "rev": 14, "config": Config{Users: users}})
		usage, _ := json.Marshal(usageFile{Users: func() map[string]savedUsage {
			m := map[string]savedUsage{}
			for _, u := range r.usage() {
				m[u.Name] = savedUsage{Period: u.Period, Up: u.Up, Down: u.Down}
			}
			return m
		}()})
		month := 30 * 86400.0
		t.Logf("users=%5d report=%7d B (%.1f GB/month at 5 s)  config=%8d B (%.1f GB/month at 60 s)  usage.json=%7d B (%.1f GB/day written at 2 s)",
			n, len(rep), float64(len(rep))*month/5/1e9, len(cfg), float64(len(cfg))*month/60/1e9, len(usage), float64(len(usage))*86400/2/1e9)
	}
}
