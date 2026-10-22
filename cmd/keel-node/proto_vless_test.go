//go:build vless

package main

import "testing"

func TestRealityDefaults(t *testing.T) {
	key := "SMJQ0FS1jB2RWpqxQHcwgqLBi5RUSDBA6ptpbkXDyFs"
	for dest, want := range map[string]string{
		"":                     "www.example.com:443",
		"www.example.org":      "www.example.org:443",
		"www.example.org:8443": "www.example.org:8443",
		"[2001:db8::1]:443":    "[2001:db8::1]:443",
	} {
		c, err := newRealityConfig(&RealityConfig{Dest: dest, ServerNames: []string{"www.example.com", "cdn.example.com"}, PrivateKey: key, ShortIDs: []string{"ab", "0123456789abcdef"}})
		if err != nil || c.Dest != want {
			t.Errorf("dest %q -> %q, %v; want %q", dest, c.Dest, err, want)
			continue
		}
		if !c.ServerNames["cdn.example.com"] || len(c.ShortIds) != 2 {
			t.Errorf("server names %v, short ids %d", c.ServerNames, len(c.ShortIds))
		}
	}
	if _, err := newRealityConfig(&RealityConfig{PrivateKey: key}); err == nil {
		t.Error("missing server_names accepted")
	}
}
