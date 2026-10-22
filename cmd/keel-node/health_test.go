package main

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestOutboundListJSON(t *testing.T) {
	var rule RuleConfig
	for in, want := range map[string]int{`{"outbound":"x1"}`: 1, `{"outbound":["x1","x2"]}`: 2, `{"outbound":""}`: 0} {
		rule = RuleConfig{}
		if err := json.Unmarshal([]byte(in), &rule); err != nil || len(rule.Outbound) != want {
			t.Errorf("%s -> %v, %v", in, rule.Outbound, err)
		}
	}
	if err := json.Unmarshal([]byte(`{"outbound":3}`), &rule); err == nil {
		t.Error("number accepted as outbound")
	}
	out, _ := json.Marshal(RouteConfig{Final: OutboundList{"x1"}})
	if string(out) != `{"final":"x1"}` {
		t.Errorf("single outbound marshals as %s", out)
	}
}

func TestFallbackOrder(t *testing.T) {
	config := &Config{
		Route: RouteConfig{Final: OutboundList{"a", "b"}},
		Outbounds: []OutboundConfig{
			{Tag: "a", Type: "socks", Server: "127.0.0.1:1"},
			{Tag: "b", Type: "socks", Server: "127.0.0.1:2"},
		},
	}
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	r, err := newRouter(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	pick := func() string { return r.firstAlive(r.final) }
	fail := errors.New("down")
	a, b := r.health["a"], r.health["b"]

	a.record("a", false, 0, fail, time.Minute)
	if pick() != "a" {
		t.Fatal("one failure must not switch")
	}
	a.record("a", false, 0, fail, time.Minute)
	if pick() != "b" {
		t.Fatal("two failures must switch to b")
	}
	b.record("b", false, 0, fail, time.Minute)
	b.record("b", false, 0, fail, time.Minute)
	if pick() != "a" {
		t.Fatal("all dead must use the first")
	}
	a.record("a", true, time.Millisecond, nil, time.Minute)
	a.record("a", true, time.Millisecond, nil, time.Minute)
	if pick() != "a" || !a.isAlive() {
		t.Fatal("two successes must bring a back")
	}

	// A reload with the same outbound settings keeps the health state.
	b2, _ := newRouter(config, r)
	if b2.health["b"] != b || b2.health["b"].isAlive() {
		t.Fatal("health not carried over a reload")
	}
	config.Outbounds[1].Server = "127.0.0.1:3"
	b3, _ := newRouter(config, r)
	if !b3.health["b"].isAlive() {
		t.Fatal("changed outbound must start fresh")
	}
}
