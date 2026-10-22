package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config is the whole node configuration. It is read from a local JSON file
// and re-read whenever the file changes; later the master pushes the same
// structure over its control connection.
type Config struct {
	// Rev is set by the master; a node reports the rev it runs.
	Rev       int64            `json:"rev,omitempty"`
	Route     RouteConfig      `json:"route"`
	Outbounds []OutboundConfig `json:"outbounds,omitempty"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Users     []UserConfig     `json:"users"`
	// Probes are TCPing targets (China Telecom / Unicom / Mobile) reported
	// with latency, jitter and loss.
	Probes []ProbeTarget `json:"probes,omitempty"`
	// ProbeInterval is the time between probe rounds; default 30s.
	ProbeInterval Duration `json:"probe_interval,omitempty"`
}

// RouteConfig picks an outbound for each connection: the first rule whose
// list matches the destination wins, otherwise Final.
type RouteConfig struct {
	// IPv4Only dials and resolves IPv4 only (the old -4 flag).
	IPv4Only bool         `json:"ipv4_only,omitempty"`
	Rules    []RuleConfig `json:"rules,omitempty"`
	// Final is the outbound for everything no rule matched; default "direct".
	Final string `json:"final,omitempty"`
}

type RuleConfig struct {
	Name     string   `json:"name,omitempty"` // shown in logs, e.g. "ai"
	File     string   `json:"file,omitempty"` // list file, reloaded when it changes
	Domains  []string `json:"domains,omitempty"`
	Outbound string   `json:"outbound"`
}

// OutboundConfig is a way out of the node besides the built-in "direct".
type OutboundConfig struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`   // ss2022 | socks
	Server string `json:"server"` // host:port

	// ss2022: Password is "<server psk>:<user key>" as for any SS 2022 client.
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	// UDPOverTCP carries UDP inside the TCP connection to the server instead
	// of SS 2022 UDP packets.
	UDPOverTCP bool `json:"udp_over_tcp,omitempty"`
}

// InboundConfig describes one listener. Which fields apply depends on Type.
type InboundConfig struct {
	Type   string `json:"type"` // anytls | vless | ss2022
	Listen string `json:"listen"`

	// anytls
	Cert string `json:"cert,omitempty"`
	Key  string `json:"key,omitempty"`

	// vless
	Reality *RealityConfig `json:"reality,omitempty"`

	// ss2022
	Method   string `json:"method,omitempty"`   // e.g. 2022-blake3-aes-128-gcm
	Password string `json:"password,omitempty"` // server PSK, base64
	Network  string `json:"network,omitempty"`  // "tcp", "udp" or "" for both
}

// RealityConfig uses the same names as Xray's realitySettings.
type RealityConfig struct {
	Dest        string   `json:"dest"`
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"` // X25519, base64 raw URL encoding
	ShortIDs    []string `json:"short_ids"`
	MaxTimeDiff Duration `json:"max_time_diff,omitempty"`
}

type UserConfig struct {
	Name string `json:"name"`

	// Credentials; a user without one is not enabled on that protocol.
	AnyTLSPassword string `json:"anytls_password,omitempty"`
	UUID           string `json:"uuid,omitempty"`
	Flow           string `json:"flow,omitempty"` // "" or xtls-rprx-vision
	SSKey          string `json:"ss_key,omitempty"`

	// QuotaBytes limits upload+download within Period; 0 means unlimited.
	QuotaBytes int64 `json:"quota_bytes,omitempty"`
	// ExpireAt is a unix time in seconds; 0 means never.
	ExpireAt int64 `json:"expire_at,omitempty"`
	// Period names the current accounting period (e.g. "2026-10"). When it
	// changes, the user's counters start again from zero.
	Period string `json:"period,omitempty"`
	// UsedBase is traffic the master already knows about for this period
	// (e.g. used on this node before a reinstall); counted toward the quota.
	UsedBase int64 `json:"used_base,omitempty"`
}

// Key identifies a listener across reloads: the same key with the same
// settings keeps the listening socket and its connections.
func (c InboundConfig) ID() string {
	return c.Type + "@" + c.Listen
}

func (c InboundConfig) equal(other InboundConfig) bool {
	a, _ := json.Marshal(c)
	b, _ := json.Marshal(other)
	return bytes.Equal(a, b)
}

// loadConfig reads a config file. strict rejects unknown fields, which
// catches typos in hand-written files; a master's cached config may carry
// fields from a newer master and is loaded with strict false.
func loadConfig(path string, strict bool) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config, err := parseConfig(content, strict)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return config, nil
}

// parseConfig decodes and validates a config. strict rejects unknown fields
// (to catch typos in hand-written files); configs from the master are read
// leniently so a newer master can add fields older nodes ignore.
func parseConfig(content []byte, strict bool) (*Config, error) {
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(content))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *Config) validate() error {
	tags := map[string]bool{"direct": true}
	for _, o := range c.Outbounds {
		if o.Tag == "" || tags[o.Tag] {
			return fmt.Errorf("outbound tag %q is empty or used twice (\"direct\" is built in)", o.Tag)
		}
		if o.Type != "ss2022" && o.Type != "socks" {
			return fmt.Errorf("outbound %s: unknown type %q", o.Tag, o.Type)
		}
		if o.Server == "" {
			return fmt.Errorf("outbound %s: server is required", o.Tag)
		}
		tags[o.Tag] = true
	}
	for i, r := range c.Route.Rules {
		if !tags[r.Outbound] {
			return fmt.Errorf("route rule %d: unknown outbound %q", i+1, r.Outbound)
		}
		if r.File == "" && len(r.Domains) == 0 {
			return fmt.Errorf("route rule %d: needs file or domains", i+1)
		}
	}
	if c.Route.Final != "" && !tags[c.Route.Final] {
		return fmt.Errorf("route final: unknown outbound %q", c.Route.Final)
	}
	keys := make(map[string]bool)
	for _, inbound := range c.Inbounds {
		if _, ok := protocols[inbound.Type]; !ok {
			return fmt.Errorf("inbound %s: protocol %q is not built into this binary (built with: %s)", inbound.Listen, inbound.Type, builtProtocols())
		}
		if keys[inbound.ID()] {
			return fmt.Errorf("duplicate inbound %s", inbound.ID())
		}
		keys[inbound.ID()] = true
	}
	names := make(map[string]bool)
	for _, user := range c.Users {
		if user.Name == "" {
			return fmt.Errorf("user without name")
		}
		if names[user.Name] {
			return fmt.Errorf("duplicate user %s", user.Name)
		}
		names[user.Name] = true
	}
	return nil
}

// Duration is a time.Duration written as a Go duration string ("1m30s").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}
