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
	Outbound OutboundConfig  `json:"outbound"`
	Inbounds []InboundConfig `json:"inbounds"`
	Users    []UserConfig    `json:"users"`
}

type OutboundConfig struct {
	// IPv4Only dials and resolves IPv4 only (the old -4 flag).
	IPv4Only bool `json:"ipv4_only,omitempty"`
	// Socks sends outbound TCP/UDP through this SOCKS5 proxy (host:port).
	Socks string `json:"socks,omitempty"`
	// SocksDomains, when set, limits Socks to the domains in this file.
	SocksDomains string `json:"socks_domains,omitempty"`
	// DirectDomains always bypasses Socks for the domains in this file.
	DirectDomains string `json:"direct_domains,omitempty"`
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

func loadConfig(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err = config.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &config, nil
}

func (c *Config) validate() error {
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
