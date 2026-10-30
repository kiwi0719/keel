package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is the whole node configuration. It is read from a local JSON file
// and re-read whenever the file changes; later the master pushes the same
// structure over its control connection.
type Config struct {
	// Rev is set by the master; a node reports the rev it runs.
	Rev int64 `json:"rev,omitempty"`
	// MasterSPKI is the SHA-256 (hex) of the master's public key. The node
	// accepts a master certificate with this key as well as the -fingerprint
	// one, so the master can move to a CA certificate for the same key.
	MasterSPKI string           `json:"master_spki,omitempty"`
	Route      RouteConfig      `json:"route"`
	Outbounds  []OutboundConfig `json:"outbounds,omitempty"`
	Inbounds   []InboundConfig  `json:"inbounds"`
	Users      []UserConfig     `json:"users"`
	// Probes are TCPing targets (China Telecom / Unicom / Mobile) reported
	// with latency, jitter and loss.
	Probes []ProbeTarget `json:"probes,omitempty"`
	// ProbeInterval is the time between probe rounds; default 30s.
	ProbeInterval Duration `json:"probe_interval,omitempty"`
	// DestProbes are sites (host:port) a REALITY inbound could borrow, timed
	// every destProbeInterval so the panel can offer the nearest.
	DestProbes []string `json:"dest_probes,omitempty"`
}

// RouteConfig picks an outbound for each connection: the first rule whose
// list matches the destination wins, otherwise Final.
type RouteConfig struct {
	// IPv4Only dials and resolves IPv4 only (the old -4 flag).
	IPv4Only bool `json:"ipv4_only,omitempty"`
	// AllowPrivate lets users reach loopback, LAN and other non-public
	// addresses through the direct outbound. Off by default.
	AllowPrivate bool         `json:"allow_private,omitempty"`
	Rules        []RuleConfig `json:"rules,omitempty"`
	// Final is the outbound for everything no rule matched; default "direct".
	Final OutboundList `json:"final,omitempty"`
	// HealthCheck decides when an outbound counts as dead, so lists with
	// several outbounds fall back to the next one.
	HealthCheck HealthCheckConfig `json:"health_check,omitzero"`
}

// HealthCheckConfig: every Interval the node fetches URL (plain http) through
// each outbound. Two failures in a row mark it dead, two successes alive.
type HealthCheckConfig struct {
	URL      string   `json:"url,omitempty"`      // default http://www.gstatic.com/generate_204
	Interval Duration `json:"interval,omitempty"` // default 15s, minimum 5s
}

// OutboundList is one outbound tag or an ordered list of them; the first
// alive one is used. In JSON it is a string or an array of strings.
type OutboundList []string

func (l *OutboundList) UnmarshalJSON(content []byte) error {
	var one string
	if err := json.Unmarshal(content, &one); err == nil {
		*l = OutboundList{one}
		if one == "" {
			*l = nil
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(content, &many); err != nil {
		return fmt.Errorf("outbound must be a tag or a list of tags: %w", err)
	}
	*l = many
	return nil
}

func (l OutboundList) MarshalJSON() ([]byte, error) {
	if len(l) == 1 {
		return json.Marshal(l[0])
	}
	return json.Marshal([]string(l))
}

type RuleConfig struct {
	Name    string   `json:"name,omitempty"` // shown in logs, e.g. "ai"
	File    string   `json:"file,omitempty"` // list file, reloaded when it changes
	Domains []string `json:"domains,omitempty"`
	// Outbound is a tag or an ordered fallback list of tags.
	Outbound OutboundList `json:"outbound"`
}

// OutboundConfig is a way out of the node besides the built-in "direct".
type OutboundConfig struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`   // ss2022 | socks | vless
	Server string `json:"server"` // host:port

	// ss2022: Password is "<server psk>:<user key>" as for any SS 2022 client.
	// Method defaults to 2022-blake3-aes-128-gcm; classic AEAD methods
	// (aes-128-gcm, chacha20-ietf-poly1305, ...) take a plain password.
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	// UDPOverTCP carries UDP inside the TCP connection to the server instead
	// of SS 2022 UDP packets.
	UDPOverTCP bool `json:"udp_over_tcp,omitempty"`

	// vless: a third-party VLESS server (no flow), over TLS when TLS is set,
	// else plain TCP.
	UUID    string                 `json:"uuid,omitempty"`
	Flow    string                 `json:"flow,omitempty"` // "" or "xtls-rprx-vision"
	TLS     *OutboundTLSConfig     `json:"tls,omitempty"`
	Reality *OutboundRealityConfig `json:"reality,omitempty"`
}

// OutboundRealityConfig connects to a VLESS server behind REALITY: the
// server's X25519 public key (base64url), a short ID, the borrowed site's
// name and the TLS fingerprint to present.
type OutboundRealityConfig struct {
	ServerName  string `json:"server_name"`
	PublicKey   string `json:"public_key"`
	ShortID     string `json:"short_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// OutboundTLSConfig makes an outbound connect over TLS, verifying the
// server's certificate (system roots) for ServerName.
type OutboundTLSConfig struct {
	ServerName string `json:"server_name"`
}

// InboundConfig describes one listener. Which fields apply depends on Type.
type InboundConfig struct {
	Type   string `json:"type"` // anytls | vless | ss2022
	Listen string `json:"listen"`

	// anytls. The certificate comes from cert_pem/key_pem, else from the
	// cert/key files (which must exist); with neither the node uses its own
	// self-signed one for server_name (see anytlsCert).
	ServerName string `json:"server_name,omitempty"` // the domain clients use
	Cert       string `json:"cert,omitempty"`
	Key        string `json:"key,omitempty"`
	CertPEM    string `json:"cert_pem,omitempty"`
	KeyPEM     string `json:"key_pem,omitempty"`
	// ACME obtains and renews a certificate for ServerName automatically;
	// until it is issued the node serves a self-signed one.
	ACME *ACMEConfig `json:"acme,omitempty"`
	// PaddingScheme overrides AnyTLS's default padding, one rule per line
	// as in sing-box ("stop=8", "0=30-30", ...).
	PaddingScheme []string `json:"padding_scheme,omitempty"`

	// vless
	Reality *RealityConfig `json:"reality,omitempty"`

	// ss2022
	Method   string `json:"method,omitempty"`   // e.g. 2022-blake3-aes-128-gcm
	Password string `json:"password,omitempty"` // server PSK, base64
	Network  string `json:"network,omitempty"`  // "tcp", "udp" or "" for both
}

// RealityConfig uses the same names as Xray's realitySettings.
type RealityConfig struct {
	// Dest is the site Reality borrows its handshake from, host:port; when
	// empty it is the first server name on port 443.
	Dest string `json:"dest,omitempty"`
	// ServerNames are the SNIs clients may use; the first is the default
	// the master puts in client links.
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
	// UsedSelf is what the master has recorded from this node for this
	// period; the node's own counters never start below it.
	UsedSelf int64 `json:"used_self,omitempty"`
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
		if o.Type != "ss2022" && o.Type != "socks" && o.Type != "vless" {
			return fmt.Errorf("outbound %s: unknown type %q", o.Tag, o.Type)
		}
		if o.Server == "" {
			return fmt.Errorf("outbound %s: server is required", o.Tag)
		}
		if o.Type == "vless" && o.UUID == "" {
			return fmt.Errorf("outbound %s: uuid is required", o.Tag)
		}
		tags[o.Tag] = true
	}
	checkList := func(where string, list OutboundList) error {
		for _, tag := range list {
			if !tags[tag] {
				return fmt.Errorf("%s: unknown outbound %q", where, tag)
			}
		}
		return nil
	}
	for i, r := range c.Route.Rules {
		if len(r.Outbound) == 0 {
			return fmt.Errorf("route rule %d: needs an outbound", i+1)
		}
		if err := checkList(fmt.Sprint("route rule ", i+1), r.Outbound); err != nil {
			return err
		}
		if r.File == "" && len(r.Domains) == 0 {
			return fmt.Errorf("route rule %d: needs file or domains", i+1)
		}
	}
	if err := checkList("route final", c.Route.Final); err != nil {
		return err
	}
	if u := c.Route.HealthCheck.URL; u != "" && !strings.HasPrefix(u, "http://") {
		return fmt.Errorf("route health_check url must be plain http://, got %q", u)
	} else if parsed, err := url.Parse(u); u != "" && (err != nil || parsed.Host == "") {
		return fmt.Errorf("route health_check url %q is not a valid URL", u)
	}
	keys := make(map[string]bool)
	for _, inbound := range c.Inbounds {
		if _, ok := protocols[inbound.Type]; !ok {
			return fmt.Errorf("inbound %s: protocol %q is not built into this binary (built with: %s)", inbound.Listen, inbound.Type, builtProtocols())
		}
		if inbound.ACME != nil && (inbound.Cert != "" || inbound.Key != "" || inbound.CertPEM != "" || inbound.KeyPEM != "") {
			return fmt.Errorf("inbound %s: acme and cert/key/cert_pem are mutually exclusive", inbound.Listen)
		}
		if inbound.ACME != nil && inbound.ServerName == "" {
			return fmt.Errorf("inbound %s: acme needs server_name", inbound.Listen)
		}
		// The name becomes file names under the certificate directory.
		if inbound.ACME != nil && !isDNSName(inbound.ServerName) {
			return fmt.Errorf("inbound %s: acme server_name %q is not a domain name", inbound.Listen, inbound.ServerName)
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

// isDNSName reports a plain domain name: letters, digits, hyphens and dots,
// no empty or leading-hyphen labels.
func isDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
