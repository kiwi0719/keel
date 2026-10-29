package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// The master<->node protocol is described in docs/node-protocol.md.

// reportInterval is a var so tests can shorten it.
var reportInterval = 5 * time.Second

const (
	pingInterval     = 30 * time.Second
	maxReconnectWait = time.Minute
	maxMessageSize   = 16 << 20
)

// version can be set with -ldflags "-X main.version=..."; otherwise main
// sets it to the git commit the binary was built from (see buildVersion).
var version string

// masterClient keeps a WebSocket connection to the master: it receives
// configs and sends reports. The node keeps running on its cached config
// while the master is unreachable.
type masterClient struct {
	url     string
	token   string
	pin     []byte // optional SHA-256 of the master's leaf certificate (DER)
	node    *node
	configs chan<- masterConfig
	sampler sysSampler
	// probesSent is the newest probe round already sent; reports only carry
	// rounds finished after it.
	probesSent int64
	// delta: the master on this connection takes reports that only carry
	// the users whose figures changed (it says so with each config and
	// usage message). sent holds what this connection last reported for
	// each user, lastFull when every user was last sent. All three start
	// over with each connection.
	delta    atomic.Bool
	sent     map[string]UserUsage
	lastFull time.Time
}

// fullReportInterval: even when sending changes only, every user is
// reported this often.
const fullReportInterval = 5 * time.Minute

// masterConfig hands a config from the master to the main loop, which
// applies it and answers on result.
type masterConfig struct {
	content []byte
	rev     int64
	result  chan error
	// revoke: the master no longer accepts this node's token (it was
	// rotated, or the node deleted). The node stops serving.
	revoke bool
	// usage: new used_base/used_self figures for the running config.
	usage *usageUpdate
}

// errRevoked is a 401 from the master: the token is no longer valid.
var errRevoked = errors.New("the master rejected this node's token (rotated or node deleted)")

// revokeAfter is how long the master must keep rejecting the token before
// the node stops serving, so a master briefly restored from an old backup
// does not take every node down.
var revokeAfter = 10 * time.Minute

type helloMessage struct {
	Type        string   `json:"type"`
	NodeVersion string   `json:"node_version"`
	Protocols   []string `json:"protocols"`
	Hostname    string   `json:"hostname"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	ConfigRev   int64    `json:"config_rev"`
	// Features this node understands; "spki_pin": it accepts master_spki.
	Features []string `json:"features"`
}

type reportMessage struct {
	Type      string      `json:"type"`
	TS        int64       `json:"ts"`
	ConfigRev int64       `json:"config_rev"`
	Users     []UserUsage `json:"users"`
	// Full: Users lists every user; otherwise only those whose figures
	// changed since the previous report on this connection.
	Full   bool        `json:"full"`
	System SystemStats `json:"system"`
	// Outbounds is the health of every outbound but direct.
	Outbounds []OutboundStatus `json:"outbounds,omitempty"`
	// Certs is the state of ACME certificates.
	Certs []CertStatus `json:"certs,omitempty"`
	// Probes holds results of probe rounds finished since the previous
	// report, so each round is sent once; omitted when there is none.
	Probes []ProbeResult `json:"probes,omitempty"`
}

type appliedMessage struct {
	Type  string `json:"type"`
	Rev   int64  `json:"rev"`
	Error string `json:"error,omitempty"`
}

type incomingMessage struct {
	Type   string          `json:"type"`
	Rev    int64           `json:"rev"`
	Config json.RawMessage `json:"config"`
	// ReportDelta (with a config or usage): the master accepts reports of
	// changed users only.
	ReportDelta bool `json:"report_delta"`
	// usage: name -> [used_base, used_self] for the config of Rev.
	Users map[string][2]int64 `json:"users"`
	ID    int64               `json:"id"`    // acme_dns_done
	Error string              `json:"error"` // acme_dns_done
}

func (m *masterClient) run(ctx context.Context) {
	wait := time.Second
	var rejectedSince time.Time
	revoked := false
	for {
		start := time.Now()
		err := m.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if !errors.Is(err, errRevoked) {
			rejectedSince = time.Time{}
			revoked = false
		} else if rejectedSince.IsZero() {
			rejectedSince = time.Now()
		} else if !revoked && time.Since(rejectedSince) >= revokeAfter {
			revoked = true
			result := make(chan error, 1)
			select {
			case m.configs <- masterConfig{revoke: true, result: result}:
				<-result
			case <-ctx.Done():
				return
			}
		}
		log.Print("master: ", err)
		m.node.masterState.Store(&MasterState{URL: m.url, Error: err.Error(), Since: time.Now().Unix()})
		if time.Since(start) > maxReconnectWait {
			wait = time.Second
		}
		sleep := wait/2 + rand.N(wait/2+1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
		wait = min(wait*2, maxReconnectWait)
	}
}

func (m *masterClient) session(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m.delta.Store(false)
	m.sent, m.lastFull = nil, time.Time{} // a new connection starts with a full report
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: m.tlsConfig()}
	conn, resp, err := websocket.Dial(dialCtx, m.url, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport},
		HTTPHeader: http.Header{"Authorization": {"Bearer " + m.token}},
	})
	dialCancel()
	if err != nil {
		// A failed handshake leaves its connection idle in this transport;
		// close it, or every retry would keep one open on both ends.
		transport.CloseIdleConnections()
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return errRevoked
		}
		return fmt.Errorf("connect %s: %w", m.url, err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxMessageSize)
	log.Print("master: connected to ", m.url)
	m.node.masterState.Store(&MasterState{URL: m.url, Connected: true, Since: time.Now().Unix()})

	var writeMu sync.Mutex
	send := func(v any) error {
		content, err := json.Marshal(v)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return conn.Write(writeCtx, websocket.MessageText, content)
	}

	hostname, _ := os.Hostname()
	if err = send(helloMessage{
		Type: "hello", NodeVersion: version, Protocols: strings.Split(builtProtocols(), ","),
		Hostname: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH, ConfigRev: m.node.rev(),
		Features: []string{"spki_pin", "usage_msg"},
	}); err != nil {
		return err
	}

	masterDNS.attach(send)
	defer masterDNS.detach()
	errs := make(chan error, 2)
	go func() { errs <- m.readLoop(ctx, conn, send) }()
	go func() { errs <- m.reportLoop(ctx, conn, send) }()
	err = <-errs
	conn.Close(websocket.StatusNormalClosure, "")
	cancel()
	<-errs // the next session resets what the loops use
	return err
}

func (m *masterClient) readLoop(ctx context.Context, conn *websocket.Conn, send func(any) error) error {
	for {
		_, content, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var msg incomingMessage
		if err = json.Unmarshal(content, &msg); err != nil {
			log.Print("master: bad message: ", err)
			continue
		}
		switch msg.Type {
		case "config":
			m.delta.Store(msg.ReportDelta)
			result := make(chan error, 1)
			select {
			case m.configs <- masterConfig{content: msg.Config, rev: msg.Rev, result: result}:
			case <-ctx.Done():
				return ctx.Err()
			}
			applied := appliedMessage{Type: "applied", Rev: msg.Rev}
			if err = <-result; err != nil {
				applied.Error = err.Error()
				log.Print("master: config rev ", msg.Rev, " rejected: ", err)
			}
			if err = send(applied); err != nil {
				return err
			}
		case "usage":
			m.delta.Store(msg.ReportDelta)
			result := make(chan error, 1)
			select {
			case m.configs <- masterConfig{usage: &usageUpdate{rev: msg.Rev, users: msg.Users}, result: result}:
			case <-ctx.Done():
				return ctx.Err()
			}
			<-result
		case "acme_dns_done":
			masterDNS.done(msg.ID, msg.Error)
		default:
			if verbose {
				log.Print("master: ignoring message type ", msg.Type)
			}
		}
	}
}

func (m *masterClient) reportLoop(ctx context.Context, conn *websocket.Conn, send func(any) error) error {
	report := time.NewTicker(reportInterval)
	defer report.Stop()
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-report.C:
			if err := send(m.report()); err != nil {
				return err
			}
			m.node.lastReport.Store(time.Now().Unix())
		case <-ping.C:
			pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return fmt.Errorf("ping: %w", err)
			}
		}
	}
}

func (m *masterClient) report() reportMessage {
	var probes []ProbeResult
	newest := m.probesSent
	for _, r := range m.node.prober.latest() {
		if r.At > m.probesSent {
			probes = append(probes, r)
			newest = max(newest, r.At)
		}
	}
	m.probesSent = newest
	users, full := m.reportUsers(time.Now())
	return reportMessage{
		Type:      "report",
		TS:        time.Now().Unix(),
		ConfigRev: m.node.rev(),
		Users:     users,
		Full:      full,
		System:    m.sampler.sample(),
		Outbounds: currentRouter.Load().outboundStatus(),
		Certs:     certStatuses(),
		Probes:    probes,
	}
}

// reportUsers returns the users for the next report and whether that is all
// of them. Usage is absolute, so a user left out is one the master already
// has right; a full report every fullReportInterval (and on each new
// connection) puts any drift right.
func (m *masterClient) reportUsers(now time.Time) ([]UserUsage, bool) {
	users := m.node.users.usage()
	if !m.delta.Load() || m.sent == nil || now.Sub(m.lastFull) >= fullReportInterval {
		m.sent = make(map[string]UserUsage, len(users))
		for _, u := range users {
			m.sent[u.Name] = u
		}
		m.lastFull = now
		return users, true
	}
	changed := users[:0]
	for _, u := range users {
		if m.sent[u.Name] != u {
			m.sent[u.Name] = u
			changed = append(changed, u)
		}
	}
	return changed, false
}

func (m *masterClient) tlsConfig() *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if m.pin == nil {
		return config
	}
	// With a fingerprint the master may use a self-signed certificate: the
	// fingerprint replaces CA verification.
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("master sent no certificate")
		}
		// The pin may be the whole certificate's hash (older installs) or its
		// public key's; the master may also have pushed its key's hash.
		leaf := state.PeerCertificates[0]
		sum := sha256.Sum256(leaf.Raw)
		key := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if bytes.Equal(sum[:], m.pin) || bytes.Equal(key[:], m.pin) {
			return nil
		}
		if c := m.node.config.Load(); c != nil && c.MasterSPKI != "" && strings.EqualFold(c.MasterSPKI, hex.EncodeToString(key[:])) {
			return nil
		}
		return fmt.Errorf("master certificate fingerprint %s does not match -fingerprint", hex.EncodeToString(sum[:]))
	}
	return config
}

// parseFingerprint reads a hex SHA-256 certificate fingerprint; case and
// colons are ignored.
func parseFingerprint(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	pin, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(s), ":", ""))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("-fingerprint must be the hex SHA-256 of the master's certificate")
	}
	return pin, nil
}

// masterWebSocketURL turns the -master address (https://host:port) into the
// node endpoint.
func masterWebSocketURL(master string) (string, error) {
	u, err := url.Parse(master)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("-master must look like https://host:port, got %q", master)
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		// Plain text would send the token and receive every user's
		// credentials in the clear; only allowed on this machine.
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("-master %q is plain http; use https (http only works for a master on this machine)", master)
		}
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("-master must look like https://host:port, got %q", master)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/node/ws"
	}
	return u.String(), nil
}
