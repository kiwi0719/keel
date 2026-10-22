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
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
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

var version = "dev"

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
}

// masterConfig hands a config from the master to the main loop, which
// applies it and answers on result.
type masterConfig struct {
	content []byte
	rev     int64
	result  chan error
}

type helloMessage struct {
	Type        string   `json:"type"`
	NodeVersion string   `json:"node_version"`
	Protocols   []string `json:"protocols"`
	Hostname    string   `json:"hostname"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	ConfigRev   int64    `json:"config_rev"`
}

type reportMessage struct {
	Type      string      `json:"type"`
	TS        int64       `json:"ts"`
	ConfigRev int64       `json:"config_rev"`
	Users     []UserUsage `json:"users"`
	System    SystemStats `json:"system"`
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
}

func (m *masterClient) run(ctx context.Context) {
	wait := time.Second
	for {
		start := time.Now()
		err := m.session(ctx)
		if ctx.Err() != nil {
			return
		}
		log.Print("master: ", err)
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
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	conn, _, err := websocket.Dial(dialCtx, m.url, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: m.tlsConfig(),
		}},
		HTTPHeader: http.Header{"Authorization": {"Bearer " + m.token}},
	})
	dialCancel()
	if err != nil {
		return fmt.Errorf("connect %s: %w", m.url, err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxMessageSize)
	log.Print("master: connected to ", m.url)

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
	}); err != nil {
		return err
	}

	errs := make(chan error, 2)
	go func() { errs <- m.readLoop(ctx, conn, send) }()
	go func() { errs <- m.reportLoop(ctx, conn, send) }()
	err = <-errs
	conn.Close(websocket.StatusNormalClosure, "")
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
	return reportMessage{
		Type:      "report",
		TS:        time.Now().Unix(),
		ConfigRev: m.node.rev(),
		Users:     m.node.users.usage(),
		System:    m.sampler.sample(),
		Outbounds: currentRouter.Load().outboundStatus(),
		Certs:     certStatuses(),
		Probes:    probes,
	}
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
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		if !bytes.Equal(sum[:], m.pin) {
			return fmt.Errorf("master certificate fingerprint %s does not match -fingerprint", hex.EncodeToString(sum[:]))
		}
		return nil
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
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("-master must look like https://host:port, got %q", master)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/node/ws"
	}
	return u.String(), nil
}
