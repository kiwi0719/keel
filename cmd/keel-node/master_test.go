package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeMaster accepts one node connection at a time and hands it to the test.
type fakeMaster struct {
	*httptest.Server
	conns chan *websocket.Conn
}

func newFakeMaster(t *testing.T) *fakeMaster {
	m := &fakeMaster{conns: make(chan *websocket.Conn, 1)}
	m.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/ws" || r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		m.conns <- conn
		<-r.Context().Done()
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *fakeMaster) fingerprint() []byte {
	sum := sha256.Sum256(m.Certificate().Raw)
	return sum[:]
}

func readMessage(t *testing.T, conn *websocket.Conn, want string) map[string]json.RawMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		_, content, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for %s: %v", want, err)
		}
		var msg map[string]json.RawMessage
		if err = json.Unmarshal(content, &msg); err != nil {
			t.Fatal(err)
		}
		if string(msg["type"]) == `"`+want+`"` {
			return msg
		}
	}
}

func sendJSON(t *testing.T, conn *websocket.Conn, v any) {
	t.Helper()
	content, _ := json.Marshal(v)
	if err := conn.Write(context.Background(), websocket.MessageText, content); err != nil {
		t.Fatal(err)
	}
}

// startNode runs a node with no inbounds plus the part of main's loop that
// applies master configs.
func startNode(t *testing.T, m *fakeMaster, pin []byte, configPath string) (*node, context.CancelFunc) {
	n := &node{users: newRegistry(""), running: make(map[string]*runningInbound), prober: newProber()}
	n.handler = &handler{users: n.users}
	if err := n.reload(&Config{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	configs := make(chan masterConfig)
	go n.prober.run(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case mc := <-configs:
				mc.result <- n.applyMaster(mc.content, mc.rev, configPath)
			}
		}
	}()
	wsURL, _ := masterWebSocketURL(m.URL)
	client := &masterClient{url: wsURL, token: "secret", pin: pin, node: n, configs: configs}
	go client.run(ctx)
	return n, cancel
}

func TestMasterSession(t *testing.T) {
	reportInterval, probeSpacing = 200*time.Millisecond, 10*time.Millisecond
	probeTarget, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probeTarget.Close()
	go func() {
		for {
			c, err := probeTarget.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	m := newFakeMaster(t)
	configPath := filepath.Join(t.TempDir(), "node.json")
	n, _ := startNode(t, m, m.fingerprint(), configPath)
	conn := <-m.conns

	hello := readMessage(t, conn, "hello")
	if string(hello["config_rev"]) != "0" {
		t.Errorf("hello config_rev = %s, want 0", hello["config_rev"])
	}

	// A config with an unknown field (newer master) and no rev inside: the
	// message rev must win and end up in the cache.
	sendJSON(t, conn, map[string]any{"type": "config", "rev": 7, "config": map[string]any{
		"future_field":   true,
		"users":          []map[string]any{{"name": "u1", "anytls_password": "p", "period": "2026-10"}},
		"probes":         []map[string]any{{"name": "ct", "host": probeTarget.Addr().String()}},
		"probe_interval": "5s",
	}})
	applied := readMessage(t, conn, "applied")
	if string(applied["rev"]) != "7" || applied["error"] != nil {
		t.Fatalf("applied = %v", applied)
	}
	if n.rev() != 7 {
		t.Errorf("node rev = %d, want 7", n.rev())
	}
	// main loads the cache leniently on restart: the unknown field is kept
	// and must not stop the node.
	cached, err := loadConfig(configPath, false)
	if err != nil || cached.Rev != 7 || len(cached.Users) != 1 {
		t.Errorf("cached config = %+v, %v", cached, err)
	}

	// Reports carry the user and, once, the probe round.
	var probeRounds int
	deadline := time.Now().Add(15 * time.Second)
	for probeRounds == 0 || time.Now().Before(deadline) && probeRounds < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no probe results reported")
		}
		report := readMessage(t, conn, "report")
		var r reportMessage
		raw, _ := json.Marshal(report)
		json.Unmarshal(raw, &r)
		if r.ConfigRev != 7 || len(r.Users) != 1 || r.Users[0].Name != "u1" || r.Users[0].Period != "2026-10" {
			t.Fatalf("report = %s", raw)
		}
		if len(r.Probes) > 0 {
			probeRounds++
			p := r.Probes[0]
			if p.Name != "ct" || p.Samples != probeSamples || p.LossPct != 0 || p.At == 0 {
				t.Fatalf("probe = %+v", p)
			}
			if probeRounds == 1 {
				// The same round must not be sent again: watch a few more
				// reports (shorter than the 5 s probe interval).
				deadline = time.Now().Add(time.Second)
			}
		}
	}
	if probeRounds != 1 {
		t.Errorf("probe round reported %d times", probeRounds)
	}

	// An invalid config is rejected and the node keeps rev 7.
	sendJSON(t, conn, map[string]any{"type": "config", "rev": 8, "config": map[string]any{
		"route": map[string]any{"final": "nowhere"},
	}})
	applied = readMessage(t, conn, "applied")
	if string(applied["rev"]) != "8" || applied["error"] == nil {
		t.Fatalf("applied = %v, want an error", applied)
	}
	if n.rev() != 7 {
		t.Errorf("node rev after rejected config = %d, want 7", n.rev())
	}

	// The node reconnects after the master drops it and says which rev it has.
	conn.CloseNow()
	conn = <-m.conns
	defer conn.CloseNow()
	hello = readMessage(t, conn, "hello")
	if string(hello["config_rev"]) != "7" {
		t.Errorf("hello after reconnect config_rev = %s, want 7", hello["config_rev"])
	}
}

func TestMasterFingerprintMismatch(t *testing.T) {
	m := newFakeMaster(t)
	pin := m.fingerprint()
	pin[0] ^= 0xff
	client := &masterClient{pin: pin, token: "secret", node: &node{}}
	client.url, _ = masterWebSocketURL(m.URL)
	err := client.session(context.Background())
	if err == nil {
		t.Fatal("connected despite a wrong fingerprint")
	}
	select {
	case <-m.conns:
		t.Fatal("master accepted the node")
	default:
	}
}

func TestParseFingerprint(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	for _, s := range []string{
		"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
		"2D:71:16:42:B7:26:B0:44:01:62:7C:A9:FB:AC:32:F5:C8:53:0F:B1:90:3C:C4:DB:02:25:87:17:92:1A:48:81",
	} {
		pin, err := parseFingerprint(s)
		if err != nil || string(pin) != string(sum[:]) {
			t.Errorf("parseFingerprint(%q) = %x, %v", s, pin, err)
		}
	}
	if _, err := parseFingerprint("abcd"); err == nil {
		t.Error("short fingerprint accepted")
	}
}

func TestMasterWebSocketURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://panel.example:8443":      "wss://panel.example:8443/api/node/ws",
		"https://panel.example:8443/":     "wss://panel.example:8443/api/node/ws",
		"https://panel.example/custom/ws": "wss://panel.example/custom/ws",
		"http://127.0.0.1:8080":           "ws://127.0.0.1:8080/api/node/ws",
	} {
		if got, err := masterWebSocketURL(in); err != nil || got != want {
			t.Errorf("masterWebSocketURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := masterWebSocketURL("panel.example:8443"); err == nil {
		t.Error("address without scheme accepted")
	}
}

func TestSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key")
	first, err := loadOrCreateCert(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateCert(certPath, keyPath)
	if err != nil || string(second.Certificate[0]) != string(first.Certificate[0]) {
		t.Fatal("second load did not reuse the generated certificate")
	}
	if _, err = loadOrCreateCert("", ""); err != nil {
		t.Fatal(err)
	}
	os.Remove(keyPath)
	if _, err = loadOrCreateCert(certPath, keyPath); err == nil {
		t.Error("a half-missing key pair must be an error, not silently replaced")
	}
}
