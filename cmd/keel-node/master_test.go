package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

func TestAnyTLSCert(t *testing.T) {
	defer func(old string) { certDir = old }(certDir)
	certDir = t.TempDir()
	name := func(cert tls.Certificate) string {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		return leaf.Subject.CommonName
	}
	first, err := anytlsCert(InboundConfig{ServerName: "a.example.com"})
	if err != nil || name(first) != "a.example.com" {
		t.Fatal(name(first), err)
	}
	second, _ := anytlsCert(InboundConfig{ServerName: "a.example.com"})
	if string(second.Certificate[0]) != string(first.Certificate[0]) {
		t.Fatal("the generated certificate must be kept")
	}
	third, _ := anytlsCert(InboundConfig{ServerName: "b.example.com"})
	if name(third) != "b.example.com" {
		t.Fatal("a new server name must replace the generated certificate")
	}
	// Given paths must exist: no silent self-signed replacement.
	_, err = anytlsCert(InboundConfig{Cert: filepath.Join(certDir, "x.crt"), Key: filepath.Join(certDir, "x.key")})
	if err == nil {
		t.Fatal("missing cert files accepted")
	}
	certPEM, keyPEM, _ := selfSigned("c.example.com")
	inline, err := anytlsCert(InboundConfig{CertPEM: string(certPEM), KeyPEM: string(keyPEM), ServerName: "ignored"})
	if err != nil || name(inline) != "c.example.com" {
		t.Fatal("inline certificate not used", err)
	}
	certDir = ""
	if _, err = anytlsCert(InboundConfig{}); err != nil {
		t.Fatal(err)
	}
}

func TestRevokedTokenStopsServing(t *testing.T) {
	revokeAfter = 0
	t.Cleanup(func() { revokeAfter = 10 * time.Minute })
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad token", http.StatusUnauthorized)
	}))
	defer master.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "node.json")
	if err := os.WriteFile(configPath, []byte(`{"users":[{"name":"u1","anytls_password":"x"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	n := &node{users: newRegistry(""), running: make(map[string]*runningInbound), prober: newProber()}
	n.handler = &handler{users: n.users}
	if err := n.reload(&Config{Users: []UserConfig{{Name: "u1", AnyTLSPassword: "x"}}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	configs := make(chan masterConfig)
	wsURL, _ := masterWebSocketURL(master.URL)
	go (&masterClient{url: wsURL, token: "old", node: n, configs: configs}).run(ctx)
	select {
	case mc := <-configs:
		if !mc.revoke {
			t.Fatal("got a config, want a revocation")
		}
		n.revoke(configPath)
		mc.result <- nil
	case <-ctx.Done():
		t.Fatal("no revocation after repeated 401s")
	}
	if len(n.users.active()) != 0 {
		t.Error("users still active after revocation")
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Error("cached config kept after revocation")
	}
}

func TestMasterPinBySPKI(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	leaf := server.Certificate()
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	whole := sha256.Sum256(leaf.Raw)
	wrong := sha256.Sum256([]byte("other"))
	try := func(pin []byte, pushed string) error {
		n := &node{}
		n.config.Store(&Config{MasterSPKI: pushed})
		c := &masterClient{pin: pin, node: n}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: c.tlsConfig()}}
		resp, err := client.Get(server.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := try(whole[:], ""); err != nil {
		t.Errorf("certificate pin: %v", err)
	}
	if err := try(spki[:], ""); err != nil {
		t.Errorf("public key pin: %v", err)
	}
	if err := try(wrong[:], hex.EncodeToString(spki[:])); err != nil {
		t.Errorf("pushed public key: %v", err)
	}
	if err := try(wrong[:], ""); err == nil {
		t.Error("a wrong pin was accepted")
	}
}
