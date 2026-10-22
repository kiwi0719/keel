//go:build anytls

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestACME issues certificates from a local Pebble (Let's Encrypt's test
// CA) with each challenge type. Set PEBBLE_DIR to a directory holding the
// pebble and pebble-challtestsrv binaries and PEBBLE_SRC to pebble's source
// tree (for its test certificates); otherwise the test is skipped:
//
//	GOBIN=$PWD/pebble go install github.com/letsencrypt/pebble/v2/cmd/...@v2.7.0
//	PEBBLE_DIR=$PWD/pebble PEBBLE_SRC=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.7.0 \
//	    go test -tags anytls -run ACME ./cmd/keel-node
func TestACME(t *testing.T) {
	bin, src := os.Getenv("PEBBLE_DIR"), os.Getenv("PEBBLE_SRC")
	if bin == "" || src == "" {
		t.Skip("PEBBLE_DIR and PEBBLE_SRC not set")
	}
	work := t.TempDir()
	start := func(name string, env []string, args ...string) {
		cmd := exec.Command(filepath.Join(bin, name), args...)
		cmd.Env = append(os.Environ(), env...)
		log, _ := os.Create(filepath.Join(work, name+".log"))
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	start("pebble-challtestsrv", nil, "-defaultIPv4", "127.0.0.1", "-defaultIPv6", "",
		"-dns01", "127.0.0.1:18053", "-management", "127.0.0.1:18055",
		"-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
	config := fmt.Sprintf(`{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000",
		"certificate":%q,"privateKey":%q,"httpPort":5002,"tlsPort":5001}}`,
		filepath.Join(src, "test/certs/localhost/cert.pem"), filepath.Join(src, "test/certs/localhost/key.pem"))
	os.WriteFile(filepath.Join(work, "pebble.json"), []byte(config), 0o600)
	start("pebble", []string{"PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0"},
		"-config", filepath.Join(work, "pebble.json"), "-dnsserver", "127.0.0.1:18053")

	roots := x509.NewCertPool()
	minica, _ := os.ReadFile(filepath.Join(src, "test/certs/pebble.minica.pem"))
	roots.AppendCertsFromPEM(minica)
	defer func(c *http.Client, dir, httpAddr, dnsServer, cf string) {
		acmeHTTPClient, certDir, httpChallengeAddr, dnsCheckServer, cloudflareAPI = c, dir, httpAddr, dnsServer, cf
	}(acmeHTTPClient, certDir, httpChallengeAddr, dnsCheckServer, cloudflareAPI)
	acmeHTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	certDir = filepath.Join(work, "node")
	httpChallengeAddr = "127.0.0.1:5002"
	dnsCheckServer = "127.0.0.1:18053"
	cloudflareAPI = fakeCloudflare(t, "http://127.0.0.1:18055")
	for deadline := time.Now().Add(10 * time.Second); ; {
		if conn, err := net.Dial("tcp", "127.0.0.1:14000"); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pebble did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}

	ca := "https://127.0.0.1:14000/dir"
	for _, c := range []struct {
		domain, listen string
		acme           ACMEConfig
	}{
		{"alpn.example.test", "127.0.0.1:5001", ACMEConfig{Challenge: "tls-alpn", CA: ca}},
		{"http.example.test", "127.0.0.1:0", ACMEConfig{Challenge: "http", CA: ca}},
		{"dns.example.test", "127.0.0.1:0", ACMEConfig{DNSProvider: "cloudflare", DNSToken: "test-token", CA: ca, Email: "a@example.test"}},
	} {
		t.Run(c.acme.Challenge+c.acme.DNSProvider, func(t *testing.T) {
			in, err := newAnyTLSInbound(InboundConfig{Type: "anytls", Listen: c.listen, ServerName: c.domain, ACME: &c.acme}, &handler{users: newRegistry("")})
			if err != nil {
				t.Fatal(err)
			}
			defer in.close()
			addr := in.(*anytlsInbound).listener.Addr().String()
			if issuer := servedIssuer(t, addr, c.domain); issuer != c.domain {
				t.Errorf("before issuance served issuer %q, want the self-signed %q", issuer, c.domain)
			}
			m := in.(*anytlsInbound).acme
			deadline := time.Now().Add(90 * time.Second)
			for m.status.Load().Issuer != "acme" {
				if time.Now().After(deadline) {
					t.Fatalf("not issued: %+v", *m.status.Load())
				}
				time.Sleep(200 * time.Millisecond)
			}
			if issuer := servedIssuer(t, addr, c.domain); !strings.Contains(issuer, "Pebble") {
				t.Errorf("served issuer %q after issuance", issuer)
			}
			// A restarted node loads the stored certificate instead of ordering again.
			again, err := newCertManager(c.domain, c.listen, c.acme)
			if err != nil {
				t.Fatal(err)
			}
			defer again.close()
			if s := again.status.Load(); s.Issuer != "acme" || s.NotAfter == 0 {
				t.Errorf("stored certificate not reused: %+v", *s)
			}
		})
	}
	t.Run("failure", func(t *testing.T) { testACMEFailure(t, ca) })
}

func testACMEFailure(t *testing.T, ca string) {
	// tls-alpn on a port the CA does not connect to must fail cleanly and
	// keep serving the self-signed certificate.
	m, err := newCertManager("fail.example.test", "127.0.0.1:1", ACMEConfig{Challenge: "tls-alpn", CA: ca})
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	deadline := time.Now().Add(60 * time.Second)
	for m.status.Load().Error == "" {
		if time.Now().After(deadline) {
			t.Fatal("no error reported")
		}
		time.Sleep(200 * time.Millisecond)
	}
	s := m.status.Load()
	if s.Issuer != "self-signed" || s.NextTry <= time.Now().Unix() {
		t.Errorf("status after failure: %+v", *s)
	}
	t.Logf("reported error: %s", s.Error)
}

func servedIssuer(t *testing.T, addr, name string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: name, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].Issuer.CommonName
}

// fakeCloudflare answers the zone lookup and record calls, publishing TXT
// records through pebble-challtestsrv's management API.
func fakeCloudflare(t *testing.T, challtestsrv string) string {
	records := map[string]string{}
	post := func(path string, body any) {
		content, _ := json.Marshal(body)
		resp, err := http.Post(challtestsrv+path, "application/json", bytes.NewReader(content))
		if err == nil {
			resp.Body.Close()
		}
	}
	reply := func(w http.ResponseWriter, result any) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"message": "bad token"}}})
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "example.test" {
				reply(w, []any{map[string]any{"id": "zone1"}})
			} else {
				reply(w, []any{})
			}
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone1/dns_records":
			var record struct{ Name, Content string }
			json.NewDecoder(r.Body).Decode(&record)
			post("/set-txt", map[string]string{"host": record.Name + ".", "value": record.Content})
			records["rec1"] = record.Name
			reply(w, map[string]any{"id": "rec1"})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone1/dns_records/")
			post("/clear-txt", map[string]string{"host": records[id] + "."})
			reply(w, map[string]any{"id": id})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}
