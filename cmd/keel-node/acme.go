package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

// ACMEConfig makes the node obtain and renew a certificate for the
// inbound's server_name from an ACME CA (Let's Encrypt by default).
type ACMEConfig struct {
	Email string `json:"email,omitempty"`
	// Challenge is "dns" (needs DNSProvider/DNSToken; works behind NAT),
	// "tls-alpn" (answered on this inbound's listener; the domain's public
	// port 443 must reach it), "http" (a temporary listener on port 80) or
	// "" to choose: dns when a token is set, else tls-alpn when the inbound
	// listens on 443, else http.
	Challenge   string `json:"challenge,omitempty"`
	DNSProvider string `json:"dns_provider,omitempty"` // "cloudflare"
	DNSToken    string `json:"dns_token,omitempty"`    // API token allowed to edit the zone's DNS
	CA          string `json:"ca,omitempty"`           // ACME directory URL
}

const (
	letsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"
	// renewBefore is how long before expiry a certificate is renewed.
	renewBefore   = 30 * 24 * time.Hour
	acmeTimeout   = 5 * time.Minute
	acmeRetryMin  = 5 * time.Minute
	acmeRetryMax  = 6 * time.Hour
	acmeTLSALPN   = "acme-tls/1"
	dnsWaitMax    = 3 * time.Minute
	dnsCheckEvery = 5 * time.Second
)

// Overridable by tests.
var (
	httpChallengeAddr = ":80"
	cloudflareAPI     = "https://api.cloudflare.com/client/v4"
	// dnsCheckServer is asked whether a DNS-01 record is visible before the
	// CA is told to look; empty skips the check.
	dnsCheckServer = "1.1.1.1:53"
	acmeHTTPClient *http.Client // nil: http.DefaultClient
)

// certManager keeps one inbound's certificate: it serves the stored one,
// or a self-signed one until the CA has issued, and renews in the
// background. The certificate is swapped without restarting the listener.
type certManager struct {
	domain     string
	config     ACMEConfig
	listenPort string
	dir        string

	cert   atomic.Pointer[tls.Certificate]
	alpn   atomic.Pointer[tls.Certificate] // pending tls-alpn-01 answer
	status atomic.Pointer[CertStatus]
	cancel context.CancelFunc
}

// CertStatus is reported to the master for each ACME certificate.
type CertStatus struct {
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer"`              // "acme" once issued, else "self-signed"
	NotAfter int64  `json:"not_after,omitempty"` // unix seconds
	Error    string `json:"error,omitempty"`     // last failed attempt
	NextTry  int64  `json:"next_try,omitempty"`  // unix seconds of the next attempt after a failure
}

var (
	certManagersMu sync.Mutex
	certManagers   = map[*certManager]bool{}
)

func certStatuses() []CertStatus {
	certManagersMu.Lock()
	defer certManagersMu.Unlock()
	var list []CertStatus
	for m := range certManagers {
		list = append(list, *m.status.Load())
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Domain < list[j].Domain })
	return list
}

func newCertManager(domain, listen string, config ACMEConfig) (*certManager, error) {
	if domain == "" {
		return nil, errors.New("acme needs server_name")
	}
	if certDir == "" {
		return nil, errors.New("acme needs a config directory to keep certificates in")
	}
	switch config.Challenge {
	case "", "dns", "tls-alpn", "http":
	default:
		return nil, fmt.Errorf("acme: unknown challenge %q", config.Challenge)
	}
	if config.Challenge == "dns" || config.DNSToken != "" {
		if config.DNSProvider != "cloudflare" {
			return nil, fmt.Errorf("acme: dns_provider must be \"cloudflare\", got %q", config.DNSProvider)
		}
		if config.DNSToken == "" {
			return nil, errors.New("acme: dns challenge needs dns_token")
		}
	}
	_, port, _ := net.SplitHostPort(listen)
	m := &certManager{domain: domain, config: config, listenPort: port, dir: filepath.Join(certDir, "acme")}
	m.status.Store(&CertStatus{Domain: domain, Issuer: "self-signed"})
	if cert, err := m.load(); err == nil {
		m.setCert(cert, "acme")
	} else {
		self, err := selfSignedPair(domain)
		if err != nil {
			return nil, err
		}
		m.cert.Store(&self)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	certManagersMu.Lock()
	certManagers[m] = true
	certManagersMu.Unlock()
	go m.run(ctx)
	return m, nil
}

func (m *certManager) close() {
	m.cancel()
	certManagersMu.Lock()
	delete(certManagers, m)
	certManagersMu.Unlock()
}

// tlsConfig serves the current certificate and answers tls-alpn-01.
func (m *certManager) tlsConfig() *tls.Config {
	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.cert.Load(), nil
		},
	}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if !slices.Contains(hello.SupportedProtos, acmeTLSALPN) {
			return nil, nil
		}
		answer := m.alpn.Load()
		if answer == nil {
			return nil, errors.New("no tls-alpn-01 challenge pending")
		}
		return &tls.Config{Certificates: []tls.Certificate{*answer}, NextProtos: []string{acmeTLSALPN}}, nil
	}
	return base
}

func (m *certManager) setCert(cert *tls.Certificate, issuer string) {
	m.cert.Store(cert)
	status := &CertStatus{Domain: m.domain, Issuer: issuer}
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		status.NotAfter = leaf.NotAfter.Unix()
	}
	m.status.Store(status)
}

func (m *certManager) paths() (certPath, keyPath string) {
	return filepath.Join(m.dir, m.domain+".crt"), filepath.Join(m.dir, m.domain+".key")
}

// load returns the stored certificate if it is for this domain.
func (m *certManager) load() (*tls.Certificate, error) {
	certPath, keyPath := m.paths()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if !matchesName(cert, m.domain) {
		return nil, errors.New("stored certificate is for another name")
	}
	return &cert, nil
}

func (m *certManager) run(ctx context.Context) {
	retry := acmeRetryMin
	for {
		wait := time.Duration(0)
		if s := m.status.Load(); s.Issuer == "acme" {
			wait = time.Until(time.Unix(s.NotAfter, 0).Add(-renewBefore))
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(min(wait, 24*time.Hour)):
				continue // re-check, e.g. after a clock jump
			}
		}
		err := m.obtain(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			retry = acmeRetryMin
			continue
		}
		log.Printf("acme %s: %v (retrying in %s)", m.domain, err, retry)
		status := *m.status.Load()
		status.Error, status.NextTry = err.Error(), time.Now().Add(retry).Unix()
		m.status.Store(&status)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(retry*2, acmeRetryMax)
	}
}

func (m *certManager) challenge() string {
	switch {
	case m.config.Challenge != "":
		return m.config.Challenge
	case m.config.DNSToken != "":
		return "dns"
	case m.listenPort == "443":
		return "tls-alpn"
	default:
		return "http"
	}
}

// obtain runs one ACME order and stores the new certificate.
func (m *certManager) obtain(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	client, err := m.client(ctx)
	if err != nil {
		return err
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.domain))
	if err != nil {
		return fmt.Errorf("new order: %w", err)
	}
	kind := m.challenge()
	for _, authzURL := range order.AuthzURLs {
		if err = m.authorize(ctx, client, authzURL, kind); err != nil {
			return err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{m.domain}}, key)
	if err != nil {
		return err
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("order: %w", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	var certPEM bytes.Buffer
	for _, der := range chain {
		pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM)
	if err != nil {
		return err
	}
	certPath, keyPath := m.paths()
	if err = writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err = writeFileAtomic(certPath, certPEM.Bytes(), 0o644); err != nil {
		return err
	}
	m.setCert(&cert, "acme")
	log.Printf("acme %s: certificate issued via %s, valid until %s", m.domain, kind, time.Unix(m.status.Load().NotAfter, 0).UTC().Format(time.DateOnly))
	return nil
}

// client returns an ACME client with this node's account, registering the
// account key on first use.
func (m *certManager) client(ctx context.Context) (*acme.Client, error) {
	keyPath := filepath.Join(m.dir, "account.key")
	var key crypto.Signer
	if content, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(content)
		if block == nil {
			return nil, fmt.Errorf("%s: not PEM", keyPath)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keyPath, err)
		}
		key = parsed.(crypto.Signer)
	} else {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, _ := x509.MarshalPKCS8PrivateKey(generated)
		if err = writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		key = generated
	}
	directory := m.config.CA
	if directory == "" {
		directory = letsEncrypt
	}
	client := &acme.Client{Key: key, DirectoryURL: directory, UserAgent: "keel-node", HTTPClient: acmeHTTPClient}
	account := &acme.Account{}
	if m.config.Email != "" {
		account.Contact = []string{"mailto:" + m.config.Email}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register account: %w", err)
	}
	return client, nil
}

func (m *certManager) authorize(ctx context.Context, client *acme.Client, authzURL, kind string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return err
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	want := map[string]string{"dns": "dns-01", "tls-alpn": "tls-alpn-01", "http": "http-01"}[kind]
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == want {
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("CA offers no %s challenge", want)
	}
	cleanup, err := m.prepare(ctx, client, chal, kind)
	if err != nil {
		return fmt.Errorf("%s challenge: %w", kind, err)
	}
	defer cleanup()
	if _, err = client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept %s challenge: %w", kind, err)
	}
	if _, err = client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("%s challenge: %w", kind, err)
	}
	return nil
}

// prepare publishes the challenge answer and returns a function removing it.
func (m *certManager) prepare(ctx context.Context, client *acme.Client, chal *acme.Challenge, kind string) (func(), error) {
	switch kind {
	case "tls-alpn":
		cert, err := client.TLSALPN01ChallengeCert(chal.Token, m.domain)
		if err != nil {
			return nil, err
		}
		m.alpn.Store(&cert)
		return func() { m.alpn.Store(nil) }, nil
	case "http":
		body, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, err
		}
		path := client.HTTP01ChallengePath(chal.Token)
		listener, err := net.Listen("tcp", httpChallengeAddr)
		if err != nil {
			return nil, fmt.Errorf("port 80 is needed for the http challenge: %w", err)
		}
		server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			io.WriteString(w, body)
		})}
		go server.Serve(listener)
		return func() { server.Close() }, nil
	case "dns":
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, err
		}
		name := "_acme-challenge." + m.domain
		cf := cloudflare{token: m.config.DNSToken}
		zone, id, err := cf.addTXT(ctx, m.domain, name, value)
		if err != nil {
			return nil, err
		}
		cleanup := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := cf.delete(ctx, zone, id); err != nil {
				log.Printf("acme %s: remove TXT record: %v", m.domain, err)
			}
		}
		if err = waitTXT(ctx, name, value); err != nil {
			cleanup()
			return nil, err
		}
		return cleanup, nil
	}
	return nil, fmt.Errorf("unknown challenge %q", kind)
}

// waitTXT waits until a public resolver sees the record, so the CA does
// not look before it has propagated.
func waitTXT(ctx context.Context, name, value string) error {
	if dnsCheckServer == "" {
		return nil
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, dnsCheckServer)
	}}
	deadline := time.Now().Add(dnsWaitMax)
	for {
		records, _ := resolver.LookupTXT(ctx, name)
		if slices.Contains(records, value) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TXT record %s not visible at %s after %s", name, dnsCheckServer, dnsWaitMax)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dnsCheckEvery):
		}
	}
}

// cloudflare is the part of the Cloudflare API that DNS-01 needs.
type cloudflare struct {
	token string
}

func (c cloudflare) call(ctx context.Context, method, path string, body any, result any) error {
	var reader io.Reader
	if body != nil {
		content, _ := json.Marshal(body)
		reader = bytes.NewReader(content)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPI+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var envelope struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&envelope); err != nil {
		return fmt.Errorf("cloudflare %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if !envelope.Success {
		var messages []string
		for _, e := range envelope.Errors {
			messages = append(messages, e.Message)
		}
		return fmt.Errorf("cloudflare %s %s: %s", method, path, strings.Join(messages, "; "))
	}
	if result != nil {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

// addTXT finds the zone holding domain and adds the record to it.
func (c cloudflare) addTXT(ctx context.Context, domain, name, value string) (zone, id string, err error) {
	labels := strings.Split(domain, ".")
	for i := 0; i < len(labels)-1 && zone == ""; i++ {
		var zones []struct{ ID string }
		if err = c.call(ctx, http.MethodGet, "/zones?name="+strings.Join(labels[i:], "."), nil, &zones); err != nil {
			return "", "", err
		}
		if len(zones) > 0 {
			zone = zones[0].ID
		}
	}
	if zone == "" {
		return "", "", fmt.Errorf("no Cloudflare zone for %s visible to this token", domain)
	}
	var record struct{ ID string }
	err = c.call(ctx, http.MethodPost, "/zones/"+zone+"/dns_records",
		map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60}, &record)
	return zone, record.ID, err
}

func (c cloudflare) delete(ctx context.Context, zone, id string) error {
	return c.call(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil)
}
