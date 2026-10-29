package tls

// Scratch benchmark for the keel audit: utls Conn record write/read vs
// crypto/tls over loopback TCP. Not part of the repo.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func keelCert(tb testing.TB) ([]byte, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench.test"},
		DNSNames:     []string{"bench.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	return der, key
}

func keelTCPPair(tb testing.TB) (net.Conn, net.Conn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	return <-ch, c
}

type rw interface {
	io.ReadWriter
	Close() error
}

func benchTLSWrite(b *testing.B, size int, mk func(tb testing.TB) (server rw, client rw)) {
	server, client := mk(b)
	defer server.Close()
	defer client.Close()
	go io.Copy(io.Discard, server) // the peer decrypts and discards
	p := make([]byte, size)
	// get past dynamic record sizing (first 128 KiB)
	for i := 0; i < 256*1024/size+1; i++ {
		client.Write(p)
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecordWrite(b *testing.B) {
	der, key := keelCert(b)
	utlsPair := func(tb testing.TB) (rw, rw) {
		s, c := keelTCPPair(tb)
		srv := Server(s, &Config{Certificates: []Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: VersionTLS13,
			CipherSuites: nil})
		cli := Client(c, &Config{InsecureSkipVerify: true, ServerName: "bench.test", MinVersion: VersionTLS13})
		errc := make(chan error, 1)
		go func() { errc <- srv.Handshake() }()
		if err := cli.Handshake(); err != nil {
			tb.Fatal(err)
		}
		if err := <-errc; err != nil {
			tb.Fatal(err)
		}
		return srv, cli
	}
	stdPair := func(tb testing.TB) (rw, rw) {
		s, c := keelTCPPair(tb)
		srv := stdtls.Server(s, &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: stdtls.VersionTLS13})
		cli := stdtls.Client(c, &stdtls.Config{InsecureSkipVerify: true, ServerName: "bench.test", MinVersion: stdtls.VersionTLS13})
		errc := make(chan error, 1)
		go func() { errc <- srv.Handshake() }()
		if err := cli.Handshake(); err != nil {
			tb.Fatal(err)
		}
		if err := <-errc; err != nil {
			tb.Fatal(err)
		}
		return srv, cli
	}
	for _, size := range []int{1200, 32 * 1024} {
		b.Run("utls/"+itoaK(size), func(b *testing.B) { benchTLSWrite(b, size, utlsPair) })
		b.Run("crypto-tls/"+itoaK(size), func(b *testing.B) { benchTLSWrite(b, size, stdPair) })
	}
}

func itoaK(n int) string {
	if n%1024 == 0 {
		return big.NewInt(int64(n/1024)).String() + "KiB"
	}
	return big.NewInt(int64(n)).String() + "B"
}
