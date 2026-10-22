package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log"
	"math/big"
	"os"
	"time"
)

// loadOrCreateCert loads the key pair at certPath/keyPath. When neither file
// exists it generates a self-signed ECDSA certificate and writes it there, so
// a master can push an AnyTLS inbound without shipping a certificate (clients
// skip verification for AnyTLS anyway). Empty paths give an in-memory one.
func loadOrCreateCert(certPath, keyPath string) (tls.Certificate, error) {
	if certPath != "" || keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil || !missing(certPath) || !missing(keyPath) {
			return cert, err
		}
	}
	certPEM, keyPEM, err := selfSigned()
	if err != nil {
		return tls.Certificate{}, err
	}
	if certPath != "" && keyPath != "" {
		for _, f := range []struct {
			path string
			data []byte
		}{{keyPath, keyPEM}, {certPath, certPEM}} {
			if err := writeFileAtomic(f.path, f.data, 0o600); err != nil {
				return tls.Certificate{}, err
			}
		}
		log.Printf("generated self-signed certificate %s", certPath)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func missing(path string) bool {
	_, err := os.Stat(path)
	return path == "" || errors.Is(err, fs.ErrNotExist)
}

func selfSigned() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
