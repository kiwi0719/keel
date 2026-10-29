package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

// realityClient connects to a third-party VLESS server behind REALITY, the
// way Xray's client does: the ClientHello's session ID carries the short ID
// and a timestamp, sealed with a key only the holder of the server's private
// key can derive, and the server proves itself with a certificate signed by
// that key. A server that is not the expected REALITY server (the borrowed
// site itself, or anyone in between) fails the handshake.
type realityClient struct {
	serverName  string
	publicKey   *ecdh.PublicKey
	shortID     [8]byte
	fingerprint utls.ClientHelloID
}

var errRealityUnverified = errors.New("reality: the server did not prove it holds the key (not the expected server)")

func newRealityClient(c *OutboundRealityConfig) (*realityClient, error) {
	if c.ServerName == "" {
		return nil, errors.New("reality: server_name is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c.PublicKey, "="))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("reality: public_key must be a 32-byte base64url X25519 key")
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, err
	}
	r := &realityClient{serverName: c.ServerName, publicKey: pub, fingerprint: fingerprintByName(c.Fingerprint)}
	sid, err := hex.DecodeString(c.ShortID)
	if err != nil || len(sid) > 8 {
		return nil, errors.New("reality: short_id must be up to 16 hex digits")
	}
	copy(r.shortID[:], sid)
	return r, nil
}

func fingerprintByName(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// handshake runs REALITY over conn and returns the TLS connection.
func (r *realityClient) handshake(ctx context.Context, conn net.Conn) (*utls.UConn, error) {
	var authKey []byte
	config := &utls.Config{
		ServerName:             r.serverName,
		SessionTicketsDisabled: true,
		// The certificate is REALITY's own, checked below against authKey.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || authKey == nil {
				return errRealityUnverified
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return errRealityUnverified
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errRealityUnverified
			}
			h := hmac.New(sha512.New, authKey)
			h.Write(pub)
			if !hmac.Equal(h.Sum(nil), cert.Signature) {
				return errRealityUnverified
			}
			return nil
		},
	}
	uConn := utls.UClient(conn, config, r.fingerprint)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uConn.HandshakeState.Hello
	if len(hello.Raw) < 39+32 {
		return nil, errors.New("reality: unexpected ClientHello layout")
	}
	keys := uConn.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil, errors.New("reality: the fingerprint sent no key share")
	}
	priv := keys.Ecdhe
	if priv == nil {
		priv = keys.MlkemEcdhe
	}
	if priv == nil {
		return nil, errors.New("reality: the fingerprint sent no X25519 key share")
	}
	shared, err := priv.ECDH(r.publicKey)
	if err != nil {
		return nil, err
	}
	authKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return nil, err
	}
	// Session ID plaintext: version (3 bytes), reserved, unix time, short ID.
	sessionID := make([]byte, 32)
	copy(sessionID, []byte{26, 10, 30})
	binary.BigEndian.PutUint32(sessionID[4:], uint32(time.Now().Unix()))
	copy(sessionID[8:], r.shortID[:])
	// The server checks the seal against the ClientHello with the session
	// ID zeroed, so zero it in Raw before sealing.
	copy(hello.Raw[39:39+32], make([]byte, 32))
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, hello.Random[20:], sessionID[:16], hello.Raw)
	if len(sealed) != 32 {
		return nil, fmt.Errorf("reality: sealed session id is %d bytes", len(sealed))
	}
	copy(hello.Raw[39:], sealed)
	hello.SessionId = hello.Raw[39 : 39+32]
	if err = uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if uConn.ConnectionState().Version != utls.VersionTLS13 {
		uConn.Close()
		return nil, errRealityUnverified
	}
	return uConn, nil
}
