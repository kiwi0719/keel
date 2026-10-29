//go:build with_utls

// benchcli: SS2022 and VLESS-Reality download clients for benchmarks.
//
//	benchcli ss <server> <psk:key> <target> <path> <parallel> [tls]
//	benchcli reality <server> <sni> <pubkey> <shortid> <uuid> <flow|-> <target> <path> <parallel> [tls]
//	benchcli conns-ss <server> <psk:key> <target> <conc> <secs>
//	benchcli conns-reality <server> <sni> <pubkey> <shortid> <uuid> <target> <conc> <secs>
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/hkdf"
)

type nopLogger struct{}

func (nopLogger) Trace(...any)                            {}
func (nopLogger) Debug(...any)                            {}
func (nopLogger) Info(...any)                             {}
func (nopLogger) Warn(...any)                             {}
func (nopLogger) Error(...any)                            {}
func (nopLogger) Fatal(...any)                            {}
func (nopLogger) Panic(...any)                            {}
func (nopLogger) TraceContext(context.Context, ...any)    {}
func (nopLogger) DebugContext(context.Context, ...any)    {}
func (nopLogger) InfoContext(context.Context, ...any)     {}
func (nopLogger) WarnContext(context.Context, ...any)     {}
func (nopLogger) ErrorContext(context.Context, ...any)    {}
func (nopLogger) FatalContext(context.Context, ...any)    {}
func (nopLogger) PanicContext(context.Context, ...any)    {}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	return errors.New("not reality")
}

type realityClientConn struct{ *utls.UConn }

func (c *realityClientConn) Upstream() any           { return c.UConn }
func (c *realityClientConn) CloseWrite() error       { return c.Close() }
func (c *realityClientConn) ReaderReplaceable() bool { return true }
func (c *realityClientConn) WriterReplaceable() bool { return true }

func realityDial(server, sni string, pub []byte, shortID [8]byte) (net.Conn, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	verifier := &realityVerifier{serverName: sni}
	uConfig := &utls.Config{ServerName: sni, InsecureSkipVerify: true, SessionTicketsDisabled: true, VerifyPeerCertificate: verifier.VerifyPeerCertificate}
	uConn := utls.UClient(conn, uConfig, utls.HelloChrome_Auto)
	verifier.UConn = uConn
	if err = uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	for _, ext := range uConn.Extensions {
		if ce, ok := ext.(*utls.SupportedCurvesExtension); ok {
			var keep []utls.CurveID
			for _, c := range ce.Curves {
				if c != utls.X25519MLKEM768 {
					keep = append(keep, c)
				}
			}
			ce.Curves = keep
		}
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			var keep []utls.KeyShare
			for _, s := range ks.KeyShares {
				if s.Group != utls.X25519MLKEM768 {
					keep = append(keep, s)
				}
			}
			ks.KeyShares = keep
		}
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 1, 8, 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID[:])
	publicKey, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	authKey, err := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	verifier.authKey = authKey
	if _, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(authKey)
	gcm, _ := cipher.NewGCM(block)
	gcm.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verifier.verified {
		uConn.Close()
		return nil, errors.New("reality verification failed")
	}
	return &realityClientConn{uConn}, nil
}

func get(conn net.Conn, path string, useTLS bool, small bool) (int64, error) {
	defer conn.Close()
	var rw io.ReadWriter = conn
	if useTLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "blast.test"})
		if err := tc.Handshake(); err != nil {
			return 0, err
		}
		rw = tc
	}
	if _, err := fmt.Fprintf(rw, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(rw, 64<<10), nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if small {
		n, err := io.Copy(io.Discard, resp.Body)
		return n, err
	}
	buf := make([]byte, 256<<10)
	var n int64
	for {
		k, err := resp.Body.Read(buf)
		n += int64(k)
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

func parallel(par int, one func() (int64, error)) {
	var total atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < par; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := one()
			if err != nil {
				log.Print("get: ", err)
			}
			total.Add(n)
		}()
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	fmt.Printf("get bytes=%d secs=%.2f MBps=%.0f\n", total.Load(), el, float64(total.Load())/el/1e6)
}

func churn(conc, secs int, one func() error) {
	var ok, fail atomic.Int64
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	var wg sync.WaitGroup
	var lat atomic.Int64
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				start := time.Now()
				if err := one(); err != nil {
					if fail.Add(1) < 3 {
						log.Print(err)
					}
					continue
				}
				lat.Add(int64(time.Since(start)))
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	avg := time.Duration(0)
	if ok.Load() > 0 {
		avg = time.Duration(lat.Load() / ok.Load())
	}
	fmt.Printf("conns ok=%d fail=%d rate=%.0f/s avg=%v\n", ok.Load(), fail.Load(), float64(ok.Load())/float64(secs), avg)
}

// hold opens n proxied connections, does one keep-alive request on each and
// keeps them open until killed.
func hold(n int, dial func() (net.Conn, error)) { holdPath(n, "/small", dial) }

func holdPath(n int, path string, dial func() (net.Conn, error)) {
	var conns []net.Conn
	for i := 0; i < n; i++ {
		c, err := dial()
		if err != nil {
			log.Fatal(err)
		}
		if _, err = fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path); err != nil {
			log.Fatal(err)
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			log.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		conns = append(conns, c)
	}
	fmt.Printf("holding %d\n", len(conns))
	time.Sleep(24 * time.Hour)
}

func main() {
	a := os.Args
	switch a[1] {
	case "udp-ss":
		// udp-ss <server> <psk:key> <dest> <mode ping|flood> <secs> [pps]
		method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm", a[3], time.Now)
		if err != nil {
			log.Fatal(err)
		}
		uc, err := net.Dial("udp", a[2])
		if err != nil {
			log.Fatal(err)
		}
		pc := method.DialPacketConn(uc)
		dest := M.ParseSocksaddr(a[4])
		secs, _ := strconv.Atoi(a[6])
		end := time.Now().Add(time.Duration(secs) * time.Second)
		payload := make([]byte, 200)
		if a[5] == "flood" {
			pps, _ := strconv.Atoi(a[7])
			tick := time.NewTicker(time.Second / time.Duration(pps))
			n := 0
			for time.Now().Before(end) {
				<-tick.C
				b := buf.NewSize(2600)
				b.Resize(1024, 0)
				b.Write(payload)
				if err := pc.WritePacket(b, dest); err != nil {
					log.Print(err)
				}
				n++
			}
			fmt.Printf("flood sent %d\n", n)
			return
		}
		start := time.Now()
		var sec int
		var worst time.Duration
		var lost, ok int
		for time.Now().Before(end) {
			b := buf.NewSize(2600)
			b.Resize(1024, 0)
			b.Write(payload)
			t := time.Now()
			if err := pc.WritePacket(b, dest); err != nil {
				log.Fatal(err)
			}
			uc.SetReadDeadline(time.Now().Add(time.Second))
			rb := buf.NewSize(2048)
			_, err := pc.ReadPacket(rb)
			rb.Release()
			rtt := time.Since(t)
			if err != nil {
				lost++
			} else {
				ok++
				worst = max(worst, rtt)
			}
			if s := int(time.Since(start).Seconds()); s != sec {
				fmt.Printf("t=%2ds ok=%5d lost=%d worst_rtt=%v\n", sec, ok, lost, worst.Round(time.Microsecond))
				sec, worst, lost, ok = s, 0, 0, 0
			}
		}
	case "hold-ss":
		method, _ := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm", a[3], time.Now)
		n, _ := strconv.Atoi(a[5])
		path := "/small"
		if len(a) > 6 {
			path = a[6]
		}
		holdPath(n, path, func() (net.Conn, error) {
			c, err := net.Dial("tcp", a[2])
			if err != nil {
				return nil, err
			}
			return method.DialConn(c, M.ParseSocksaddr(a[4]))
		})
	case "hold-reality":
		// hold-reality <server> <sni> <pubkey> <shortid> <uuid> <target> <n>
		pub, _ := base64.RawURLEncoding.DecodeString(a[4])
		var sid [8]byte
		hex.Decode(sid[:], []byte(a[5]))
		client, _ := vless.NewClient(a[6], "", nopLogger{})
		n, _ := strconv.Atoi(a[8])
		hold(n, func() (net.Conn, error) {
			rc, err := realityDial(a[2], a[3], pub, sid)
			if err != nil {
				return nil, err
			}
			return client.DialEarlyConn(rc, M.ParseSocksaddr(a[7]))
		})
	case "ss", "conns-ss":
		method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-128-gcm", a[3], time.Now)
		if err != nil {
			log.Fatal(err)
		}
		dial := func() (net.Conn, error) {
			c, err := net.Dial("tcp", a[2])
			if err != nil {
				return nil, err
			}
			return method.DialConn(c, M.ParseSocksaddr(a[4]))
		}
		if a[1] == "ss" {
			par, _ := strconv.Atoi(a[6])
			useTLS := len(a) > 7 && a[7] == "tls"
			parallel(par, func() (int64, error) {
				c, err := dial()
				if err != nil {
					return 0, err
				}
				return get(c, a[5], useTLS, false)
			})
		} else {
			conc, _ := strconv.Atoi(a[5])
			secs, _ := strconv.Atoi(a[6])
			churn(conc, secs, func() error {
				c, err := dial()
				if err != nil {
					return err
				}
				_, err = get(c, "/small", false, true)
				return err
			})
		}
	case "reality", "conns-reality":
		pub, err := base64.RawURLEncoding.DecodeString(a[4])
		if err != nil {
			log.Fatal(err)
		}
		var sid [8]byte
		hex.Decode(sid[:], []byte(a[5]))
		flow := ""
		if a[1] == "reality" && a[7] != "-" {
			flow = a[7]
		}
		client, err := vless.NewClient(a[6], flow, nopLogger{})
		if err != nil {
			log.Fatal(err)
		}
		dial := func(target string) (net.Conn, error) {
			rc, err := realityDial(a[2], a[3], pub, sid)
			if err != nil {
				return nil, err
			}
			return client.DialEarlyConn(rc, M.ParseSocksaddr(target))
		}
		if a[1] == "reality" {
			par, _ := strconv.Atoi(a[10])
			useTLS := len(a) > 11 && a[11] == "tls"
			parallel(par, func() (int64, error) {
				c, err := dial(a[8])
				if err != nil {
					return 0, err
				}
				return get(c, a[9], useTLS, false)
			})
		} else {
			conc, _ := strconv.Atoi(a[8])
			secs, _ := strconv.Atoi(a[9])
			churn(conc, secs, func() error {
				c, err := dial(a[7])
				if err != nil {
					return err
				}
				_, err = get(c, "/small", false, true)
				return err
			})
		}
	}
}
