// blast: load-test endpoints for keel-node benchmarks.
//
//	blast serve <http-addr> <https-addr>   GET /n/<bytes> streams that many bytes; /small returns 2 KB
//	blast conns <socks5> <target-host:port> <concurrency> <seconds>
//	                                        new SOCKS5 connection per HTTP GET /small; prints conns/s
//	blast udp <socks5> <echo-addr> <seconds> <size>   UDP ASSOCIATE through socks5, ping-pong pps
//	blast udpecho <addr>
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var chunk = make([]byte, 1<<20)

func serveN(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/n/"), 10, 64)
	if err != nil {
		http.Error(w, "bad", 400)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	for n > 0 {
		k := min(n, int64(len(chunk)))
		if _, err := w.Write(chunk[:k]); err != nil {
			return
		}
		n -= k
	}
}

func main() {
	rand.Read(chunk)
	switch os.Args[1] {
	case "serve":
		mux := http.NewServeMux()
		mux.HandleFunc("/n/", serveN)
		small := make([]byte, 2048)
		mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) { w.Write(small) })
		go func() { log.Fatal(http.ListenAndServe(os.Args[2], mux)) }()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "blast.test"}, DNSNames: []string{"blast.test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		srv := &http.Server{Addr: os.Args[3], Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	case "blackhole":
		pc, err := net.ListenPacket("udp", os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		ln, err := net.Listen("tcp", os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go io.Copy(io.Discard, c)
			}
		}()
		buf := make([]byte, 65536)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				log.Fatal(err)
			}
		}
	case "udpecho":
		pc, err := net.ListenPacket("udp", os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				log.Fatal(err)
			}
			pc.WriteTo(buf[:n], addr)
		}
	case "conns":
		conc, _ := strconv.Atoi(os.Args[4])
		secs, _ := strconv.Atoi(os.Args[5])
		var ok, fail atomic.Int64
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		var wg sync.WaitGroup
		var latMu sync.Mutex
		var lats []time.Duration
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(deadline) {
					start := time.Now()
					if err := oneGet(os.Args[2], os.Args[3]); err != nil {
						fail.Add(1)
						continue
					}
					ok.Add(1)
					latMu.Lock()
					lats = append(lats, time.Since(start))
					latMu.Unlock()
				}
			}()
		}
		wg.Wait()
		var sum time.Duration
		for _, l := range lats {
			sum += l
		}
		avg := time.Duration(0)
		if len(lats) > 0 {
			avg = sum / time.Duration(len(lats))
		}
		fmt.Printf("conns ok=%d fail=%d rate=%.0f/s avg=%v\n", ok.Load(), fail.Load(), float64(ok.Load())/float64(secs), avg)
	case "get":
		// blast get <socks5> <host:port> <path> <parallel> [tls]
		par, _ := strconv.Atoi(os.Args[5])
		useTLS := len(os.Args) > 6 && os.Args[6] == "tls"
		var total atomic.Int64
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < par; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := download(os.Args[2], os.Args[3], os.Args[4], useTLS)
				if err != nil {
					log.Print("get: ", err)
				}
				total.Add(n)
			}()
		}
		wg.Wait()
		el := time.Since(start).Seconds()
		fmt.Printf("get bytes=%d secs=%.2f MBps=%.0f\n", total.Load(), el, float64(total.Load())/el/1e6)
	case "hold":
		// blast hold <socks5> <target> <n>
		n, _ := strconv.Atoi(os.Args[4])
		var conns []net.Conn
		for i := 0; i < n; i++ {
			c, br, _, err := socksConnect(os.Args[2], os.Args[3], 1)
			if err != nil {
				log.Fatal(err)
			}
			c.SetDeadline(time.Time{})
			fmt.Fprintf(c, "GET /small HTTP/1.1\r\nHost: x\r\n\r\n")
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				log.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			conns = append(conns, c)
		}
		fmt.Printf("holding %d\n", len(conns))
		time.Sleep(24 * time.Hour)
	case "udp":
		secs, _ := strconv.Atoi(os.Args[4])
		size, _ := strconv.Atoi(os.Args[5])
		if err := udpBench(os.Args[2], os.Args[3], secs, size); err != nil {
			log.Fatal(err)
		}
	}
}

func socksConnect(socks, target string, cmd byte) (net.Conn, *bufio.Reader, []byte, error) {
	c, err := net.DialTimeout("tcp", socks, 5*time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(br, hdr); err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	ap := netip.MustParseAddrPort(target)
	req := []byte{5, cmd, 0, 1}
	a4 := ap.Addr().As4()
	req = append(req, a4[:]...)
	req = binary.BigEndian.AppendUint16(req, ap.Port())
	if _, err = c.Write(req); err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	resp := make([]byte, 10)
	if _, err = io.ReadFull(br, resp); err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	if resp[1] != 0 {
		c.Close()
		return nil, nil, nil, fmt.Errorf("socks reply %d", resp[1])
	}
	return c, br, resp, nil
}

func oneGet(socks, target string) error {
	c, br, _, err := socksConnect(socks, target, 1)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err = fmt.Fprintf(c, "GET /small HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return err
}

func download(socks, target, path string, useTLS bool) (int64, error) {
	c, br, _, err := socksConnect(socks, target, 1)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Time{})
	var rw io.ReadWriter = struct {
		io.Reader
		io.Writer
	}{br, c}
	if useTLS {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "blast.test"})
		if err := tc.Handshake(); err != nil {
			return 0, err
		}
		rw = tc
	}
	if _, err = fmt.Fprintf(rw, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(rw, 64<<10), nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
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

func udpBench(socks, echo string, secs, size int) error {
	c, _, resp, err := socksConnect(socks, "0.0.0.0:0", 3)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Time{})
	relay := netip.AddrPortFrom(netip.AddrFrom4([4]byte(resp[4:8])), binary.BigEndian.Uint16(resp[8:10]))
	if relay.Addr().IsUnspecified() {
		relay = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relay.Port())
	}
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		return err
	}
	ap := netip.MustParseAddrPort(echo)
	hdr := []byte{0, 0, 0, 1}
	a4 := ap.Addr().As4()
	hdr = append(hdr, a4[:]...)
	hdr = binary.BigEndian.AppendUint16(hdr, ap.Port())
	pkt := append(hdr, make([]byte, size)...)
	buf := make([]byte, 65536)
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	var n, lost int
	for time.Now().Before(deadline) {
		u.Write(pkt)
		u.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := u.Read(buf); err != nil {
			lost++
			continue
		}
		n++
	}
	fmt.Printf("udp pingpong ok=%d lost=%d rate=%.0f/s\n", n, lost, float64(n)/float64(secs))
	return nil
}
