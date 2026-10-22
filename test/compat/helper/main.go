// helper provides the local endpoints the compatibility test needs:
//
//	helper dest <addr> <server-name> [dir]   TLS 1.3 site (Reality dest; serves dir if given)
//	helper udpecho <addr>              UDP echo server
//	helper socksudp <socks> <target>   send UDP through a SOCKS5 proxy and expect the echo
package main

import (
	"bytes"
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
	"time"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: helper dest|udpecho|socksudp ...")
	}
	switch os.Args[1] {
	case "dest":
		dir := ""
		if len(os.Args) > 4 {
			dir = os.Args[4]
		}
		dest(os.Args[2], os.Args[3], dir)
	case "udpecho":
		udpEcho(os.Args[2])
	case "socksudp":
		if err := socksUDP(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("udp ok")
	}
}

func dest(addr, name, dir string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "dest-ok\n")
	})
	if dir != "" {
		handler = http.FileServer(http.Dir(dir))
	}
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func udpEcho(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, 65536)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Fatal(err)
		}
		conn.WriteTo(buffer[:n], from)
	}
}

// socksUDP does a SOCKS5 UDP ASSOCIATE and checks that 20 packets of
// different sizes come back unchanged.
func socksUDP(socksAddr, target string) error {
	ctrl, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(20 * time.Second))
	ctrl.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	if _, err = io.ReadFull(ctrl, reply); err != nil || reply[1] != 0 {
		return fmt.Errorf("socks greeting: %v %v", reply, err)
	}
	ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	head := make([]byte, 4)
	if _, err = io.ReadFull(ctrl, head); err != nil || head[1] != 0 {
		return fmt.Errorf("udp associate: %v %v", head, err)
	}
	var relay netip.AddrPort
	switch head[3] {
	case 1:
		b := make([]byte, 6)
		io.ReadFull(ctrl, b)
		relay = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), binary.BigEndian.Uint16(b[4:]))
	case 4:
		b := make([]byte, 18)
		io.ReadFull(ctrl, b)
		relay = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[:16])), binary.BigEndian.Uint16(b[16:]))
	default:
		return fmt.Errorf("unexpected bind address type %d", head[3])
	}
	if relay.Addr().IsUnspecified() {
		relay = netip.AddrPortFrom(netip.MustParseAddrPort(ctrl.RemoteAddr().String()).Addr(), relay.Port())
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		return err
	}
	defer conn.Close()
	targetAddr := netip.MustParseAddrPort(target)
	header := []byte{0, 0, 0, 1}
	header = append(header, targetAddr.Addr().AsSlice()...)
	header = binary.BigEndian.AppendUint16(header, targetAddr.Port())
	buffer := make([]byte, 65536)
	for i := 0; i < 20; i++ {
		payload := make([]byte, 16+i*60)
		rand.Read(payload)
		ok := false
		for attempt := 0; attempt < 3 && !ok; attempt++ {
			conn.Write(append(append([]byte{}, header...), payload...))
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buffer)
			if err != nil {
				continue
			}
			ok = n >= len(header) && bytes.Equal(buffer[len(header):n], payload)
		}
		if !ok {
			return fmt.Errorf("packet %d not echoed", i)
		}
	}
	return nil
}
