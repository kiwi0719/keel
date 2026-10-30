// interop: SS2022 peers built from the unmodified upstream libraries, to
// check keel's patched sing-shadowsocks against them.
//
//	interop echo <listen>                                   TCP echo server
//	interop get <ss1|ss2|socks> <server> <password|-> <target> <path>
//	                                                         HTTP GET, prints bytes and sha256
//	interop echoes <ss1|ss2|socks> <server> <password|-> <target> <bytes> <conns>
//	                                                         sends random bytes to an echo server, checks them
//	interop serve-ss1 <listen> <psk> <user key>             upstream multi-user server, dials destinations directly
package main

import (
	stdbufio "bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	ss1 "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	ss2 "github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const method = "2022-blake3-aes-128-gcm"

func dial(kind, server, password, target string) (net.Conn, error) {
	c, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "ss1":
		m, err := ss1.NewWithPassword(method, password, time.Now)
		if err != nil {
			return nil, err
		}
		return m.DialConn(c, M.ParseSocksaddr(target))
	case "ss2":
		m, err := ss2.CreateMethod(context.Background(), method, ss2.MethodOptions{Password: password})
		if err != nil {
			return nil, err
		}
		return m.DialConn(c, M.ParseSocksaddr(target))
	case "socks":
		c.Write([]byte{5, 1, 0})
		br := make([]byte, 2)
		io.ReadFull(c, br)
		ap := netip.MustParseAddrPort(target)
		a := ap.Addr().As4()
		req := append([]byte{5, 1, 0, 1}, a[:]...)
		req = binary.BigEndian.AppendUint16(req, ap.Port())
		c.Write(req)
		resp := make([]byte, 10)
		if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
			return nil, fmt.Errorf("socks: %v %v", err, resp)
		}
		return c, nil
	}
	return nil, fmt.Errorf("unknown %s", kind)
}

type relay struct{}

func (relay) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	remote, err := net.Dial("tcp", metadata.Destination.String())
	if err != nil {
		return err
	}
	return bufio.CopyConn(ctx, conn, remote)
}

func (relay) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (relay) NewError(ctx context.Context, err error) { log.Print(err) }

func main() {
	a := os.Args
	switch a[1] {
	case "echo":
		ln, err := net.Listen("tcp", a[2])
		if err != nil {
			log.Fatal(err)
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	case "get":
		c, err := dial(a[2], a[3], a[4], a[5])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", a[6])
		resp, err := http.ReadResponse(stdbufio.NewReaderSize(c, 64<<10), nil)
		if err != nil {
			log.Fatal(err)
		}
		h := sha256.New()
		n, err := io.Copy(h, resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s get bytes=%d sha256=%s\n", a[2], n, hex.EncodeToString(h.Sum(nil))[:16])
	case "echoes":
		size, _ := strconv.Atoi(a[6])
		conns, _ := strconv.Atoi(a[7])
		for i := 0; i < conns; i++ {
			c, err := dial(a[2], a[3], a[4], a[5])
			if err != nil {
				log.Fatal(err)
			}
			p := make([]byte, size)
			rand.Read(p)
			go func() { c.Write(p) }()
			got := make([]byte, size)
			if _, err := io.ReadFull(c, got); err != nil {
				log.Fatalf("conn %d: %v", i, err)
			}
			if !bytes.Equal(p, got) {
				log.Fatalf("conn %d: echo differs", i)
			}
			c.Close()
		}
		fmt.Printf("%s echoes ok conns=%d bytes=%d each\n", a[2], conns, size)
	case "serve-ss1":
		s, err := ss1.NewMultiServiceWithPassword[string](method, a[3], 300, relay{}, time.Now)
		if err != nil {
			log.Fatal(err)
		}
		if err := s.UpdateUsersWithPasswords([]string{"u"}, []string{a[4]}); err != nil {
			log.Fatal(err)
		}
		ln, err := net.Listen("tcp", a[2])
		if err != nil {
			log.Fatal(err)
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				if err := s.NewConnection(context.Background(), c, M.Metadata{Source: M.SocksaddrFromNet(c.RemoteAddr())}); err != nil {
					log.Print("serve: ", err)
					c.Close()
				}
			}()
		}
	}
}
