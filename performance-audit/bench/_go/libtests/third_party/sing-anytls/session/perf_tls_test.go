package session

// Scratch: Stream.Write over a real crypto/tls conn (loopback), vs the
// in-place header prototype, to size the extra copy against TLS cost.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

func tlsPair(tb testing.TB) (*tls.Conn, *tls.Conn) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "b"}, DNSNames: []string{"b"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	c, _ := net.Dial("tcp", l.Addr().String())
	s := <-ch
	srv := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	cli := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	go srv.Handshake()
	if err := cli.Handshake(); err != nil {
		tb.Fatal(err)
	}
	return srv, cli
}

func BenchmarkStreamWriteOverTLS(b *testing.B) {
	for _, inPlace := range []bool{false, true} {
		name := "Stream.Write(copy)"
		if inPlace {
			name = "in-place-header(prototype)"
		}
		b.Run(name+"/32KiB", func(b *testing.B) {
			srv, cli := tlsPair(b)
			defer srv.Close()
			defer cli.Close()
			go io.Copy(io.Discard, cli)
			s := NewServerSession(srv, nil, paddingValue(b), logger.NOP())
			st := newStream(1, s)
			const size = 32 * 1024
			src := make([]byte, size)
			for i := 0; i < 16; i++ { // past dynamic record sizing
				st.Write(src)
			}
			b.SetBytes(size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buffer := buf.NewSize(size + headerOverHeadSize) // sing copy's read buffer
				if inPlace {
					buffer.Resize(headerOverHeadSize, size)
					hdr := buffer.ExtendHeader(headerOverHeadSize)
					hdr[0] = cmdPSH
					binary.BigEndian.PutUint32(hdr[1:5], 1)
					binary.BigEndian.PutUint16(hdr[5:7], size)
					s.writeConn(buffer.Bytes())
				} else {
					buffer.Truncate(size)
					st.Write(buffer.Bytes())
				}
				buffer.Release()
			}
		})
	}
}
