package vless

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return <-accepted, c
}

// Once direct, a copy unwraps a counted VisionConn to the TCP connection
// (and keeps the counters); before, and while records read through TLS are
// still waiting, it must not.
func TestVisionUnwrapsToTCPWhenDirect(t *testing.T) {
	server, client := tcpPair(t)
	defer server.Close()
	defer client.Close()
	tlsConn := tls.Server(server, &tls.Config{})
	vc, err := NewVisionConn(tlsConn, tlsConn, [16]byte{1}, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	var up, down atomic.Int64
	counted := bufio.NewInt64CounterConn(vc, []*atomic.Int64{&up}, []*atomic.Int64{&down})
	unwrap := func() (any, int, any, int) {
		src, readCounters := N.UnwrapCountReader(counted, nil)
		dst, writeCounters := N.UnwrapCountWriter(counted, nil)
		return src, len(readCounters), dst, len(writeCounters)
	}

	if src, _, dst, _ := unwrap(); src != vc || dst != vc {
		t.Fatalf("padding phase unwrapped to %T / %T", src, dst)
	}
	if !N.NeedHandshakeForRead(counted) || !N.NeedHandshakeForWrite(counted) {
		t.Fatal("a copy would never look again")
	}

	vc.directRead, vc.directWrite = true, true
	vc.remainingBuffers = []*buf.Buffer{buf.As([]byte("still from TLS"))}
	if src, _, _, _ := unwrap(); src != vc {
		t.Fatalf("unwrapped to %T with records still waiting", src)
	}
	if !N.NeedHandshakeForRead(counted) || N.NeedHandshakeForWrite(counted) {
		t.Fatal("read side should wait for the records, write side is direct")
	}

	vc.remainingBuffers = nil
	src, readCounters, dst, writeCounters := unwrap()
	if src != server || dst != server {
		t.Fatalf("direct mode unwrapped to %T / %T, want the TCP conn", src, dst)
	}
	if readCounters != 1 || writeCounters != 1 {
		t.Fatalf("counters lost: %d read, %d write", readCounters, writeCounters)
	}
}
