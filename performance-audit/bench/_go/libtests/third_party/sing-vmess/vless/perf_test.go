package vless

// Scratch tests for the keel audit. Not part of the repo.

import (
	"io"
	"net"
	"sync/atomic"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// realityConnCopy mirrors cmd/keel-node/proto_vless.go realityConn.
type realityConnCopy struct {
	*utls.Conn
	prefix []byte
}

func (c *realityConnCopy) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
func (c *realityConnCopy) Upstream() any           { return c.Conn }
func (c *realityConnCopy) CloseWrite() error       { return c.Close() }
func (c *realityConnCopy) ReaderReplaceable() bool { return len(c.prefix) == 0 }
func (c *realityConnCopy) WriterReplaceable() bool { return true }

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		ch <- c
	}()
	c1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return <-ch, c1
}

// visionSplice is a prototype of the methods VisionConn would need so that
// sing's copy re-unwraps to the raw TCP conn once Vision goes direct.
type visionSplice struct{ *VisionConn }

func (c visionSplice) NeedHandshakeForRead() bool {
	return !c.directRead || len(c.remainingBuffers) > 0
}
func (c visionSplice) NeedHandshakeForWrite() bool { return !c.directWrite }
func (c visionSplice) ReaderReplaceable() bool {
	return c.directRead && len(c.remainingBuffers) == 0
}
func (c visionSplice) WriterReplaceable() bool { return c.directWrite }
func (c visionSplice) UpstreamReader() any {
	if c.directRead {
		return c.netConn
	}
	return c.Conn
}
func (c visionSplice) UpstreamWriter() any {
	if c.directWrite {
		return c.netConn
	}
	return c.Conn
}

func TestVisionFastPathReachability(t *testing.T) {
	server, client := tcpPair(t)
	defer server.Close()
	defer client.Close()
	tlsConn := utls.Server(server, &utls.Config{})
	rc := &realityConnCopy{Conn: tlsConn} // prefix already drained by ReadRequest
	responseConn := &serverConn{ExtendedConn: bufio.NewExtendedConn(rc)}
	vc, err := NewVisionConn(responseConn, rc, [16]byte{1}, logger.NOP())
	if err != nil {
		t.Fatalf("NewVisionConn: %v", err)
	}
	t.Logf("NewVisionConn found the *utls.Conn through realityConn: netConn=%T", vc.netConn)
	var up, down atomic.Int64
	check := func(label string, conn net.Conn) {
		counter := bufio.NewInt64CounterConn(conn, []*atomic.Int64{&up}, []*atomic.Int64{&down})
		src, rcs := N.UnwrapCountReader(counter, nil)
		dst, wcs := N.UnwrapCountWriter(counter, nil)
		_, rw := bufio.CreateReadWaiter(bufio.NewExtendedReader(src))
		_, vw := bufio.CreateVectorisedWriter(bufio.NewExtendedWriter(dst))
		hs := N.NewHandshakeState(src, dst)
		t.Logf("%-40s copy source=%T (counters %d) syscallRead=%v readWaiter=%v | dest=%T (counters %d) syscallWrite=%v vectorisedWriter=%v | upgradable=%v",
			label, src, len(rcs), N.SyscallAvailableForRead(src), rw, dst, len(wcs), N.SyscallAvailableForWrite(dst), vw, hs.Upgradable())
	}
	check("VisionConn, padding phase:", vc)
	vc.directRead, vc.directWrite = true, true
	check("VisionConn, after direct mode:", vc)
	vc.directRead, vc.directWrite = false, false
	check("prototype, padding phase:", visionSplice{vc})
	vc.directRead, vc.directWrite = true, true
	check("prototype, after direct mode:", visionSplice{vc})
}

// BenchmarkVisionDirectWrite: VisionConn.Write once in direct mode (what the
// download direction costs per chunk on top of the raw socket write).
func BenchmarkVisionDirectWrite(b *testing.B) {
	vc := &VisionConn{netConn: discard{}, directWrite: true}
	p := make([]byte, 32*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(p)))
	for i := 0; i < b.N; i++ {
		vc.Write(p)
	}
}

type discard struct{ net.Conn }

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkServerPacketConnReadPacket: plain VLESS UDP (not XUDP), per packet.
func BenchmarkServerPacketConnReadPacket(b *testing.B) {
	pkt := make([]byte, 2+1200)
	pkt[0], pkt[1] = 1200>>8, 1200&0xff
	src := &loopReader{data: pkt}
	pc := &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(src)}
	bb := buf.NewPacket()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bb.Reset()
		if _, err := pc.ReadPacket(bb); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(src.reads)/float64(b.N), "conn-reads/op")
}

type loopReader struct {
	net.Conn
	data  []byte
	pos   int
	reads int
}

func (r *loopReader) Read(p []byte) (int, error) {
	r.reads++
	n := copy(p, r.data[r.pos:])
	r.pos = (r.pos + n) % len(r.data)
	return n, nil
}

var _ io.Reader = (*loopReader)(nil)
