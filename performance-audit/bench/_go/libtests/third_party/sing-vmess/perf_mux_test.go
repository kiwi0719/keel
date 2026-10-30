package vmess

// Scratch benchmarks for the keel audit. Not part of the repo.

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type muxAddr struct{}

func (muxAddr) Network() string { return "tcp" }
func (muxAddr) String() string  { return "127.0.0.1:1" }

type frameConn struct {
	preamble []byte
	repeat   []byte
	pos      int
	reads    atomic.Int64
	closed   atomic.Bool
}

func (c *frameConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	c.reads.Add(1)
	if len(c.preamble) > 0 {
		n := copy(p, c.preamble)
		c.preamble = c.preamble[n:]
		return n, nil
	}
	n := copy(p, c.repeat[c.pos:])
	c.pos = (c.pos + n) % len(c.repeat)
	return n, nil
}
func (c *frameConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *frameConn) Close() error                       { c.closed.Store(true); return nil }
func (c *frameConn) LocalAddr() net.Addr                { return muxAddr{} }
func (c *frameConn) RemoteAddr() net.Addr               { return muxAddr{} }
func (c *frameConn) SetDeadline(t time.Time) error      { return nil }
func (c *frameConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *frameConn) SetWriteDeadline(t time.Time) error { return nil }

type muxHandler struct {
	packets atomic.Int64
	bytes   atomic.Int64
}

func (h *muxHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	p := make([]byte, 32*1024)
	for {
		n, err := conn.Read(p)
		if err != nil {
			return
		}
		h.bytes.Add(int64(n))
		h.packets.Add(1)
	}
}

func (h *muxHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	b := buf.NewPacket()
	for {
		b.Reset()
		if _, err := conn.ReadPacket(b); err != nil {
			return
		}
		h.bytes.Add(int64(b.Len()))
		h.packets.Add(1)
	}
}

// muxFrame builds a mux.cool frame; addr is included when network != 0.
func muxFrame(sid uint16, status, option, network byte, dest M.Socksaddr, data []byte) []byte {
	meta := make([]byte, 0, 64)
	meta = binary.BigEndian.AppendUint16(meta, sid)
	meta = append(meta, status, option)
	if network != 0 {
		meta = append(meta, network)
		ab := buf.NewSize(64)
		AddressSerializer.WriteAddrPort(ab, dest)
		meta = append(meta, ab.Bytes()...)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(meta)))
	out = append(out, meta...)
	if option&OptionData != 0 {
		out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
		out = append(out, data...)
	}
	return out
}

func benchMux(b *testing.B, network byte, size int, addrEachFrame bool) {
	dest := M.ParseSocksaddr("1.1.1.1:443")
	data := make([]byte, size)
	keepNet := byte(0)
	if addrEachFrame {
		keepNet = network
	}
	conn := &frameConn{
		preamble: muxFrame(1, StatusNew, OptionData, network, dest, data),
		repeat:   muxFrame(1, StatusKeep, OptionData, keepNet, dest, data),
	}
	h := &muxHandler{}
	go HandleMuxConnection(context.Background(), conn, M.Socksaddr{}, h)
	for h.packets.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	start := h.packets.Load()
	reads0 := conn.reads.Load()
	b.ResetTimer()
	for h.packets.Load()-start < int64(b.N) {
		// the recvLoop runs in its own goroutine; wait for it
		time.Sleep(50 * time.Microsecond)
	}
	b.StopTimer()
	got := h.packets.Load() - start
	b.ReportMetric(float64(conn.reads.Load()-reads0)/float64(got), "conn-reads/frame")
	conn.Close()
}

func BenchmarkMuxServerRecv(b *testing.B) {
	b.Run("udp/1200B/addr-each-frame(XUDP)", func(b *testing.B) { benchMux(b, NetworkUDP, 1200, true) })
	b.Run("udp/1200B/no-addr", func(b *testing.B) { benchMux(b, NetworkUDP, 1200, false) })
	b.Run("tcp/16KiB", func(b *testing.B) { benchMux(b, NetworkTCP, 16*1024, false) })
	b.Run("tcp/1200B", func(b *testing.B) { benchMux(b, NetworkTCP, 1200, false) })
}

// BenchmarkXUDPClientReadPacket: keel-node's VLESS outbound UDP receive path
// (XUDPConn over the plain TCP conn). conn-reads/op are read syscalls there.
func BenchmarkXUDPClientReadPacket(b *testing.B) {
	dest := M.ParseSocksaddr("1.1.1.1:443")
	data := make([]byte, 1200)
	conn := &frameConn{repeat: muxFrame(0, StatusKeep, OptionData, NetworkUDP, dest, data)}
	x := NewXUDPConn(conn, dest)
	bb := buf.NewPacket()
	b.SetBytes(1200)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bb.Reset()
		if _, err := x.ReadPacket(bb); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(conn.reads.Load())/float64(b.N), "conn-reads/op")
}
