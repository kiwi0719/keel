package session

// Scratch performance tests for the keel audit. Not part of the repo.

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/pipe"
	satomic "github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

// ---------- helpers ----------

type addr struct{}

func (addr) Network() string { return "tcp" }
func (addr) String() string  { return "127.0.0.1:1" }

// discardConn swallows writes and counts them.
type discardConn struct {
	writes atomic.Int64
	bytes  atomic.Int64
	sizes  []int
	mu     sync.Mutex
	record bool
}

func (c *discardConn) Read(p []byte) (int, error) { select {} }
func (c *discardConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	c.bytes.Add(int64(len(p)))
	if c.record {
		c.mu.Lock()
		c.sizes = append(c.sizes, len(p))
		c.mu.Unlock()
	}
	return len(p), nil
}
func (c *discardConn) Close() error                     { return nil }
func (c *discardConn) LocalAddr() net.Addr              { return addr{} }
func (c *discardConn) RemoteAddr() net.Addr             { return addr{} }
func (c *discardConn) SetDeadline(time.Time) error      { return nil }
func (c *discardConn) SetReadDeadline(time.Time) error  { return nil }
func (c *discardConn) SetWriteDeadline(time.Time) error { return nil }

func paddingValue(tb testing.TB) *satomic.TypedValue[*padding.PaddingFactory] {
	var v satomic.TypedValue[*padding.PaddingFactory]
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &v) {
		tb.Fatal("padding")
	}
	return &v
}

func rawFrame(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, headerOverHeadSize+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}

// frameSource is a net.Conn whose Read returns preamble once and then the
// same frame forever, until closed.
type frameSource struct {
	discardConn
	preamble []byte
	repeat   []byte
	pos      int
	closed   atomic.Bool
	reads    atomic.Int64
}

func (c *frameSource) Read(p []byte) (int, error) {
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
func (c *frameSource) Close() error { c.closed.Store(true); return nil }

func settingsFrame(tb testing.TB) []byte {
	pf := padding.NewPaddingFactory(padding.DefaultPaddingScheme)
	data := []byte("v=2\npadding-md5=" + pf.Md5)
	return rawFrame(cmdSettings, 0, data)
}

// ---------- write path ----------

// BenchmarkStreamWrite measures Stream.Write -> writeDataFrame on a server
// session whose conn discards (isolates the lib's own cost, no TLS).
func BenchmarkStreamWrite(b *testing.B) {
	for _, size := range []int{1024, 16 * 1024, 32 * 1024, 65535} {
		b.Run(sizeName(size), func(b *testing.B) {
			conn := &discardConn{}
			s := NewServerSession(conn, nil, paddingValue(b), logger.NOP())
			st := newStream(1, s)
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := st.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStreamWriteBufferHeadroom is a prototype of a WriteBuffer +
// FrontHeadroom(7) fast path: sing's copy would hand us a buffer with 7
// bytes of headroom, so the header is written in place, no copy, no
// second pooled buffer.
func BenchmarkStreamWriteBufferHeadroom(b *testing.B) {
	for _, size := range []int{1024, 16 * 1024, 32 * 1024, 65535} {
		b.Run(sizeName(size), func(b *testing.B) {
			conn := &discardConn{}
			s := NewServerSession(conn, nil, paddingValue(b), logger.NOP())
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// what sing's copy loop does per read: pooled buffer with headroom
				buffer := buf.NewSize(size + headerOverHeadSize)
				buffer.Resize(headerOverHeadSize, size)
				// --- the prototype WriteBuffer:
				dataLen := buffer.Len()
				hdr := buffer.ExtendHeader(headerOverHeadSize)
				hdr[0] = cmdPSH
				binary.BigEndian.PutUint32(hdr[1:5], 1)
				binary.BigEndian.PutUint16(hdr[5:7], uint16(dataLen))
				if _, err := s.writeConn(buffer.Bytes()); err != nil {
					b.Fatal(err)
				}
				buffer.Release()
			}
		})
	}
}

// BenchmarkCopyLoopWriteToStream models the download direction as keel-node
// runs it: sing copy reads into a pooled 32 KiB buffer, then Stream.Write
// copies it again into a 64 KiB pooled frame buffer. Reported B/op is what
// is allocated per 32 KiB chunk.
func BenchmarkCopyLoopWriteToStream(b *testing.B) {
	conn := &discardConn{}
	s := NewServerSession(conn, nil, paddingValue(b), logger.NOP())
	st := newStream(1, s)
	b.SetBytes(32 * 1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buffer := buf.NewSize(buf.BufferSize) // sing copy's read buffer
		buffer.Truncate(buf.BufferSize)
		if _, err := st.Write(buffer.Bytes()); err != nil {
			b.Fatal(err)
		}
		buffer.Release()
	}
}

// ---------- read path ----------

// BenchmarkRecvLoopToStream feeds PSH frames for one stream into a server
// session and reads them out of the Stream with a 32 KiB buffer, as sing's
// copy does. Per op = one frame.
func BenchmarkRecvLoopToStream(b *testing.B) {
	for _, size := range []int{1024, 16 * 1024} {
		b.Run(sizeName(size), func(b *testing.B) {
			payload := make([]byte, size)
			src := &frameSource{
				preamble: append(settingsFrame(b), rawFrame(cmdSYN, 1, nil)...),
				repeat:   rawFrame(cmdPSH, 1, payload),
			}
			streamCh := make(chan *Stream, 1)
			s := NewServerSession(src, func(st *Stream) { streamCh <- st }, paddingValue(b), logger.NOP())
			go s.Run()
			st := <-streamCh
			p := make([]byte, 32*1024)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			got := 0
			for got < b.N*size {
				n, err := st.Read(p)
				if err != nil {
					b.Fatal(err)
				}
				got += n
			}
			b.StopTimer()
			s.Close()
		})
	}
}

// BenchmarkPipeHandoff measures the synchronous pipe alone (one Write that
// one Read consumes), i.e. the goroutine handoff per frame.
func BenchmarkPipeHandoff(b *testing.B) {
	for _, size := range []int{1024, 16 * 1024} {
		b.Run(sizeName(size), func(b *testing.B) {
			r, w := pipe.Pipe()
			data := make([]byte, size)
			go func() {
				for {
					if _, err := w.Write(data); err != nil {
						return
					}
				}
			}()
			p := make([]byte, 32*1024)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := r.Read(p); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			r.Close()
		})
	}
}

// BenchmarkChanHandoffBuffered is the alternative design: recvLoop hands the
// pooled frame buffer to the stream through a small buffered channel and
// the reader takes ownership (no second copy, writer not blocked per frame).
func BenchmarkChanHandoffBuffered(b *testing.B) {
	for _, size := range []int{1024, 16 * 1024} {
		b.Run(sizeName(size), func(b *testing.B) {
			ch := make(chan *buf.Buffer, 8)
			done := make(chan struct{})
			go func() {
				for {
					bb := buf.NewSize(size)
					bb.Truncate(size)
					select {
					case ch <- bb:
					case <-done:
						bb.Release()
						return
					}
				}
			}()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bb := <-ch
				bb.Release()
			}
			b.StopTimer()
			close(done)
		})
	}
}

// TestHeadOfLineBlocking: stream 1's reader never reads; a frame for stream 2
// queued behind one frame for stream 1 is not delivered.
func TestHeadOfLineBlocking(t *testing.T) {
	data := make([]byte, 100)
	pre := append(settingsFrame(t), rawFrame(cmdSYN, 1, nil)...)
	pre = append(pre, rawFrame(cmdSYN, 2, nil)...)
	pre = append(pre, rawFrame(cmdPSH, 1, data)...)
	pre = append(pre, rawFrame(cmdPSH, 2, data)...)
	src := &frameSource{preamble: pre, repeat: rawFrame(cmdHeartResponse, 0, nil)}
	streams := make(chan *Stream, 2)
	s := NewServerSession(src, func(st *Stream) { streams <- st }, paddingValue(t), logger.NOP())
	go s.Run()
	defer s.Close()
	var st2 *Stream
	for i := 0; i < 2; i++ {
		st := <-streams
		if st.id == 2 {
			st2 = st
		}
	}
	st2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	p := make([]byte, 1024)
	n, err := st2.Read(p)
	t.Logf("stream 2 read while stream 1 is not being read: n=%d err=%v", n, err)
	if err == nil {
		t.Logf("NOT blocked")
	} else {
		t.Logf("BLOCKED: stream 2 gets nothing because recvLoop is parked in stream 1's pipe write")
	}
}

// TestPaddingWrites counts conn.Write calls and bytes for the first writes
// of a client session (padding active) and a server session (never pads).
func TestPaddingWrites(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		conn := &discardConn{record: true}
		var s *Session
		if role == "client" {
			s = NewClientSession(conn, paddingValue(t), logger.NOP())
		} else {
			s = NewServerSession(conn, nil, paddingValue(t), logger.NOP())
		}
		payload := make([]byte, 200)
		for i := 1; i <= 10; i++ {
			before := conn.writes.Load()
			beforeB := conn.bytes.Load()
			if _, err := s.writeConn(rawFrame(cmdPSH, 1, payload)); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s write #%d (207 B frame): %d conn writes, %d bytes on the wire", role, i, conn.writes.Load()-before, conn.bytes.Load()-beforeB)
		}
	}
	// a client's large first data write
	conn := &discardConn{record: true}
	s := NewClientSession(conn, paddingValue(t), logger.NOP())
	for i := 1; i <= 8; i++ {
		before := conn.writes.Load()
		beforeB := conn.bytes.Load()
		s.writeConn(rawFrame(cmdPSH, 1, make([]byte, 16*1024)))
		t.Logf("client write #%d (16 KiB frame): %d conn writes, %d bytes", i, conn.writes.Load()-before, conn.bytes.Load()-beforeB)
	}
}

func sizeName(n int) string {
	switch {
	case n >= 1024 && n%1024 == 0:
		return itoa(n/1024) + "KiB"
	default:
		return itoa(n) + "B"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
