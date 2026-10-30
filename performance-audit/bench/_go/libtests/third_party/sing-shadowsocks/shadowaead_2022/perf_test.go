package shadowaead_2022

// Scratch performance tests for the keel audit. Not part of the repo.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/replay"

	"golang.org/x/crypto/chacha20poly1305"
)

const method128 = "2022-blake3-aes-128-gcm"

type tAddr struct{}

func (tAddr) Network() string { return "tcp" }
func (tAddr) String() string  { return "127.0.0.1:1" }

type memConn struct {
	r       io.Reader
	w       bytes.Buffer
	discard bool
	reads   int
	writes  int
}

func (c *memConn) Read(p []byte) (int, error) { c.reads++; return c.r.Read(p) }
func (c *memConn) Write(p []byte) (int, error) {
	c.writes++
	if !c.discard {
		c.w.Write(p)
	}
	return len(p), nil
}
func (c *memConn) Close() error                     { return nil }
func (c *memConn) LocalAddr() net.Addr              { return tAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return tAddr{} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type benchHandler struct {
	writeResponse bool
	packets       atomic.Int64
	natConn       chan N.PacketConn
}

func (h *benchHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if h.writeResponse {
		conn.Write([]byte{1})
	}
	return nil
}

func (h *benchHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	if h.natConn != nil {
		h.natConn <- conn
	}
	b := buf.NewPacket()
	defer b.Release()
	for {
		b.Reset()
		if _, err := conn.ReadPacket(b); err != nil {
			return nil
		}
		h.packets.Add(1)
	}
}
func (h *benchHandler) NewError(ctx context.Context, err error) {}

func randKey(n int) []byte {
	k := make([]byte, n)
	rand.Read(k)
	return k
}

func newMulti(tb testing.TB, users int, h *benchHandler) (*MultiService[string], []byte, []byte) {
	iPSK := randKey(16)
	s, err := NewMultiService[string](method128, iPSK, 300, h, nil)
	if err != nil {
		tb.Fatal(err)
	}
	names := make([]string, users)
	keys := make([][]byte, users)
	for i := range names {
		names[i] = fmt.Sprint("u", i)
		keys[i] = randKey(16)
	}
	if err := s.UpdateUsers(names, keys); err != nil {
		tb.Fatal(err)
	}
	return s, iPSK, keys[users-1] // the last user: no linear scan can favour it
}

// ---------- TCP: per-connection handshake on the multi-user server ----------

func BenchmarkTCPHandshakeServer(b *testing.B) {
	dest := M.ParseSocksaddr("example.com:443")
	for _, users := range []int{1, 1000, 100000} {
		for _, write := range []bool{false, true} {
			b.Run(fmt.Sprintf("users=%d/firstWrite=%v", users, write), func(b *testing.B) {
				h := &benchHandler{writeResponse: write}
				s, iPSK, uPSK := newMulti(b, users, h)
				client, err := New(method128, [][]byte{iPSK, uPSK}, nil)
				if err != nil {
					b.Fatal(err)
				}
				payload := make([]byte, 100)
				const batch = 2048
				conns := make([]*memConn, 0, batch)
				gen := func() {
					conns = conns[:0]
					for i := 0; i < batch; i++ {
						cc := &memConn{}
						c := client.DialEarlyConn(cc, dest)
						if _, err := c.Write(payload); err != nil {
							b.Fatal(err)
						}
						conns = append(conns, &memConn{r: bytes.NewReader(cc.w.Bytes()), discard: true})
					}
				}
				gen()
				b.ReportAllocs()
				b.ResetTimer()
				idx := 0
				for i := 0; i < b.N; i++ {
					if idx == batch {
						b.StopTimer()
						gen()
						idx = 0
						b.StartTimer()
					}
					if err := s.NewConnection(context.Background(), conns[idx], M.Metadata{}); err != nil {
						b.Fatal(err)
					}
					idx++
				}
			})
		}
	}
}

// ---------- TCP data path: shadowaead Reader/Writer as SS 2022 uses them ----------

func gcm128() cipher.AEAD {
	blk, _ := aes.NewCipher(randKey(16))
	a, _ := cipher.NewGCM(blk)
	return a
}

func BenchmarkAEADWriterWrite(b *testing.B) {
	for _, size := range []int{1400, 32 * 1024, 65535} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			c := &memConn{discard: true}
			w := shadowaead.NewWriter(c, gcm128(), MaxPacketSize)
			p := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := w.Write(p); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(c.writes)/float64(b.N), "conn-writes/op")
		})
	}
}

// loopReader replays the same encrypted stream; the Reader's nonce would
// diverge, so we re-create the Reader each time the stream wraps.
func BenchmarkAEADReaderRead(b *testing.B) {
	type tc struct {
		chunk, readBuf int
		fused          bool
	}
	cases := []tc{
		{16 * 1024, 32 * 1024, false}, // fits: decrypt in place into caller buffer
		{32 * 1024, 32 * 1024, false}, // sing peer writes 32 KiB chunks, sing copy reads with 32 KiB: misses
		{32 * 1024, 32 * 1024, true},  // prototype: Open from r.buffer straight into b
		{65535, 65535, false},         // after IncreaseBuffer on both sides: misses again
		{65535, 32 * 1024, false},     // 64 KiB chunks into 32 KiB reads
	}
	for _, c := range cases {
		b.Run(fmt.Sprintf("chunk=%d/read=%d/fused=%v", c.chunk, c.readBuf, c.fused), func(b *testing.B) {
			key := randKey(16)
			mk := func() cipher.AEAD {
				blk, _ := aes.NewCipher(key)
				a, _ := cipher.NewGCM(blk)
				return a
			}
			const chunks = 256
			wc := &memConn{}
			w := shadowaead.NewWriter(wc, mk(), MaxPacketSize)
			p := make([]byte, c.chunk)
			for i := 0; i < chunks; i++ {
				w.Write(p)
			}
			stream := wc.w.Bytes()
			out := make([]byte, c.readBuf)
			var rc *memConn
			var r *shadowaead.Reader
			var rawBuf, nonce []byte
			reset := func() {
				rc = &memConn{r: bytes.NewReader(stream)}
				rawBuf = make([]byte, MaxPacketSize+shadowaead.Overhead)
				nonce = make([]byte, 12)
				r = shadowaead.NewRawReader(rc, mk(), rawBuf, nonce)
			}
			reset()
			aead := mk()
			readFused := func(b []byte) (int, error) {
				// prototype of the fused path in Reader.Read
				start := shadowaead.PacketLengthBufferSize + shadowaead.Overhead
				if _, err := io.ReadFull(rc, rawBuf[:start]); err != nil {
					return 0, err
				}
				if _, err := aead.Open(rawBuf[:0], nonce, rawBuf[:start], nil); err != nil {
					return 0, err
				}
				incNonce(nonce)
				length := int(binary.BigEndian.Uint16(rawBuf[:2]))
				end := length + shadowaead.Overhead
				if _, err := io.ReadFull(rc, rawBuf[:end]); err != nil {
					return 0, err
				}
				if _, err := aead.Open(b[:0], nonce, rawBuf[:end], nil); err != nil {
					return 0, err
				}
				incNonce(nonce)
				return length, nil
			}
			if c.fused {
				rc = &memConn{r: bytes.NewReader(stream)}
				nonce = make([]byte, 12)
			}
			total := int64(chunks * c.chunk)
			b.SetBytes(int64(c.chunk))
			b.ReportAllocs()
			b.ResetTimer()
			var got int64
			var reads, chunksRead int
			for i := 0; i < b.N; i++ {
				// one op = one chunk's worth of plaintext
				need := c.chunk
				for need > 0 {
					var n int
					var err error
					if c.fused {
						n, err = readFused(out)
					} else {
						n, err = r.Read(out)
					}
					if err != nil {
						b.Fatal(err)
					}
					need -= n
					got += int64(n)
				}
				chunksRead++
				if got == total {
					b.StopTimer()
					reads += rc.reads
					if c.fused {
						rc = &memConn{r: bytes.NewReader(stream)}
						nonce = make([]byte, 12)
					} else {
						reset()
					}
					got = 0
					b.StartTimer()
				}
			}
			reads += rc.reads
			b.ReportMetric(float64(reads)/float64(chunksRead), "conn-reads/chunk")
		})
	}
}

func incNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// ---------- UDP: multi-user server, inbound packet path ----------

type capturePacketConn struct {
	memConn
	packets [][]byte
}

func (c *capturePacketConn) Write(p []byte) (int, error) {
	c.packets = append(c.packets, append([]byte(nil), p...))
	return len(p), nil
}

type sinkPacketConn struct {
	writes atomic.Int64
}

func (c *sinkPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) { select {} }
func (c *sinkPacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	c.writes.Add(1)
	b.Release()
	return nil
}
func (c *sinkPacketConn) Close() error                     { return nil }
func (c *sinkPacketConn) LocalAddr() net.Addr              { return tAddr{} }
func (c *sinkPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *sinkPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sinkPacketConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkUDPServerInbound(b *testing.B) {
	dest := M.ParseSocksaddr("1.1.1.1:443")
	for _, users := range []int{1, 1000} {
		b.Run(fmt.Sprintf("users=%d/1200B", users), func(b *testing.B) {
			h := &benchHandler{}
			s, iPSK, uPSK := newMulti(b, users, h)
			client, err := New(method128, [][]byte{iPSK, uPSK}, nil)
			if err != nil {
				b.Fatal(err)
			}
			cap := &capturePacketConn{}
			pc := client.DialPacketConn(cap).(*clientPacketConn)
			front := pc.FrontHeadroom()
			rear := pc.RearHeadroom()
			const batch = 4096
			gen := func() {
				cap.packets = cap.packets[:0]
				for i := 0; i < batch; i++ {
					bb := buf.NewSize(front + 1200 + rear)
					bb.Resize(front, 1200)
					if err := pc.WritePacket(bb, dest); err != nil {
						b.Fatal(err)
					}
				}
			}
			gen()
			src := &sinkPacketConn{}
			b.ReportAllocs()
			b.ResetTimer()
			idx := 0
			for i := 0; i < b.N; i++ {
				if idx == batch {
					b.StopTimer()
					gen()
					idx = 0
					b.StartTimer()
				}
				// what keel-node's loopUDP does per datagram
				bb := buf.NewPacket()
				bb.Write(cap.packets[idx])
				if err := s.NewPacket(context.Background(), src, bb, M.Metadata{Source: M.ParseSocksaddr("10.0.0.1:5000")}); err != nil {
					b.Fatal(err)
				}
				idx++
			}
			b.StopTimer()
			for h.packets.Load() < int64(b.N) {
				time.Sleep(time.Millisecond)
			}
		})
	}
}

// BenchmarkUDPServerOutbound: serverPacketWriter.WritePacket per reply packet.
func BenchmarkUDPServerOutbound(b *testing.B) {
	dest := M.ParseSocksaddr("1.1.1.1:443")
	h := &benchHandler{natConn: make(chan N.PacketConn, 1)}
	s, iPSK, uPSK := newMulti(b, 1, h)
	client, _ := New(method128, [][]byte{iPSK, uPSK}, nil)
	cap := &capturePacketConn{}
	pc := client.DialPacketConn(cap).(*clientPacketConn)
	bb := buf.NewSize(pc.FrontHeadroom() + 100 + pc.RearHeadroom())
	bb.Resize(pc.FrontHeadroom(), 100)
	pc.WritePacket(bb, dest)
	src := &sinkPacketConn{}
	in := buf.NewPacket()
	in.Write(cap.packets[0])
	if err := s.NewPacket(context.Background(), src, in, M.Metadata{Source: M.ParseSocksaddr("10.0.0.1:5000")}); err != nil {
		b.Fatal(err)
	}
	nat := <-h.natConn
	front := N.CalculateFrontHeadroom(nat)
	rear := N.CalculateRearHeadroom(nat)
	b.Logf("server reply headroom front=%d rear=%d", front, rear)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := buf.NewSize(front + 1200 + rear)
		out.Resize(front, 1200)
		if err := nat.WritePacket(out, dest); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------- encoding/binary in the per-packet path ----------

func BenchmarkBinaryReadUint64(b *testing.B) {
	data := make([]byte, 8*1024)
	b.Run("binary.Read", func(b *testing.B) {
		b.ReportAllocs()
		bb := buf.As(data)
		var v uint64
		for i := 0; i < b.N; i++ {
			if bb.Len() < 8 {
				bb.Resize(0, len(data))
			}
			binary.Read(bb, binary.BigEndian, &v)
		}
	})
	b.Run("BigEndian.Uint64", func(b *testing.B) {
		b.ReportAllocs()
		bb := buf.As(data)
		var v uint64
		for i := 0; i < b.N; i++ {
			if bb.Len() < 8 {
				bb.Resize(0, len(data))
			}
			v += binary.BigEndian.Uint64(bb.Bytes())
			bb.Advance(8)
		}
		_ = v
	})
	b.Run("binary.Write", func(b *testing.B) {
		b.ReportAllocs()
		bb := buf.NewSize(8 * 1024)
		x := uint64(time.Now().Unix())
		for i := 0; i < b.N; i++ {
			if bb.FreeLen() < 8 {
				bb.Reset()
			}
			binary.Write(bb, binary.BigEndian, x+uint64(i))
		}
	})
}

// ---------- replay filter ----------

func BenchmarkReplayFilterCheck(b *testing.B) {
	for _, prefill := range []int{0, 100000} {
		b.Run(fmt.Sprint("prefill=", prefill), func(b *testing.B) {
			f := replay.NewSimple(60 * time.Second)
			salt := make([]byte, 16)
			for i := 0; i < prefill; i++ {
				rand.Read(salt)
				f.Check(salt)
			}
			salts := make([][]byte, 4096)
			for i := range salts {
				salts[i] = randKey(16)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := salts[i%len(salts)]
				binary.BigEndian.PutUint64(s, uint64(i))
				f.Check(s)
			}
		})
	}
}

// ---------- AEAD choices ----------

func BenchmarkAEADSeal(b *testing.B) {
	aes128 := gcm128()
	blk256, _ := aes.NewCipher(randKey(32))
	aes256, _ := cipher.NewGCM(blk256)
	chacha, _ := chacha20poly1305.New(randKey(32))
	for _, a := range []struct {
		name string
		aead cipher.AEAD
	}{{"aes128gcm", aes128}, {"aes256gcm", aes256}, {"chacha20poly1305", chacha}} {
		for _, size := range []int{1200, 16 * 1024} {
			b.Run(fmt.Sprintf("%s/%d", a.name, size), func(b *testing.B) {
				p := make([]byte, size+16)
				nonce := make([]byte, a.aead.NonceSize())
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					a.aead.Seal(p[:0], nonce, p[:size], nil)
				}
			})
		}
	}
}

var _ = sync.Mutex{}

// ---------- UDP: one stalled NAT session blocks the shared receive loop ----------

type stallHandler struct {
	first   atomic.Bool
	release chan struct{}
}

func (h *stallHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return nil
}
func (h *stallHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	if h.first.CompareAndSwap(false, true) {
		<-h.release // this session's relay is stuck (e.g. its UoT outbound is congested)
	}
	b := buf.NewPacket()
	defer b.Release()
	for {
		b.Reset()
		if _, err := conn.ReadPacket(b); err != nil {
			return nil
		}
	}
}
func (h *stallHandler) NewError(ctx context.Context, err error) {}

func TestUDPStalledSessionBlocksLoop(t *testing.T) {
	h := &stallHandler{release: make(chan struct{})}
	iPSK := randKey(16)
	s, _ := NewMultiService[string](method128, iPSK, 300, h, nil)
	keys := [][]byte{randKey(16), randKey(16)}
	s.UpdateUsers([]string{"a", "b"}, keys)
	dest := M.ParseSocksaddr("1.1.1.1:443")
	mk := func(key []byte, n int) [][]byte {
		client, _ := New(method128, [][]byte{iPSK, key}, nil)
		cap := &capturePacketConn{}
		pc := client.DialPacketConn(cap).(*clientPacketConn)
		for i := 0; i < n; i++ {
			bb := buf.NewSize(pc.FrontHeadroom() + 100 + pc.RearHeadroom())
			bb.Resize(pc.FrontHeadroom(), 100)
			pc.WritePacket(bb, dest)
		}
		return cap.packets
	}
	stuck := mk(keys[0], 100)
	other := mk(keys[1], 1)
	src := &sinkPacketConn{}
	done := make(chan int, 1)
	go func() {
		for i, p := range append(stuck, other...) {
			bb := buf.NewPacket()
			bb.Write(p)
			s.NewPacket(context.Background(), src, bb, M.Metadata{Source: M.ParseSocksaddr("10.0.0.1:5000")})
			done <- i + 1
		}
	}()
	last := 0
	timeout := time.After(time.Second)
loop:
	for {
		select {
		case n := <-done:
			last = n
		case <-timeout:
			break loop
		}
	}
	t.Logf("receive loop handled %d of %d packets in 1 s; the other user's packet (#%d) is %s",
		last, len(stuck)+1, len(stuck)+1, map[bool]string{true: "delivered", false: "stuck behind the stalled session"}[last == len(stuck)+1])
	close(h.release)
}

// BenchmarkUDPClientWritePacket: keel's SS 2022 outbound (entry -> exit),
// native UDP. With "iPSK:uPSK" (EIH, what keel exits require) the client
// builds an AES block cipher for the identity header on every packet.
func BenchmarkUDPClientWritePacket(b *testing.B) {
	dest := M.ParseSocksaddr("1.1.1.1:443")
	for _, eih := range []bool{false, true} {
		b.Run(fmt.Sprintf("eih=%v/1200B", eih), func(b *testing.B) {
			keys := [][]byte{randKey(16)}
			if eih {
				keys = append(keys, randKey(16))
			}
			client, err := New(method128, keys, nil)
			if err != nil {
				b.Fatal(err)
			}
			sink := &memConn{discard: true}
			pc := client.DialPacketConn(sink).(*clientPacketConn)
			front, rear := pc.FrontHeadroom(), pc.RearHeadroom()
			b.SetBytes(1200)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bb := buf.NewSize(front + 1200 + rear)
				bb.Resize(front, 1200)
				if err := pc.WritePacket(bb, dest); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
