package session

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
)

// sessionPair connects a client and a server session over TCP; streams the
// client opens arrive on the channel (already acknowledged).
func sessionPair(t *testing.T) (*Session, chan *Stream) {
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
	cc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-accepted
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	streams := make(chan *Stream, 16)
	server := NewServerSession(sc, func(s *Stream) {
		s.HandshakeSuccess()
		streams <- s
	}, &pad, logger.NOP())
	go server.Run()
	client := NewClientSession(cc, &pad, logger.NOP())
	client.Run()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, streams
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(int64(n))).Read(b)
	return b
}

func accept(t *testing.T, streams chan *Stream) *Stream {
	t.Helper()
	select {
	case s := <-streams:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no stream arrived")
		return nil
	}
}

// Writes of any size, frames longer than 16 bits allow included, arrive
// whole and in order, through Read and through a copy (WaitReadBuffer).
func TestStreamDeliversInOrder(t *testing.T) {
	client, streams := sessionPair(t)
	for _, viaCopy := range []bool{false, true} {
		data := randomBytes(1 << 20)
		cs, err := client.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			r := rand.New(rand.NewSource(1))
			for rest := data; len(rest) > 0; {
				n := 1 + r.Intn(200000)
				if n > len(rest) {
					n = len(rest)
				}
				if _, err := cs.Write(rest[:n]); err != nil {
					t.Error(err)
					return
				}
				rest = rest[n:]
			}
			cs.Close()
		}()
		ss := accept(t, streams)
		var got bytes.Buffer
		if viaCopy {
			bufio.Copy(&got, ss)
		} else {
			io.Copy(&got, ss)
		}
		if !bytes.Equal(got.Bytes(), data) {
			t.Fatalf("copy=%v: got %d bytes, want %d intact", viaCopy, got.Len(), len(data))
		}
		ss.Close()
	}
}

// A copy into the stream writes frame headers into the buffers' headroom.
func TestStreamWriteBuffer(t *testing.T) {
	client, streams := sessionPair(t)
	data := randomBytes(3 << 20)
	cs, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		bufio.Copy(cs, bytes.NewReader(data))
		cs.Close()
	}()
	ss := accept(t, streams)
	got, _ := io.ReadAll(ss)
	if !bytes.Equal(got, data) {
		t.Fatalf("got %d bytes, want %d intact", len(got), len(data))
	}
}

// The peer's FIN follows its last data: everything queued before it is
// still read.
func TestStreamDataBeforeFIN(t *testing.T) {
	client, streams := sessionPair(t)
	data := randomBytes(300 << 10)
	cs, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	for rest := data; len(rest) > 0; {
		n := min(len(rest), 32<<10)
		cs.Write(rest[:n])
		rest = rest[n:]
	}
	cs.Close()
	ss := accept(t, streams)
	time.Sleep(100 * time.Millisecond) // let the FIN arrive while data waits
	got, err := io.ReadAll(ss)
	if !bytes.Equal(got, data) {
		t.Fatalf("got %d of %d bytes (%v)", len(got), len(data), err)
	}
}

// A stream nobody reads holds the session only once its queue is full; a
// second stream gets its data meanwhile.
func TestSlowStreamDoesNotStallOthers(t *testing.T) {
	client, streams := sessionPair(t)
	slow, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	slowData := randomBytes(StreamBuffer / 2)
	slow.Write(slowData)
	slowServer := accept(t, streams)

	fast, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	fastData := randomBytes(10 << 10)
	fast.Write(fastData)
	fastServer := accept(t, streams)
	fastServer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(fastData))
	if _, err := io.ReadFull(fastServer, got); err != nil || !bytes.Equal(got, fastData) {
		t.Fatalf("second stream stalled behind the first: %v", err)
	}

	got = make([]byte, len(slowData))
	if _, err := io.ReadFull(slowServer, got); err != nil || !bytes.Equal(got, slowData) {
		t.Fatalf("first stream lost data: %v", err)
	}
}

// Queued data is accounted for, and given back when read or when the
// stream is closed with data still in it.
func TestStreamQueueAccounting(t *testing.T) {
	client, streams := sessionPair(t)
	cs, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	cs.Write(randomBytes(40 << 10))
	ss := accept(t, streams)
	deadline := time.Now().Add(5 * time.Second)
	for queuedBytes.Load() < 40<<10 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := queuedBytes.Load(); n != 40<<10 || ss.sess.queued.Load() != n {
		t.Fatalf("queued %d (session %d), want %d", n, ss.sess.queued.Load(), 40<<10)
	}
	io.ReadFull(ss, make([]byte, 10<<10))
	if n := queuedBytes.Load(); n != 30<<10 {
		t.Fatalf("queued %d after reading 10 KiB, want %d", n, 30<<10)
	}
	ss.Close()
	if n := queuedBytes.Load(); n != 0 || ss.sess.queued.Load() != 0 {
		t.Fatalf("queued %d (session %d) after close, want 0", n, ss.sess.queued.Load())
	}
}
