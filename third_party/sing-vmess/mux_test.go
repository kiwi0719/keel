package vmess

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// muxTestHandler passes the sub-streams to the test and, like keel's
// handler, closes them in the end.
type muxTestHandler struct {
	tcp    chan net.Conn
	udp    chan N.PacketConn
	access sync.Mutex
	conns  []io.Closer
}

func (h *muxTestHandler) keep(c io.Closer) {
	h.access.Lock()
	h.conns = append(h.conns, c)
	h.access.Unlock()
}

func (h *muxTestHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.keep(conn)
	h.tcp <- conn
}

func (h *muxTestHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.keep(conn)
	h.udp <- conn
}

// muxPair runs a mux session over TCP; the test writes the client's frames.
func muxPair(t *testing.T) (net.Conn, *muxTestHandler) {
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
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	h := &muxTestHandler{tcp: make(chan net.Conn, 8), udp: make(chan N.PacketConn, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	go HandleMuxConnection(ctx, server, M.Socksaddr{}, h)
	t.Cleanup(func() {
		cancel()
		client.Close()
		server.Close()
		h.access.Lock()
		for _, c := range h.conns {
			c.Close()
		}
		h.access.Unlock()
	})
	return client, h
}

// muxFrame builds one mux.cool frame; network 0 leaves out the address.
func muxFrame(sid uint16, status, option, network byte, destination M.Socksaddr, data []byte) []byte {
	var meta bytes.Buffer
	binary.Write(&meta, binary.BigEndian, sid)
	meta.WriteByte(status)
	meta.WriteByte(option)
	if network != 0 {
		meta.WriteByte(network)
		AddressSerializer.WriteAddrPort(&meta, destination)
	}
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, uint16(meta.Len()))
	frame.Write(meta.Bytes())
	if option&OptionData != 0 {
		binary.Write(&frame, binary.BigEndian, uint16(len(data)))
		frame.Write(data)
	}
	return frame.Bytes()
}

func muxRandom(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(int64(n))).Read(b)
	return b
}

// readAll reads a mux conn to its end, failing after a while: mux conns
// have no deadlines.
func readAll(t *testing.T, r io.Reader, want int) []byte {
	t.Helper()
	done := make(chan []byte, 1)
	go func() {
		got := make([]byte, want)
		n, _ := io.ReadFull(r, got)
		done <- got[:n]
	}()
	select {
	case got := <-done:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("stalled")
		return nil
	}
}

var muxTarget = M.ParseSocksaddr("1.2.3.4:443")

func TestMuxTCPInOrderThenEnd(t *testing.T) {
	client, h := muxPair(t)
	data := muxRandom(300 << 10)
	client.Write(muxFrame(1, StatusNew, OptionData, NetworkTCP, muxTarget, data[:1000]))
	for rest := data[1000:]; len(rest) > 0; {
		n := len(rest)
		if n > 30000 {
			n = 30000
		}
		client.Write(muxFrame(1, StatusKeep, OptionData, 0, M.Socksaddr{}, rest[:n]))
		rest = rest[n:]
	}
	client.Write(muxFrame(1, StatusEnd, 0, 0, M.Socksaddr{}, nil))
	conn := <-h.tcp
	time.Sleep(50 * time.Millisecond) // the end arrives while data waits
	got, err := io.ReadAll(conn)
	if !bytes.Equal(got, data) || err != nil {
		t.Fatalf("got %d of %d bytes (%v)", len(got), len(data), err)
	}

	conn.Close()

	// What the server writes is what the old encoder produced: data, and
	// the end when the reader closes a sub-stream the client has not ended.
	client.Write(muxFrame(2, StatusNew, 0, NetworkTCP, muxTarget, nil))
	conn = <-h.tcp
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	want := muxFrame(2, StatusKeep, OptionData, 0, M.Socksaddr{}, []byte("pong"))
	if reply := readAll(t, client, len(want)); !bytes.Equal(reply, want) {
		t.Fatalf("reply % x, want % x", reply, want)
	}
	conn.Close()
	want = []byte{0, 4, 0, 2, StatusEnd, 0}
	if end := readAll(t, client, len(want)); !bytes.Equal(end, want) {
		t.Fatalf("close frame % x, want % x", end, want)
	}
}

func TestMuxSlowStreamDoesNotStallOthers(t *testing.T) {
	client, h := muxPair(t)
	slowData, fastData := muxRandom(MuxStreamBuffer/2), muxRandom(10<<10)
	client.Write(muxFrame(1, StatusNew, OptionData, NetworkTCP, muxTarget, slowData))
	slow := <-h.tcp
	client.Write(muxFrame(2, StatusNew, OptionData, NetworkTCP, muxTarget, fastData))
	fast := <-h.tcp
	if got := readAll(t, fast, len(fastData)); !bytes.Equal(got, fastData) {
		t.Fatal("second stream lost data")
	}
	if got := readAll(t, slow, len(slowData)); !bytes.Equal(got, slowData) {
		t.Fatal("first stream lost data")
	}
}

// A UDP sub-stream nobody reads drops packets past its limit instead of
// holding the session.
func TestMuxUDPDropsInsteadOfWaiting(t *testing.T) {
	client, h := muxPair(t)
	packet := muxRandom(1000)
	client.Write(muxFrame(1, StatusNew, OptionData, NetworkUDP, muxTarget, packet))
	udp := <-h.udp
	other := M.ParseSocksaddr("5.6.7.8:53")
	for i := 0; i < 199; i++ {
		client.Write(muxFrame(1, StatusKeep, OptionData, NetworkUDP, other, packet))
	}
	tcpData := muxRandom(1000)
	client.Write(muxFrame(2, StatusNew, OptionData, NetworkTCP, muxTarget, tcpData))
	tcp := <-h.tcp
	if got := readAll(t, tcp, len(tcpData)); !bytes.Equal(got, tcpData) {
		t.Fatal("the session waited for the UDP reader")
	}

	var received int
	for {
		buffer := buf.NewPacket()
		done := make(chan error, 1)
		var from M.Socksaddr
		go func() {
			var err error
			from, err = udp.ReadPacket(buffer)
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil || !bytes.Equal(buffer.Bytes(), packet) {
				t.Fatalf("packet %d: %v", received, err)
			}
			if want := muxTarget; received > 0 {
				want = other
				if from != want {
					t.Fatalf("packet %d from %v, want %v", received, from, want)
				}
			}
			received++
			buffer.Release()
			continue
		case <-time.After(200 * time.Millisecond):
		}
		break
	}
	if limit := MuxStreamBuffer / len(packet); received < limit-1 || received > limit+1 {
		t.Fatalf("%d packets kept, want about %d", received, limit)
	}
}

func TestMuxPacketWriteBytes(t *testing.T) {
	client, h := muxPair(t)
	client.Write(muxFrame(7, StatusNew, OptionData, NetworkUDP, muxTarget, []byte("q")))
	udp := <-h.udp
	payload := []byte("answer")
	from := M.ParseSocksaddr("9.9.9.9:53")
	buffer := buf.NewSize(64 + len(payload))
	buffer.Resize(64, 0)
	buffer.Write(payload)
	if err := udp.WritePacket(buffer, from); err != nil {
		t.Fatal(err)
	}
	want := muxFrame(7, StatusKeep, OptionData, NetworkUDP, from, payload)
	if got := readAll(t, client, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("WritePacket wrote % x, want % x", got, want)
	}
	udp.(net.PacketConn).WriteTo(payload, from.UDPAddr())
	if got := readAll(t, client, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("WriteTo wrote % x, want % x", got, want)
	}
}

func TestMuxQueueAccounting(t *testing.T) {
	client, h := muxPair(t)
	base := muxQueued.Load()
	client.Write(muxFrame(1, StatusNew, OptionData, NetworkTCP, muxTarget, muxRandom(20000)))
	conn := <-h.tcp
	deadline := time.Now().Add(5 * time.Second)
	for muxQueued.Load()-base != 20000 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := muxQueued.Load() - base; n != 20000 {
		t.Fatalf("queued %d, want 20000", n)
	}
	readAll(t, conn, 5000)
	if n := muxQueued.Load() - base; n != 15000 {
		t.Fatalf("queued %d after reading 5000, want 15000", n)
	}
	conn.Close()
	if n := muxQueued.Load() - base; n != 0 {
		t.Fatalf("queued %d after close, want 0", n)
	}
}
