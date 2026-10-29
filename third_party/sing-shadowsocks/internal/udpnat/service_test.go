package udpnat

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type stallHandler struct {
	stalled netip.AddrPort
	release chan struct{}
	got     chan M.Socksaddr
}

func (h *stallHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	if metadata.Source.AddrPort() == h.stalled {
		<-h.release // never reads: its queue fills up
		return nil
	}
	buffer := buf.NewPacket()
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil {
		return err
	}
	h.got <- metadata.Source
	return nil
}

func (h *stallHandler) NewError(context.Context, error) {}

type discard struct{}

func (discard) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

// A session whose handler does not read must not stop packets for others.
func TestFullQueueDropsInsteadOfBlocking(t *testing.T) {
	stalled := netip.MustParseAddrPort("192.0.2.1:1000")
	other := netip.MustParseAddrPort("192.0.2.2:2000")
	h := &stallHandler{stalled: stalled, release: make(chan struct{}), got: make(chan M.Socksaddr, 1)}
	defer close(h.release)
	s := New[netip.AddrPort](60, h)
	send := func(source netip.AddrPort) {
		buffer := buf.NewPacket()
		buffer.WriteString("x")
		s.NewContextPacket(context.Background(), source, buffer, M.Metadata{Source: M.SocksaddrFromNetIP(source)},
			func(natConn N.PacketConn) (context.Context, N.PacketWriter) { return context.Background(), discard{} })
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ { // far past the 64-packet queue
			send(stalled)
		}
		send(other)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("NewContextPacket blocked on a session that does not read")
	}
	select {
	case from := <-h.got:
		if from.AddrPort() != other {
			t.Fatalf("got a packet from %v", from)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the other session's packet never arrived")
	}
}
