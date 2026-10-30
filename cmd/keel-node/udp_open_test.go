package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// recordingRemote is an outbound's packet conn that keeps what it is sent.
type recordingRemote struct {
	mu     sync.Mutex
	sent   []string
	closed chan struct{}
	once   sync.Once
}

func newRecordingRemote() *recordingRemote { return &recordingRemote{closed: make(chan struct{})} }

func (r *recordingRemote) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	r.mu.Lock()
	r.sent = append(r.sent, string(buffer.Bytes()))
	r.mu.Unlock()
	buffer.Release()
	return nil
}

func (r *recordingRemote) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	<-r.closed
	return M.Socksaddr{}, net.ErrClosed
}

func (r *recordingRemote) Close() error                     { r.once.Do(func() { close(r.closed) }); return nil }
func (r *recordingRemote) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (r *recordingRemote) SetDeadline(time.Time) error      { return nil }
func (r *recordingRemote) SetReadDeadline(time.Time) error  { return nil }
func (r *recordingRemote) SetWriteDeadline(time.Time) error { return nil }

func (r *recordingRemote) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

// slowOutbound opens its packet conn only once released.
type slowOutbound struct {
	release chan struct{}
	remote  *recordingRemote
	err     error
}

func (o *slowOutbound) dialTCP(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unused")
}

func (o *slowOutbound) listenUDP(ctx context.Context, _ M.Socksaddr) (N.PacketConn, error) {
	select {
	case <-o.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if o.err != nil {
		return nil, o.err
	}
	return o.remote, nil
}

func packet(s string) *buf.Buffer {
	b := buf.NewSize(64)
	b.WriteString(s)
	return b
}

func TestUDPRoutesOpenWithoutBlocking(t *testing.T) {
	slow := &slowOutbound{release: make(chan struct{}), remote: newRecordingRemote()}
	r := &router{final: []string{"slow"}, outbound: map[string]outbound{"slow": slow}, allowPrivate: true}
	first := newRecordingRemote()
	u := newUDPRoutes(context.Background(), r, "u", "first", first)
	defer u.Close()
	dest := M.ParseSocksaddr("192.0.2.9:53")
	start := time.Now()
	for i := 0; i < udpPendingMax+4; i++ {
		if err := u.WritePacket(packet(string(rune('a'+i))), dest); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("writes waited %v for the outbound to open", d)
	}
	close(slow.release)
	deadline := time.Now().Add(2 * time.Second)
	for len(slow.remote.got()) < udpPendingMax && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	u.WritePacket(packet("later"), dest)
	got := slow.remote.got()
	if len(got) != udpPendingMax+1 {
		t.Fatalf("remote got %d packets, want the %d that waited plus the later one: %q", len(got), udpPendingMax, got)
	}
	for i := 0; i < udpPendingMax; i++ {
		if got[i] != string(rune('a'+i)) {
			t.Fatalf("packet %d out of order: %q", i, got)
		}
	}
	if got[udpPendingMax] != "later" {
		t.Fatalf("the packet sent after opening went missing: %q", got)
	}
}

func TestUDPRoutesBackOffAfterAFailedOpen(t *testing.T) {
	failing := &slowOutbound{release: make(chan struct{}), err: errors.New("refused")}
	close(failing.release)
	r := &router{final: []string{"bad"}, outbound: map[string]outbound{"bad": failing}, allowPrivate: true}
	u := newUDPRoutes(context.Background(), r, "u", "first", newRecordingRemote())
	defer u.Close()
	dest := M.ParseSocksaddr("192.0.2.9:53")
	u.WritePacket(packet("x"), dest)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		u.mu.Lock()
		_, opening := u.opening["bad"]
		_, failed := u.failed["bad"]
		u.mu.Unlock()
		if !opening && failed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	u.mu.Lock()
	until := u.failed["bad"]
	u.mu.Unlock()
	if time.Until(until) <= 0 {
		t.Fatal("a failed open was not backed off")
	}
	u.WritePacket(packet("y"), dest) // dropped without another attempt
	u.mu.Lock()
	_, opening := u.opening["bad"]
	u.mu.Unlock()
	if opening {
		t.Fatal("retried during the backoff")
	}
}
