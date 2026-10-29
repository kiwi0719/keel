package shadowaead_2022

// Scratch: heap held per idle SS 2022 connection after a download, with the
// relay keel-node runs (CounterConn + sing bufio.CopyConn). Not part of the repo.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// hideVectorised strips WriteVectorised (and everything else but net.Conn).
type hideVectorised struct{ net.Conn }

type relayHandler struct {
	remote string
	hide   bool
	wg     *sync.WaitGroup
}

func (h *relayHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	defer h.wg.Done()
	remote, err := net.Dial("tcp", h.remote)
	if err != nil {
		return err
	}
	if h.hide {
		conn = hideVectorised{conn}
	}
	var up, down atomic.Int64
	conn = bufio.NewInt64CounterConn(conn, []*atomic.Int64{&up}, []*atomic.Int64{&down})
	bufio.CopyConn(ctx, conn, remote)
	return nil
}
func (h *relayHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}
func (h *relayHandler) NewError(ctx context.Context, err error) {}

func heapInuse() uint64 {
	var ms runtime.MemStats
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

func TestIdleHeapPerConn(t *testing.T) {
	n := 64
	if v, err := strconv.Atoi(os.Getenv("CONNS")); err == nil {
		n = v
	}
	download := 1 << 20 // > sing's IncreaseBufferAfter (512000)
	if v, err := strconv.Atoi(os.Getenv("DOWNLOAD")); err == nil {
		download = v
	}
	for _, hide := range []bool{false, true} {
		t.Run(fmt.Sprintf("hideWriteVectorised=%v/download=%d", hide, download), func(t *testing.T) {
			// remote: sends `download` bytes then idles until closed
			rl, _ := net.Listen("tcp", "127.0.0.1:0")
			defer rl.Close()
			var remoteConns sync.WaitGroup
			go func() {
				payload := make([]byte, download)
				for {
					c, err := rl.Accept()
					if err != nil {
						return
					}
					remoteConns.Add(1)
					go func() {
						defer remoteConns.Done()
						c.Write(payload)
						io.Copy(io.Discard, c)
						c.Close()
					}()
				}
			}()
			var relays sync.WaitGroup
			h := &relayHandler{remote: rl.Addr().String(), hide: hide, wg: &relays}
			s, iPSK, uPSK := newMulti(t, 1, nil)
			s.Service.handler = h
			sl, _ := net.Listen("tcp", "127.0.0.1:0")
			defer sl.Close()
			go func() {
				for {
					c, err := sl.Accept()
					if err != nil {
						return
					}
					relays.Add(1)
					go func() {
						if err := s.NewConnection(context.Background(), c, M.Metadata{}); err != nil {
							relays.Done()
							c.Close()
						}
					}()
				}
			}()
			client, _ := New(method128, [][]byte{iPSK, uPSK}, nil)
			before := heapInuse()
			gBefore := runtime.NumGoroutine()
			conns := make([]net.Conn, 0, n)
			buf := make([]byte, download)
			for i := 0; i < n; i++ {
				tc, err := net.Dial("tcp", sl.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				c, err := client.DialConn(tc, M.ParseSocksaddr(rl.Addr().String()))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(c, buf); err != nil {
					t.Fatal(err)
				}
				conns = append(conns, c)
			}
			time.Sleep(200 * time.Millisecond)
			after := heapInuse()
			t.Logf("%d idle conns: heap in use +%.1f MiB = %.0f KiB per conn (both ends in this process), goroutines +%d",
				n, float64(after-before)/(1<<20), float64(after-before)/1024/float64(n), runtime.NumGoroutine()-gBefore)
			for _, c := range conns {
				c.Close()
			}
			relays.Wait()
		})
	}
}
