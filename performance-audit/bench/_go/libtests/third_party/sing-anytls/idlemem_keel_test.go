package anytls

// Scratch: heap held per idle AnyTLS stream (plaintext session, no TLS) with
// the relay keel-node runs. Not part of the repo.

import (
	"context"
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
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type relay struct {
	remote string
	wg     sync.WaitGroup
}

func (h *relay) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.wg.Add(1)
	defer h.wg.Done()
	remote, err := net.Dial("tcp", h.remote)
	if err != nil {
		conn.Close()
		return
	}
	var up, down atomic.Int64
	conn = bufio.NewInt64CounterConn(conn, []*atomic.Int64{&up}, []*atomic.Int64{&down})
	N.ReportHandshakeSuccess(conn)
	bufio.CopyConn(ctx, conn, remote)
}

func heapInuse() uint64 {
	var ms runtime.MemStats
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

func TestIdleHeapPerStream(t *testing.T) {
	n := 64
	if v, err := strconv.Atoi(os.Getenv("CONNS")); err == nil {
		n = v
	}
	download := 1 << 20
	if v, err := strconv.Atoi(os.Getenv("DOWNLOAD")); err == nil {
		download = v
	}
	rl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer rl.Close()
	go func() {
		payload := make([]byte, download)
		for {
			c, err := rl.Accept()
			if err != nil {
				return
			}
			go func() { c.Write(payload); io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	h := &relay{remote: rl.Addr().String()}
	svc, err := NewService(ServiceConfig{Users: []User{{Name: "u", Password: "pw"}}, Handler: h, Logger: logger.NOP(), PaddingScheme: []byte("stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000")})
	if err != nil {
		t.Fatal(err)
	}
	sl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sl.Close()
	go func() {
		for {
			c, err := sl.Accept()
			if err != nil {
				return
			}
			go svc.NewConnection(context.Background(), c, M.Socksaddr{}, nil)
		}
	}()
	client, _ := NewClient(context.Background(), ClientConfig{
		Password: "pw",
		DialOut:  func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", sl.Addr().String()) },
		Logger:   logger.NOP(),
	})
	before := heapInuse()
	gBefore := runtime.NumGoroutine()
	streams := make([]net.Conn, 0, n)
	buf := make([]byte, download)
	for i := 0; i < n; i++ {
		c, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(rl.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		streams = append(streams, c)
	}
	time.Sleep(200 * time.Millisecond)
	after := heapInuse()
	t.Logf("%d idle streams (one session each), download %d: heap in use +%.1f MiB = %.0f KiB per stream (both ends in this process), goroutines +%d",
		n, download, float64(after-before)/(1<<20), float64(after-before)/1024/float64(n), runtime.NumGoroutine()-gBefore)
	for _, c := range streams {
		c.Close()
	}
	client.Close()
}
