// procnet <pairs>: opens <pairs> loopback TCP connections (2 sockets each), then
// times keel-node's connection count (read all of /proc/net/tcp{,6}) against
// reading /proc/net/sockstat{,6}.
package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func countLines(path string) int {
	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 {
		return 0
	}
	return strings.Count(string(content), "\n") - 1
}

var streamBuf = make([]byte, 64<<10)

func countStream(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	for {
		k, err := f.Read(streamBuf)
		n += bytes.Count(streamBuf[:k], []byte{'\n'})
		if err != nil || k == 0 {
			break
		}
	}
	return n - 1
}

func sockstat() (tcp int) {
	for _, p := range []string{"/proc/net/sockstat", "/proc/net/sockstat6"} {
		b, _ := os.ReadFile(p)
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 3 && (f[0] == "TCP:" || f[0] == "TCP6:") {
				n, _ := strconv.Atoi(f[2])
				tcp += n
			}
		}
	}
	return tcp
}

func cpu() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func measure(name string, f func() int) {
	var walls []time.Duration
	var n int
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	alloc0 := ms.TotalAlloc
	c0 := cpu()
	const rounds = 15
	for i := 0; i < rounds; i++ {
		t := time.Now()
		n = f()
		walls = append(walls, time.Since(t))
	}
	c1 := cpu()
	runtime.ReadMemStats(&ms)
	sort.Slice(walls, func(i, j int) bool { return walls[i] < walls[j] })
	fmt.Printf("  %-22s count=%6d  median=%9v  cpu/call=%9v  alloc/call=%6.1f MB\n", name, n, walls[rounds/2],
		(c1-c0)/rounds, float64(ms.TotalAlloc-alloc0)/rounds/1e6)
}

func main() {
	pairs, _ := strconv.Atoi(os.Args[1])
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	var keep []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			keep = append(keep, c)
		}
	}()
	var mine []net.Conn
	for i := 0; i < pairs; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			fmt.Println("dial:", err, "after", i)
			break
		}
		mine = append(mine, c)
	}
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("pairs=%d\n", len(mine))
	measure("/proc/net/tcp{,6} read", func() int { return countLines("/proc/net/tcp") + countLines("/proc/net/tcp6") })
	measure("/proc/net/tcp{,6} stream", func() int { return countStream("/proc/net/tcp") + countStream("/proc/net/tcp6") })
	measure("/proc/net/sockstat", sockstat)
	b, _ := os.ReadFile("/proc/net/sockstat")
	fmt.Print(string(b))
	_ = keep
}
