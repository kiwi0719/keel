package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// SystemStats is the machine part of a report.
type SystemStats struct {
	CPUPct       float64 `json:"cpu_pct"`
	Load1        float64 `json:"load1"`
	MemTotal     uint64  `json:"mem_total"`
	MemUsed      uint64  `json:"mem_used"`
	SwapTotal    uint64  `json:"swap_total"`
	SwapUsed     uint64  `json:"swap_used"`
	DiskTotal    uint64  `json:"disk_total"`
	DiskUsed     uint64  `json:"disk_used"`
	NetRx        uint64  `json:"net_rx"` // bytes since boot, all interfaces but lo
	NetTx        uint64  `json:"net_tx"`
	RxRate       float64 `json:"rx_rate"` // bytes/s since the previous sample
	TxRate       float64 `json:"tx_rate"`
	TCPConns     int     `json:"tcp_conns"`
	UDPConns     int     `json:"udp_conns"`
	UptimeS      uint64  `json:"uptime_s"`
	RSS          uint64  `json:"rss"`             // this process
	TCPRetransPc float64 `json:"tcp_retrans_pct"` // retransmitted / sent TCP segments since the previous sample
}

// sysSampler turns the kernel's cumulative counters into rates between
// consecutive samples. Only Linux is read; elsewhere the stats stay zero.
type sysSampler struct {
	last        time.Time
	cpuIdle     uint64
	cpuTotal    uint64
	rx, tx      uint64
	retrans     uint64
	outSegments uint64
}

func (s *sysSampler) sample() SystemStats {
	var st SystemStats
	now := time.Now()
	elapsed := now.Sub(s.last).Seconds()
	first := s.last.IsZero()
	s.last = now

	if idle, total, ok := readCPU(); ok {
		if !first && total > s.cpuTotal {
			st.CPUPct = 100 * (1 - float64(idle-s.cpuIdle)/float64(total-s.cpuTotal))
		}
		s.cpuIdle, s.cpuTotal = idle, total
	}
	if fields := readFields("/proc/loadavg"); len(fields) > 0 {
		st.Load1, _ = strconv.ParseFloat(fields[0], 64)
	}
	mem := readKeyValues("/proc/meminfo")
	st.MemTotal = mem["MemTotal"] * 1024
	if available, ok := mem["MemAvailable"]; ok {
		st.MemUsed = st.MemTotal - available*1024
	} else {
		st.MemUsed = st.MemTotal - (mem["MemFree"]+mem["Buffers"]+mem["Cached"])*1024
	}
	st.SwapTotal = mem["SwapTotal"] * 1024
	st.SwapUsed = st.SwapTotal - mem["SwapFree"]*1024
	st.DiskTotal, st.DiskUsed = diskUsage("/")

	st.NetRx, st.NetTx = readNetDev()
	if !first && elapsed > 0 && st.NetRx >= s.rx && st.NetTx >= s.tx {
		st.RxRate = float64(st.NetRx-s.rx) / elapsed
		st.TxRate = float64(st.NetTx-s.tx) / elapsed
	}
	s.rx, s.tx = st.NetRx, st.NetTx

	st.TCPConns = countLines("/proc/net/tcp") + countLines("/proc/net/tcp6")
	st.UDPConns = countLines("/proc/net/udp") + countLines("/proc/net/udp6")
	if fields := readFields("/proc/uptime"); len(fields) > 0 {
		uptime, _ := strconv.ParseFloat(fields[0], 64)
		st.UptimeS = uint64(uptime)
	}
	st.RSS = readKeyValues("/proc/self/status")["VmRSS"] * 1024

	if retrans, out, ok := readTCPSegments(); ok {
		if !first && out > s.outSegments {
			st.TCPRetransPc = 100 * float64(retrans-s.retrans) / float64(out-s.outSegments)
		}
		s.retrans, s.outSegments = retrans, out
	}
	return st
}

func readFields(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Fields(string(content))
}

// readKeyValues parses "Key: 123 kB" lines (meminfo, status), values as written.
func readKeyValues(path string) map[string]uint64 {
	values := make(map[string]uint64)
	f, err := os.Open(path)
	if err != nil {
		return values
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			values[key] = v
		}
	}
	return values
}

func readCPU() (idle, total uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i, field := range fields[1:] {
		v, _ := strconv.ParseUint(field, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle, iowait
			idle += v
		}
	}
	return idle, total, true
}

func readNetDev() (rx, tx uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		name, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(fields[0], 10, 64)
		t, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += r
		tx += t
	}
	return rx, tx
}

// countLines counts socket entries in a /proc/net table (minus its header).
func countLines(path string) int {
	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 {
		return 0
	}
	return strings.Count(string(content), "\n") - 1
}

// readTCPSegments returns RetransSegs and OutSegs from /proc/net/snmp.
func readTCPSegments() (retrans, out uint64, ok bool) {
	content, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0, 0, false
	}
	var header []string
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.HasPrefix(line, "Tcp:") {
			continue
		}
		fields := strings.Fields(line)
		if header == nil {
			header = fields
			continue
		}
		for i, name := range header {
			if i >= len(fields) {
				break
			}
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			switch name {
			case "RetransSegs":
				retrans = v
			case "OutSegs":
				out = v
			}
		}
		return retrans, out, true
	}
	return 0, 0, false
}
