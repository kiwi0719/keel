package main

import "testing"

func TestParseSockstat(t *testing.T) {
	v4 := "sockets: used 2050\nTCP: inuse 1001 orphan 0 tw 37 alloc 1033 mem 999\nUDP: inuse 12 mem 4\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0\n"
	v6 := "TCP6: inuse 20\nUDP6: inuse 3\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n"
	tcp, udp := parseSockstat(v4)
	tcp6, udp6 := parseSockstat(v6)
	if tcp+tcp6 != 1021 || udp+udp6 != 15 {
		t.Fatalf("tcp %d udp %d", tcp+tcp6, udp+udp6)
	}
}
