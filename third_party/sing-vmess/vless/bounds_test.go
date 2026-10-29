package vless

import (
	"bytes"
	"github.com/sagernet/sing/common/buf"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

func TestReadAddonsRejectsOversizedLengths(t *testing.T) {
	for _, in := range [][]byte{
		{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		{0x12, 0x7f, 'x'},
	} {
		if _, err := readAddons(bytes.NewReader(in)); err == nil {
			t.Errorf("readAddons(%x) accepted an oversized length", in)
		}
	}
	addons, err := readAddons(bytes.NewReader(append([]byte{0x0a, 16}, "xtls-rprx-vision"...)))
	if err != nil || addons.Flow != "xtls-rprx-vision" {
		t.Fatalf("valid flow: %v %+v", err, addons)
	}
}

func TestFilterTLSShortSessionID(t *testing.T) {
	c := &VisionConn{logger: logger.NOP(), numberOfPacketToFilter: 8}
	hello := make([]byte, 80)
	hello[0], hello[1], hello[2], hello[3], hello[4], hello[5] = 22, 3, 3, 0x10, 0, 2
	hello[43] = 255              // session id length past the end of the record
	c.filterTLS([][]byte{hello}) // must not panic
}

func TestUnPaddingHeaderAcrossReads(t *testing.T) {
	c := &VisionConn{logger: logger.NOP(), remainingContent: 0, remainingPadding: 0}
	// block header: command 0, 3 bytes of content, 0 padding; split after 2 bytes
	got := c.unPadding([]byte{0, 0})
	if len(got) != 0 || len(c.headerCarry) != 2 {
		t.Fatalf("first part: %d buffers, carry %d", len(got), len(c.headerCarry))
	}
	got = c.unPadding([]byte{3, 0, 0, 'a', 'b', 'c'})
	if len(got) != 1 || string(got[0].Bytes()) != "abc" {
		t.Fatalf("second part: %v", got)
	}
}

func TestVisionPaddingIsZeroed(t *testing.T) {
	// Leave dirty buffers in the pool, as earlier connections would.
	for i := 0; i < 64; i++ {
		b := buf.NewSize(2048)
		b.Extend(b.FreeLen())
		for j := range b.Bytes() {
			b.Bytes()[j] = 0xAA
		}
		b.Release()
	}
	c := &VisionConn{logger: logger.NOP(), isTLS: true}
	for i := 0; i < 32; i++ {
		out := c.padding(nil, commandPaddingContinue)
		pad := out.Bytes()[5:] // command, content length, padding length
		for _, x := range pad {
			if x != 0 {
				t.Fatalf("padding carries leftover byte %#x", x)
			}
		}
		out.Release()
	}
}
