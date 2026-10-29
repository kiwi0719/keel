package vmess

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestXUDPConnReadsFrames(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	target := M.ParseSocksaddr("1.1.1.1:53")
	conn := NewXUDPConn(client, target)
	other := M.ParseSocksaddr("8.8.8.8:53")
	go func() {
		server.Write(muxFrame(0, StatusKeep, OptionData, NetworkUDP, other, []byte("one")))
		server.Write(muxFrame(0, StatusKeepAlive, 0, 0, M.Socksaddr{}, nil))
		server.Write(muxFrame(0, StatusKeep, OptionData, 0, M.Socksaddr{}, []byte("two")))
		var many bytes.Buffer
		for i := 0; i < 100; i++ {
			many.Write(muxFrame(0, StatusKeep, OptionData, NetworkUDP, other, bytes.Repeat([]byte{byte(i)}, 1+i*13)))
		}
		server.Write(many.Bytes())
		server.Write(muxFrame(0, StatusEnd, 0, 0, M.Socksaddr{}, nil))
	}()
	read := func() ([]byte, M.Socksaddr, error) {
		buffer := buf.NewPacket()
		defer buffer.Release()
		from, err := conn.ReadPacket(buffer)
		return append([]byte(nil), buffer.Bytes()...), from, err
	}
	if data, from, err := read(); err != nil || string(data) != "one" || from != other {
		t.Fatalf("first packet %q from %v: %v", data, from, err)
	}
	if data, from, err := read(); err != nil || string(data) != "two" || from != target {
		t.Fatalf("second packet %q from %v: %v", data, from, err)
	}
	for i := 0; i < 100; i++ {
		data, from, err := read()
		if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{byte(i)}, 1+i*13)) || from != other {
			t.Fatalf("packet %d: %d bytes from %v: %v", i, len(data), from, err)
		}
	}
	if _, _, err := read(); err != io.EOF {
		t.Fatalf("after the end: %v", err)
	}
}
