package shadowaead_2022_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// echoHandler sends back what each TCP or UDP session receives, through
// sing's copy for TCP (so through WaitReadBuffer and WriteBuffer).
type echoHandler struct{}

func (echoHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	bufio.Copy(conn, conn)
	return conn.Close()
}

func (echoHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	for {
		// Room for the reply's header and tag, as a copy would leave.
		buffer := buf.NewSize(1024 + 16384 + 64)
		buffer.Resize(1024, 0)
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		if err = conn.WritePacket(buffer, destination); err != nil {
			return err
		}
	}
}

func (echoHandler) NewError(ctx context.Context, err error) {}

// udpSocket is the server's UDP socket as the service writes to it.
type udpSocket struct{ *net.UDPConn }

func (s udpSocket) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := s.ReadFromUDPAddrPort(buffer.FreeBytes())
	buffer.Truncate(n)
	return M.SocksaddrFromNetIP(addr), err
}

func (s udpSocket) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := s.WriteToUDPAddrPort(buffer.Bytes(), destination.AddrPort())
	return err
}

func udpRoundTrip(t *testing.T, service shadowsocks.Service, client shadowsocks.Method) {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		for {
			buffer := buf.NewPacket()
			n, addr, err := server.ReadFromUDPAddrPort(buffer.FreeBytes())
			if err != nil {
				buffer.Release()
				return
			}
			buffer.Truncate(n)
			service.NewPacket(context.Background(), udpSocket{server}, buffer, M.Metadata{Source: M.SocksaddrFromNetIP(addr)})
		}
	}()
	conn, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packetConn := client.DialPacketConn(conn)
	// Port 53 makes the replies carry padding.
	for _, target := range []string{"1.2.3.4:443", "8.8.8.8:53", "[2001:db8::1]:53"} {
		destination := M.ParseSocksaddr(target)
		for i := 0; i < 50; i++ {
			payload := make([]byte, 1+i*20)
			rand.Read(payload)
			buffer := buf.NewSize(1024 + len(payload) + 64) // room for the header and the tag
			buffer.Resize(1024, 0)
			buffer.Write(payload)
			if err := packetConn.WritePacket(buffer, destination); err != nil {
				t.Fatal(err)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			reply := buf.NewSize(4096)
			from, err := packetConn.ReadPacket(reply)
			if err != nil || !bytes.Equal(reply.Bytes(), payload) || from != destination {
				t.Fatalf("%s packet %d: %d bytes from %v: %v", target, i, reply.Len(), from, err)
			}
			reply.Release()
		}
	}
}

func tcpRoundTrip(t *testing.T, service shadowsocks.Service, client shadowsocks.Method) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go service.NewConnection(context.Background(), serverConn, M.Metadata{})
	conn, err := client.DialConn(clientConn, M.ParseSocksaddr("test.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := make([]byte, 3<<20)
	rand.Read(data)
	go bufio.Copy(conn, bytes.NewReader(data))
	got := make([]byte, len(data))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("echo differs: %v", err)
	}
}

func TestServiceRoundTrips(t *testing.T) {
	method := "2022-blake3-aes-128-gcm"
	var psk [16]byte
	rand.Read(psk[:])
	service, err := shadowaead_2022.NewService(method, psk[:], 500, echoHandler{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := shadowaead_2022.New(method, [][]byte{psk[:]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	udpRoundTrip(t, service, client)
	tcpRoundTrip(t, service, client)
}

func TestMultiServiceRoundTrips(t *testing.T) {
	method := "2022-blake3-aes-128-gcm"
	var iPSK, uPSK [16]byte
	rand.Read(iPSK[:])
	rand.Read(uPSK[:])
	service, err := shadowaead_2022.NewMultiService[string](method, iPSK[:], 500, echoHandler{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]string{"user"}, [][]byte{uPSK[:]})
	client, err := shadowaead_2022.New(method, [][]byte{iPSK[:], uPSK[:]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	udpRoundTrip(t, service, client)
	tcpRoundTrip(t, service, client)
}
