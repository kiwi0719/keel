package vmess

import (
	std_bufio "bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func HandleMuxConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, handler Handler) error {
	ctx, cancel := context.WithCancelCause(ctx)
	session := &serverSession{
		ctx:          ctx,
		source:       source,
		conn:         conn,
		reader:       std_bufio.NewReaderSize(conn, 4096),
		directWriter: bufio.NewExtendedWriter(conn),
		handler:      handler,
		streams:      make(map[uint16]*serverStream),
		space:        make(chan struct{}, 1),
		writer:       std_bufio.NewWriter(conn),
	}
	go func() {
		<-ctx.Done()
		session.cleanup(ctx.Err())
	}()
	return session.recvLoop(cancel)
}

type serverSession struct {
	ctx    context.Context
	source M.Socksaddr
	conn   net.Conn
	// Frames are read through a buffer: headers and addresses come a few
	// bytes at a time.
	reader       *std_bufio.Reader
	directWriter N.ExtendedWriter
	handler      Handler
	streamAccess sync.RWMutex
	streams      map[uint16]*serverStream
	writer       *std_bufio.Writer
	writeAccess  sync.Mutex
	writeRace    uint32
	queued       atomic.Int64  // unread data of its sub-streams (see MuxStreamBuffer)
	space        chan struct{} // a reader of one of its sub-streams took data
}

type serverStream struct {
	network     byte
	destination M.Socksaddr
	queue       *muxQueue
}

func (c *serverSession) recvLoop(cancel context.CancelCauseFunc) error {
	for {
		err := c.recv()
		if err != nil {
			cancel(err)
			return E.Cause(err, "mux connection closed")
		}
	}
}

func (c *serverSession) cleanup(err error) {
	c.streamAccess.Lock()
	for _, stream := range c.streams {
		stream.queue.end(err) // what came before is still read
	}
	c.streamAccess.Unlock()
}

func (c *serverSession) recv() error {
	var header [6]byte
	if _, err := io.ReadFull(c.reader, header[:]); err != nil {
		return E.Cause(err, "read frame header")
	}
	length := binary.BigEndian.Uint16(header[0:])
	sessionID := binary.BigEndian.Uint16(header[2:])
	status, option := header[4], header[5]

	var err error
	var network byte
	var destination M.Socksaddr
	if length > 4 {
		limitReader := io.LimitReader(c.reader, int64(length-4))
		var networkByte [1]byte
		if _, err = io.ReadFull(limitReader, networkByte[:]); err != nil {
			return err
		}
		network = networkByte[0]
		destination, err = AddressSerializer.ReadAddrPort(limitReader)
		if err != nil {
			return err
		}
		if limitReader.(*io.LimitedReader).N > 0 {
			_, err = io.Copy(io.Discard, limitReader)
			if err != nil {
				return err
			}
		}
	}

	var stream *serverStream
	switch status {
	case StatusNew:
		stream = &serverStream{
			network,
			destination,
			newMuxQueue(c),
		}
		c.streamAccess.Lock()
		// A reused id would orphan the old stream's relay: end it first.
		if old, loaded := c.streams[sessionID]; loaded {
			old.queue.end(nil)
		}
		c.streams[sessionID] = stream
		c.streamAccess.Unlock()
		switch network {
		case NetworkTCP, NetworkUDP:
		default:
			return E.New("bad network: ", network)
		}
		go func() {
			if network == NetworkTCP {
				conn := &serverMuxConn{
					sessionID,
					stream.queue,
					c,
				}
				c.handler.NewConnectionEx(c.ctx, conn, c.source, destination, nil)
			} else {
				conn := &serverMuxPacketConn{
					sessionID,
					stream.queue,
					c,
					destination,
				}
				c.handler.NewPacketConnectionEx(c.ctx, conn, c.source, destination, nil)
			}
		}()
	case StatusKeep:
		var loaded bool
		c.streamAccess.Lock()
		stream, loaded = c.streams[sessionID]
		c.streamAccess.Unlock()
		if !loaded {
			go c.syncClose(sessionID, true)
		}
	case StatusEnd:
		if option&OptionError == OptionError {
			err = E.New("remote closed wth error")
		}
		c.localClose(sessionID, err, false)
	case StatusKeepAlive:
	default:
		return E.New("bad session status: ", status)
	}

	if option&OptionData != OptionData {
		return nil
	}

	var lengthBytes [2]byte
	if _, err = io.ReadFull(c.reader, lengthBytes[:]); err != nil {
		return err
	}
	length = binary.BigEndian.Uint16(lengthBytes[:])

	if length == 0 {
		return nil
	}

	if stream == nil {
		return common.Error(io.CopyN(io.Discard, c.reader, int64(length)))
	}

	// The sub-stream's reader gets this buffer itself.
	data := buf.NewSize(int(length))
	_, err = data.ReadFullFrom(c.reader, int(length))
	if err != nil {
		data.Release()
		return err
	}

	if !destination.IsValid() {
		destination = stream.destination
	}
	stream.queue.push(data, destination, stream.network == NetworkTCP)
	return nil
}

func (c *serverSession) syncWrite(sessionID uint16, data []byte) (int, error) {
	writeRace := atomic.AddUint32(&c.writeRace, 1)
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	err := c.writeFrame(sessionID, data)
	if err != nil {
		return 0, err
	}
	if writeRace == atomic.LoadUint32(&c.writeRace) {
		err = c.writer.Flush()
		if err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func (c *serverSession) writeFrame(sessionID uint16, data []byte) error {
	var header [8]byte
	binary.BigEndian.PutUint16(header[0:], 4)
	binary.BigEndian.PutUint16(header[2:], sessionID)
	header[4] = StatusKeep
	header[5] = OptionData
	binary.BigEndian.PutUint16(header[6:], uint16(len(data)))
	if _, err := c.writer.Write(header[:]); err != nil {
		return err
	}
	return common.Error(c.writer.Write(data))
}

func (c *serverSession) syncWritePacket(sessionID uint16, data []byte, destination M.Socksaddr) (int, error) {
	writeRace := atomic.AddUint32(&c.writeRace, 1)
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	err := c.writePacketFrame(sessionID, data, destination)
	if err != nil {
		return 0, err
	}
	if writeRace == atomic.LoadUint32(&c.writeRace) {
		err = c.writer.Flush()
		if err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func (c *serverSession) writePacketFrame(sessionID uint16, data []byte, destination M.Socksaddr) error {
	var header [7]byte
	binary.BigEndian.PutUint16(header[0:], uint16(5+AddressSerializer.AddrPortLen(destination)))
	binary.BigEndian.PutUint16(header[2:], sessionID)
	header[4] = StatusKeep
	header[5] = OptionData
	header[6] = NetworkUDP
	fixed := header[:6]
	if destination.IsValid() {
		fixed = header[:]
	}
	if _, err := c.writer.Write(fixed); err != nil {
		return err
	}
	if destination.IsValid() {
		if err := AddressSerializer.WriteAddrPort(c.writer, destination); err != nil {
			return err
		}
	}
	var lengthBytes [2]byte
	binary.BigEndian.PutUint16(lengthBytes[:], uint16(len(data)))
	if _, err := c.writer.Write(lengthBytes[:]); err != nil {
		return err
	}
	return common.Error(c.writer.Write(data))
}

func (c *serverSession) close(sessionID uint16, err error) error {
	if c.localClose(sessionID, err, true) {
		return c.syncClose(sessionID, err != nil)
	}
	return nil
}

// localClose ends a sub-stream; discard when its reader closed it, else
// (the client ended it) what came before is still read.
func (c *serverSession) localClose(sessionID uint16, err error, discard bool) bool {
	var closed bool
	c.streamAccess.Lock()
	if stream, loaded := c.streams[sessionID]; loaded {
		delete(c.streams, sessionID)
		stream.queue.end(err)
		if discard {
			stream.queue.discard()
		}
		closed = true
	}
	c.streamAccess.Unlock()
	return closed
}

func (c *serverSession) syncClose(sessionID uint16, hasError bool) error {
	writeRace := atomic.AddUint32(&c.writeRace, 1)
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	err := c.writeCloseFrame(sessionID, hasError)
	if err != nil {
		return err
	}
	if writeRace == atomic.LoadUint32(&c.writeRace) {
		err = c.writer.Flush()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *serverSession) writeCloseFrame(sessionID uint16, hasError bool) error {
	var header [6]byte
	binary.BigEndian.PutUint16(header[0:], 4)
	binary.BigEndian.PutUint16(header[2:], sessionID)
	header[4] = StatusEnd
	if hasError {
		header[5] = OptionError
	}
	_, err := c.writer.Write(header[:])
	return err
}

type serverMuxConn struct {
	sessionID uint16
	queue     *muxQueue
	session   *serverSession
}

func (c *serverMuxConn) Read(b []byte) (n int, err error) {
	return c.queue.read(b)
}

func (c *serverMuxConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.queue.readWait = options
	return false
}

// WaitReadBuffer hands over the queued buffer itself, copied only when the
// destination needs headroom it does not have.
func (c *serverMuxConn) WaitReadBuffer() (*buf.Buffer, error) {
	item, err := c.queue.pop()
	if err != nil {
		return nil, err
	}
	return c.queue.readWait.Copy(item.buffer), nil
}

func (c *serverMuxConn) Write(b []byte) (n int, err error) {
	return c.session.syncWrite(c.sessionID, b)
}

func (c *serverMuxConn) WriteBuffer(buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	header := buffer.ExtendHeader(8)
	binary.BigEndian.PutUint16(header[0:], 4)
	binary.BigEndian.PutUint16(header[2:], c.sessionID)
	header[4] = StatusKeep
	header[5] = OptionData
	binary.BigEndian.PutUint16(header[6:], uint16(dataLen))
	return c.session.directWriter.WriteBuffer(buffer)
}

func (c *serverMuxConn) FrontHeadroom() int {
	return 8
}

func (c *serverMuxConn) UpstreamWriter() any {
	return c.session.directWriter
}

func (c *serverMuxConn) Close() error {
	// The client may have ended the stream already, leaving data queued.
	c.queue.end(nil)
	c.queue.discard()
	return c.session.close(c.sessionID, nil)
}

func (c *serverMuxConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxConn) NeedAdditionalReadDeadline() bool {
	return true
}

var _ PacketConn = (*serverMuxPacketConn)(nil)

type serverMuxPacketConn struct {
	sessionID   uint16
	queue       *muxQueue
	session     *serverSession
	destination M.Socksaddr
}

func (c *serverMuxPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *serverMuxPacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.destination)
}

func (c *serverMuxPacketConn) RemoteAddr() net.Addr {
	return c.destination.UDPAddr()
}

func (c *serverMuxPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	item, err := c.queue.pop()
	if err != nil {
		return
	}
	defer item.buffer.Release()
	if item.buffer.Len() > len(p) {
		return 0, nil, E.Extend(io.ErrShortBuffer, "mux need ", item.buffer.Len())
	}
	return copy(p, item.buffer.Bytes()), item.destination, nil
}

func (c *serverMuxPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	item, err := c.queue.pop()
	if err != nil {
		return
	}
	defer item.buffer.Release()
	if item.buffer.Len() > buffer.FreeLen() {
		return M.Socksaddr{}, E.Extend(io.ErrShortBuffer, "mux need ", item.buffer.Len())
	}
	common.Must1(buffer.Write(item.buffer.Bytes()))
	return item.destination.Unwrap(), nil
}

func (c *serverMuxPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.queue.readWait = options
	return false
}

// WaitReadPacket hands over the queued packet itself, copied only when the
// destination needs headroom it does not have.
func (c *serverMuxPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	item, err := c.queue.pop()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	return c.queue.readWait.Copy(item.buffer), item.destination.Unwrap(), nil
}

func (c *serverMuxPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.session.syncWritePacket(c.sessionID, p, M.SocksaddrFromNet(addr))
}

func (c *serverMuxPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	dataLen := buffer.Len()
	addrLen := AddressSerializer.AddrPortLen(destination)
	header := buffer.ExtendHeader(9 + addrLen)
	binary.BigEndian.PutUint16(header[0:], uint16(5+addrLen))
	binary.BigEndian.PutUint16(header[2:], c.sessionID)
	header[4] = StatusKeep
	header[5] = OptionData
	header[6] = NetworkUDP
	err := AddressSerializer.WriteAddrPort(buf.With(header[7:7+addrLen]), destination)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(header[7+addrLen:], uint16(dataLen))
	return c.session.directWriter.WriteBuffer(buffer)
}

func (c *serverMuxPacketConn) FrontHeadroom() int {
	return 9 + M.MaxSocksaddrLength
}

func (c *serverMuxPacketConn) UpstreamWriter() any {
	return c.session.directWriter
}

func (c *serverMuxPacketConn) Close() error {
	c.queue.end(nil)
	c.queue.discard()
	return c.session.close(c.sessionID, nil)
}

func (c *serverMuxPacketConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverMuxPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverMuxPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}
