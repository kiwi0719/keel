package session

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anytls/sing-anytls/pipe"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// Data the session's receive loop has read for a stream but its reader has
// not taken yet is kept up to these limits: per stream, per session and for
// the whole process. Past them the receive loop waits, as it did for every
// frame before: AnyTLS has no flow control, so the alternatives would be
// dropping data or holding any amount of it.
var (
	StreamBuffer  = 64 << 10
	SessionBuffer = 256 << 10
	TotalBuffer   = 32 << 20
)

// queuedBytes is the unread data of every stream in the process.
var queuedBytes atomic.Int64

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	// What the receive loop read for this stream, in order: whole pooled
	// buffers, handed to the reader without copying. closed: nothing more
	// will be queued; what is queued is still read, unless the stream was
	// closed here.
	mu       sync.Mutex
	queue    []*buf.Buffer
	queued   int
	closed   bool
	readable chan struct{} // data arrived or the stream closed
	space    chan struct{} // the reader took data, or the stream closed here
	readWait N.ReadWaitOptions

	readDeadline  pipe.PipeDeadline
	writeDeadline pipe.PipeDeadline

	dieOnce sync.Once
	dieHook func()
	dieErr  atomic.Pointer[error] // set once on close; read by Read/Write on other goroutines

	reportOnce sync.Once
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.readable = make(chan struct{}, 1)
	s.space = make(chan struct{}, 1)
	s.readDeadline = pipe.MakePipeDeadline()
	s.writeDeadline = pipe.MakePipeDeadline()
	return s
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// fits reports whether n more bytes may be queued where have are: always
// when nothing is, so a full frame can never wait forever.
func fits(have int64, n int, limit int) bool {
	return have == 0 || have+int64(n) <= int64(limit)
}

// push hands a buffer the receive loop read for this stream to its reader,
// waiting while the stream, the session or the process holds as much
// unread data as allowed. The session reads nothing meanwhile.
func (s *Stream) push(b *buf.Buffer) {
	n := b.Len()
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			b.Release()
			return
		}
		if fits(int64(s.queued), n, StreamBuffer) && fits(s.sess.queued.Load(), n, SessionBuffer) && fits(queuedBytes.Load(), n, TotalBuffer) {
			s.queue = append(s.queue, b)
			s.queued += n
			s.sess.queued.Add(int64(n))
			queuedBytes.Add(int64(n))
			s.mu.Unlock()
			signal(s.readable)
			return
		}
		s.mu.Unlock()
		select {
		case <-s.space:
		case <-s.sess.space:
		case <-s.sess.die:
			b.Release()
			return
		case <-time.After(10 * time.Millisecond): // other sessions free the process-wide room
		}
	}
}

// taken accounts for n queued bytes the reader took, with s.mu held.
func (s *Stream) taken(n int) {
	s.queued -= n
	s.sess.queued.Add(int64(-n))
	queuedBytes.Add(int64(-n))
	signal(s.space)
	signal(s.sess.space)
}

// next waits for queued data, or returns why there is none.
func (s *Stream) next() error {
	for {
		select {
		case <-s.readDeadline.Wait():
			return os.ErrDeadlineExceeded
		default:
		}
		s.mu.Lock()
		if len(s.queue) > 0 {
			return nil // with s.mu held
		}
		closed := s.closed
		s.mu.Unlock()
		if closed {
			if dieErr := s.dieErr.Load(); dieErr != nil {
				return *dieErr
			}
			return io.EOF
		}
		select {
		case <-s.readable:
		case <-s.readDeadline.Wait():
			return os.ErrDeadlineExceeded
		}
	}
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	if err = s.next(); err != nil {
		return 0, err
	}
	head := s.queue[0]
	n, _ = head.Read(b)
	if head.IsEmpty() {
		head.Release()
		s.queue[0] = nil
		s.queue = s.queue[1:]
	}
	s.taken(n)
	s.mu.Unlock()
	return n, nil
}

func (s *Stream) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	s.readWait = options
	return false
}

// WaitReadBuffer hands over the next queued buffer itself, copied only when
// the destination needs headroom the buffer does not have.
func (s *Stream) WaitReadBuffer() (*buf.Buffer, error) {
	if err := s.next(); err != nil {
		return nil, err
	}
	head := s.queue[0]
	s.queue[0] = nil
	s.queue = s.queue[1:]
	s.taken(head.Len())
	s.mu.Unlock()
	return s.readWait.Copy(head), nil
}

// discard drops what is queued: the reader is gone.
func (s *Stream) discard() {
	s.mu.Lock()
	for _, b := range s.queue {
		b.Release()
	}
	s.queue = nil
	s.taken(s.queued)
	s.mu.Unlock()
}

// end marks that no more data will come; the reader still gets what came.
func (s *Stream) end() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	signal(s.readable)
	signal(s.space)
}

func (s *Stream) writable() error {
	select {
	case <-s.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
	}
	if dieErr := s.dieErr.Load(); dieErr != nil {
		return *dieErr
	}
	return nil
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	if err = s.writable(); err != nil {
		return 0, err
	}
	return s.sess.writeDataFrame(s.id, b)
}

// FrontHeadroom has a copy into the stream leave room for the frame header,
// so WriteBuffer sends the data where it is.
func (s *Stream) FrontHeadroom() int {
	return headerOverHeadSize
}

func (s *Stream) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	if err := s.writable(); err != nil {
		return err
	}
	dataLen := buffer.Len()
	if dataLen > maxFrameData || buffer.Start() < headerOverHeadSize {
		_, err := s.sess.writeDataFrame(s.id, buffer.Bytes())
		return err
	}
	header := buffer.ExtendHeader(headerOverHeadSize)
	header[0] = cmdPSH
	binary.BigEndian.PutUint32(header[1:], s.id)
	binary.BigEndian.PutUint16(header[5:], uint16(dataLen))
	_, err := s.sess.writeConn(buffer.Bytes())
	return err
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer. What was
// received before stays readable: the peer's FIN, or the session ending,
// follows its last data.
func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		dieErr := net.ErrClosed
		s.dieErr.Store(&dieErr)
		s.end()
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.dieErr.Store(&err)
		s.end()
		once = true
	})
	// Closed here: nobody will read what is still queued.
	s.discard()
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		return s.sess.streamClosed(s.id)
	} else {
		return *s.dieErr.Load()
	}
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion.Load() >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion.Load() >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
