package vmess

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// What a mux session has read for a sub-stream but its reader has not taken
// yet is kept up to these limits: per sub-stream, per session and for the
// whole process. Past them a TCP sub-stream makes the session wait, as every
// frame did before (mux.cool has no flow control), and a UDP packet is
// dropped, as datagrams may be.
var (
	MuxStreamBuffer  = 64 << 10
	MuxSessionBuffer = 256 << 10
	MuxTotalBuffer   = 32 << 20
)

// muxQueued is the unread data of every sub-stream in the process.
var muxQueued atomic.Int64

type muxItem struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

// muxQueue hands what the session read for one sub-stream to its reader:
// whole buffers, in order, without copying.
type muxQueue struct {
	session  *serverSession
	mu       sync.Mutex
	items    []muxItem
	queued   int
	closed   bool
	err      error         // why nothing more comes; nil means io.EOF
	readable chan struct{} // an item arrived or the queue ended
	space    chan struct{} // the reader took data, or the queue ended
	readWait N.ReadWaitOptions
}

func newMuxQueue(session *serverSession) *muxQueue {
	return &muxQueue{session: session, readable: make(chan struct{}, 1), space: make(chan struct{}, 1)}
}

func signalMux(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// muxFits reports whether n more bytes may be queued where have are: always
// when nothing is, so a full frame can never wait forever.
func muxFits(have int64, n int, limit int) bool {
	return have == 0 || have+int64(n) <= int64(limit)
}

// push queues b. With wait it waits for room, the session reading nothing
// meanwhile; without, b is dropped when there is none.
func (q *muxQueue) push(b *buf.Buffer, destination M.Socksaddr, wait bool) {
	n := b.Len()
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			b.Release()
			return
		}
		if muxFits(int64(q.queued), n, MuxStreamBuffer) && muxFits(q.session.queued.Load(), n, MuxSessionBuffer) && muxFits(muxQueued.Load(), n, MuxTotalBuffer) {
			q.items = append(q.items, muxItem{b, destination})
			q.queued += n
			q.session.queued.Add(int64(n))
			muxQueued.Add(int64(n))
			q.mu.Unlock()
			signalMux(q.readable)
			return
		}
		q.mu.Unlock()
		if !wait {
			b.Release()
			return
		}
		select {
		case <-q.space:
		case <-q.session.space:
		case <-q.session.ctx.Done():
			b.Release()
			return
		case <-time.After(10 * time.Millisecond): // other sessions free the process-wide room
		}
	}
}

// taken accounts for n queued bytes the reader took, with q.mu held.
func (q *muxQueue) taken(n int) {
	q.queued -= n
	q.session.queued.Add(int64(-n))
	muxQueued.Add(int64(-n))
	signalMux(q.space)
	signalMux(q.session.space)
}

// next waits for an item and returns with q.mu held, or returns why there
// is none.
func (q *muxQueue) next() error {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			return nil
		}
		closed, err := q.closed, q.err
		q.mu.Unlock()
		if closed {
			if err == nil {
				err = io.EOF
			}
			return err
		}
		<-q.readable
	}
}

// read copies from the head of the queue (TCP).
func (q *muxQueue) read(p []byte) (int, error) {
	if err := q.next(); err != nil {
		return 0, err
	}
	head := q.items[0].buffer
	n, _ := head.Read(p)
	if head.IsEmpty() {
		head.Release()
		q.items[0] = muxItem{}
		q.items = q.items[1:]
	}
	q.taken(n)
	q.mu.Unlock()
	return n, nil
}

// pop takes the head item whole.
func (q *muxQueue) pop() (muxItem, error) {
	if err := q.next(); err != nil {
		return muxItem{}, err
	}
	item := q.items[0]
	q.items[0] = muxItem{}
	q.items = q.items[1:]
	q.taken(item.buffer.Len())
	q.mu.Unlock()
	return item, nil
}

// end marks that nothing more will be queued; what was is still read.
func (q *muxQueue) end(err error) {
	q.mu.Lock()
	if !q.closed {
		q.closed, q.err = true, err
	}
	q.mu.Unlock()
	signalMux(q.readable)
	signalMux(q.space)
}

// discard drops what is queued: the reader is gone.
func (q *muxQueue) discard() {
	q.mu.Lock()
	for _, item := range q.items {
		item.buffer.Release()
	}
	q.items = nil
	q.taken(q.queued)
	q.mu.Unlock()
}
