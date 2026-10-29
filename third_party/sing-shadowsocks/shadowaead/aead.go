package shadowaead

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
const (
	MaxPacketSize          = 16*1024 - 1
	PacketLengthBufferSize = 2
)

const (
	// Overhead
	// crypto/cipher.gcmTagSize
	// golang.org/x/crypto/chacha20poly1305.Overhead
	Overhead = 16
)

var ErrPacketTooLarge = errors.New("shadowsocks: chunk longer than the maximum packet size")

// chunkBuffer is the scratch space of a Reader or Writer. Buffers of NewReader
// and NewWriter come from sing's pool when a chunk needs one and go back as
// soon as it is done with, so an idle connection holds none (two buffers of up
// to 64 KiB each used to stay with every connection for its lifetime). The
// raw constructors keep the caller's buffer.
type chunkBuffer struct {
	data   []byte
	pooled bool // from buf.Get, goes back with buf.Put
	raw    bool // the caller's, never released
}

func (b *chunkBuffer) acquire(n int) []byte {
	if b.raw {
		return b.data[:n]
	}
	if cap(b.data) < n {
		b.release()
		if data := buf.Get(n); data != nil {
			b.data, b.pooled = data, true
		} else {
			b.data = make([]byte, n)
		}
	}
	return b.data[:n]
}

func (b *chunkBuffer) release() {
	if b.raw {
		return
	}
	if b.pooled {
		buf.Put(b.data)
	}
	b.data, b.pooled = nil, false
}

type Reader struct {
	upstream      io.Reader
	cipher        cipher.AEAD
	maxPacketSize int
	length        [PacketLengthBufferSize + Overhead]byte
	buffer        chunkBuffer
	nonce         []byte
	index         int
	cached        int
}

func NewReader(upstream io.Reader, cipher cipher.AEAD, maxPacketSize int) *Reader {
	return &Reader{
		upstream:      upstream,
		cipher:        cipher,
		maxPacketSize: maxPacketSize,
		nonce:         make([]byte, cipher.NonceSize()),
	}
}

func NewRawReader(upstream io.Reader, cipher cipher.AEAD, buffer []byte, nonce []byte) *Reader {
	return &Reader{
		upstream:      upstream,
		cipher:        cipher,
		maxPacketSize: len(buffer) - Overhead,
		buffer:        chunkBuffer{data: buffer, raw: true},
		nonce:         nonce,
	}
}

func (r *Reader) Upstream() any {
	return r.upstream
}

// readLength reads and opens the next length chunk.
func (r *Reader) readLength() (int, error) {
	_, err := io.ReadFull(r.upstream, r.length[:])
	if err != nil {
		return 0, err
	}
	return r.openLength(r.length[:])
}

func (r *Reader) openLength(lengthChunk []byte) (int, error) {
	_, err := r.cipher.Open(r.length[:0], r.nonce, lengthChunk, nil)
	if err != nil {
		return 0, err
	}
	increaseNonce(r.nonce)
	length := int(binary.BigEndian.Uint16(r.length[:PacketLengthBufferSize]))
	if length > r.maxPacketSize {
		return 0, ErrPacketTooLarge
	}
	return length, nil
}

// readPayload reads and opens a payload chunk of length bytes into the
// reader's buffer.
func (r *Reader) readPayload(length int) error {
	end := length + Overhead
	data := r.buffer.acquire(end)
	_, err := io.ReadFull(r.upstream, data)
	if err == nil {
		_, err = r.cipher.Open(data[:0], r.nonce, data, nil)
	}
	if err != nil {
		r.buffer.release()
		return err
	}
	increaseNonce(r.nonce)
	r.cached = length
	r.index = 0
	return nil
}

// consumed gives the buffer back once nothing is cached in it.
func (r *Reader) consumed() {
	if r.cached == 0 {
		r.index = 0
		r.buffer.release()
	}
}

// ReadBuffer returns the next data in a buffer of its own with the front and
// rear room options ask for: what is cached first, else the next chunk, read
// and opened in that buffer. Only an opened chunk is handed out, and nothing
// is held between calls: a reader waiting for data holds no buffer.
func (r *Reader) ReadBuffer(options N.ReadWaitOptions) (*buf.Buffer, error) {
	if r.cached > 0 {
		buffer := buf.NewSize(options.FrontHeadroom + r.cached + options.RearHeadroom)
		buffer.Resize(options.FrontHeadroom, 0)
		common.Must1(buffer.Write(r.buffer.data[r.index : r.index+r.cached]))
		r.cached = 0
		r.consumed()
		return buffer, nil
	}
	length, err := r.readLength()
	if err != nil {
		return nil, err
	}
	buffer := buf.NewSize(options.FrontHeadroom + length + Overhead + options.RearHeadroom)
	buffer.Resize(options.FrontHeadroom, 0)
	_, err = buffer.ReadFullFrom(r.upstream, length+Overhead)
	if err == nil {
		data := buffer.Bytes()
		_, err = r.cipher.Open(data[:0], r.nonce, data, nil)
	}
	if err != nil {
		buffer.Release()
		return nil, err
	}
	increaseNonce(r.nonce)
	buffer.Truncate(length)
	return buffer, nil
}

func (r *Reader) WriteTo(writer io.Writer) (n int64, err error) {
	if r.cached > 0 {
		writeN, writeErr := writer.Write(r.buffer.data[r.index : r.index+r.cached])
		r.cached = 0
		r.consumed()
		if writeErr != nil {
			return int64(writeN), writeErr
		}
		n += int64(writeN)
	}
	for {
		var length int
		length, err = r.readLength()
		if err != nil {
			return
		}
		err = r.readPayload(length)
		if err != nil {
			return
		}
		writeN, writeErr := writer.Write(r.buffer.data[:length])
		r.cached = 0
		r.consumed()
		if writeErr != nil {
			return int64(writeN), writeErr
		}
		n += int64(writeN)
	}
}

func (r *Reader) readInternal() (err error) {
	length, err := r.readLength()
	if err != nil {
		return err
	}
	return r.readPayload(length)
}

func (r *Reader) ReadByte() (byte, error) {
	for r.cached == 0 {
		err := r.readInternal()
		if err != nil {
			return 0, err
		}
	}
	c := r.buffer.data[r.index]
	r.index++
	r.cached--
	r.consumed()
	return c, nil
}

func (r *Reader) Read(b []byte) (n int, err error) {
	if r.cached > 0 {
		n = copy(b, r.buffer.data[r.index:r.index+r.cached])
		r.cached -= n
		r.index += n
		r.consumed()
		return
	}
	length, err := r.readLength()
	if err != nil {
		return 0, err
	}
	end := length + Overhead

	if len(b) >= end {
		data := b[:end]
		_, err = io.ReadFull(r.upstream, data)
		if err != nil {
			return 0, err
		}
		_, err = r.cipher.Open(b[:0], r.nonce, data, nil)
		if err != nil {
			return 0, err
		}
		increaseNonce(r.nonce)
		return length, nil
	} else {
		err = r.readPayload(length)
		if err != nil {
			return 0, err
		}
		n = copy(b, r.buffer.data[:length])
		r.cached = length - n
		r.index = n
		r.consumed()
		return
	}
}

func (r *Reader) Discard(n int) error {
	for {
		if r.cached >= n {
			r.cached -= n
			r.index += n
			r.consumed()
			return nil
		} else if r.cached > 0 {
			n -= r.cached
			r.cached = 0
			r.consumed()
		}
		err := r.readInternal()
		if err != nil {
			return err
		}
	}
}

func (r *Reader) Buffer() *buf.Buffer {
	buffer := buf.With(r.buffer.data)
	buffer.Resize(r.index, r.cached)
	return buffer
}

func (r *Reader) Cached() int {
	return r.cached
}

func (r *Reader) CachedSlice() []byte {
	return r.buffer.data[r.index : r.index+r.cached]
}

func (r *Reader) ReadWithLengthChunk(lengthChunk []byte) error {
	length, err := r.openLength(lengthChunk)
	if err != nil {
		return err
	}
	return r.readPayload(length)
}

func (r *Reader) ReadWithLength(length uint16) error {
	if int(length) > r.maxPacketSize {
		return ErrPacketTooLarge
	}
	return r.readPayload(int(length))
}

func (r *Reader) ReadExternalChunk(chunk []byte) error {
	data := r.buffer.acquire(len(chunk))
	bb, err := r.cipher.Open(data[:0], r.nonce, chunk, nil)
	if err != nil {
		r.buffer.release()
		return err
	}
	increaseNonce(r.nonce)
	r.cached = len(bb)
	r.index = 0
	r.consumed()
	return nil
}

func (r *Reader) ReadChunk(buffer *buf.Buffer, chunk []byte) error {
	bb, err := r.cipher.Open(buffer.Index(buffer.Len()), r.nonce, chunk, nil)
	if err != nil {
		return err
	}
	increaseNonce(r.nonce)
	buffer.Extend(len(bb))
	return nil
}

type Writer struct {
	upstream      io.Writer
	cipher        cipher.AEAD
	maxPacketSize int
	buffer        chunkBuffer
	nonce         []byte
	// access is held from sealing a chunk until it is written, so chunks go
	// out in nonce order and the buffer is not given back while in use.
	access sync.Mutex
}

func NewWriter(upstream io.Writer, cipher cipher.AEAD, maxPacketSize int) *Writer {
	return &Writer{
		upstream:      upstream,
		cipher:        cipher,
		nonce:         make([]byte, cipher.NonceSize()),
		maxPacketSize: maxPacketSize,
	}
}

func NewRawWriter(upstream io.Writer, cipher cipher.AEAD, maxPacketSize int, buffer []byte, nonce []byte) *Writer {
	return &Writer{
		upstream:      upstream,
		cipher:        cipher,
		maxPacketSize: maxPacketSize,
		buffer:        chunkBuffer{data: buffer, raw: true},
		nonce:         nonce,
	}
}

// fullSize is the room one chunk of maxPacketSize takes once sealed.
func (w *Writer) fullSize() int {
	return w.maxPacketSize + PacketLengthBufferSize + Overhead*2
}

func (w *Writer) Upstream() any {
	return w.upstream
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	// Its own buffer: reading from r may block for long, and must not do so
	// holding the writer.
	var buffer chunkBuffer
	defer buffer.release()
	data := buffer.acquire(w.fullSize())
	for {
		offset := Overhead + PacketLengthBufferSize
		readN, readErr := r.Read(data[offset : offset+w.maxPacketSize])
		if readErr != nil {
			return 0, readErr
		}
		w.access.Lock()
		binary.BigEndian.PutUint16(data[:PacketLengthBufferSize], uint16(readN))
		w.cipher.Seal(data[:0], w.nonce, data[:PacketLengthBufferSize], nil)
		increaseNonce(w.nonce)
		packet := w.cipher.Seal(data[offset:offset], w.nonce, data[offset:offset+readN], nil)
		increaseNonce(w.nonce)
		_, err = w.upstream.Write(data[:offset+len(packet)])
		w.access.Unlock()
		if err != nil {
			return
		}
		n += int64(readN)
	}
}

// FrontHeadroom and RearHeadroom ask for room around the data for its sealed
// length and its tag, so that WriteBuffer seals a chunk where it is.
func (w *Writer) FrontHeadroom() int {
	return PacketLengthBufferSize + Overhead
}

func (w *Writer) RearHeadroom() int {
	return Overhead
}

// WriteBuffer writes what Write would for the same data; without the room,
// or with more than one chunk of data, it goes through Write.
func (w *Writer) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	if dataLen == 0 {
		return nil
	}
	if dataLen > w.maxPacketSize || buffer.Start() < w.FrontHeadroom() || buffer.FreeLen() < w.RearHeadroom() {
		_, err := w.Write(buffer.Bytes())
		return err
	}
	w.access.Lock()
	defer w.access.Unlock()
	header := buffer.ExtendHeader(PacketLengthBufferSize + Overhead)
	binary.BigEndian.PutUint16(header, uint16(dataLen))
	w.cipher.Seal(header[:0], w.nonce, header[:PacketLengthBufferSize], nil)
	increaseNonce(w.nonce)
	payload := buffer.Bytes()[PacketLengthBufferSize+Overhead:]
	w.cipher.Seal(payload[:0], w.nonce, payload, nil)
	increaseNonce(w.nonce)
	buffer.Extend(Overhead)
	_, err := w.upstream.Write(buffer.Bytes())
	return err
}

func (w *Writer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	w.access.Lock()
	defer w.access.Unlock()
	defer w.buffer.release()
	buffer := w.buffer.acquire(minInt(len(p), w.maxPacketSize) + PacketLengthBufferSize + Overhead*2)

	for pLen := len(p); pLen > 0; {
		var data []byte
		if pLen > w.maxPacketSize {
			data = p[:w.maxPacketSize]
			p = p[w.maxPacketSize:]
			pLen -= w.maxPacketSize
		} else {
			data = p
			pLen = 0
		}
		binary.BigEndian.PutUint16(buffer[:PacketLengthBufferSize], uint16(len(data)))
		w.cipher.Seal(buffer[:0], w.nonce, buffer[:PacketLengthBufferSize], nil)
		increaseNonce(w.nonce)
		offset := Overhead + PacketLengthBufferSize
		packet := w.cipher.Seal(buffer[offset:offset], w.nonce, data, nil)
		increaseNonce(w.nonce)
		_, err = w.upstream.Write(buffer[:offset+len(packet)])
		if err != nil {
			return
		}
		n += len(data)
	}

	return
}

func (w *Writer) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	w.access.Lock()
	defer w.access.Unlock()
	defer w.buffer.release()
	buffer := w.buffer.acquire(w.fullSize())
	var index int
	var err error
	for _, b := range buffers {
		pLen := b.Len()
		if pLen > w.maxPacketSize {
			if index > 0 {
				_, err = w.upstream.Write(buffer[:index])
				index = 0
				if err != nil {
					return err
				}
			}
			// The chunks of a long buffer are sealed and written one at a
			// time, in the same buffer.
			for data := b.Bytes(); len(data) > 0; {
				chunk := data[:minInt(len(data), w.maxPacketSize)]
				data = data[len(chunk):]
				binary.BigEndian.PutUint16(buffer[:PacketLengthBufferSize], uint16(len(chunk)))
				w.cipher.Seal(buffer[:0], w.nonce, buffer[:PacketLengthBufferSize], nil)
				increaseNonce(w.nonce)
				offset := Overhead + PacketLengthBufferSize
				packet := w.cipher.Seal(buffer[offset:offset], w.nonce, chunk, nil)
				increaseNonce(w.nonce)
				_, err = w.upstream.Write(buffer[:offset+len(packet)])
				if err != nil {
					return err
				}
			}
		} else {
			if len(buffer) < index+PacketLengthBufferSize+pLen+2*Overhead {
				_, err = w.upstream.Write(buffer[:index])
				index = 0
				if err != nil {
					return err
				}
			}
			binary.BigEndian.PutUint16(buffer[index:index+PacketLengthBufferSize], uint16(pLen))
			w.cipher.Seal(buffer[index:index], w.nonce, buffer[index:index+PacketLengthBufferSize], nil)
			increaseNonce(w.nonce)
			offset := index + Overhead + PacketLengthBufferSize
			w.cipher.Seal(buffer[offset:offset], w.nonce, b.Bytes(), nil)
			increaseNonce(w.nonce)
			index = offset + pLen + Overhead
		}
	}
	if index > 0 {
		_, err = w.upstream.Write(buffer[:index])
	}
	return err
}

// Buffer returns the writer's scratch space for building a handshake header
// with WriteChunk and BufferedWriter. Release gives it back once the header
// has been flushed.
func (w *Writer) Buffer() *buf.Buffer {
	return buf.With(w.buffer.acquire(w.fullSize()))
}

// Release gives back the buffer taken by Buffer. Nothing may use that buffer,
// or a BufferedWriter made on it, afterwards.
func (w *Writer) Release() {
	w.access.Lock()
	w.buffer.release()
	w.access.Unlock()
}

func (w *Writer) WriteChunk(buffer *buf.Buffer, chunk []byte) {
	bb := w.cipher.Seal(buffer.Index(buffer.Len()), w.nonce, chunk, nil)
	buffer.Extend(len(bb))
	increaseNonce(w.nonce)
}

func (w *Writer) BufferedWriter(reversed int) *BufferedWriter {
	buffer := w.buffer.acquire(w.fullSize())
	return &BufferedWriter{
		upstream: w,
		reversed: reversed,
		data:     buffer[PacketLengthBufferSize+Overhead : len(buffer)-Overhead],
	}
}

type BufferedWriter struct {
	upstream *Writer
	data     []byte
	reversed int
	index    int
}

func (w *BufferedWriter) Write(p []byte) (n int, err error) {
	for {
		cachedN := copy(w.data[w.reversed+w.index:], p[n:])
		w.index += cachedN
		if cachedN == len(p[n:]) {
			n += cachedN
			return
		}
		err = w.Flush()
		if err != nil {
			return
		}
		n += cachedN
	}
}

func (w *BufferedWriter) Flush() error {
	full := w.upstream.buffer.data[:w.upstream.fullSize()]
	if w.index == 0 {
		if w.reversed > 0 {
			_, err := w.upstream.upstream.Write(full[:w.reversed])
			w.reversed = 0
			return err
		}
		return nil
	}
	buffer := full[w.reversed:]
	binary.BigEndian.PutUint16(buffer[:PacketLengthBufferSize], uint16(w.index))
	w.upstream.cipher.Seal(buffer[:0], w.upstream.nonce, buffer[:PacketLengthBufferSize], nil)
	increaseNonce(w.upstream.nonce)
	offset := Overhead + PacketLengthBufferSize
	packet := w.upstream.cipher.Seal(buffer[offset:offset], w.upstream.nonce, buffer[offset:offset+w.index], nil)
	increaseNonce(w.upstream.nonce)
	_, err := w.upstream.upstream.Write(full[:w.reversed+offset+len(packet)])
	w.reversed = 0
	w.index = 0
	return err
}

// minInt: the module is built at go 1.18, before the min builtin.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func increaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
