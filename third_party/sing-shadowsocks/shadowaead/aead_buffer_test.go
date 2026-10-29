package shadowaead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func testAEAD(t testing.TB) cipher.AEAD {
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

// refChunks is the stream the writer produced before its buffers were
// pooled: each chunk is a sealed length followed by the sealed payload.
func refChunks(aead cipher.AEAD, nonce []byte, p []byte, maxPacketSize int) []byte {
	var out []byte
	for len(p) > 0 {
		data := p[:minInt(len(p), maxPacketSize)]
		p = p[len(data):]
		var length [PacketLengthBufferSize]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(data)))
		out = aead.Seal(out, nonce, length[:], nil)
		increaseNonce(nonce)
		out = aead.Seal(out, nonce, data, nil)
		increaseNonce(nonce)
	}
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(int64(n))).Read(b)
	return b
}

var testSizes = []int{1, 15, 16, 1000, 16383, 16384, 32768, 65535, 65536, 200000}

func TestWriterOutputUnchanged(t *testing.T) {
	for _, max := range []int{MaxPacketSize, 65535} {
		for _, size := range testSizes {
			aead := testAEAD(t)
			var got bytes.Buffer
			w := NewWriter(&got, aead, max)
			p := randomBytes(size)
			if n, err := w.Write(p); err != nil || n != size {
				t.Fatalf("write %d: %d %v", size, n, err)
			}
			want := refChunks(aead, make([]byte, aead.NonceSize()), p, max)
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("max %d size %d: output differs from the unpooled writer", max, size)
			}
			if w.buffer.data != nil {
				t.Fatalf("writer kept its buffer after Write")
			}
		}
	}
}

func readAll(t *testing.T, r *Reader, step int) []byte {
	var out []byte
	b := make([]byte, step)
	for {
		n, err := r.Read(b)
		out = append(out, b[:n]...)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}

func TestReaderRoundTrip(t *testing.T) {
	for _, size := range testSizes {
		for _, step := range []int{1, 7, 100, 16384, 70000} {
			aead := testAEAD(t)
			var stream bytes.Buffer
			p := randomBytes(size)
			if _, err := NewWriter(&stream, aead, 65535).Write(p); err != nil {
				t.Fatal(err)
			}
			r := NewReader(iotest.HalfReader(bytes.NewReader(stream.Bytes())), aead, 65535)
			if got := readAll(t, r, step); !bytes.Equal(got, p) {
				t.Fatalf("size %d step %d: round trip differs", size, step)
			}
			if r.buffer.data != nil || r.cached != 0 {
				t.Fatalf("size %d step %d: reader kept a buffer after draining it", size, step)
			}
		}
	}
}

func TestReaderOneByteAtATime(t *testing.T) {
	aead := testAEAD(t)
	var stream bytes.Buffer
	p := randomBytes(40000)
	if _, err := NewWriter(&stream, aead, 16383).Write(p); err != nil {
		t.Fatal(err)
	}
	r := NewReader(iotest.OneByteReader(bytes.NewReader(stream.Bytes())), aead, 16383)
	var got []byte
	for i := 0; ; i++ {
		switch i % 3 {
		case 0:
			c, err := r.ReadByte()
			if err == io.EOF {
				goto done
			}
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, c)
		case 1:
			if r.Cached() >= 3 {
				got = append(got, r.CachedSlice()[:3]...)
				if err := r.Discard(3); err != nil {
					t.Fatal(err)
				}
			}
		default:
			b := make([]byte, 5000)
			n, err := r.Read(b)
			got = append(got, b[:n]...)
			if err == io.EOF {
				goto done
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
done:
	if !bytes.Equal(got, p) {
		t.Fatalf("mixed ReadByte/Discard/Read differs from the input")
	}
}

func TestReaderRejectsTampering(t *testing.T) {
	aead := testAEAD(t)
	var stream bytes.Buffer
	first, second := randomBytes(1000), randomBytes(2000)
	w := NewWriter(&stream, aead, 65535)
	w.Write(first)
	w.Write(second)
	for _, at := range []int{1000 + 34 + 1, stream.Len() - 1} { // second length chunk, last tag byte
		data := append([]byte(nil), stream.Bytes()...)
		data[at] ^= 1
		r := NewReader(bytes.NewReader(data), aead, 65535)
		b := make([]byte, 100)
		var got []byte
		var err error
		for err == nil {
			var n int
			n, err = r.Read(b)
			got = append(got, b[:n]...)
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("tampered byte %d went unnoticed", at)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("tampered byte %d: got %d bytes, want only the intact first chunk", at, len(got))
		}
	}
}

func TestReaderRejectsOversizedChunk(t *testing.T) {
	aead := testAEAD(t)
	var stream bytes.Buffer
	NewWriter(&stream, aead, 65535).Write(randomBytes(20000))
	r := NewReader(bytes.NewReader(stream.Bytes()), aead, MaxPacketSize)
	if _, err := r.Read(make([]byte, 100)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("a 20000-byte chunk for a %d-byte reader: %v", MaxPacketSize, err)
	}
}

// The handshake path: a plaintext prefix in Buffer, then a BufferedWriter
// that flushes on its own when full, then Release.
func TestBufferedWriterHandshake(t *testing.T) {
	aead := testAEAD(t)
	var stream bytes.Buffer
	w := NewWriter(&stream, aead, MaxPacketSize)
	header := w.Buffer()
	header.Write([]byte("SALT"))
	bw := w.BufferedWriter(header.Len())
	p := randomBytes(3*MaxPacketSize + 123)
	if _, err := bw.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	w.Release()
	if w.buffer.data != nil {
		t.Fatal("Release kept the buffer")
	}
	more := randomBytes(5000)
	w.Write(more)
	out := stream.Bytes()
	if !bytes.HasPrefix(out, []byte("SALT")) {
		t.Fatal("lost the plaintext prefix")
	}
	r := NewReader(bytes.NewReader(out[4:]), aead, MaxPacketSize)
	if got := readAll(t, r, 4096); !bytes.Equal(got, append(p, more...)) {
		t.Fatal("handshake stream does not decode to its input")
	}
}

// Chunks from concurrent writers must reach the stream whole and in nonce
// order.
func TestWriterConcurrentWritesStayInOrder(t *testing.T) {
	aead := testAEAD(t)
	pr, pw := io.Pipe()
	w := NewWriter(pw, aead, 65535)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				w.Write(bytes.Repeat([]byte{byte(g)}, 3000))
			}
		}(g)
	}
	go func() { wg.Wait(); pw.Close() }()
	got := readAll(t, NewReader(pr, aead, 65535), 3000)
	if len(got) != 4*50*3000 {
		t.Fatalf("got %d bytes", len(got))
	}
}

func TestRawBuffersStayWithTheCaller(t *testing.T) {
	aead := testAEAD(t)
	var stream bytes.Buffer
	raw := make([]byte, MaxPacketSize+PacketLengthBufferSize+Overhead*2)
	w := NewRawWriter(&stream, aead, MaxPacketSize, raw, make([]byte, aead.NonceSize()))
	p := randomBytes(40000)
	w.Write(p)
	if len(w.buffer.data) != len(raw) || &w.buffer.data[0] != &raw[0] {
		t.Fatal("raw writer dropped the caller's buffer")
	}
	rawRead := make([]byte, MaxPacketSize+Overhead)
	r := NewRawReader(bytes.NewReader(stream.Bytes()), aead, rawRead, make([]byte, aead.NonceSize()))
	if got := readAll(t, r, 100); !bytes.Equal(got, p) {
		t.Fatal("raw round trip differs")
	}
	if len(r.buffer.data) != len(rawRead) {
		t.Fatal("raw reader dropped the caller's buffer")
	}
}

// WriteBuffer, sealing in the caller's buffer, writes what Write writes.
func TestWriteBufferOutputUnchanged(t *testing.T) {
	for _, size := range testSizes {
		aead := testAEAD(t)
		var got bytes.Buffer
		w := NewWriter(&got, aead, 65535)
		p := randomBytes(size)
		// Room as a copy into the writer leaves it; too little falls back to Write.
		for _, room := range [][2]int{{w.FrontHeadroom(), w.RearHeadroom()}, {0, 0}} {
			buffer := buf.NewSize(room[0] + size + room[1])
			buffer.Resize(room[0], 0)
			buffer.Write(p)
			if err := w.WriteBuffer(buffer); err != nil {
				t.Fatal(err)
			}
		}
		nonce := make([]byte, aead.NonceSize())
		want := append(refChunks(aead, nonce, p, 65535), refChunks(aead, nonce, p, 65535)...)
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("size %d: WriteBuffer output differs from Write", size)
		}
	}
}

// ReadBuffer hands out each opened chunk, with the room asked for, what is
// cached first; a tampered chunk is an error and nothing of it comes out.
func TestReadBuffer(t *testing.T) {
	aead := testAEAD(t)
	var stream bytes.Buffer
	chunks := [][]byte{randomBytes(1000), randomBytes(65535), randomBytes(3)}
	w := NewWriter(&stream, aead, 65535)
	for _, c := range chunks {
		w.Write(c)
	}
	r := NewReader(iotest.HalfReader(bytes.NewReader(stream.Bytes())), aead, 65535)
	head := make([]byte, 10)
	if _, err := io.ReadFull(r, head); err != nil {
		t.Fatal(err)
	}
	options := N.ReadWaitOptions{FrontHeadroom: 7, RearHeadroom: 16}
	got := append([]byte(nil), head...)
	for {
		buffer, err := r.ReadBuffer(options)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if buffer.Start() < 7 || buffer.FreeLen() < 16 {
			t.Fatalf("room %d/%d, want 7/16", buffer.Start(), buffer.FreeLen())
		}
		got = append(got, buffer.Bytes()...)
		buffer.Release()
		if r.buffer.data != nil {
			t.Fatal("reader kept a buffer between chunks")
		}
	}
	if !bytes.Equal(got, bytes.Join(chunks, nil)) {
		t.Fatalf("got %d bytes, want %d intact", len(got), stream.Len())
	}

	data := append([]byte(nil), stream.Bytes()...)
	data[len(data)-1] ^= 1
	r = NewReader(bytes.NewReader(data), aead, 65535)
	var out []byte
	var err error
	for err == nil {
		var buffer *buf.Buffer
		if buffer, err = r.ReadBuffer(options); err == nil {
			out = append(out, buffer.Bytes()...)
			buffer.Release()
		}
	}
	if errors.Is(err, io.EOF) || len(out) != 1000+65535 {
		t.Fatalf("tampered last chunk: %v after %d bytes", err, len(out))
	}
}
