# Changes from upstream sing-anytls v0.0.11

- `session`: the client version string is no longer sent in settings (`util.Verison` is empty).
- `Service.UpdateUsers`: the user table is swapped atomically, so users can be changed while connections are being accepted.
- `session.Stream`: the close error is stored atomically. Closing a stream from another goroutine (the node does this to cut off a user) raced with `Read`/`Write`.
- `session.Session`: at most `MaxStreams` (1024) open streams per session; a client past it gets an alert and the session ends.
- `Service`: a new stream must name its destination within 30 s, and a stream that fails to is closed instead of left open.
- `session.Stream`: data the receive loop reads for a stream is queued as whole pooled buffers instead of handed over through a synchronous pipe, up to 64 KiB per stream, 256 KiB per session and 32 MiB per process (`StreamBuffer`, `SessionBuffer`, `TotalBuffer`); past them the receive loop waits, which upstream did for every frame. A stream nobody reads no longer stops the session's other streams until its queue is full. The peer's FIN or the session ending leaves what was queued readable; closing the stream locally drops it.
- `session.Stream`: `WaitReadBuffer` (sing's `ReadWaiter`) hands over the queued buffer itself, so an idle stream holds no copy buffer and a copy out of it does not copy again; `WriteBuffer` with `FrontHeadroom` 7 writes the frame header in front of the data instead of copying it into a new buffer.
- `Session.writeDataFrame`: a write is sent in frames of at most 65535 bytes. Upstream cut the length to 16 bits, so a longer write corrupted the session.
- `Session.peerVersion` is atomic: the receive loop sets it while `OpenStream` reads it on another goroutine.
- `session/stream_test.go`: tests for the above.
