# Changes from upstream sing-vmess v0.2.8-0.20250909125414-3aed155119a1

- `vless.readAddons`: the flow and seed lengths may not exceed what is left of the addons block. Upstream allocated whatever length the client claimed, before looking at the UUID, so a crafted request panicked the whole server for anyone who could complete the Reality handshake.
- `vless.VisionConn.filterTLS`: a ServerHello-shaped record is only read for its cipher suite when the session ID it claims fits in the record. Upstream sliced past the buffer, a panic any VLESS user could trigger.
- `vless.VisionConn.unPadding`: a 5-byte padding block header split across two reads is carried over instead of read past the end of the buffer.
- `ServerMuxConn`: a `StatusNew` frame that reuses a live session ID closes the old stream's pipe instead of orphaning its relay.
- `vless.VisionConn.padding` and the VMess client header: padding is written as zeros. Upstream reserved it with `Buffer.Extend` over pooled buffers that are never cleared, so a Vision server sent up to about 1.4 KB of whatever an earlier connection left in the buffer (possibly another user's data) to every client.
- `vless.VisionConn`: `NeedHandshakeForRead/Write`, `ReaderReplaceable/WriterReplaceable` and `UpstreamReader/UpstreamWriter`, so that once Vision has gone direct (and the records that arrived through TLS have been handed out) sing's copy unwraps to the TCP connection, keeping its counters, and splices on Linux. Before that they point at the TLS connection, which sing also follows for headroom. Padding and filtering are unchanged. Upstream left the copy reading and writing through `VisionConn` for the whole connection.
- `vless/bounds_test.go`, `vless/vision_direct_test.go`: tests for the above.
