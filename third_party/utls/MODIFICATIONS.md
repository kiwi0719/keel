# Changes from upstream metacubex/utls v1.8.4

Test files, testdata and examples are left out.

- `RealityServer`: a fallback relay to dest passes on each direction's end (`CloseWrite`, or `Close`), as upstream XTLS/REALITY does. Before, a client never saw dest close the connection, which told a prober the server was not dest, and every probe kept two sockets open until the prober gave up.
- `Conn.readRecordOrCCS`: only application data, and handshake messages before the handshake completes, reset the useless-record count; `maxUselessRecords` is 16. This is Go's fix for GO-2026-6090: a peer could otherwise stream post-handshake KeyUpdate messages forever.
- `Conn.handleKeyUpdate`: a key update with handshake data still buffered is refused, as in Go's fixes for GO-2026-4870 and GO-2026-4340.
