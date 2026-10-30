# keel performance audit: evidence appendix

Raw measurements behind [REPORT.md](REPORT.md), in English. Snapshots: node benchmarks used the working tree of 2026-10-30 02:54 (`8037faf` plus the uncommitted security fixes, committed at 03:27 as `e9b7de4`…`44b5fb9`); the master sub-audit used 02:49 and 03:01 copies; the library sub-audit used a copy from about 03:00 whose `third_party/` is byte-identical to `44b5fb9`. R1 was reproduced on a build of the committed code (03:28).

Scripts and tests are kept in [bench/](bench/README.md): the node harness (`bench.sh`, `churn.sh`, `hold.sh`, `prof.sh`, `udp-hol.sh`, `_go/`), the library tests (`_go/libtests/`), and the master sub-audit's tools and logs (`bench/master/`, full sub-audit report in `bench/master/REPORT-subaudit.md`).

## R1. Per-packet UDP routing panics on SS2022 headers (committed in `1e9c67f`)

Build of the working tree at 03:28, same containers as below.

- SS2022 inbound UDP (benchcli `udp-ss` ping to the echo server): the first reply kills the process.
  ```
  panic: buffer overflow: capacity 16384,start 0, need 42
  github.com/sagernet/sing/common/buf.(*Buffer).ExtendHeader(0x1d2aefffe040, 0x2a)
  github.com/sagernet/sing-shadowsocks/shadowaead_2022.(*serverPacketWriter).WritePacket ... service.go:522
  github.com/sagernet/sing/common/udpnat.(*conn).WritePacket ... udpnat/service.go:180
  github.com/sagernet/sing/common/bufio.(*CounterPacketConn).WritePacket ... counter_packet_conn.go:61
  main.(*udpSession).back ... outbound.go:321
  created by main.(*udpSession).run in goroutine 19 ... outbound.go:245
  ```
  The client then sees `write udp ...->127.0.0.1:20002: write: connection refused` (nothing listening).
- AnyTLS UoT (sing-box client) → entry → `x1` ss2022 exit, native UDP: `udp pingpong ok=0 lost=911877`, and the entry logs a recovered panic in `shadowaead_2022.(*clientPacketConn).WritePacket` → `ExtendHeader(0x32)` called from `main.(*udpSession).run`.
- AnyTLS UoT → direct: `udp pingpong ok=25849 lost=0 rate=8616/s`.

## Node (keel-node): environment

- Host: Apple M4 (10 cores), Docker Desktop 28.3.2, Linux VM 6.10.14-linuxkit arm64, 6 vCPU.
- keel-node built from the working tree snapshot taken 2026-10-30 02:54 AEDT (`8037faf` plus the uncommitted changes at that time), `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -tags anytls,vless,with_utls,ss`. The pprof variant adds `bench/_go/nodetests/zz_pprof.go` (build tag `pprof`, listens only when `KEEL_PPROF` is set).
- Containers share one network namespace: `kp-srv` (cpuset 0: the keel-node under test, so `GOMAXPROCS=1`), `kp-exit` (cpuset 1: a second keel-node as SS2022 exit), `kp-cli` (cpuset 2-5: clients, the HTTP source `blast serve`, the Reality dest `test/compat/helper dest`).
- Clients: sing-box 1.14 dev (the user's AnyTLS-only build, `~/Documents/sing-box/bin/sing-box-linux-arm64`) for AnyTLS; `bench/_go/benchcli` (sing-shadowsocks client; a port of sing-box's Reality client on metacubex/utls with sing-vmess VLESS) for SS2022 and VLESS Reality.
- CPU per GB = (utime+stime of the server process over the run) / bytes moved. Throughput is bounded by the server core: CPU-s/GB × GB/s ≈ 1.0 in every saturated row.
- Everything runs on loopback, so absolute GB/s are far above any VPS NIC; the useful numbers are CPU per GB, CPU per connection, and memory per connection. A typical VPS core is roughly 2-3× slower than an M4 core.

## Throughput and CPU per GB (`bench.sh keel`, `bench.sh sb`, `bench.sh chain`)

```
keel anytls x1                       2602 MB/s  srv  0.32 cpu-s/GB  VmRSS 16.0MB
keel anytls x8                       2595 MB/s  srv  0.39 cpu-s/GB  VmRSS 18.3MB
keel ss2022 x1                       4431 MB/s  srv  0.22 cpu-s/GB  VmRSS 18.0MB
keel ss2022 x8                       4092 MB/s  srv  0.24 cpu-s/GB  VmRSS 22.2MB
keel vless-reality x1                2700 MB/s  srv  0.37 cpu-s/GB  VmRSS 24.5MB
keel vless-reality x8                2632 MB/s  srv  0.38 cpu-s/GB  VmRSS 16.8MB (HWM 24.6)
keel vision http x1                  2901 MB/s  srv  0.34 cpu-s/GB
keel vision https x1                 3784 MB/s  srv  0.25 cpu-s/GB
keel vision https x8                 5437 MB/s  srv  0.18 cpu-s/GB
sing-box anytls x1 (server)          2337 MB/s  srv  0.34 cpu-s/GB  VmRSS 28.4MB
sing-box anytls x8 (server)          2473 MB/s  srv  0.40 cpu-s/GB  VmRSS 31.1MB
keel anytls -> ss2022 exit x1        1891 MB/s  entry 0.53 cpu-s/GB  exit 0.24 cpu-s/GB
keel anytls -> ss2022 exit x8        1876 MB/s  entry 0.53 cpu-s/GB  exit 0.24 cpu-s/GB
```

A second keel AnyTLS run right after the sing-box run gave 2369 MB/s / 0.31 and 2551 MB/s / 0.39 (run-to-run noise about 10%).

## CPU profiles during bulk downloads (`prof.sh`, 4 s each, one client at a time)

- AnyTLS x8: 55% syscalls (read/write), 32% `gcmAesEnc` (TLS records), 11% memmove; no keel function above 0.5%.
- SS2022 x1: 51% `gcmAesEnc`, 48% syscalls.
- VLESS Reality x1: 54% syscalls, 37% `gcmAesEnc` (utls records), 5% memmove.
- Vision HTTPS x1: 94% syscalls via `syscallReadWaiter.WaitReadBuffer` → `VisionConn.Write` → `net.(*conn).Write`; no AES (direct mode works) but no splice either.
- Chain entry: 31% syscalls, 28% `gcmAesEnc`, 24% `gcmAesDec`, 12% memmove.

## New connections (`churn.sh`, 32 concurrent clients, 8 s, small HTTP GET per connection)

```
anytls(stream) c32   ok=83945  rate=10493/s avg=3.0ms   srv cpu-ms/conn=0.088
ss2022 c32           ok=103291 rate=12911/s avg=2.5ms   srv cpu-ms/conn=0.076   VmHWM 55 MB
vless-reality c32    ok=21696  rate=2712/s  avg=11.8ms  srv cpu-ms/conn=0.357
chain (anytls->exit) ok=21981  rate=2748/s  avg=11.6ms  entry cpu-ms/conn=0.334  exit cpu-ms/conn=0.290
```

SS2022 churn heap profile (`alloc_space`, since start): `shadowaead.NewReader` 4182 MB, `shadowaead.NewWriter` 4076 MB, together 95% of all allocation; `NumGC` 1359 in about 12 s. Exit CPU profile under chain churn: syscalls 38%, `runtime.mallocgc` 17% cumulative, `gcBgMarkWorker` 9%, `blake3.DeriveKey` 9%, `directOutbound.dialTCP` 19%.

## Memory per open connection (`hold.sh 1000`: 1000 proxied keep-alive connections, one small request each, then idle)

```
                      entry RSS   heapInuse  goroutines | exit RSS
idle                    11-13 MB     0.9 MB        12   |  9-12 MB
anytls (1000 streams)    97.5 MB    48.6 MB      4012   |
ss2022                  271.8 MB   179.0 MB      3012   |
vless-reality            82.5 MB    45.5 MB      3012   |
anytls -> ss2022 exit   311.0 MB   223.3 MB      4012   | 261.1 MB
```

Heap with 1000 open SS2022 connections (`inuse_space` after GC): `shadowaead.NewWriter` 77.7 MB, `shadowaead.NewReader` 71.8 MB, `buf.newDefaultAllocator` 33.5 MB (copy buffer held while the SS reader blocks). Goroutine stacks: 1000 × `shadowaead.(*Reader).Read` under `copyExtendedWithPool`, 1000 × `syscallReadWaiter.WaitReadBuffer`, 1000 × handler.

The AnyTLS client (sing-box) opened one session per concurrent stream; after the streams closed it kept those 1000 sessions idle (server: 1012 goroutines, ~48 KB heap per idle session) until its idle timeout. That is client pool behaviour, not a server leak.

After the clients close (3 s later, forced GC): SS2022 RSS 258.9 MB with heap 34.2 MB; chain entry 296 MB, exit 261 MB.

`GOMEMLIMIT` (same SS2022 test):

```
GOMEMLIMIT=off    open=248 MB  after close: t+5s=249MB t+30s=249MB t+60s=249MB
GOMEMLIMIT=64MiB  open=196 MB  after close: t+5s=39MB  t+30s=39MB  t+60s=39MB
```

## SS2022 UDP head-of-line blocking (`udp-hol.sh`)

Node DNS pointed at a resolver that never answers (`blast blackhole 127.0.0.53:53`). Victim session: SS2022 UDP ping-pong to an IP (no DNS involved). From t=4 s another session sends 2000 pps for 6 s to `slow-dns.test:9`.

```
t= 0s ok= 7646 lost=0 worst_rtt=3.915ms
t= 1s ok= 6013 lost=0 worst_rtt=3.606ms
t= 2s ok= 4714 lost=0 worst_rtt=10.146ms
t= 3s ok= 3860 lost=0 worst_rtt=8.805ms
t= 4s ok=  801 lost=1 worst_rtt=918µs
t= 5s ok=    0 lost=1
t= 6s ok=    0 lost=1
t= 7s ok=    0 lost=1
t= 8s ok=    1 lost=0 worst_rtt=888.273ms
flood sent 3092
t= 9s .. t=15s: ok=0 every second
```

With Docker's own DNS (fast NXDOMAIN) the same test shows no stall (worst RTT 0.6-5.7 ms throughout), which isolates the cause to the synchronous lookup in `udpOutbound.WritePacket` plus the blocking `c.data <- packet` in sing's udpnat behind the single `loopUDP` reader.

## /proc/net/tcp counting (`procnet <pairs>`, 1 vCPU, 15 rounds, median)

```
pairs=1000   /proc/net/tcp{,6} read   count=2001   3.5 ms   cpu 4.6 ms   alloc 1.8 MB
             /proc/net/sockstat                    0.014 ms cpu 0.021 ms alloc 0
pairs=5000   /proc/net/tcp{,6} read   count=10001  17.0 ms  cpu 19.5 ms  alloc 9.9 MB
             /proc/net/sockstat                    0.013 ms cpu 0.019 ms alloc 0
pairs=20000  /proc/net/tcp{,6} read   count=40001  71-88 ms cpu 80-99 ms alloc 39.3 MB
             /proc/net/tcp{,6} stream count=40001  54 ms    cpu 57 ms    alloc 0
             /proc/net/sockstat                    0.013-0.032 ms        alloc 0
```

## Microbenchmarks (`bench/_go/nodetests`, macOS arm64; numbers move with host load while other benchmarks ran, so ranges are given)

```
BenchmarkIsPublicSerial-10           70-253 ns/op   0 allocs
BenchmarkIsPublicParallel-10         125-249 ns/op  (no scaling; throughput below single-thread)
BenchmarkPickMissDomain-10           533-1542 ns/op (6 rule lists, no match)
BenchmarkPickMissDomainParallel-10   348-424 ns/op
BenchmarkPickMissIP-10               135-417 ns/op
BenchmarkUsageSave/100               10.6 ms/op   37 KB/op
BenchmarkUsageSave/1000              11.4 ms/op   459 KB/op
BenchmarkUsageSave/5000              15.6 ms/op   2.6 MB/op   (fsync of file and directory dominates)
BenchmarkUsageSnapshot/1000          0.38 ms/op
BenchmarkUsageSnapshot/5000          2.3 ms/op
BenchmarkQuotaCheck/1000             23 µs/op
BenchmarkQuotaCheck/5000             121 µs/op
BenchmarkConfigPush/100              0.50 ms/op   277 KB/op
BenchmarkConfigPush/1000             5.2 ms/op    3.4 MB/op
BenchmarkConfigPush/5000             24 ms/op     17 MB/op
```

`TestPerfSizes` (JSON as keel-node and the master produce it):

```
users=   10 report=   1253 B (0.6 GB/month at 5 s)    config=    3024 B (0.1 GB/month at 60 s)   usage.json=    631 B
users=  100 report=   9803 B (5.1 GB/month at 5 s)    config=   29574 B (1.3 GB/month at 60 s)   usage.json=   6211 B (0.3 GB/day at 2 s)
users= 1000 report=  95303 B (49.4 GB/month at 5 s)   config=  295074 B (12.7 GB/month at 60 s)  usage.json=  62011 B (2.7 GB/day at 2 s)
users= 5000 report= 479124 B (248.4 GB/month at 5 s)  config= 1475074 B (63.7 GB/month at 60 s)  usage.json= 313832 B (13.6 GB/day at 2 s)
```

`TestPerUserMemory` (registry plus the AnyTLS, VLESS and SS2022 user tables, heap after GC):

```
users=1000 heap=1.1 MB (1123 B/user)
users=5000 heap=5.3 MB (1061 B/user)
```

## SS2022 idle memory after a large download (real keel-node, `benchcli hold-ss ... 300 <path>`)

```
path=/small      conns=300 RSS=89.5MB  heapInuse=54.3MB
path=/n/1048576  conns=300 RSS=234.7MB heapInuse=204.9MB
  inuse: buf.newDefaultAllocator.func11 (64 KiB class) 153.2 MB, shadowaead.NewReader 26.3 MB, shadowaead.NewWriter 25.2 MB
```

## Protocol libraries (library-level tests in `bench/_go/libtests`, Apple M4, loaded machine, medians of 3 where noted)

Written and run by the library sub-audit against a copy of the tree taken around 03:00 (its `third_party/` is byte-identical to the current one), with a `go.work` so the libraries build against keel's sing v0.8.12. Raw outputs: `bench/_go/libtests/results/`.

- `TestIdleHeapPerConn` (SS2022, 64-128 idle connections, both ends in one process): 1 MiB downloaded → 854 KiB per connection; with `WriteVectorised` hidden → 337-339 KiB; 100 KB downloaded → 339 vs 336 KiB. Re-run for this report from the documented steps: 854 / 339 KiB.
- `BenchmarkTCPHandshakeServer` (SS2022, per connection): handshake only 8.2 µs, 76.2 KB, 23 allocs; with the first response write 14.8 µs, 151.5 KB, 34 allocs. Flat at 8.2 / 8.2 / 6.8 µs for 1 / 1000 / 100000 users (identity lookup is O(1)).
- `TestUDPStalledSessionBlocksLoop`: with one session not draining, the receive loop handled 64 of 101 packets in 1 s and the other user's packet never got through. Re-run for this report: same result.
- `TestVisionFastPathReachability`: `NewVisionConn` finds `*utls.Conn` through keel's `realityConn` (netConn is `*net.TCPConn`), so direct mode works; in both phases sing's copy sees `*vless.VisionConn` (no syscall read, no read waiter, no syscall write, no vectorised writer). A test-only wrapper with `NeedHandshakeForRead/Write`, `ReaderReplaceable/WriterReplaceable`, `UpstreamReader/UpstreamWriter` lets the copy unwrap to `*net.TCPConn` on both sides after direct mode. `VisionConn.Write` in direct mode: 23 ns, 0 allocs.
- `TestIdleHeapPerStream` (AnyTLS, 128 idle streams, plaintext, both ends): 54 KiB per stream plus session.
- `BenchmarkStreamWrite` (AnyTLS, discard conn): 32 KiB 387 ns, 64 KB 755 ns, 64 B / 1 alloc each; in-place header prototype about 30 ns. Over crypto/tls on loopback (`BenchmarkStreamWriteOverTLS`): 11.68 vs 10.92 µs per 32 KiB.
- `BenchmarkRecvLoopToStream` (AnyTLS): 540 ns per 1 KiB frame, 928 ns per 16 KiB; pipe handoff alone 459 / 617 ns, buffered channel with ownership transfer 108 ns. `TestHeadOfLineBlocking`: while stream 1 is not read, stream 2 receives nothing.
- `BenchmarkMuxServerRecv` (sing-vmess mux, fake conn): XUDP 1200 B 2.29 µs, 236 B, 21 allocs, 10 conn reads (6.6 µs under load); TCP 1200 B 0.60 µs; TCP 16 KiB 1.04 µs.
- `BenchmarkUDPServerInbound/Outbound` (SS2022): inbound 851 ns, ~200 B, 10 allocs per packet; outbound 380 ns, 216 B, 9 allocs. `binary.Read` 19.9 ns + 1 alloc vs `BigEndian.Uint64` 2.6 ns.
- `BenchmarkUDPClientWritePacket` (SS2022 client): with EIH 450-493 ns, 672 B, 8 allocs per packet; without 349-351 ns, 160 B, 7 allocs.
- `BenchmarkAEADReaderRead`: 16 KiB chunks (in place) 2158 ns; 32 KiB 4661 ns, fused-decrypt prototype 4288 ns; 64 KiB chunks into 32 KiB buffers 15265 ns.
- `BenchmarkXUDPClientReadPacket`: 233 ns, 12 B, 5 allocs, 3 reads per packet.
- `BenchmarkAEADSeal` (16 KiB): AES-128-GCM 6.6 GB/s, AES-256-GCM 5.1 GB/s, ChaCha20-Poly1305 0.71 GB/s.
- `BenchmarkReplayFilterCheck`: 371-387 ns, 1 alloc per connection.
- `BenchmarkRecordWrite` (utls vs crypto/tls, 32 KiB): 21.3-24.0 µs vs 21.3-28.6 µs, 0-1 allocs.
- keel's own modifications vs upstream sing-anytls v0.0.11 (interleaved, median of 6): `StreamWrite` 32 KiB 699 ns (upstream) vs 555 ns (keel), `RecvLoop` 1 KiB 1114 vs 766 ns: noise, no regression.
- `TestPaddingWrites`: server sessions never pad (`sendPadding` stays false); clients pad the auth packet and their first 7 writes per session.

## Master (keel-master) — from the master sub-audit

Release builds of the 02:49 and 03:01 working trees (hot paths identical to `44b5fb9`), Apple M4, loopback, TLS 1.2, 20-50% run-to-run noise from other jobs. Datasets from `bench/master/seed.py DB ENTRIES EXIT_NODES USERS PERIODS` (every user on every entry, 90% with a quota, 12 periods of history):

| Dataset | Nodes | Users | Usage rows (table / loaded) |
|---|---|---|---|
| small | 10 + 10 | 200 | 25.2K / 6.9K |
| medium | 10 + 10 | 1000 | 121K / 32.8K |
| large | 25 + 25 | 2000 | 607K / 164K |

- `World::used` (M1): profiles show `used` plus `memcmp` at about 95% of `/api/state` CPU and 97% of `sync` CPU. `/api/state` 7-23 ms (small), 120 ms (medium), 1.75-2.0 s and 740 KB (large). One large entry config about 1.5 s. `PATCH /api/users/2` 0.18 s with no node online, 3.1-3.4 s with 2 entries online (`patch_lat.sh`).
- `sync` (M2), `sim.py` connect storms: small first config median 0.13 s; medium median 3.9 s, max 11.7 s, `/api/session` stalled up to 8.3 s, `/app.js` up to 4.4 s; large 5 of 50 nodes got a config in 195 s, 49 dropped on WebSocket ping timeouts, no HTTP answer during the run, 100% CPU for more than 3.5 min after the clients left, SIGTERM ignored for over 20 s. Steady state medium: each 30 s sync stalls the server 0.7-1 s. Logs: `bench/master/results/sim-*.txt`, `lat-*.txt`.
- `store_usage` (M3), `wal_bench.py` (autocheckpoint off, frames counted): 2000 rows per report — one commit per row 2000 WAL frames (7.8 MB) in 13-38 ms; one transaction 46 frames (0.18 MB) in about 2 ms; one transaction skipping rows that did not grow 0 frames when idle. 200 rows: 200 vs 22 frames. Live server (`mon.py`, disk bytes written): small 1.54 MB/s (about 130 GB/day), medium 7.95 MB/s (about 690 GB/day), independent of traffic.
- `/api/state` under polling (M4, `panel_poll.py` emulating `setInterval(refresh, 2000)` with no in-flight guard and 6 connections per host): large, one tab 86% of a core; two tabs 27 requests in flight, p50 24 s, max 44 s; 4 concurrent clients same throughput as 1. `/api/public` rebuild after cache expiry: 1.8 s large, 130-146 ms medium.
- Subscriptions (M5, `bench_http.sh`): small 2.5-3.3 ms, medium 12-13 ms, large 66-99 ms per request with 1 client (10-15 rps); 8 clients 6.6 rps, max 3.9 s, RSS 44 → 188 MB. Raw: `bench/master/results/http-*.txt`.
- Global mutex on async workers (M6): `/app.js` max 4.4 s on medium; 12.8 s with `TOKIO_WORKER_THREADS=1`.
- Usage-only config pushes (M7): 56 KB per entry per minute (small), 267 KB (medium), 532 KB (large).
- `load_world` (M9): scans 607K usage rows to return 164K, 18 ms (large).
- Memory (M11, macOS): idle 5-6 MB; small with 2 nodes and the panel polling 23-29 MB RSS; after a login (argon2, m = 19 MiB) 45 MB transient; large 151-188 MB transient.
- Panel (M13, `performance.now()` around `render()` against a `-no-tls` master): 10 polls → 10 full re-renders; users tab 18,020 elements, about 73 ms including layout; lines tab 16 ms; probe tab 5 ms; `JSON.stringify` 0.6 ms, parse 0.9 ms; heap flat.

Commands (scratch paths replaced by `bench/master/`):

```sh
cd master && cargo build --release --locked
BIN=master/target/release/keel-master
$BIN -data /tmp/km-large -listen 127.0.0.1:18444 & sleep 2; kill %1          # creates the schema
python3 -I performance-audit/bench/master/seed.py /tmp/km-large/keel.db 25 25 2000 12   # small: 10 10 200 12, medium: 10 10 1000 12
sqlite3 /tmp/km-large/keel.db "INSERT INTO settings(key,value) VALUES('public_page','1') ON CONFLICT(key) DO UPDATE SET value='1'"
$BIN -data /tmp/km-large -listen 127.0.0.1:18444 &
performance-audit/bench/master/login.sh /tmp/km-large 18444
performance-audit/bench/master/bench_http.sh 18444 /tmp/km-large <PID> 10
performance-audit/bench/master/patch_lat.sh 18444 3
python3 -I performance-audit/bench/master/sim.py --port 18444 --db /tmp/km-large/keel.db --duration 195 --traffic 0.2   # needs the websockets package
python3 -I performance-audit/bench/master/panel_poll.py https://127.0.0.1:18444/api/state <cookie-file> 60 2
python3 -I performance-audit/bench/master/wal_bench.py /tmp/km-large/keel.db 1 20
python3 -I performance-audit/bench/master/mon.py <PID> 5 205 label   # macOS (libproc) only
```

## After the fixes

### Node: audit-time code against the final build, back to back

`bench/build-ref.sh` for `6b8fe80` (the audit commit; it still has R1, so TCP only) and `5a6fa4f`, then `bench/ab.sh` (entry and exit swapped together, same containers, node on CPU 0), and `bench.sh keel` once more for each.

```
=== orig (6b8fe80)
keel anytls x1                       2384 MB/s  srv  0.33 cpu-s/GB
keel anytls x8                       2616 MB/s  srv  0.38 cpu-s/GB
keel ss2022 x1                       4328 MB/s  srv  0.23 cpu-s/GB
keel ss2022 x8                       4221 MB/s  srv  0.23 cpu-s/GB
keel vless-reality x1                2945 MB/s  srv  0.34 cpu-s/GB
keel vless-reality x8                2952 MB/s  srv  0.34 cpu-s/GB
keel vision http x1                  3000 MB/s  srv  0.33 cpu-s/GB
keel vision https x1                 3575 MB/s  srv  0.22 cpu-s/GB
keel vision https x8                 6374 MB/s  srv  0.15 cpu-s/GB
keel->exit anytls x1                 1904 MB/s  srv  0.53 cpu-s/GB  exit  0.23 cpu-s/GB
keel->exit anytls x8                 1858 MB/s  srv  0.54 cpu-s/GB  exit  0.25 cpu-s/GB
anytls(stream) c32   rate=21170/s  srv cpu-ms/conn=0.042
ss2022 c32           rate=14214/s  srv cpu-ms/conn=0.070
vless-reality c32    rate=3686/s   srv cpu-ms/conn=0.257
anytls(1 session)   1000 conns entry RSS= 103.3MB heapInuse= 48.6MB | closed RSS=  95.9MB
ss2022              1000 conns entry RSS= 268.8MB heapInuse=178.9MB | closed RSS= 247.4MB
vless-reality       1000 conns entry RSS=  83.3MB heapInuse= 45.0MB | closed RSS=  78.0MB
anytls->ss2022 exit 1000 conns entry RSS= 313.9MB heapInuse=223.1MB exit RSS= 271.1MB | closed entry RSS= 285.4MB
=== final (5a6fa4f)
keel anytls x1                       2614 MB/s  srv  0.27 cpu-s/GB
keel anytls x8                       2902 MB/s  srv  0.34 cpu-s/GB
keel ss2022 x1                       3951 MB/s  srv  0.25 cpu-s/GB
keel ss2022 x8                       3851 MB/s  srv  0.26 cpu-s/GB
keel vless-reality x1                2947 MB/s  srv  0.34 cpu-s/GB
keel vless-reality x8                2997 MB/s  srv  0.33 cpu-s/GB
keel vision http x1                  2937 MB/s  srv  0.34 cpu-s/GB
keel vision https x1                 3435 MB/s  srv  0.21 cpu-s/GB
keel vision https x8                 6212 MB/s  srv  0.11 cpu-s/GB
keel->exit anytls x1                 2186 MB/s  srv  0.46 cpu-s/GB  exit  0.23 cpu-s/GB
keel->exit anytls x8                 2136 MB/s  srv  0.47 cpu-s/GB  exit  0.24 cpu-s/GB
anytls(stream) c32   rate=23945/s  srv cpu-ms/conn=0.038
ss2022 c32           rate=20176/s  srv cpu-ms/conn=0.049
vless-reality c32    rate=3641/s   srv cpu-ms/conn=0.257
anytls(1 session)   1000 conns entry RSS=  73.8MB heapInuse= 16.5MB | closed RSS=  48.5MB
ss2022              1000 conns entry RSS= 101.6MB heapInuse=  7.2MB | closed RSS=  61.7MB
vless-reality       1000 conns entry RSS=  85.1MB heapInuse= 45.1MB | closed RSS=  72.6MB
anytls->ss2022 exit 1000 conns entry RSS= 111.9MB heapInuse= 18.6MB exit RSS= 110.4MB | closed entry RSS=  53.9MB
=== second round, bench.sh keel only
orig:  anytls 2568/2604 MB/s 0.33/0.38; ss2022 4326/4275 MB/s 0.23/0.23; vless 2914/3024 0.34/0.33; vision https 3609/6558 0.22/0.15
final: anytls 2613/2990 MB/s 0.27/0.34; ss2022 3897/3887 MB/s 0.26/0.26; vless 2962/3021 0.34/0.33; vision https 3387/7371 0.21/0.12
```

SS 2022 single hop is the one case that got slower. CPU profiles of the same download (`prof.sh`, 4 s, both builds saturate the core):

```
orig:  gcmAesEnc 52.1%, syscalls 46.9% (readv via vectorisedSyscallReadWaiter 18.6%, write 28.5%); serverConn.WriteVectorised 81.1% cum
final: syscalls 51.4% (read via syscallReadWaiter 20.7%), gcmAesEnc 46.6%; serverConn.WriteBuffer 79.4% cum
```

With `WriteVectorised` on the connection, sing reads with `readv` into up to 8 buffers (`DefaultBatchSize`) and keeps the ones it did not fill for the next read (`copy_direct_posix.go`, `vectorisedSyscallReadWaiter`), which is where most of N1's idle memory came from. Without it each read takes at most one 64 KiB buffer. In the chain the exit runs the same SS 2022 download path unsaturated at 2.1 GB/s, and its CPU per GB is unchanged (0.23-0.25 before, 0.23-0.24 after).

Vision inbound -> keel's VLESS REALITY Vision outbound -> second node's Vision inbound (`bench/vchain.sh`), single stream, final build, six runs: entry 0.21, 0.16, 0.15, 0.15, 0.15, 0.18 CPU-s/GB; exit 0.24, 0.20, 0.21, 0.18, 0.18, 0.21. Before the Vision change: entry 0.23, exit 0.24. In the final build 83% of the entry's CPU is in `unix.Splice` under `bufio.copyDirect`.

SS 2022 UDP head-of-line test (`udp-hol.sh`, final build): the victim's ping-pong ran 13 400-15 600 round trips every second with `lost=0` for all 16 s while the other session flooded a name whose lookup never answers (before: interrupted for 11+ s).

```
t= 0s ok=15551 lost=0 worst_rtt=14.379ms
t= 4s ok=13486 lost=0 worst_rtt=1.11ms
t= 8s ok=14089 lost=0 worst_rtt=1.013ms
flood sent 3309
t=12s ok=14190 lost=0 worst_rtt=1.1ms
t=15s ok=14335 lost=0 worst_rtt=241µs
```

### Protocol libraries

- AnyTLS (`session/stream_test.go`): on the old code a 1 MiB transfer written in pieces of up to 200 KB arrives as 32 KiB (16-bit frame length cut), and a second stream never arrives behind an unread one; both pass now. Data queued before a FIN is read in full on both.
- VLESS mux (`mux_test.go`): the frame-encoding test passes on the old code too (same bytes on the wire); on the old code the second sub-stream never arrives behind an unread first one (test blocked until its timeout).
- SS 2022 UDP (`perf_test.go` benchmarks from the library sub-audit, 2000 iterations x 5): inbound 10 -> 5 allocations per packet (1 or 1000 users); outbound 9 -> 3 allocations, 218 -> 130 B, 584 -> 464 ns median.
- SS 2022 interop (unmodified peers built from the module cache): sing-shadowsocks v0.2.8 and sing-shadowsocks2 v0.2.1 clients through keel's inbound and keel's outbound to a v0.2.8 server: 8 x 3 MB random echoes intact, 100 MB downloads with the same SHA-256 every way.

### Master

- `/api/state`, large (2000 users, 50 nodes, 164k usage rows in the 70-day window), idle: rebuild 48-50 ms to first byte once warm (75-100 ms the first time), a shared copy 3 ms. The rebuild is SQLite stepping through the usage rows; JSON is about 5%.
- Two tabs polling `/api/state` for 60 s with 16 simulated nodes reporting (large): previous build (`5186ce0`) p50 0.17 s, max 0.22 s, `/api/session` p90 37 ms, p99 124 ms, master CPU 13.4%; final p50 0.11 s, max 0.12 s, `/api/session` p90 1.5 ms, p99 84 ms, CPU 8.2%. State and public JSON identical between the two builds.
- Subscriptions, large: 80.2 ms -> 1.1 ms median (60 sequential requests); 65 users x 6 formats compared with the previous build, identical except Surge's own URL, which carried each test master's port.
- Control channel, medium (20 nodes, 1000 users, 20% of users active per report), 210 s, old-style nodes vs new nodes on the same master: config re-pushes 30 (7.65 MB) vs usage messages 70 (1.97 MB); reports 41.2 MB (479 users each) vs 15.8 MB (179 users each); master CPU 3.65 s vs 2.65 s; disk written 129 vs 131 MB (0.6 MB/s; the sub-audit measured 7.95 MB/s for medium before the per-frame transaction).
- Panel, users page with 1000 users in a hidden browser pane (no layout): full redraw 9-20 ms; a poll whose markup is unchanged 0.8 ms; a poll with 100 changed users 2.5-3 ms. Polls are one at a time, every 2 s, and with 3 s answers spaced 9.3 s apart.
- `/dl` of a 20 MB file at 2 MB/s: master RSS 14.5 MB during the download, SHA-256 and length unchanged.
