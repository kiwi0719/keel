# keel 性能审计报告

- 审计对象：keel-node、keel-master、面板、third_party。基准是 `main` 上的 `c201f07` 加当时未提交的安全修复；这些修复在审计期间（2026-10-30 03:27）提交成 `4ce2f5c`…`df07256`。测量用的是 02:49–03:01 的工作区快照，之后的改动逐个比对过，行号按提交后的代码核对。
- 日期：2026-10-30
- 原始数据见 [EVIDENCE.md](EVIDENCE.md)，复现脚本和测试在 [bench/](bench/README.md)。编号和安全审计报告无关：R 是回归，N 是节点和协议库，M 是主控和面板。
- 修复已按确认的计划全部完成：结果见「修复结果」，逐项状态和提交见文末「修复计划」。

## 结论

**节点的数据面没有问题。** keel-node 单核能跑 AnyTLS 约 2.6 GB/s、SS2022 约 4.4 GB/s、VLESS Reality 约 2.7 GB/s。同样的 AnyTLS，每 GB 用的 CPU 和 sing-box 1.14 做服务端时一样，内存少约 45%。CPU 剖析里 95% 以上是系统调用和 AES-GCM，keel 自己的代码几乎看不到。按 VPS 的一个核比测试机慢 3 倍算，跑满 1 Gbps 也只用 5%–20% 的一个核。

问题集中在五处：

1. **主控撑不住规模。**
   - 算每个用户的用量要扫全部用量行，复杂度是 O(用户²)（M1）：2000 用户、50 节点时一次面板刷新要 2 秒，改一个用户 3 秒。
   - 配置同步在锁里重建所有节点的配置（M2）：节点一起重连时，1000 用户的规模下第一份配置要等 4–12 秒；2000 用户、50 节点时 50 个节点里只有 5 个拿到配置，HTTP 完全不响应。
   - 上报逐行提交、每 5 秒重写全部计数（M3）：200 用户、20 节点时 WAL 每天就写约 130 GB，而且和有没有流量无关。
2. **节点内存随连接数涨得太快，主要是 SS2022。**
   - 每条 SS2022 连接占 150–740 KB，空闲也不释放（N1）。出口上每条用户连接都是一条 SS2022 连接：1000 条连接时入口 311 MB、出口 261 MB；连接下载过 1 MB 后每条约 740 KB。
   - 其他协议的空闲连接也各拿着一块 32–64 KB 的拷贝缓冲（N6）；没设内存上限，突发后要约 2 分钟才部分还给系统（N8）。
   - 512 MB–1 GB 的 VPS 会被 OOM 杀掉。
3. **UDP 会整体卡死。** SS2022 入站只有一个收包协程，一个会话卡住（比如目标域名解析不出来），同一端口所有用户的 UDP 都停，复现时中断 11 秒以上（N2）。出口默认走原生 SS2022 UDP，所以影响所有入口、所有用户。
4. **审计期间提交的逐包 UDP 转发会让节点崩溃（R1）。** 出口收到第一个 UDP 回包，整个进程就退出。另一个会话正在修。
5. **随规模线性增长的周期性工作。**
   - 控制通道每 5 秒全量上报全部用户，每分钟整份重推配置；1000 用户时每个节点每月约 62 GB（N3、M7）。
   - 节点每 5 秒整读 `/proc/net/tcp` 数连接数，4 万个 socket 时每次耗 99 ms CPU、产生 39 MB 垃圾（N4）。
   - 面板每次轮询都整页重绘，用户页 2000 用户时每次约 73 ms（M13）。

| 严重程度 | 编号 |
| --- | --- |
| 严重（回归） | R1 |
| 高 | N1、N2、M1、M2、M3 |
| 中 | N3、N4、N5、N6、M4、M5、M6、M7 |
| 低 | N7、N8、N9、N10、N11（7 小项）、M8–M13 |
| 提示 | N12、M14 |

## 修复结果

节点的数字是审计时的代码（`42014bf`）和最终版（`e06be4d`）在同一组容器里背靠背跑的，被测节点独占 1 核；主控的数字来自各次修复前后的对比。原始数据见 [EVIDENCE.md](EVIDENCE.md) 末尾「After the fixes」。

### 节点

| 场景 | 审计时 | 修复后 |
| --- | --- | --- |
| 1000 条打开的 SS2022 连接（入口 RSS / 堆） | 269 MB / 179 MB | **102 MB / 7 MB** |
| 1000 条连接经入口 → ss2022 出口（入口 RSS / 出口 RSS） | 314 MB / 271 MB | **112 MB / 110 MB** |
| 1000 个 AnyTLS 流，一个会话（RSS / 堆） | 103 MB / 49 MB | **74 MB / 17 MB** |
| 1000 条 VLESS Reality 连接 | 83 MB | 85 MB（没动这条路径） |
| 关掉 1000 条 SS2022 连接后 | 247 MB | 62 MB |
| 新建连接：AnyTLS 流 / SS2022 / VLESS Reality（每秒） | 21 200 / 14 200 / 3 690 | 23 900 / 20 200 / 3 640 |
| 每条新连接的 CPU：AnyTLS / SS2022 / VLESS Reality | 0.042 / 0.070 / 0.257 ms | 0.038 / 0.049 / 0.257 ms |
| SS2022 UDP：另一会话的目标名字解析卡住时，受害会话 | 中断 11 秒以上 | 16 秒里一个包都没丢 |

| 吞吐 / 每 GB 的 CPU 秒（两轮） | 审计时 | 修复后 |
| --- | --- | --- |
| AnyTLS 单流 | 2.38–2.57 GB/s，0.33 | 2.61 GB/s，0.27 |
| AnyTLS 8 流 | 2.60–2.62 GB/s，0.38 | 2.90–2.99 GB/s，0.34 |
| VLESS Reality | 2.91–3.02 GB/s，0.33–0.34 | 2.95–3.02 GB/s，0.33–0.34 |
| Vision，内层 HTTPS，8 流 | 6.37–6.56 GB/s，0.15 | 6.21–7.37 GB/s，0.11–0.12（走 splice） |
| 入口（AnyTLS 入、ss2022 出）→ 出口 | 1.86–1.90 GB/s；入口 0.53–0.54，出口 0.23–0.25 | 2.14–2.19 GB/s；入口 0.46–0.47，出口 0.23–0.24 |
| Vision 入 → VLESS Reality Vision 出 → 第二个节点，单流 | 入口 0.23，出口 0.24 | 六次：入口 0.15–0.21（中位数 0.15），出口 0.18–0.24（中位数 0.20）；入口两头都 splice |
| **SS2022 单跳，单核打满** | **4.33 GB/s，0.23** | **3.90–3.95 GB/s，0.25–0.26** |

最后一行是这次唯一变差的地方，是有意的取舍：审计时 SS2022 连接带 `WriteVectorised`，sing 的拷贝于是用 `readv` 一次最多读 8 × 64 KB，但没用上的缓冲留在连接上不还，这正是 N1 里每条连接几百 KB 的来源。去掉以后一次 `read` 最多 64 KB，节点在回环上满速（约 4 GB/s）时系统调用多了，每 GB 的 CPU 多约 10%。没打满时看不出：同一条 SS2022 下载路径在入口 → 出口链路里只跑 2.1 GB/s，出口每 GB 的 CPU 前后都是 0.23–0.25。真实网卡上没测。

其他：DNS 有了缓存（N5）；UDP 打开出口不再卡收包协程，热路径去掉了全局锁（N2、N10）；连接数改读 `/proc/net/sockstat`（N4）；用量没变不再写盘，`status.json` 不再 fsync（N7）；默认内存上限是机器或 cgroup 内存的一半（N8）。AnyTLS 和 mux.cool 的子流改成有上限的队列，一个子流没人读不再马上卡住同一会话的其他子流（N11）。

### 主控

| 场景 | 修复前 | 修复后 |
| --- | --- | --- |
| `/api/state`（large） | 1.75–2.0 s | 重建约 48 ms，1 秒内的轮询共用一份（3 ms） |
| 两个标签页一起轮询（large，16 个节点在上报） | 排队，中位数 24 s | 中位数 0.11 s；`/api/session` p90 1.5 ms |
| 订阅一次（large） | 66–99 ms | 1.1 ms，输出逐字节不变 |
| 节点一起重连拿到第一份配置（medium） | 中位数 3.9 s，最长 11.7 s | 中位数 0.08 s，最长 0.09 s |
| 节点一起重连（large） | 50 个里只有 5 个拿到 | 同一地址放进来的 31 个（每地址上限 32）0.46 s 内全拿到 |
| 上报写盘（medium） | 7.95 MB/s，和有没有流量无关 | 每帧 20% 用户有流量时 0.62 MB/s；没流量时不写 |
| 控制通道 210 秒（medium，20 节点 1000 用户） | 整份重推 7.65 MB，上报 41.2 MB | 用量消息 1.97 MB（每 30 秒更新，原来 60 秒），上报 15.8 MB |
| 面板用户页一次轮询（1000 用户，不含布局） | 每次整页重绘 9–20 ms | 没变化 0.8 ms，100 个用户变了 2.5–3 ms |

面板状态、会话检查、订阅和令牌查询改走一个只读的第二连接，会话检查、上报和节点注册放到了阻塞线程池；`/dl` 从磁盘流式发送，20 MB 的下载期间主控 RSS 14.5 MB。

## 实测结果

### 节点数据面

环境：Apple M4 上 Docker 的 Linux arm64 虚拟机，被测的 keel-node 独占 1 个 CPU（`GOMAXPROCS=1`），客户端和目标服务器在另外 4 个 CPU 上，全部走回环。回环上的 GB/s 远高于任何 VPS 网卡，有参考价值的是「每 GB 的 CPU」「每条连接的 CPU」「每条连接的内存」。一般 VPS 的一个核比 M4 慢 2–3 倍。

| 场景 | 单流 | 8 流 | 每 GB 的 CPU 秒 | 内存（RSS） |
| --- | --- | --- | --- | --- |
| AnyTLS | 2.6 GB/s | 2.6 GB/s | 0.31–0.39 | 16–18 MB |
| AnyTLS，sing-box 1.14 做服务端（对照） | 2.3 GB/s | 2.5 GB/s | 0.34–0.40 | 28–31 MB |
| SS2022 | 4.4 GB/s | 4.1 GB/s | 0.22–0.24 | 18–22 MB |
| VLESS Reality | 2.7 GB/s | 2.6 GB/s | 0.37–0.38 | 17–25 MB |
| Vision，内层 HTTP | 2.9 GB/s | – | 0.34 | |
| Vision，内层 HTTPS（直连模式） | 3.8 GB/s | 5.4 GB/s | 0.18–0.25 | |
| 入口（AnyTLS 入、ss2022 出）→ 出口 | 1.9 GB/s | 1.9 GB/s | 入口 0.53，出口 0.24 | 16–20 MB |

- 吞吐不是问题。按 VPS 慢 3 倍算，跑满 1 Gbps（125 MB/s）也只用 5%–20% 的一个核。
- 和 sing-box 服务端相比，同样的 AnyTLS 每 GB 的 CPU 一样，内存少约 45%。
- CPU 剖析里 95% 以上是系统调用和 AES-GCM，keel 自己的代码（计数、分流、跟踪）几乎看不到。

| 新建连接（单核，32 并发，每次一个小 HTTP 请求） | 速率 | 每条连接的 CPU |
| --- | --- | --- |
| AnyTLS（会话里开新流） | 10 500 次/秒 | 0.09 ms |
| SS2022 | 12 900 次/秒 | 0.08 ms |
| VLESS Reality（含服务端连 dest 的那次握手） | 2 700 次/秒 | 0.36 ms |
| 入口 → 出口 | 2 750 次/秒 | 入口 0.33 ms，出口 0.29 ms |

| 1000 条打开的空闲连接 | 入口 RSS | 每条 |
| --- | --- | --- |
| 空闲进程 | 11–13 MB | |
| AnyTLS（1000 个并发流） | 98 MB | ~86 KB |
| VLESS Reality | 83 MB | ~70 KB |
| SS2022 | **272 MB** | **~260 KB** |
| 入口 → 出口 | 入口 **311 MB**，出口 **261 MB** | 入口 ~300 KB，出口 ~250 KB |

内存才是节点的瓶颈，主要来自 SS2022（P1）。

### 主控

| 场景 | small（20 节点 / 200 用户） | medium（20 / 1000） | large（50 / 2000） |
| --- | --- | --- | --- |
| `/api/state` 一次 | 7–23 ms | 120 ms | 1.75–2.0 s |
| 订阅一次（1 个客户端） | 2.5–3.3 ms | 12–13 ms | 66–99 ms |
| 所有节点一起连上，拿到第一份配置 | 中位数 0.13 s | 中位数 3.9 s，最长 11.7 s | 50 个里只有 5 个拿到 |
| 每 30 秒的同步让服务卡住 | — | 0.7–1 s | — |
| 上报写 WAL | 1.54 MB/s | 7.95 MB/s | — |
| 只有用量变化的整份配置推送（每入口每分钟） | 56 KB | 267 KB | 532 KB |

主控的瓶颈是 M1–M3：一个 O(用户²) 的用量计算、一把锁里的全量配置重建、一个逐行提交的写库。

## 审计期间引入的回归

### R1. 新加的逐包 UDP 转发会让节点崩溃 【严重】

- **位置**：`cmd/keel-node/outbound.go:256`、`:314`（两处 `buf.NewPacket()`），`:289`、`:321`（写包），`:245`、`:287`（`go s.back(...)`，没有 recover）。这段 `udpSession` 是修安全审计 L29（UDP 逐包分流）时加的，2026-10-30 03:27 随 `03bb150` 提交。
- **问题**：两个方向都用 `buf.NewPacket()` 取缓冲，没给写端留头部空间。SS2022 的服务端和客户端写包时都要在缓冲前面原地加头（`ExtendHeader`），空间不够就 panic。原来的 `bufio.CopyPacketConn` 会按写端的 `FrontHeadroom` / `RearHeadroom` 预留空间，手写的循环没有。`back` 是单独起的协程，没有 `recoverConn`。
- **证据**（03:28 的工作区重新编译，同一套容器）：
  - 经 SS2022 入站发 UDP：第一个回包就 `panic: buffer overflow: capacity 16384, start 0, need 42`（`shadowaead_2022.(*serverPacketWriter).WritePacket` ← `udpSession.back`），**整个 keel-node 退出**。出口只开 SS2022，所以任何入口的任何 UDP 都会让出口反复崩溃重启。
  - 入口经 ss2022 出口转发 UDP（默认是原生 UDP）：`clientPacketConn.WritePacket` 同样 panic，被 `recoverConn` 接住，结果是经出口的 UDP 全部不通（0 个回包）。
  - AnyTLS UoT → 直连正常（8616 次往返/秒）。
- **修复**：头部空间要按写端预留（sing 的 `CalculateFrontHeadroom` / `CalculateRearHeadroom`），`back` 这类单独起的协程要有 `recoverConn`，并补一个经 SS2022 入站、经 ss2022 出口收发 UDP 的测试。安全审计会话正在修：把逐包路由包成一个 `N.PacketConn`（`udpRoutes`），客户端那一侧交还给 sing 的 `CopyPacketConn`，头部空间由 `LazyHeadroom` 统一预留（sing 默认前后各 1024 字节，够 SS2022 和 XUDP 用）。修复提交后按上面的复现再验证一遍。

## 节点和协议库

节点的数据面就是 third_party 里的几个协议库加 sing 的拷贝循环，所以放在一起讲。库里的改动都要记进各自的 MODIFICATIONS.md。

### N1. SS2022 每条连接占 150–740 KB，空闲也不释放；出口和入口的内存随连接数线性上涨 【高】

- **位置**：
  - 固定缓冲：`third_party/sing-shadowsocks/shadowaead/aead.go:38`（`NewReader`）、`:287`（`NewWriter`），`shadowaead_2022/protocol.go:40`（`MaxPacketSize = 65535`）。服务端在 `service_multi.go:185`、`service.go:271` 创建，客户端（入口的 ss2022 出站）在 `protocol.go:271`、`:344`。
  - 读缓冲扩容：`shadowaead_2022/service.go:338`、`protocol.go:427-429`（`WriteVectorised`），sing 的 `common/bufio/copy_direct.go:56-63`、`common/network/direct.go:57`。keel 在 `handler.go:52`、`outbound.go:189`（`bufio.CopyConn`）走到这里。
- **问题**：
  - 每条 SS2022 连接在服务端和客户端各有两块 64 KB 缓冲，Go 按大对象分配，实际各占 72 KB。连接活多久就占多久，不走缓冲池。
  - 一条连接下载超过 512 KB 后，sing 的拷贝循环会改成用 readv 一次读 8 块 64 KB；条件是来源是裸 socket、目标实现了 `VectorisedWriter`，而 keel 的目标里只有 SS2022 的连接实现了它。读等待器在 readv 之前就把 8 块都拿好，遇到 EAGAIN 也不放，所以连接空闲时这 512 KB 一直占着。出口上每个大下载（视频、更新包）都会走到这一步。
  - sing 的拷贝循环在 SS 读端阻塞等数据时还拿着一块 32 KB 的池缓冲（见 N6）。
- **证据**（详见 EVIDENCE.md「内存」）：
  - 1000 条空闲连接、每条只做过一个 2 KB 请求：SS2022 入站 RSS 13 → **272 MB**（堆里 `NewWriter` 77.7 MB、`NewReader` 71.8 MB、拷贝缓冲 33.5 MB）；VLESS Reality 83 MB，AnyTLS 98 MB。
  - 300 条空闲 SS2022 连接：每条下过 2 KB 时 RSS 89.5 MB；每条下过 1 MB 后 **234.7 MB**，即每条约 **740 KB**，其中 153 MB 是那 8 块 64 KB 的读缓冲。
  - 入口（AnyTLS 入、ss2022 出）→ 出口（ss2022 入），1000 条小请求连接：入口 **311 MB**，出口 **261 MB**。
  - 库级测量（协议库子审计，`TestIdleHeapPerConn`，两端在一个进程里）：下载 1 MiB 后每条 854 KiB，把 `WriteVectorised` 藏起来后 337 KiB。
  - 高频建连（单核 1.29 万次/秒）时每条连接留下约 150 KB 垃圾，GC 一秒约 100 次；出口的 CPU 剖析里分配和 GC 约占四分之一。
- **影响**：入口到出口的连接不复用，用户的每条 TCP 连接在出口上都是一条新的 SS2022 连接，入口作为客户端也付一份。几十个用户各开几十条连接、其中一部分下过大文件，512 MB–1 GB 的 VPS 就会被 OOM 杀掉。
- **修复**：
  - 先做的一步：`serverConn` 和 `clientConn` 去掉 `WriteVectorised`（连同 `protocol.go:427` 的接口断言），或者加一个返回 `nil, false` 的 `CreateVectorisedWriter`，拷贝就不会扩到 8 块 readv。库级测量每条从 854 KiB 降到 337 KiB。
  - Reader 实现 `ReadBuffer` / `N.ReadWaiter`：18 字节的长度块读进固定数组，再从池里取 `length+16` 的缓冲原地解密，用完归还；空闲连接不占内存，拷贝循环也不用拿着池缓冲。
  - Writer 实现 `WriteBuffer`，`FrontHeadroom` 18、`RearHeadroom` 16，在调用方的缓冲里原地加密，去掉内部的 64 KB 缓冲。
  - 这两步就是 sing-shadowsocks2 的 `internal/shadowio` 的做法，可以照着改。过渡方案：写块上限降到 16 KB（协议允许），读缓冲改成按需从池里取、读完释放。
  - 同时做 N8（内存上限）可以立刻压低峰值并在突发后把内存还给系统，但挡不住活连接本身的占用。

### N2. SS2022 UDP 入站：一个会话卡住，同一端口所有用户的 UDP 一起停 【高】

- **位置**：`cmd/keel-node/proto_ss.go:79-97`（一个 `loopUDP` 协程收所有包，同步调用 `service.NewPacket`），sing `common/udpnat/service.go:106`、`:142`（每会话队列 64，`c.data <- packet` 是阻塞发送），`third_party/sing-shadowsocks/shadowaead_2022/service_multi.go:389`；会话里的阻塞点：`cmd/keel-node/outbound.go:660-685`（`udpOutbound.WritePacket` 同步解析域名，超时 5 秒，失败不缓存），`outbound.go:275-276`（`udpSession.run` 里同步打开出口，UoT / SOCKS 最多等 10 秒）
- **问题**：只要有一个会话的写协程被卡住（解析域名、打开出口、UoT 的 TCP 背压），它的 64 包队列一满，`loopUDP` 就阻塞在投递上，整个端口不再收包，所有用户的 UDP 都停。失败的解析不缓存，每个包都重新等 5 秒，积压要几分钟才消化完。排队的每个包还占着一块 16 KB 的缓冲，一个落后的会话最多 1 MB。
- **证据**：
  - 节点 DNS 指向一个不回应的服务器。用户 A 经 SS2022 UDP 往一个 IP 做 ping-pong（每秒 3800–7600 次往返，最慢 RTT ≤ 10 ms）；第 4 秒起另一个会话往一个解析不了的域名发包 6 秒。A 从这一刻起全部超时，直到测试结束（11 秒里只回来 1 个包，RTT 888 ms）。换成很快就返回失败的 DNS，同样的测试没有任何停顿。见 EVIDENCE.md「UDP 队头阻塞」。
  - 库级测量（`TestUDPStalledSessionBlocksLoop`）：卡住一个会话后，1 秒内只处理了 101 个包里的 64 个，另一个用户的包一直没过去。
- **影响**：出口默认用原生 SS2022 UDP（`udp_over_tcp` 默认关），所以一个出口上所有入口、所有用户的 UDP（QUIC、语音、游戏、DNS）会同时卡死。有人访问一个解析慢或失败的域名就会触发，不需要恶意。
- **修复**：
  - 投递改成非阻塞：队列满就丢包（`select` 加 `default` 并 `buffer.Release()`），sing 的 `udpnat2` 已经这么做（`common/udpnat2/service.go:97`）。可以在 sing-shadowsocks 里放一份小的 `udpnat` 拷贝。
  - `udpOutbound.WritePacket` 不阻塞：域名没缓存就后台解析（同名合并），本包丢掉；失败也缓存约 30 秒。和 N5 的 DNS 缓存共用。
  - `udpSession.run` 打开出口时不要卡住读循环（异步打开，期间的包丢弃或少量排队）。
  - 可选：多个收包协程或 `SO_REUSEPORT` 多 socket、`recvmmsg` 批量收包，把解密分到多核。

### N3. 控制通道流量随用户数线性增长：每 5 秒报全部用户，每分钟整份重推配置 【中】

- **位置**：`cmd/keel-node/master.go:274-298`（每帧上报都带 `users.usage()` 的全部用户），`master/src/app.rs:22`、`:92`（只有用量变了也每 60 秒整份重推），`master/src/nodecfg.rs:262-282`（每个用户的凭据、额度、`used_base`、`used_self` 都在配置里）
- **问题**：用量按绝对值上报、主控直接覆盖，这个设计很稳；代价是没流量的用户也每 5 秒报一次。而任何用户有流量，`used_self` / `used_base` 就会变，于是整份配置连同所有用户的密码、UUID、密钥每分钟重推一次。
- **证据**（`TestPerfSizes`，JSON 和节点、主控实际产生的一样）：

  | 每节点用户数 | 每帧上报 | 上报流量/月 | 每份配置 | 配置流量/月 |
  | --- | --- | --- | --- | --- |
  | 100 | 9.8 KB | 5.1 GB | 29.6 KB | 1.3 GB |
  | 1000 | 95 KB | 49 GB | 295 KB | 12.7 GB |
  | 5000 | 479 KB | 248 GB | 1.48 MB | 64 GB |

  主控那边再乘以节点数，每份上报还要解析、写库（见主控部分）。节点每应用一次配置要 5 ms CPU、产生 3.4 MB 垃圾（1000 用户），再写一次 300 KB 的缓存文件并 fsync。
- **修复**：
  - 上报只带上次之后有变化的用户，每隔几分钟或重连后发一次全量；主控把「没出现」当作「没变」。
  - 用量走单独的小消息（如 `{"type":"usage","users":{"u7":[base,self]}}`），不再触发整份配置推送，配置只在真正改了东西时推。
  - 可选：压缩。coder/websocket 支持 permessage-deflate，主控用的 axum/tungstenite 能否协商要确认；不能就在应用层压缩。这类 JSON 一般能压到 1/5 以下。

### N4. 每 5 秒整读 `/proc/net/tcp{,6}`、`udp{,6}` 来数连接数 【中】

- **位置**：`cmd/keel-node/sysstat.go:77-78`、`:176-182`（`os.ReadFile` 整个读进来，`strings.Count(string(content))` 又复制一遍）
- **问题**：内核每读一次都要遍历全部 socket（含 TIME_WAIT）并格式化成文本，开销和 socket 数成正比；Go 这边 `ReadFile` 从 512 字节开始倍增扩容，再加一次 `string()` 复制。代理节点的 socket 数是连接数的两倍多。
- **证据**（1 核 Linux 容器，`procnet`）：

  | TCP socket 数 | 每次耗时 | CPU | 分配 |
  | --- | --- | --- | --- |
  | 2 000 | 3.5 ms | 4.6 ms | 1.8 MB |
  | 10 000 | 17 ms | 19.5 ms | 9.9 MB |
  | 40 000 | 71–88 ms | 80–99 ms | **39 MB** |
  | 读 `/proc/net/sockstat`（多少都一样） | 0.01–0.03 ms | 0.02–0.04 ms | 0 |

  40 000 个 socket 时，改成流式读取（不分配）内核格式化本身仍要 57 ms CPU。对一个空闲 RSS 只有约 12 MB 的进程，每 5 秒 10–40 MB 的垃圾会把堆和 RSS 撑大好几倍。
- **修复**：改读 `/proc/net/sockstat`、`sockstat6` 的 `inuse`（不含 TIME_WAIT，面板上的「连接数」本来也不该算它们）；需要精确的 ESTABLISHED 数就用 netlink `sock_diag` 加状态过滤。

### N5. 直连出站没有 DNS 缓存 【中】

- **位置**：`cmd/keel-node/outbound.go:475-477`（`dialTCP` 直接把域名交给 `net.Dialer`），`outbound.go:660-685`（UDP 每个会话各自解析）
- **问题**：`CGO_ENABLED=0` 编译，用的是 Go 自带的解析器，没有缓存。每条到域名的 TCP 连接都要先向系统 DNS 发 A + AAAA 查询、等一个来回才开始连目标，UDP 每个新会话也一样。经出口的流量由出口解析，所以出口承担全部用户的查询。Debian/Ubuntu 有 systemd-resolved 时还有一层缓存；Alpine（install.sh 支持的 OpenRC）和很多精简系统默认没有，每次都是一个到机房 DNS 的网络往返（通常 1–30 ms，DNS 慢时更多）。
- **证据**：读代码确认。延迟取决于机房和 DNS，没有在真实 VPS 上测。
- **修复**：直连出站加一个小缓存：按 TTL 缓存（上限约 60 秒），同名查询合并，失败也短暂缓存，条数有上限；拨号时直接用缓存的 IP（私网检查在 `Control` 里，照样生效）。UDP 共用这个缓存，同时解决 N2 的一部分。

### N6. 每条空闲连接都拿着一块 32 KB（扩容后 64 KB）的拷贝缓冲，所有协议都一样 【中】

- **位置**：sing `common/bufio/copy.go:190-191`（`copyExtendedWithPool` 先取缓冲，再阻塞在 `ReadBuffer`）。这些读端都没有 `N.ReadWaiter`：AnyTLS `Stream`（`third_party/sing-anytls/session/stream.go:42`）、`VisionConn`（`sing-vmess/vless/vision.go:104`）、SS2022 `serverConn`（`service.go:321`）和 `clientConn`、`*utls.Conn`（不带 Vision 的 VLESS）。
- **问题**：拷贝循环在等客户端发数据时就拿着一块池缓冲；连接上传过 512 KB 后这块还会长到 64 KB。来源是裸 TCP 时 sing 会用读等待器、等有数据才取缓冲，但上面这些协议连接都不支持。
- **证据**：VLESS / AnyTLS 每条空闲连接约 70–86 KB（`hold.sh`），其中这块缓冲占了将近一半；SS2022 的 1000 条连接里它占 33.5 MB。库级测量：一条空闲 AnyTLS 流加会话两端共 54 KiB（明文，不含 TLS）。
- **修复**：给这些连接实现 `N.ReadWaiter`，有数据了再取缓冲。SS2022 见 N1；AnyTLS 见 N11；`VisionConn` 进入直连后交给底层连接的等待器；`utls.Conn` 需要在分叉里加 `WaitReadBuffer`（可选）。

### N7. 周期写盘：没变化也每 2 秒写一次用量，每 5 秒 fsync 一次状态文件 【低】

- **位置**：`cmd/keel-node/main.go:36`、`:150-151`（`saveInterval = 2s`，无条件 `save`），`users.go:241-258`，`status.go:99-110`（`status.json` 每 5 秒写一次、fsync 两次，位置在 `/etc/keel/`），`main.go:185`（每次配置推送都重写缓存）
- **问题**：为了防止崩溃丢用量（安全审计 M14），用量改成 2 秒一存，这是对的；但节点空闲、计数没变时也照样写，每次都 fsync 文件和目录。`status.json` 只是给 `agent` 看的，丢了无所谓，也每次 fsync。这些都在主循环里做，盘慢的时候会推迟配置应用和额度检查。
- **证据**：1000 用户时 `usage.json` 62 KB，一天写 2.7 GB；`BenchmarkUsageSave` 每次 10–16 ms，几乎全是 fsync（macOS APFS；云盘一般 1–50 ms）。合计每秒约 1.4 次 fsync。
- **修复**：计数没变就跳过（记一个总和或脏标记）；`status.json` 不 fsync，最好放 `/run/keel/`（tmpfs）；存盘挪出主循环。

### N8. 没有设内存上限，突发过后内存要约 2 分钟才部分还给系统 【低】

- **位置**：`cmd/keel-node/main.go`（没有 `debug.SetMemoryLimit`），`master/install.sh` 生成的服务没有 `GOMEMLIMIT`
- **证据**：1000 条 SS2022 连接关掉后，RSS 停在 249 MB 至少 60 秒不降（堆里只剩 34 MB）。同样的测试加 `GOMEMLIMIT=64MiB`：连接开着时峰值 196 MB（低 20%），关掉后 5 秒内降到 39 MB。
- **更正**：初稿说内存「不还」，不准确。Go 每 2 分钟一次的强制 GC 之后会还掉一部分：后来一次测试里 RSS 在第 130 秒从 132 MB 降到 71 MB。问题是突发期间没有上限，之后要等约 2 分钟、而且只还一部分。
- **修复**：启动时按物理内存或 cgroup 上限自动设一个软上限（比如 40%），允许环境变量覆盖；或者在 install.sh 生成的服务里写 `GOMEMLIMIT`。上限不要低于活跃数据，否则 GC 会空转（Go 会把 GC 限制在约 50% CPU）。

### N9. Vision 直连阶段没有用上 splice 【低；万兆线路上是中】

- **位置**：`third_party/sing-vmess/vless/vision.go:37-64`、`:104-120`、`:193-246`、`:397`（`VisionConn` 只暴露 `Read` / `Write` / `Upstream`）
- **问题**：Vision 识别到内层 TLS 后改为直接读写裸 TCP，省掉了外层加密，这一步在 keel 的包装下是生效的；但 sing 的拷贝循环一直只看到 `*vless.VisionConn`，没法剥到底下的 `*net.TCPConn`，所以每个字节还是读进用户态再写出去。上游 sing-vmess 也一样。
- **证据**：Vision + HTTPS 下载每 GB 0.25 CPU 秒（不带 flow 的 VLESS 是 0.37），剖析里 94% 是 read/write，没有 splice。协议库子审计做了原型：给 `VisionConn` 加上 `NeedHandshakeForRead/Write`、`ReaderReplaceable/WriterReplaceable`、`UpstreamReader/UpstreamWriter` 后，进入直连模式时拷贝循环能剥到两边的 `*net.TCPConn`、保留用户计数，于是走 `copyDirect`（Linux 上是 splice）。没有在 Linux 上端到端验证。
- **修复**：按上面的原型给 `VisionConn` 加这几个方法。`NeedHandshakeForRead` 要等 `remainingBuffers` 清空后才变 false；进入直连前 `UpstreamReader/Writer` 要返回 `c.Conn`，因为 sing 会无条件沿着它们去算 headroom 和 MTU。

### N10. UDP 每个包都要过几把全局锁 【低】

- **位置**：`cmd/keel-node/outbound.go:404-418`（`isPublic` → `isLocal` 用一把全局互斥锁，每 10 秒在锁里调用 `net.InterfaceAddrs()`），`outbound.go:693`（`udpOutbound.WritePacket` 每包一次），`outbound.go:263-267`（审计期间新加的 `udpSession.run`：每包再做一次 `refused`，也就是又一次 `isPublic`，以及一次 `pick`），`route.go:118-119`（`pick` 对每个规则集加一次锁）
- **问题**：逐包路由修好了安全审计的 L29，代价是 UDP 热路径上每个包要拿 2 次 `local` 锁、最多 6 次规则集锁、1 次会话锁。这些锁所有用户、所有会话共用，多核时互相争抢。
- **证据**：`BenchmarkIsPublic` 单线程 70 ns，10 个线程并行时每次 125–160 ns，总吞吐比单线程还低；`BenchmarkPickMissDomain` 单线程 0.53–0.60 µs，10 线程并行 0.35–0.42 µs/次，只快 1.5 倍。每秒几十万包时也就几个百分点的单核，所以算低危。
- **修复**：本机地址集合放进 `atomic.Pointer`，后台定时刷新，读路径不加锁；规则集同样改成原子替换的只读快照，`match` 不加锁（重新加载的检查用原子时间戳）；`udpSession` 缓存最近几个「目的地 → 出口」，同一目的地的后续包不再重新匹配。

### N11. 协议库里的小开销 【低】

都来自协议库子审计的微基准（M4，机器有负载，取 3 次中位数），没有在节点上端到端测过，每项单独看都不大。

| 位置 | 问题 | 测量 | 修复 |
| --- | --- | --- | --- |
| `sing-anytls/session/session.go:382-394`、`stream.go:53-62` | AnyTLS `Stream.Write` 每次把下载数据再复制进一块新缓冲（`len+7`，32 KB 的数据落进 64 KB 的池档） | 32 KiB 每次 387 ns；走真实 TLS 时整体慢约 7% | 加 `Stream.WriteBuffer`，`FrontHeadroom() = 7`，用 `ExtendHeader` 写帧头 |
| `sing-anytls/session/session.go:194-200`、`pipe/io_pipe.go:95-96` | 每个流一个同步 pipe，收包协程要等读者读完才继续；一个流不读，同会话的其他流都收不到 | 每帧交接 459–617 ns（带所有权转移的 channel 是 108 ns）；队头阻塞已复现 | 每流一个按字节封顶的帧缓冲队列，加 `N.ReadWaiter`。参考客户端每个会话同时只跑一个流，所以 AnyTLS 影响小 |
| `sing-vmess/mux.go:77-120`、`:125`、`:216-233`、`:486-503` | VLESS mux（Xray mux.cool）和 XUDP 服务端：每个子流一个 `io.Pipe`，长度、数据、地址分三次同步写入；每帧 5 次 `binary.Read` | XUDP 每包 2.3 µs、21 次分配、10 次读（负载高时 6.6 µs）；TCP 帧 0.6 µs | UDP 子流改用丢满即弃的包队列；帧头用 `binary.BigEndian` 从固定数组解析。开了 Xray mux 的 TCP 也有上一行的队头阻塞 |
| `sing-shadowsocks/shadowaead_2022/service_multi.go:285`、`:304-375`、`:389`，`service.go:522-560` | SS2022 UDP 每包：`binary.Read`、逃逸的头部数组、每包两个闭包、每包装箱一次地址 | 入站每包 851 ns、10 次分配；出站 380 ns、9 次 | 用 `binary.BigEndian`，缓存 NAT 地址，头部直接写进 headroom |
| `shadowaead_2022/protocol.go:515`、`:748` | 入口→出口的 SS2022 UDP 客户端带 EIH（出口是多用户，总是带），每个包都新建一次 AES | 每包 450–493 ns、672 B（不带 EIH 时 350 ns、160 B） | 在 `New` 里一次建好 |
| `shadowaead/aead.go:134-175` | 原地解密的分支在 sing 两端之间永远走不到，每块数据两次 read | 32 KiB 块融合解密的原型快约 8% | 调用方缓冲够大就直接解密进去，或者用 N1 的 `ReadWaiter` |
| `sing-vmess/xudp.go:58-118` | keel 的 VLESS 出站收 UDP 时每包 3 次 read 系统调用 | 每包 233 ns、5 次分配 | `XUDPConn` 下面垫一个带缓冲的 reader |

### N12. 不需要改的地方 【提示】

- **Reality**：服务端为了模仿 dest 的握手，每条新连接都要去连一次 dest 并完成握手（协议设计如此；本测试单核 2700 次/秒，每次 0.36 ms CPU，包括这一步），dest 的延迟直接加在用户每次建连上。主控给入口选 SNI / dest 时可以让节点先 TCPing 几个候选，挑延迟最低的。
- **加密算法**：M4 上 16 KB 加密 AES-128-GCM 6.6 GB/s、AES-256-GCM 5.1 GB/s、ChaCha20-Poly1305 0.71 GB/s，保持默认的 `2022-blake3-aes-128-gcm`（多用户 SS2022 也只接受 AES-GCM）。blake3（lukechampine v1.3.0）没有 arm64 汇编，约占 SS2022 握手 CPU 的 13%，只在建连时算一次。amd64 没测。
- **分流、额度、计数**：6 个规则集都不命中时每条连接 0.5–1.5 µs，IP 目的地 0.13–0.4 µs；1000 用户的额度检查每秒 23 µs，用量快照 0.38 ms；每个配置的用户常驻约 1.1 KB（5000 用户 5.3 MB）。计数用的是 sing 的计数连接，拷贝时会被剥掉再走快速路径，剖析里看不到 keel 自己的代码。

## 主控（keel-master）和面板

主控的测量来自主控子审计：release 构建（02:49 和 03:01 的工作区，热路径和提交后的代码相同），Apple M4、回环、TLS 1.2，用脚本灌数据、用模拟节点（`bench/master/sim.py`）按协议连上来上报。三组数据，每个用户都在每个入口上（面板默认），90% 的用户有额度，带 12 个周期的历史用量：

| 数据集 | 节点 | 用户 | 用量行（表里 / `load_world` 读出） |
| --- | --- | --- | --- |
| small | 10 入口 + 10 出口 | 200 | 2.5 万 / 6900 |
| medium | 10 + 10 | 1000 | 12.1 万 / 3.3 万 |
| large | 25 + 25 | 2000 | 60.7 万 / 16.4 万 |

VPS 的一个核按慢 1.5–3 倍估计。括号里是修复时要守住的安全审计条目。

### M1. 计算每个用户的用量时把全部用量行扫一遍，复杂度是 O(用户²) 【高】

- **位置**：`master/src/db.rs:516-522`（`World::used`）。调用方：`nodecfg.rs:278`（每份入口配置里每个有额度的用户算一次 `used_base`），`nodecfg.rs:60-62`（`user_used`，`/api/state` 里每个用户一次，`api.rs:474`；订阅 `sub.rs:502`）。同样的写法还在 `nodecfg.rs:68-75`（`exit_used`，`api.rs:464`）和 `nodecfg.rs:312-317`。
- **问题**：一份入口配置 O(U²·E)，一次 `sync` O(U²·E²)，一次 `/api/state` O(U²·E)。
- **证据**：剖析里 `used` 加上比较字符串的 `memcmp` 占 `/api/state` CPU 的约 95%、`sync` 的约 97%。`/api/state`：small 7–23 ms，medium 120 ms，large 1.75–2.0 秒（响应 740 KB）。large 上一份入口配置约 1.5 秒；改一个用户（`PATCH /api/users/2`）在没有节点在线时 0.18 秒，2 个入口在线时 3.1–3.4 秒。
- **修复**：每个 `World` 只聚合一次，得到 `HashMap<(name, period), total>` 和各节点的份额，`used = total − own` 变成 O(1)；出口按 `(exit, period)` 同样处理。（H4/M1：在 Rust 里饱和求和并跳过坏行，不在 SQL 里算 `up+down`；只统计各节点有权写的计数名。）

### M2. 配置同步在 DB 锁和 live 锁里重建所有节点的配置，节点一起重连时主控会瘫痪 【高】

- **位置**：`master/src/app.rs:66-111`（DB 锁在 67 行，live 锁在 79 行）。触发：每个节点连上时（`ws.rs:124`）、每 30 秒（`main.rs:550`）、每个编辑接口返回前（`api.rs` 里 14 处 `app.sync()`）。
- **问题**：每次都重建所有在线节点的配置，每份序列化三次（`shape()` 整份 clone，`json!` 又复制一次），每推一个节点就单独一次自动提交的 UPDATE。N 个节点一起连上就是 O(N²) 次构建，而且全程持锁，面板、订阅、上报都在等。
- **证据**：
  - 节点一起连上：small 第一份配置的中位数 0.13 秒；medium 中位数 3.9 秒、最长 11.7 秒，期间 `/api/session` 卡 8.3 秒、`/app.js` 卡 4.4 秒；large 195 秒里 50 个节点只有 5 个拿到配置，49 个因 WebSocket ping 超时断开，HTTP 全程没有响应，客户端走后 CPU 仍满载 3.5 分钟以上，SIGTERM 20 秒没有反应。
  - 稳态：medium 每 30 秒一次的同步让整个服务卡 0.7–1 秒。
  - keel-node 每 30 秒 ping 一次、15 秒超时（`cmd/keel-node/master.go:32`、`:264`），所以很可能形成「卡住 → 节点断线重连 → 再卡住」的循环（推断，没有用真节点测）。
- **修复**：一个合并请求的推送任务；节点连上时只构建它自己的配置；锁里只读数据，构建放到 `spawn_blocking` 里且不持锁；每份配置只序列化一次；rev 的 UPDATE 合并成一个事务。（M3：注册连接前在 DB 锁里复查令牌、`kick` 能结束旧连接、丢弃非当前连接的上报；M5：每节点 16 条队列和 30 秒写超时；保持先 DB 后 live 的加锁顺序；禁用或删除用户、重置订阅（L16）、每入口凭据（L17）之后最多晚一轮推送、不能丢；H7：Cloudflare 令牌不进配置。）安全审计的 L7 标为已修，但只改了 Cloudflare 那部分。

### M3. 每帧上报逐行自动提交，并且每 5 秒把所有计数重写一遍 【高】

- **位置**：`master/src/db.rs:646-655`（`store_usage`），调用方 `app.rs:154`
- **问题**：每行一个隐式事务；`updated` 每次都改，没变的计数也重写。写入量只和「节点数 × 用户数」有关，和有没有流量无关。
- **证据**：
  - 库级（`bench/master/wal_bench.py`）：一帧 2000 行，逐行提交写 2000 个 WAL 帧（7.8 MB）、13–38 ms；放进一个事务 46 帧（0.18 MB）、约 2 ms；再跳过没变的行，空闲时 0 帧。200 行时 200 帧对 22 帧。
  - 运行中的主控：small 1.54 MB/s，约 130 GB/天；medium 7.95 MB/s，约 690 GB/天。这是 WAL 的逻辑写入量，实际落盘量没有测。
- **修复**：一帧一个事务；upsert 加 `WHERE excluded.up>usage.up OR excluded.down>usage.down`。（H4/M1：只收本节点的计数名、钳位；L5：同周期只增不减；`updated` 只在增长时前进，`load_world` 的 70 天窗口照样成立；M4：行数有界。）和 N3 的增量上报一起做，写入量降到「有流量的用户数」。

### M4. 面板每次轮询都在 live 锁里重建 `/api/state`，面板也不等上一次返回 【中高】

- **位置**：`master/src/api.rs:303-304`、`:363-512`（375 行拿 live 锁，487 行是 O(U·N)），`master/web/app.js:121-131`、`:1240`。`on_report` 先拿 DB 锁再拿 live 锁（`app.rs:144`、`:158`），所以状态构建一慢，上报也被挡住。
- **证据**：large 上一个标签页就占 86% 的核；两个标签页时 27 个请求排队，中位数 24 秒、最长 44 秒；4 个并发客户端和 1 个的吞吐一样。`/api/public` 缓存过期后重建一次也要算完整状态：large 1.8 秒，medium 130–146 ms。
- **修复**：先修 M1；状态在 `spawn_blocking` 里构建，只把 live 字段复制出来；预先算好 `conns` 合计；1 秒内共享同一份快照；面板在上一次请求没返回时跳过本次并退避；用 ETag，或者把静态数据和实时数据分开。（L12：`no-store`；M9：先过登录和 `x-keel` 检查再给快照；M6：`/api/public` 每个间隔最多构建一次、不在异步线程上；L13：公开页仍需开启、字段白名单不变。）

### M5. 每个订阅请求都在 DB 锁里读整个 world 【中】

- **位置**：`master/src/sub.rs:473-480`，`sub.rs:500` 又拿一次锁，`sub.rs:502` 全量扫描
- **证据**：small 2.5–3.3 ms，medium 12–13 ms，large 66–99 ms；large 上 1 个客户端 10–15 rps，8 个并发反而降到 6.6 rps、最长 3.9 秒，RSS 从 44 MB 涨到 188 MB。
- **修复**：按令牌只查这个用户和他能用的入口，在 `spawn_blocking` 里做。（H3：只列客户端能校验或固定证书的入口，ACME 入口签发后才列；L16/L17：继续用 `credentials_for`；未知令牌 404；L12：`no-store`。）

### M6. 一把标准库互斥锁包着唯一的数据库连接，到处在异步线程上拿 【中】

- **位置**：`master/src/app.rs:31-48`；调用方包括 `api.rs:89-94`（每个登录后的请求）、`ws.rs:61`、`:92-97`、`:141`，`app.rs:142-197`
- **证据**：medium 上 `/app.js` 这种静态文件最长要等 4.4 秒；只有一个 tokio 工作线程时 12.8 秒。
- **修复**：数据库操作放进 `spawn_blocking` 或专门的 DB 线程；锁只包住 SQL；查询用第二个只读连接。（M3：连接注册和换令牌仍走同一把锁；L8：argon2 仍在线程池里；数据库和 `-wal`、`-shm` 文件仍是 0600。）

### M7. 只有用量变化也每 60 秒整份重推配置 【large 中，small 低】

- **位置**：`master/src/app.rs:22`、`:92-96`，`nodecfg.rs:342-353`
- **证据**：每个入口每分钟 56 KB（small）、267 KB（medium）、532 KB（large）。
- **修复**：用量单独走一条小消息，见 N3。（rev 单调递增；`used_base` 由主控计算；L5。）

### M8. 上报路径的重复工作 【低中】

- `ws.rs:137`、`:147`：先解析成 `Value`，再 clone 一份解析成 `Report`。
- `node_counters`（`db.rs:635-642`）全表扫 `user_entries`，因为主键是 `(user_id, node_id)`（`db.rs:95`），没有 `node_id` 开头的索引。
- `app.rs:157` 每帧读一次时区设置；`app.rs:161` 每帧重建整张 `conns` 表。
- **修复**：只解析一次；给 `user_entries(node_id)` 加索引；缓存本节点的计数名单，`user_entries` 或出口变化时失效；`conns` 增量更新。（L4：坏的 `system` 等字段不能连累用量；M1：缓存必须随 `user_entries`、出口的变化失效；M3：当前连接检查；M4：探针条数上限；4 MiB 消息上限。）

### M9. `load_world` 全表扫用量表 【低】

- **位置**：`master/src/db.rs:578`（只要最近 70 天），`db.rs:675`（用量保留 400 天）
- **证据**：large 上扫 60.7 万行、返回 16.4 万行，18 ms。
- **修复**：给 `usage(updated)` 加索引。（H4：跳过坏行的逻辑不变。）

### M10. 只要一个对象也读整个 world 【低】

- **位置**：`master/src/api.rs:1017`、`main.rs:257`（`node_ports`）、`dns.rs:60`、`dns.rs:191`
- **修复**：按 id 查单个对象。（`node_ports` 的节点令牌鉴权和错误令牌的 1 秒延迟不变；ACME 的域名只取节点自己的设置，H7。）

### M11. 内存比 README 说的大；`/dl` 把二进制常驻内存 【低】

- macOS 上：空闲 5–6 MB；small、2 个节点、面板轮询中 23–29 MB；登录一次（argon2，19 MiB）瞬时 45 MB；large 瞬时 151–188 MB。README 写的「约 7 MB」只对应空闲。
- `/dl` 把每个二进制缓存到进程结束（`main.rs:267-285`，读代码，没测）。
- **修复**：`/dl` 从磁盘流式发送；README 改成实测范围。（H1：不按连接复制、连接上限和超时、文件名白名单都保留。）

### M12. 5 秒定时器卡顿后会连发 【低】

- **位置**：`master/src/main.rs:543-556`。tokio 的 `interval` 默认补发错过的 tick，一次慢的 `sync` 之后会连着跑好几轮。
- **修复**：`set_missed_tick_behavior(MissedTickBehavior::Delay)`。

### M13. 面板每次轮询都重绘整个页面 【低中】

- **位置**：`master/web/app.js:125-130`（数据里有 `now`，「没变就不重绘」永远不成立），`:165-186`（整页 `innerHTML`），`:149-161`（每次操作渲染两遍），`:503-504`（O(U·E·N) 的查找）
- **证据**（large）：10 次轮询 10 次整页重绘；用户页 18 020 个元素，约 73 ms（含布局）；线路页 16 ms，探针页 5 ms；`JSON.stringify` 0.6 ms、解析 0.9 ms；堆不涨。
- **修复**：比较时排除易变字段；只重绘当前标签页；实时字段原地更新；用节点 `Map` 查找。（插值一律 `esc()` 或用 `textContent`；写操作带 `x-keel`，M9；同源凭据不变。）

### M14. 小开销 【提示】

- `util.rs:12-13` 的 `hex()` 每个字节调一次 `format!`；`sub.rs:82`、`:95` 每个入口算两次 `credentials_for`。修复后输出必须逐字节不变。
- `dns.rs:143-150` 每次调 Cloudflare 都新建根证书库和 TLS 配置；建一次复用即可（webpki 校验、20 秒超时、令牌只发给 `api.cloudflare.com`、H7 不变）。

## 修复计划

已确认的计划：范围包括全部可选项；和「安全审计」会话在同一个工作区协作，按文件划归属，各自只提交自己的文件。每一项都要守住安全审计已修好的性质：

- 连接级 `recover` 和握手截止时间；
- 私网防护在 Dialer 的 `Control` 钩子里逐个检查拨号的 IP，UDP 逐包检查；
- `used_self` 不回退，主控对上报的校验不变；
- SS2022 的防重放和 AEAD 分帧；
- 吊销语义；
- 含密钥的配置不压缩。

| 顺序 | 内容 | 对应问题 | 状态 |
| --- | --- | --- | --- |
| 1 | 写本报告；和「安全审计」会话约定分工 | — | 完成 |
| 2 | 用量聚合改 O(1)；上报一帧一个事务、没变的行不写 | M1、M3 | 完成（`1e06b98`） |
| 3 | SS2022：UDP 投递不阻塞；缓冲池化（先只改生命周期，再改成 ReadWaiter / 原地加密）；EIH 复用；UDP 逐包分配 | N2、N1、N6、N11 | 完成（`2a73042`、`e8fd8a5`、`8f41818`、`da249c2`） |
| 4 | 主控的锁和查询：同步不在锁里重建、状态快照和面板防堆积、订阅只查本人、数据库移出异步线程、上报路径和索引 | M2、M4、M5、M6、M8、M9、M10 | 完成（`4c65d5b`、`fe95184`、`6677c52`、`8bb8250`） |
| 5 | 节点：sockstat、少写盘、默认内存上限 | N4、N7、N8 | 完成（`ae4db7a`） |
| 6 | 节点 UDP（等对方提交 R1 后）：异步打开出口、DNS 缓存、去全局锁；验证 R1 的修复 | N2、N5、N10、R1 | 完成（`4f819fa`；R1 由安全审计会话在 `dc1ed93` 修复，已复测） |
| 7 | 控制通道：增量上报、用量单独下发；面板只更新变化部分；`/dl` 流式、定时器、小项；README 的内存数字改成实测 | N3、M7、M11–M14 | 完成（`8bb8250`、`fe95184`、`790756f`，README 是之后补的） |
| 8 | 可选项：Vision splice、AnyTLS/mux 的队列和 ReadWaiter、XUDP 等 | N9、N11、N6 | 完成（`7f9a791`、`bcd3af9`、`3350dc6`、`da249c2`） |
| 9 | Reality dest 按延迟挑 | N12 | 完成（`e06be4d`） |
| 10 | 全量回归，Docker 压测和主控模拟器的前后对比，更新本报告 | — | 完成（见「修复结果」） |

utls 的 `WaitReadBuffer`（N6 里提到的另一种做法）没有做：收益小，改动在 TLS 记录层。

### 修复过程中发现的问题

- **SS2022 的填充发出池里的旧内存**（安全审计 M24，`2068450` 修复）：填充用 `Extend` 留位置，sing 的池缓冲不清零，于是填充里可能带着别的连接留下的数据。改成写零。
- **Vision 和 VMess 客户端头的填充有同样的问题**（安全审计 M25，安全审计会话在 `18a7b00` 修复）。
- **AnyTLS 一次写超过 65535 字节会搞坏会话**：帧长被截成 16 位（`bcd3af9` 修复，拆成多帧）。sing 的拷贝最多一次写 65535 字节，所以平时碰不到。同一个提交还修了 AnyTLS 客户端 `peerVersion` 的数据竞争。
- **增量上报的约束**：在线数改成按用户合并以后，节点可以用编造的计数名把这张表越撑越大。实现时就限制为本节点的计数名，并钳位到 2^20（`8bb8250`）。增量帧里没出现的用户沿用库里原来的计数，不会当作 0。

## 核实为正常的部分

- **节点数据面**：吞吐、每 GB CPU 和 sing-box 持平，内存更低；计数用 sing 的计数连接，拷贝时会被剥掉再走快速路径；分流匹配每条连接 0.5–1.5 µs；1000 用户的额度检查每秒 23 µs；每个配置的用户常驻约 1.1 KB；健康检查、三网探测的开销可以忽略；服务的文件描述符上限是 1048576（systemd 和 OpenRC 都设了）。
- **协议库**：
  - keel 对几个库的改动没有可测的热路径开销；
  - SS2022 查用户是 O(1)，1 到 10 万用户的握手都是 7–8 µs；AEAD 每个方向建一次，不是每块建一次；防重放过滤每连接 0.37 µs；
  - AnyTLS 服务端会话从不填充；utls 的记录层和 crypto/tls 一样（池化缓冲、原地解密）；
  - Vision 的直连模式在 keel 的包装下能生效，只是没走到 splice（N9）；
  - 默认的 AES-128-GCM 是最快的选择（M4 上 6.6 GB/s，ChaCha20 是 0.71 GB/s）。
- **主控**：
  - 内存里的历史数据都有上限（速率 36 点，探针 120 点 × 8 个名字，证书 8 个）；WebSocket 每节点 16 条队列、30 秒写超时、4 MiB 消息上限；
  - 配置哈希没变就不推送；argon2 在线程池里、最多同时 2 个；
  - `/api/public` 有缓存；令牌查询走索引；静态资源编进二进制；
  - SQLite 用 WAL 加 `synchronous=NORMAL`，设置合适。
- **面板**：事件监听只绑定一次；标签页隐藏时不轮询；抽屉不随轮询重绘；图表开销小；堆不增长。

## 方法与局限

- **节点**：Docker Desktop（Apple M4）里的 Linux arm64 虚拟机，被测节点用 cpuset 独占 1 个 CPU，客户端和目标服务器在另外 4 个 CPU 上，全部走回环。客户端分别是：
  - AnyTLS：sing-box 1.14（只带 AnyTLS 的构建）；
  - SS2022：sing-shadowsocks 的客户端；
  - VLESS Reality：按 sing-box 的 Reality 客户端移植的 benchcli。
  
  吞吐和 CPU 用 `/proc/<pid>/stat`，剖析用编进 pprof 的同一份代码。
- **协议库**：库内微基准和测试，Apple M4、机器有负载，取 3 次中位数；amd64 没测。
- **主控**：macOS 上的 release 构建，灌数据加模拟节点；Linux 上的 RSS、真实的落盘量、真节点的重连行为、VPS 的 CPU 速度都没测，按 1.5–3 倍外推。
- 回环上的绝对吞吐远高于任何 VPS 网卡，结论只看每 GB 的 CPU、每条连接的 CPU 和内存这些相对量。
- 审计期间另一个会话在提交安全修复，测量用的是 02:49–03:01 的快照；之后的改动逐个比对过，R1 是在提交后的代码上复现的。
