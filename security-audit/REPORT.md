# keel 安全审计报告

- 审计对象：`main` 分支提交 `c201f07`（keel-master、keel-node、面板、install.sh、third_party、依赖）
- 日期：2026-10-29
- 每条问题的原始验证记录（英文，含复现过程和输出）见 [EVIDENCE.md](EVIDENCE.md)，编号与本文一致。

## 结论

共确认 **86 个问题**，另有 1 条候选被推翻。

| 严重程度 | 数量 | 其中默认部署就受影响 |
| --- | --- | --- |
| 高 | 7 | 5（其中 H6 只影响 Azure 上的节点） |
| 中 | 23 | 18 |
| 低 | 41 | — |
| 提示 | 15 | — |

没有发现未经认证就能执行代码或直接拿到全部密钥的漏洞。路由鉴权、会话、SQL、面板 XSS、节点证书固定、节点本地文件权限、私网防护的主体逻辑都经得起测试（见文末「核实为安全的部分」）。问题主要集中在五处：

1. **主控很容易被打下线，而且有的方式能持续几十天。** 匿名攻击者可以用慢速下载或慢速登录请求把主控内存撑爆（H1、H2）。任何一个节点发一帧上报，就能让面板、订阅和所有配置推送瘫痪 70 天，删节点、重启都没用（H4）。
2. **默认的 AnyTLS 入口不校验证书。** 网络中间人能拿到可重放的用户凭据，这个凭据在该用户所有入口都能用，而且无法更换（H3、L16）。
3. **订阅用户能让入口崩溃，并借此不受额度限制。** 开了 VLESS 的入口，现有或已删除的用户发一个请求就能让整个节点进程崩溃（H5）。每次崩溃都会丢掉最近的用量，主控还会用较小的值覆盖（M14）。
4. **一个被控节点的影响面太大。** 它可以篡改任意用户的用量（M1）；在管理员吊销之后继续写数据（M3）；如果配置了 Cloudflare 令牌，还能接管整个 DNS zone，进而劫持面板（H7）。
5. **吊销不彻底。** 删掉或换了令牌的节点会继续用旧用户表提供服务（M12）。「重置订阅」也不会更换代理凭据（L16）。

## 范围和方法

- **第一轮：** 9 个审计员按攻击面分工：主控认证、主控匿名接口与订阅、节点控制通道、面板前端、节点↔主控链路与安装、节点出站与私网防护、节点入站协议、ACME 与证书、依赖与供应链。他们只读代码，在临时目录里写测试和脚本复现，共报出 101 条。去重后得到 79 个候选问题。
- **第二轮：** 8 个验证员逐条「尝试推翻」，用 release 构建在本机 `127.0.0.1` 上复现。主控用的是 `panic = "abort"` 的版本，和线上一致。另有 1 个补漏审计员专找第一轮没覆盖的地方，新增 9 条。我又亲自复核了其中两条中危：查对 utls 的源码，并核对节点的重连逻辑和面板文案。
- **自动扫描：** govulncheck（带 `anytls,vless,with_utls,ss` 标签）和 cargo-audit。third_party 下的两个库和上游版本做了逐文件 diff。
- **攻击者模型：** 匿名的互联网用户；订阅用户（持有有效代理凭据）；被控节点（持有一个节点令牌，比如不可信的 VPS 商家）；网络中间人或做主动探测的审查者；主机上的本地普通用户；管理员粘贴进来、由第三方写的数据（商家的分享链接）。管理员本身是可信的。

## 攻击链

**链 1：匿名攻击者让主控下线（默认部署）。**
- 主控没有请求头读取、空闲连接或写入超时，也没有连接数上限。约 1000 个空闲连接就能耗尽默认的 1024 个文件描述符（H2）。
- 约 100 个停住不读的 `/dl/keel-node-linux-amd64` 下载能占约 1 GB 内存（H1）。约 500 个只发一半请求体的 `/api/login` 也一样，每个占约 1.9 MB（H2）。
- `/api/public` 洪泛会卡住整个异步运行时（M6）。
- 每 10 分钟从 10 个地址（或一个 IPv6 /64）各试错 10 次，管理员就一直登不上（M7）。

主控下线期间，节点照常用缓存配置运行，但没法禁用用户，也没法推送配置。

**链 2：订阅用户打垮入口，同时抹掉自己的用量。**
- 开了 VLESS 的入口上，Reality 参数（公钥、short id、SNI）所有用户共用、从不更换。所以现有或已删除的用户都能发一个畸形 VLESS 请求，让 keel-node 整个进程 panic（H5），systemd 3 秒后重启，可以无限重复。有效用户还能用 Vision 的越界切片达到同样效果（M13）。
- 用量每 10 秒才存一次，启动后 10 秒才第一次存，而 systemd 3 秒就重启。所以每次崩溃都会丢掉最近的用量，主控还用较小的值覆盖（M14），额度永远用不完。
- 默认只开 AnyTLS 的入口上，单个用户可以无限开流，把节点撑到 OOM，效果相同（M17）。

**链 3：中间人拿到用户凭据（默认部署）。**
- 新建的入口默认只开 AnyTLS、用自签证书，订阅里写的是 `skip-cert-verify: true` / `insecure`（H3）。
- AnyTLS 的认证就是在 TLS 里发 `sha256(password)`，没有服务器随机数，所以可以重放。
- 同一用户所有入口用同一个密码（L17），而且密码没法更换（L16）。
- 公共 Wi-Fi、ISP 或审查者解开 TLS 后，就拿到一个永久有效的凭据，以及所有目的地和明文流量。

**链 4：一个被控节点（不可信的 VPS 商家）。**
- 一帧上报（`up = i64::MAX`）就让主控的 `load_world` 永久报错 70 天（H4）。面板、公开页、所有订阅、所有节点的配置推送全部失败，删节点、换令牌、重启都没用。
- 可以给任意用户写用量：写大值，让用户在所有入口被封；写负值，解除额度（M1）。
- 如果配置了 Cloudflare 令牌并开了 ACME，节点缓存里就有整个 zone 的 DNS 编辑权限（H7）。它可以把面板域名指向自己，用 DNS-01 签一张受信任证书，劫持管理员的会话和密码。主控用 CA 证书时（安装命令里没有指纹），它还能劫持所有节点的控制通道和 `agent update`，拿到所有节点的 root。
- 管理员发现后换令牌或删节点，已经建立的连接仍能继续写用量（M3）。被删的节点本身也会继续用旧用户表服务（M12）。

**链 5：订阅用户摸到节点内部。**
- Azure 上的节点：WireServer `168.63.129.16` 被当成公网地址放行（H6）。keel-node 以 root 运行，正好满足 Azure 防火墙「只放行 uid 0」的规则。
- 任何节点：本机公网 IP 不在拦截范围里。绑在 `0.0.0.0` 上、原本靠防火墙挡住外部访问的服务（数据库、其他面板、Docker 映射端口）都能经 `lo` 访问到（M20）。
- 有 NAT64 的 IPv6 网络：`64:ff9b::/96` 等内嵌 IPv4 的地址能绕过检查（M21）。

## 修复计划（按根因合并，括号里是覆盖的问题）

**第一批：改动小，覆盖面大**

1. **主控只接受节点「自己的」计数**（H4、M1、M2、M4，以及 L4、L5 的一部分）
   - `on_report` 只收主控分配给这个节点的计数名：入口收它服务的 `u<id>`，出口收 `n<入口>x<出口>`。只收当前和上一周期，数值必须在 0..2^50 之间。
   - 求和改在 Rust 里做饱和运算，不要在 SQL 里写 `up+down`。`load_world` 遇到读不了的行就跳过，不要整个失败。
   - 删节点时把它的用量行一起删掉。
2. **主控 HTTP 加超时和上限**（H1、H2、M8、L41）
   - `http1::Builder` 加 `.timer(TokioTimer::new()).header_read_timeout(..)`，再加空闲超时和写超时。
   - 在 `tokio::spawn` 之前用信号量限制连接数。`/api/login` 的请求体限制到几 KB。
   - `/dl` 改成流式发送，或者共享一份 `Arc<Bytes>`。
   - 401 响应带 `Connection: close`。
   - 提供 keel-master 的 systemd 单元，带 `Restart=always`、更高的 `LimitNOFILE` 和 `MemoryMax`。
3. **节点：连接级容错和限额**（H5、M13 的崩溃面，M15、M16、M17、L25）
   - 每个连接 goroutine 加 `defer recover()`。
   - `acceptLoop` 遇到临时错误时退避重试，不要退出。
   - 三种入站在解析前都设 `SetDeadline`，认证后再清掉。
   - AnyTLS 每个会话限制流数，读地址时加超时，并把会话本身纳入 `user.conns` 跟踪。
   - 加全局、每 IP、每用户的连接数上限。
4. **用量持久化**（M14、L5）
   - 节点启动后立刻存一次，存盘间隔要短于重启延迟。
   - 主控在同一周期内只升不降：`max(旧值, 新值)`。
5. **补全私网防护**（H6、M20、M21、L33、L34）
   - 拒绝 `168.63.129.16`。
   - 按 IANA 特殊用途地址表拒绝；内嵌 IPv4 的 IPv6 地址先解码再判断。
   - 本机接口地址和定向广播一律拒绝。
6. **订阅里固定 AnyTLS 证书，不再跳过校验**（H3、M18）
   - 节点上报自签证书的指纹，订阅里写进去：mihomo 用 `fingerprint`，sing-box 用 `certificate_public_key_sha256`，Surge 用 `server-cert-fingerprint-sha256`。或者新入口默认启用 ACME。
   - 去掉证书里的 `O=keel-node self-signed`，有效期改为常规长度，已部署的证书重新生成。
7. **Cloudflare 令牌不再下发给节点**（H7）
   - 由主控代做 DNS-01：节点经控制通道把 key authorization 发给主控，主控只为该节点自己的 `anytls_sni` 创建 `_acme-challenge` 记录。
   - 改正面板文案。已经下发过的令牌应当作泄露，作废换新。
   - 不管主控用哪种证书，安装命令里都带上证书固定。

**第二批**

8. **吊销要彻底**（M3、M5、M12、L6、L16、L17）
   - 节点把 401 当作被撤销：宽限一段时间后停止入站、清空缓存配置。
   - `kick()` 直接终止对应的 serve 任务；serve 循环里核对连接代号，丢弃旧连接的上报。
   - 发送队列加上限和写超时。
   - 「重置订阅」同时更换代理凭据；每个入口用派生凭据。
9. **登录和 CSRF**（M7、M9、L1、L9）
   - 全局计数只用来减速，不能挡住正确的密码。
   - `-no-tls` 时只信任反代追加的最右一跳 XFF，并解析成 IP。
   - 所有写操作检查 `Sec-Fetch-Site` / `Origin`，或要求 JSON 请求头。
   - cookie 改名为 `__Host-keel_session`。
10. **`-no-tls` 的 http 回退**（M10）
    - 有反代时 scheme 默认用 https；面板里能设置 `panel_url`，地址是 http 时给出警告。
    - 节点拒绝非本机的 `ws://` 主控。
11. **探测特征和第三方库**（M19、M22、L23、L28）
    - vendor `metacubex/utls`，补上 Reality 回落的半关闭，以及 Go 的 KeyUpdate 上限修复。
    - 健康检查读状态行时限制长度。
    - SS2022 握手失败时的行为统一，并加超时。
12. **订阅 DNS**（M23、L21）
    - mihomo/Surge 的 `GEOIP,CN` 加 `no-resolve`，或者像 sing-box 配置那样只把 geosite:cn 交给国内 DNS。
    - 规则列表固定到具体 commit。

---

## 高危

### H1. 匿名请求 `/dl/{name}` 时整个节点程序读进内存，停住不读的下载能把主控撑爆

- **攻击者**：匿名，任何能连上主控端口的人。**默认部署受影响**：是（安装节点必须把程序放进 `dist/`，文件名在 install.sh 里是公开的）。
- **位置**：`master/src/main.rs:213`（`tokio::fs::read` 整个读入），`main.rs:286-296`（没有写超时，没有连接上限）
- **问题**：每个请求都把约 10 MB 的二进制完整读进一个 `Vec`，hyper 要等客户端读完才释放。客户端把接收窗口设得很小、一直不读，这块内存就一直占着。复现时，100 个这样的连接让主控从 31 MB 涨到 1032 MB，200 个涨到 2037 MB，客户端断开后才回落。在 1 GB 的 VPS 上会被 OOM 杀掉；`panic=abort` 下分配失败也会直接退出。
- **修复**：改为流式发送（`ReaderStream`），或者按文件名缓存一份 `Arc<Bytes>`，每次响应只复制引用。给 `/dl` 加并发上限，并补上 H2 的超时。也可以考虑要求带节点令牌才能下载。

### H2. 主控两种监听方式都没有超时和连接上限；`/api/login` 在认证前缓冲最多 2 MB

- **攻击者**：匿名，一台主机即可。**默认部署受影响**：是。
- **位置**：`master/src/main.rs:286-296`（`serve_tls`），`main.rs:411`（`-no-tls` 的 `axum::serve`），`master/src/api.rs:133-143`
- **问题**：每接受一个连接就无条件 `tokio::spawn`，唯一的超时是 TLS 握手的 10 秒。`http1::Builder` 没有配置 timer，所以 hyper 默认的 30 秒请求头超时实际上不生效。也没有空闲、keep-alive 或写超时。主控进程用的是默认的约 1024 个文件描述符，约 1000 个空闲连接就能让管理员和节点都连不上；攻击者断开后才恢复。另外，`Json<Login>` 会先把请求体（axum 默认上限 2 MB）完整读完，然后才执行登录限速，所以只发一半请求体的连接每个能占约 1.9 MB，约 500 个就让 1 GB 的机器 OOM。两种情况都已复现。
- **修复**：
  - `http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(10s)`，再加空闲超时和写超时。
  - 在 spawn 之前用全局和每 IP 的信号量限制连接数。
  - `/api/login` 加 `DefaultBodyLimit::max(4096)`。
  - `-no-tls` 路径做同样的处理；启动时提高 `RLIMIT_NOFILE`。

### H3. 默认 AnyTLS 入口让客户端跳过证书校验；认证值可重放、所有入口通用

- **攻击者**：网络中间人（公共 Wi-Fi、ISP、审查者），不需要任何凭据。**默认部署受影响**：是。
- **位置**：`master/src/db.rs:552-556`（新入口默认只开 AnyTLS，没有证书和 ACME），`master/src/sub.rs:73`（`verify=false`），`sub.rs:195/244/340/384`（各格式的 skip-cert-verify / insecure），`sub.rs:71`（各入口用同一个密码），`third_party/sing-anytls/service.go:65-68`
- **问题**：节点用自签证书，订阅的每种格式都告诉客户端不校验证书，也没有证书固定。AnyTLS 认证是在 TLS 里发送 `sha256(password)` 的 32 字节，没有服务器随机数。验证员用一个解开 TLS 的中继截获了这 32 字节，再拿去连真实节点，认证通过。中间人因此能读到所有目的地和明文数据，还能篡改；截获的值以后在该用户的所有入口都能用，而且凭据无法更换（L16）。开了 ACME 的入口也不保险：只有节点在线、并且正在上报一张有效的 ACME 证书时，订阅才开启校验（`sub.rs:453-465`）。签发失败、节点离线、主控刚重启还没收到上报的时候，订阅都会悄悄退回不校验。
- **修复**：
  - 节点把自签证书的 SHA-256 上报给主控，订阅里固定这个指纹：mihomo 用 `fingerprint`，sing-box 用 `certificate_public_key_sha256`，Surge 用 `server-cert-fingerprint-sha256`。
  - 或者新入口默认启用 ACME / Reality，需要明确选择才发布不校验证书的 AnyTLS。
  - 长期看，每个入口应该用不同的凭据（L17）。

### H4. 一帧节点上报就让主控瘫痪 70 天：面板、公开页、所有订阅、所有配置推送全部失败

- **攻击者**：持有任意一个节点令牌的人（被控节点）。**默认部署受影响**：是。
- **位置**：`master/src/db.rs:528-529`（SQL 里算 `up+down`，按 i64 读），`db.rs:575-583`（`store_usage` 不做任何校验），`master/src/app.rs:124-131`，`app.rs:56-64`
- **问题**：上报的 `(name, period, up, down)` 原样写进 usage 表。`load_world` 在 SQL 里计算 `up+down`，溢出后 SQLite 会把结果变成 REAL，rusqlite 按 i64 读取失败，整个 `load_world` 就出错。而 `load_world` 是 `/api/state`、`/api/public`、`/s/{token}`、所有配置推送（包括新节点连上时的首次推送）和 DNS 同步的唯一数据来源。这一行以攻击者的节点 id 为键，删节点时不会删，并且会被读取 70 天。复现结果：一帧 98 字节的上报之后，以上接口全部返回 500，禁用用户也推不到任何节点；删节点、重启都无效；把这行的时间改到 71 天前才恢复。
- **修复**：见修复计划第 1 条。至少要做到：拒绝负数，并限制上限；`up` 和 `down` 分开读，在 Rust 里饱和求和；`load_world` 跳过坏行；删节点时删除它的用量行。

### H5. VLESS 在检查 UUID 之前解析请求时可能 panic，整个 keel-node 崩溃；现有和已删除的用户都能触发

- **攻击者**：持有该入口 Reality 参数的人。这包括每个现有用户、每个已删除或已过期的用户（旧链接仍然有效），以及链接泄露后拿到它的任何人，不需要有效的 UUID。**默认部署受影响**：否，需要在入口上开启 VLESS（默认关闭）。
- **位置**：`cmd/keel-node/proto_vless.go:119`，`cmd/keel-node/inbound.go:53`（`go serve(conn)`，没有 recover），sing-vmess `vless/protocol.go:96-105`（`make([]byte, flowLen)` 没有上限，seed 字段有同样的问题），`vless/service.go:56-60`（先解析，后查 UUID），`master/src/db.rs:547`（每个节点只有一组 Reality 参数）
- **问题**：`ReadRequest` 在查 UUID 之前解析 addons。`readAddons` 读出一个 varint 长度后直接 `make`，最大可到 2^64-1，于是 panic：`makeslice: len out of range`。中等大小的值则会触发好几 GB 的分配，导致 OOM。keel 和这些库在这条路径上都没有 `recover()`，所以整个进程退出，所有入站和所有用户都会断开。Reality 握手是唯一的门槛，但它的参数所有用户共用、写在每条订阅里，而且删除用户时也不会更换。systemd 的 `Restart=always`、`RestartSec=3`、`StartLimitIntervalSec=0` 让这种崩溃可以无限重复。验证员写了单元测试，按 keel 的调用路径复现了这个 panic，过程见 EVIDENCE.md。
- **修复**：
  - 每个连接 goroutine 加 `defer func(){ recover() }()`，作为兜底。
  - vendor sing-vmess，让 `flowLen` 和 seed 的长度不能超过剩余字节数。
  - 删除用户时轮换 short id，或者改为每个用户一个 short id。
  - 同时修复 M14，让崩溃不再能刷掉用量。

### H6. 私网防护把 Azure WireServer `168.63.129.16` 当成公网地址；Azure 上的节点会被用户以 root 身份访问到它

- **攻击者**：Azure 上的入口（或者路由到 Azure 上出口）的任何订阅用户，只要流量走 direct。**默认部署受影响**：是，但只限 Azure。
- **位置**：`cmd/keel-node/outbound.go:224-231`（`isPublic`），`master/install.sh:58-63`（以 root 运行）
- **问题**：`isPublic` 只排除非全局单播地址、私网地址、CGNAT 和 `0/8`。`168.63.129.16` 是微软的公网地址段，TCP 和 UDP 都会放行，用解析到它的域名也一样。Azure 的 WALinuxAgent 防火墙只允许 uid 0 访问这个地址，而 keel-node 正好以 root 运行。用户因此能访问 WireServer（80 端口：goal state、ExtensionsConfig、Certificates）和 HostGAPlugin（32526 端口）。按公开研究（Mandiant 2024「WireServing Up Credentials」），能借此拿到租户证书，解密扩展的 protectedSettings，其中可能有 VMAccess 密码、SSH 密钥、自定义脚本里的密钥和 SAS 令牌。云平台上的效果没有在真实 Azure 上测试。
- **修复**：在 `isPublic` 里拒绝 `168.63.129.16/32`，并改用 IANA 特殊用途地址表（L33）。让 keel-node 以非 root 运行，只保留 `CAP_NET_BIND_SERVICE`（L37），这样 Azure 的防火墙规则就能生效。

### H7. Cloudflare DNS 令牌会下发到每个开了 ACME 的入口（面板却说它只存在主控里），一个被控节点就能接管整个 DNS zone

- **攻击者**：被控入口节点。**默认部署受影响**：否，需要在设置里填了 Cloudflare 令牌，并且在入口上开启 AnyTLS ACME。
- **位置**：`master/src/nodecfg.rs:88-101`、`nodecfg.rs:213-214`（`dns_token` 原样写进节点配置），`master/web/app.js:850`（面板文案「只存在主控里」），`cmd/keel-node/main.go:175`（写进 `/etc/keel/node.json`），`master/src/api.rs:203-214`（只有自签主控的安装命令带指纹）
- **问题**：面板要求的令牌权限是「区域 DNS 编辑」，作用于整个 zone，而不只是该节点自己的域名。这个 zone 里一般有所有入口的 AnyTLS 记录，往往也有面板自己的域名。拿到令牌的节点可以：
  - 把面板域名指向自己，用 DNS-01 签一张受信任的证书，再反向代理到真实面板，从而拿到管理员的 cookie 和密码；
  - 主控用 `-cert` 或 `-no-tls` 时，节点只靠 CA 校验认主控，所以它还能冒充主控接收所有节点的令牌、推送任意配置；`agent update` 会以 root 运行下载的程序，所以等于拿到所有节点的 root；
  - 把其他入口的域名指向自己。
  
  已经复现：面板里填入令牌、开启 ACME 后，用假节点连上去，收到的配置里就有这个令牌。
- **修复**：
  - 主控代做 DNS-01：节点经控制通道发送 key authorization 的摘要，主控根据数据库里该节点的 `anytls_sni` 自己拼出 `_acme-challenge` 记录名再创建，不用消息里的名字。或者由主控签好证书，只发给对应的节点。
  - 在此之前先改正面板文案，并提醒已经填过令牌的管理员作废换新。
  - 不管主控用哪种证书，安装命令都带上证书或公钥固定。

---

## 中危

### 主控：节点通道与记账

- **M1. 任何节点都能给任何用户、任何周期写用量，包括负数**（被控节点；默认受影响）
  - **位置**：`master/src/db.rs:469-475`、`db.rs:575-583`、`master/src/nodecfg.rs:260-263`、`master/src/app.rs:124-131`
  - **问题**：主控不检查计数是否属于上报的节点。不服务该用户的入口、甚至出口节点，都可以写入 `u<id>`。写一个大值，主控推给其他入口的 `used_base` 就会超过额度，用户在所有入口都被封（已用真实的 keel-node 复现，日志显示 `user u1 blocked: quota used up`）；写负值则会让额度失效。
  - **修复**：同修复计划第 1 条，并且忽略出口节点上报的用户计数。
- **M2. 节点控制的网卡流量差值让 `node_month` 溢出成 REAL，本月剩下的时间里 `/api/state` 和匿名 `/api/public` 一直返回 500**（被控节点；默认受影响）
  - **位置**：`master/src/app.rs:143-157`、`db.rs:586-599`、`api.rs:292`
  - **问题**：`net_rx` 先报 `i64::MAX` 再报一个小值，就能触发溢出，重启也不能恢复；删除该节点（会级联删除）或者到下个月才恢复。如果报负数，月流量会变成负值。订阅和配置推送不受影响。
  - **修复**：差值钳制在合理范围内，丢弃负数，读取时容错。
- **M3. 换令牌或删节点不会结束已经建立的连接：被盗的令牌还能收到完整配置，并持续写入用量**（持有被盗令牌的人或被控节点；默认受影响）
  - **位置**：`master/src/ws.rs:52`、`ws.rs:64-97`、`ws.rs:104-135`、`master/src/app.rs:171-178`
  - **问题**：令牌只在升级 WebSocket 之前检查一次。在令牌有效时完成升级的连接，换令牌后再发 hello，仍会被注册，并收到带最新密钥的配置。`kick()` 只是往无界队列里放一个 Close；连接停止读取时，Close 永远发不出去，而读循环会继续处理上报。复现中，换令牌 196 秒后，这个连接还在给用户写用量。
  - **修复**：每个节点维护一个代号，换令牌或删节点时递增，serve 循环里核对代号；`kick()` 直接中止 serve 任务；丢弃不是当前连接的上报。
- **M4. 节点能让主控存储的数据无限增长**（被控节点；默认受影响）
  - **位置**：`master/src/live.rs:156-171`、`ws.rs:137-146`、`db.rs:527-532`、`db.rs:601-602`
  - **问题**：用量行的名字由节点决定，保留 400 天，并且每次 `load_world` 都要全部读一遍。探测历史以节点给的名字为键，从不清理，节点断开也不清。`max_frame_size` 用的是 16 MiB 的默认值，比消息上限 4 MiB 还大。
  - **修复**：同修复计划第 1 条；只保留配置里有的探测名，连接断开时清掉；上报加限速。
- **M5. 每个节点连接的发送队列没有上限，写入也没有超时**（被控节点；默认受影响）
  - **位置**：`master/src/ws.rs:73`、`ws.rs:89-97`、`app.rs:56-95`
  - **问题**：节点只要继续上报、但不读数据，主控每推送一次配置，内存就多占一份完整配置。
  - **修复**：改用有界队列，只保留最新的一份配置；`sink.send` 加超时，超时就断开。

### 主控：HTTP、登录、传输

- **M6. 匿名请求 `/api/public` 会重新计算整个管理员视图，而且是在异步线程上持有全局 std 锁**（匿名；默认受影响）
  - **位置**：`master/src/api.rs:257-258`、`api.rs:287-297`、`db.rs:469-475`
  - **问题**：每次请求的开销是 O(用户数 × 用量行数)，阻塞的是 tokio 的工作线程。少量并发就能卡住节点上报、配置同步和管理员操作；被控节点灌入的用量行（M4）会让情况更糟。
  - **修复**：公开页使用每几秒重建一次的快照；用量预先聚合；SQLite 调用移到 `spawn_blocking`；按 IP 限速。
- **M7. 全局登录锁定：10 分钟内 100 次失败就锁住所有人，包括输对密码的管理员**（匿名；默认受影响）
  - **位置**：`master/src/api.rs:107-131`、`api.rs:139-143`、`master/src/ws.rs:25-37`
  - **问题**：TLS 模式下需要 10 个 IPv4 地址，或者同一个 IPv6 /64 里的 10 个地址；`-no-tls` 时伪造 `X-Forwarded-For`，一台主机就够。每 10 分钟重复一次，管理员就一直无法重新登录（已登录的会话不受影响）。
  - **修复**：全局计数只用来减速，不能拒绝正确的密码；只信任反代追加的最右一跳 XFF；IPv6 按 /64 计数。
- **M8. 节点握手失败时，两端都会留下一个 keep-alive 连接；被吊销或没人管的节点会慢慢耗尽主控的文件描述符**（被吊销的节点，不需要主动攻击者；默认受影响）
  - **位置**：`cmd/keel-node/master.go:100-138`、`master/src/ws.rs:52-56`
  - **问题**：节点每次重连都新建一个 `http.Transport`，401 之后从不关闭空闲连接；主控也没有空闲超时，一直保持着这个连接。按重连退避上限计算，每天约 1900 个连接。
  - **修复**：节点复用同一个 Transport，或者关闭 keep-alive，并在 401 后延长退避；主控在 401 响应上加 `Connection: close`，再加超时（H2）。
- **M9. 四个没有请求体的 POST 存在同站 CSRF：换节点令牌、重置流量、重置订阅、登出**（同站来源，比如被控入口在面板同一个 zone 里的域名上提供 HTTPS；不是默认情况）
  - **位置**：`master/src/api.rs:81-87`、`api.rs:634-643`、`api.rs:917-936`、`api.rs:179-185`
  - **问题**：`SameSite=Strict` 拦不住兄弟子域名，而 keel 自己就会为节点创建这样的子域名。复现：管理员打开一个页面，所有节点的令牌被更换，节点永远连不回来，必须逐台重装；所有订阅链接失效；用户的额度周期被重置。
  - **修复**：对非 GET 请求检查 `Sec-Fetch-Site`/`Origin`，或者要求一个简单请求无法携带的请求头；cookie 改名为 `__Host-` 前缀（L9）。
- **M10. `-no-tls` 时反代没有设置 `X-Forwarded-Proto`，安装命令、订阅链接和节点控制地址都会变成 http://**（网络中间人；不是默认情况）
  - **位置**：`master/src/api.rs:190-214`、`master/src/sub.rs:470`、`cmd/keel-node/master.go:288-307`
  - **问题**：nginx、Apache、HAProxy 默认都不设置这个头。结果是 `curl http://…/install.sh | sh` 以 root 执行，节点令牌和所有下发的配置都以明文传输，`-fingerprint` 也被悄悄绕过。`panel_url` 在面板里没有设置入口，节点对 http/ws 地址也不给任何警告。
  - **修复**：有反代时 scheme 默认 https；面板提供 `panel_url` 设置，地址是 http 时给出警告；节点拒绝非本机的 `ws://`，并且 `ws://` 和 `-fingerprint` 同时出现时直接报错。
- **M11. 面板默认用自签证书，管理员习惯了点过浏览器警告，中间人就能在登录时拿到密码和 30 天的会话**（网络中间人；默认受影响）
  - **位置**：`master/src/main.rs:92-123`、`main.rs:357-370`
  - **问题**：唯一能用来核对的是启动日志里那行指纹，但它的标签写的是给 keel-node 用的。拿到会话的人可以继续拿到所有节点令牌和用户凭据。
  - **修复**：面板默认用 ACME 签证书（可以复用节点的代码）；或者自签时把管理接口只绑在 127.0.0.1，配合 SSH 隧道使用；至少在文档里说明如何在浏览器里核对证书指纹。
- **M12. 在面板里删除的节点，或者换了令牌的节点，会永远用最后一份缓存配置继续提供服务**（被撤销后的用户；默认受影响）
  - **位置**：`cmd/keel-node/master.go:100-121`、`cmd/keel-node/main.go:60-72`、`master/web/app.js:1059`
  - **问题**：节点把 401 当作普通的网络故障，只是退避重连，入站和用户表保持不变。之后禁用或删除用户、更改额度、换月，都到不了这个节点。面板却提示「节点会断开」。这一条已用真实的 keel-node 复现，我也核对了代码和面板文案。
  - **修复**：把 401（或者一个明确的「已撤销」关闭码）当作吊销：宽限一段时间后停止所有入站、清空缓存配置；面板的删除对话框给出卸载命令，并改正文案。

### 节点：入站与额度

- **M13. Vision 的 `filterTLS` / `unPadding` 用客户端给的偏移量切片，会越界 panic，节点崩溃**（任何有效的 VLESS-Vision 用户；默认不开 VLESS）
  - **位置**：sing-vmess `vless/vision.go:257-260`、`vision.go:353`、`master/src/nodecfg.rs:254`
  - **修复**：加 recover 兜底（同 H5）；vendor sing-vmess，在两处切片前检查边界，并加上 fuzz 测试。
- **M14. 崩溃会丢掉最近存盘以来的用量，主控还用较小的值覆盖，所以不断让节点崩溃就能不受额度限制**（能让节点崩溃的订阅用户；默认受影响，可以经由 M17 的 OOM 触发）
  - **位置**：`cmd/keel-node/main.go:34`、`main.go:140-143`、`users.go:104-107`、`master/src/db.rs:577-578`
  - **修复**：同修复计划第 4 条。
- **M15. `acceptLoop` 遇到任何非超时的 Accept 错误（比如 EMFILE）就永久退出，进程本身不退出，所以 systemd 也不会重启它**（短暂耗尽文件描述符的人；默认受影响）
  - **位置**：`cmd/keel-node/inbound.go:43-51`、`main.go:271-284`
  - **问题**：端口还处在监听状态，内核继续完成握手，但没有人 accept，客户端只能挂着。要等进程重启，或者管理员改动这个入站才能恢复。
  - **修复**：遇到临时错误时退避重试，做法和 `net/http` 一样。
- **M16. 入站在认证前没有任何超时，也没有连接数上限**（匿名；默认受影响）
  - **位置**：`cmd/keel-node/proto_ss.go:63`、`proto_anytls.go:71-85`、`proto_vless.go:108-119`、utls `reality.go:326`
  - **问题**：SS2022 的连接连上后什么都不发，就会一直占着一个 goroutine 和一个 fd；AnyTLS 握手后的读取、以及 Reality 读取 ClientHello 也都没有超时。大量这样的连接会把节点推向 M15。
  - **修复**：同修复计划第 3 条。
- **M17. AnyTLS 的流数、连接数、UDP 会话都没有每用户上限；不发地址的流会永远挂着，而且不受跟踪**（订阅用户；被控入口也能用这种方式攻击共享的出口；默认受影响）
  - **位置**：`third_party/sing-anytls/session/session.go:211-221`、`service.go:111-118`、`cmd/keel-node/handler.go:40-41`、sing-vmess `mux.go:124-137`
  - **问题**：一个 7 字节的 SYN 就能占住一个 goroutine 和一个流，用户被删除时 `closeAll` 也清不掉它们。单个用户就能把节点撑到 OOM。sing-vmess 的 mux 在 session id 重复时，会把旧的转发 goroutine 丢下不管。
  - **修复**：每个会话限制流数；读地址前设置超时；把会话本身纳入 `user.conns`；mux 拒绝重复的 session id；加每用户的连接数和 UDP 会话数上限。

### 节点：主动探测特征

- **M18. 默认的 AnyTLS 自签证书带有 `O=keel-node self-signed`，有效期 10 年，对任何 SNI 都返回同一张证书；非 AnyTLS 数据立刻断开，没有 ALPN**（匿名探测者或审查者；默认受影响）
  - **位置**：`cmd/keel-node/cert.go:47`、`cert.go:102-104`、`cert.go:77-82`
  - **问题**：TLS 1.2 握手时证书以明文传输，扫一下就能认出这是 keel 节点。
  - **修复**：去掉 Organization，有效期改为常规长度，不用 `CN=localhost`；检测到旧证书带这个标识就重新生成；优先使用 ACME 或管理员提供的证书。
- **M19. Reality 回落时不转发 dest 的 TCP 关闭（metacubex/utls v1.8.4），匿名探测者能把 keel 的 VLESS 节点和 dest 区分开，每次探测还会在节点上占住两个 socket**（匿名探测者；默认不开 VLESS）
  - **位置**：utls `reality.go:424`、`reality.go:547-553`、`cmd/keel-node/proto_vless.go:106-117`
  - **问题**：两个方向的 `io.Copy` 结束后都没有调用 `CloseWrite`。上游 XTLS/REALITY 两个方向都会调用（`tls.go:290`、`:456`），这一点我在源码里核对过。复现：同一个 ClientHello，直连 dest 时 20 秒收到 EOF；经过 keel 节点，45 到 50 秒后连接仍然开着。100 个探测连接让节点上出现 100 个 ESTABLISHED 和 100 个 CLOSE_WAIT，每个约 70 KB，要等探测方自己断开才释放。
  - **修复**：vendor utls（和 third_party 下另外两个库一样），移植上游的半关闭处理；回落连接也加空闲上限。

### 节点：私网防护与出站

- **M20. 防护不排除节点自己的地址：用户能经 `lo` 访问到绑在 `0.0.0.0`/`::` 或公网 IP 上的服务，绕过主机防火墙和云防火墙**（订阅用户；默认受影响）
  - **位置**：`cmd/keel-node/outbound.go:224-248`、`outbound.go:415`
  - **问题**：会被绕过的有：接受回环流量的主机防火墙规则（例如 ufw 的 `-i lo -j ACCEPT`）、VM 外部的云防火墙（DigitalOcean、Vultr、Hetzner、Linode，以及 AWS/OCI 对网卡上 IPv6 地址的安全组），还有 Docker 的 `DOCKER-USER` 限制。只绑在 127.0.0.1 上的服务不受影响。
  - **修复**：定期读取本机接口地址，拒绝这些地址和定向广播；在 Linux 上，也可以在 Control 钩子里查路由表，拒绝 `RTN_LOCAL`、`RTN_BROADCAST`、`RTN_MULTICAST`。
- **M21. 内嵌 IPv4 的 IPv6 地址（`64:ff9b::/96`、`64:ff9b:1::/48`、`2002::/16`、`::/96`、Teredo）能绕过防护**（订阅用户；只在节点 `ipv4_only=false` 且网络里有 NAT64/6to4 时；可信度：「可能」）
  - **位置**：`cmd/keel-node/outbound.go:224-231`、`master/src/db.rs:23`（`ipv4_only` 默认是 1）
  - **修复**：先解码出内嵌的 IPv4，再按 IPv4 的规则判断；`64:ff9b:1::/48`、`::/96`、`2001::/32` 直接拒绝。
- **M22. 健康检查读取状态行时不限长度，并且把它原样上报：出口的另一端能让入口一直掉线，甚至 OOM**（被控出口或者第三方商家；默认受影响）
  - **位置**：`cmd/keel-node/health.go:184-190`、`health.go:98-137`
  - **问题**：一行 800 KiB 以上的状态行，就能让上报超过主控 4 MiB 的消息上限，主控每次都会断开这个入口。
  - **修复**：读取限制在 512 字节以内，错误信息截断。

### 订阅

- **M23. 默认的 mihomo 和 Surge 订阅，为了判断 `GEOIP,CN`，会把用户访问的境外域名发给国内 DNS 解析**（国内 DNS 运营方，以及能要求它们提供数据的人；默认受影响）
  - **位置**：`master/src/sub.rs:160-173`、`sub.rs:231`、`sub.rs:328`、`sub.rs:362`；sing-box 配置（`sub.rs:286-293`）不受影响
  - **问题**：`GEOIP,CN` 没有加 `no-resolve`。前面规则没有匹配到的境外域名，会交给 AliDNS 或 doh.pub 解析，结果就是国内解析服务器上留下了每个用户访问被墙网站的记录。
  - **修复**：`GEOIP,CN` 加 `no-resolve`；或者像 sing-box 配置那样，用 nameserver-policy 只把 geosite:cn 交给国内 DNS，其余域名经代理用境外 DoH 解析。

---

## 低危

| 编号 | 问题 | 位置 | 修复要点 |
| --- | --- | --- | --- |
| L1 | `-no-tls` 时节点地址直接取 XFF 最左边的值，不做校验。这个地址会写进其他入口的出口地址、订阅和 Cloudflare A 记录。任何持有节点令牌的人换一个源地址重连，也能改写它 | `master/src/ws.rs:25-37` | 解析为 IP，拒绝非公网地址；只取反代追加的最右一跳 |
| L2 | 用户 id 会被复用，新用户会继承已删用户本周期的用量 | `master/src/db.rs:566-571` | 用 `fresh_id`，或者 AUTOINCREMENT |
| L3 | 节点上报的字符串原样写进主控日志，可以伪造日志行 | `master/src/app.rs:166` | 用 `{:?}` 转义并截断 |
| L4 | 上报里任何一个字段类型不对，整帧（包括用量）都会被丢弃；sysstat 的无符号减法可能下溢触发这种情况 | `master/src/ws.rs:111-116`，`cmd/keel-node/sysstat.go:62` | `system` 段单独、宽松地解析；用饱和减法 |
| L5 | 同一周期内把用户从节点配置里删掉再加回，该节点的用量归零，主控随后用这个较小的值覆盖 | `cmd/keel-node/users.go:97-123` | 节点保留已删用户的计数直到周期结束；主控在同一周期内只升不降 |
| L6 | 换节点令牌不会更换节点已经拿到的任何密钥；出口 PSK 根本无法轮换 | `master/src/api.rs:634-643`，`nodecfg.rs:195-201` | 每个入口一个盐值参与 `exit_key`，换令牌时重新生成；出口提供「换密钥」 |
| L7 | 每次节点 hello 都会触发完整的配置重建和一次 Cloudflare 同步，没有节流 | `master/src/ws.rs:86-99`，`dns.rs:51-90` | 去抖；地址没变就不调用 Cloudflare |
| L8 | 设置里校验当前密码没有失败计数，argon2 在异步线程上运行，而且持有数据库锁 | `master/src/api.rs:946-948` | 走登录的限速逻辑；放到 `spawn_blocking` |
| L9 | 会话 cookie 没有 `__Host-` 前缀，同站兄弟域名可以写入一个同名 cookie，让管理员无法登录 | `master/src/api.rs:66-72` | 改名为 `__Host-keel_session` |
| L10 | `install_command` 把 base URL 不加引号拼进 root 执行的 shell 命令；`panel_url` 和 Host 基本不做校验 | `master/src/api.rs:203-214` | 校验后再做 shell 引用 |
| L11 | 会话令牌明文存在数据库里，拿到一份数据库副本就等于拿到 30 天的管理员权限 | `master/src/db.rs:115` | 只存 sha256 |
| L12 | `/api/state` 每 2 秒下发一次所有用户的订阅链接；含密钥的响应没有 `Cache-Control: no-store` | `master/src/api.rs` | 所有 `/api/*` 响应加 no-store；订阅链接改为按需获取 |
| L13 | 匿名探针页无法关闭，公开了拓扑、节点名、在线状态和流量 | `master/src/api.rs:254-285` | 加一个开关（默认关闭），或者放到随机路径下 |
| L14 | 主控很容易被识别：自签证书 CN 是 `rcgen self signed cert`，SAN 是 `keel-master`，有效期 1975 到 4096 年；根路径就是 keel 页面 | `master/src/main.rs:104` | 证书用中性的信息和常规有效期；探针页改为可选 |
| L15 | 被控的 ACME 节点上报一个超大的证书时间戳，就能让自己的节点抽屉打不开（RangeError），管理员没法在面板里删它或换令牌 | `master/web/app.js:588` | 服务端钳制时间戳；前端加容错 |
| L16 | 「重置订阅」只更换订阅令牌，用户的代理凭据（`anytls_password`、`uuid`、`ss_key`）永远不能换，订阅泄露后只能禁用或删除用户 | `master/src/api.rs:930-936` | 重置订阅时一并重新生成凭据，并同步到节点 |
| L17 | 每个用户只有一套凭据，会推送到他能用的所有入口，所以一个入口被控就能拿到在所有入口都有效的凭据 | `master/src/nodecfg.rs:244-270` | 每个入口用派生凭据（HMAC） |
| L18 | 安装过程中，节点令牌出现在进程参数里（`sh -s -- --token`、`curl -H`），也会留在 root 的 shell 历史里 | `master/src/api.rs:209` | 改用环境变量传递 |
| L19 | 导入的 SS-2022 密钥不做校验，一条坏链接会让所有用到它的入口拒收之后的每份配置，禁用或删除用户都推不下去 | `master/src/link.rs:149` | 导入时校验 base64 解码后的长度 |
| L20 | 导入接受回环、内网、元数据地址的出口，而节点连接出口服务器时不经过私网防护 | `master/src/link.rs:227`，`cmd/keel-node/outbound.go:262` | 导入时拒绝这类地址；`dialServer` 也做检查 |
| L21 | 生成的客户端配置从 GitHub 分支的最新版本加载第三方规则列表，上游被入侵就能让用户流量直连，或者改掉 DNS | `master/src/sub.rs:122` | 固定到具体 commit，或者由主控提供 |
| L22 | 导入链接里的控制字符、双向文本字符、ANSI 转义序列原样成为出口名和地址，并经 `agent` 输出到 root 的终端 | `master/src/link.rs:73-91` | 导入时拒绝这类字符；`agent` 输出时转义 |
| L23 | SS2022 出口对任何首段数据都立即关闭，用 FIN 还是 RST 暴露了 59 字节的头部长度，而且从不超时（主动探测特征） | `cmd/keel-node/proto_ss.go:61-69` | 统一失败时的行为，并加读取超时 |
| L24 | AnyTLS 每次认证失败都写日志（不受 `-v` 控制），在 OpenRC 下可能写满小硬盘 | `cmd/keel-node/proto_anytls.go:85-88` | 只在 verbose 模式下记录，或者限速 |
| L25 | 删除或封禁用户只会关闭已经进入 handler 的流，不会关闭 AnyTLS 会话和 VLESS mux 的承载连接。新的流仍会被拒绝，但会话一直残留；用户重新启用后，会话不经认证就恢复使用 | `cmd/keel-node/handler.go:21-27` | 跟踪会话本身（同 M17） |
| L26 | SS2022 的防重放表在认证之前就记下 salt，匿名请求就能让内存增长 | `third_party/sing-shadowsocks/shadowaead_2022/service_multi.go:144-147` | 认证成功后再记录 |
| L27 | 所有 keel 入口的 Reality 默认伪装都一样：SNI 和 dest 都是 `www.apple.com`，端口是随机的高位端口 | `master/src/db.rs:552-556` | 让管理员选择，或者从一个列表里随机选；默认用 443 |
| L28 | Reality 用的 `metacubex/utls` 没有 Go 的 GO-2026-6090 修复，持有 Reality 参数的人可以无限发送 KeyUpdate 消耗 CPU。影响是暂时的，放大约 1:1（验证员评为中危，我降为低危） | `cmd/keel-node/proto_vless.go:109` | vendor utls，回移标准库的修复 |
| L29 | UDP 会话只按第一个目的地路由一次（旧版 UoT 总是走 final），之后的包会绕过分流规则（仍然经过私网防护） | `cmd/keel-node/outbound.go:179-204` | 按包路由 |
| L30 | 直连 UDP 会话缓存解析结果没有上限，而且在写路径上同步解析，没有超时 | `cmd/keel-node/outbound.go:370-375` | 改用 LRU 缓存，加超时 |
| L31 | SOCKS 出站握手没有超时，不回应的 SOCKS 服务器会卡住转发，也让健康状态一直不更新 | `cmd/keel-node/outbound.go:291-301` | 握手加 deadline |
| L32 | VLESS 出站按设计是明文：入口和商家之间能看到商家 UUID、目的地和数据；健康检查的 User-Agent 是 keel-node | `cmd/keel-node/outbound_vless.go:12-41` | 支持 TLS/Reality；改用中性的 UA |
| L33 | `isPublic` 会放行 IANA 的非全局地址段（`192.0.0.0/24`、TEST-NET、`198.18/15`、`240/4`、`fec0::/10` 等），也识别不了定向广播 | `cmd/keel-node/outbound.go:224-231` | 按 IANA 特殊用途地址表拒绝 |
| L34 | 路由到 socks、vless 或第三方 SS 出站的私网目的地不做检查（防护只在 direct 上） | `cmd/keel-node/outbound.go:291-301` | 非 keel 出站也拒绝私网 IP 字面量 |
| L35 | 证书剩余寿命不足 30 天时，ACME 续期循环会毫无延迟地反复下单（Let's Encrypt 目前的默认证书不会触发） | `cmd/keel-node/acme.go:204-238` | 按证书寿命的比例安排续期，并设最小间隔 |
| L36 | `writeFileAtomic` 用固定的 `.tmp` 文件名，不 fsync，还会跟随符号链接；断电后缓存配置可能被截断，主控模式的节点就起不来 | `cmd/keel-node/main.go:185-194` | 用 `CreateTemp`，写完 `Sync` 再改名，并 fsync 目录；解析失败时回退 |
| L37 | keel-node 以完整的 root 权限运行；`ProtectSystem=full` 而不是 strict，也没有限制能力集；单元文件里「只写 `/etc/keel`」的注释与事实不符；OpenRC 没有沙箱 | `master/install.sh:64-81` | `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`，改用 `ProtectSystem=strict` 等 |
| L38 | go.mod 写的是 `go 1.24.0`，设置 `GOTOOLCHAIN=local` 时会用旧的标准库悄悄完成构建 | `go.mod:3` | `go` 指令升到 1.26.10 |
| L39 | `go 1.24.0` 让二进制带上 Go 1.24 的 GODEBUG 默认值（`tlssha1=1`），AnyTLS 端口在 TLS 1.2 下用 SHA-1 签名 | `go.mod:3` | 同上，或者设置 `godebug tlssha1=0` |
| L40 | vendor 进来的 sing-anytls 把默认填充方案从 `stop=8` 改成了 `stop=3`，客户端之后的记录（包括内层的 CCS/Finished）不再填充 | `third_party/sing-anytls/padding/padding.go:17-20` | 恢复上游的方案，或者由主控下发 |
| L41 | 主控的 release 构建用 `panic="abort"`，又没有守护进程，任何 panic 或 OOM 都会导致整站中断；overflow-checks 也是关着的 | `master/Cargo.toml:34` | 提供带 `Restart=always` 的 systemd 单元；关键的算术改用 checked 运算 |

## 提示

| 编号 | 问题 | 位置 | 建议 |
| --- | --- | --- | --- |
| I1 | Reality 没有设置时间窗口，回落也不限速（和上游的默认行为一致） | `cmd/keel-node/proto_vless.go:71-78` | 修好 M19 后，可以考虑下发 `max_time_diff` |
| I2 | `server_name` 未经校验就用作 ACME 文件名（只有管理员能控制） | `cmd/keel-node/acme.go:187-189` | 校验必须是合法域名 |
| I3 | 签发的 ACME 证书不校验域名和有效期；接受 `http://` 的 `ca` | `cmd/keel-node/acme.go:282-306` | 写入前先校验 |
| I4 | 开了 ACME 的 AnyTLS 入站对任何 `acme-tls/1` 请求都回 internal_error，DNS-01 节点也一样 | `cmd/keel-node/acme.go:158-176` | 只在 tls-alpn 模式并且有挑战进行时才处理 |
| I5 | `account.key` 的类型断言不做检查，遇到不能签名的密钥节点会 panic | `cmd/keel-node/acme.go:321-325` | 检查类型 |
| I6 | 默认探测目标是第三方域名，每次都重新解析，而且不经过私网过滤；结果是公开的 | `cmd/keel-node/probe.go:138-165` | 解析后过滤，或者直接用 IP |
| I7 | CSP 缺少 `base-uri` 和 `form-action`（目前没有找到注入点） | `master/src/main.rs:226-231` | 补上 `base-uri 'none'; form-action 'self'` |
| I8 | 设置表单的第一个密码框是 Cloudflare 令牌，密码管理器可能把管理员密码填进去 | `master/web/app.js:848` | 设置正确的 `autocomplete` 属性 |
| I9 | 探测目标名不经转义就拼进 input 的 name 属性（只有管理员能改，也是唯一一个未转义的服务端字符串） | `master/web/app.js:837` | 用 `esc()`，并在服务端校验 |
| I10 | 首次启动时的密码打印在日志里；`-password NEW` 会留在 argv 和 shell 历史里 | `master/src/main.rs:343-347` | 写进一个 0600 的文件 |
| I11 | `health_check.url` 通过了校验但 `url.Parse` 失败时会是 nil，健康检查 goroutine 会 panic，缓存配置又让节点反复崩溃（只有主控能控制这个值） | `cmd/keel-node/config.go:254-256` | 在校验时就解析 URL |
| I12 | install.sh 会悄悄覆盖已有的 `/usr/local/bin/agent` | `master/install.sh:42` | 已存在时不覆盖 |
| I13 | 依赖：govulncheck 没有发现可达的漏洞；cargo-audit 只报了 rustls-pemfile 停止维护 | `go.mod`，`master/Cargo.lock` | 顺手升级 x/crypto、klauspost/compress、x/sys；换成 rustls-pki-types |
| I14 | IPv6 的出口地址写进入口配置时没有加方括号，入口连不上走 IPv6 的出口（功能问题） | `master/src/nodecfg.rs:198` | 加上方括号 |
| I15 | 文档说节点不使用 `HTTP(S)_PROXY`，但 ACME 和 Cloudflare 的请求用的是 `http.DefaultClient`，会使用这两个环境变量 | `cmd/keel-node/acme.go:66`、`:341` | 改用 `Proxy: nil` 的专用 client，或者改正文档 |

被推翻的 1 条：「hello 里的 `config_rev` 和主控存的相同时，不做首次推送」。这个行为是有意为之，离线期间的改动之后仍会推送下去，没有安全影响。

---

## 核实为安全的部分（节选）

- **路由鉴权**：14 个私有路径在所有 HTTP 方法和各种路径变体（尾斜杠、`//`、大小写、`%2f`、`..`）下，未登录时都返回 401。`/api/session` 只返回 `logged_in`；`/api/public` 用白名单过滤，不含用户、订阅链接和设置。
- **会话**：令牌 192 位，用 CSPRNG 生成；过期由服务端判断；登出、在面板里改密码、在命令行改密码都会让其他会话失效；不存在会话固定。cookie 带 HttpOnly、Secure、SameSite=Strict，`-no-tls` 模式下同样带 Secure。
- **注入**：所有 SQL 都参数化。Clash YAML 的值全部用 JSON 引号转义，sing-box 配置完全由 serde_json 生成，订阅里没有注入。`/dl` 用文件名白名单，不存在路径穿越。订阅令牌 128 位，不可能枚举。
- **面板 XSS**：422 处模板插值逐一核对过，节点上报的和第三方的字符串全部经过 `esc()`；没有 href、src、eval 之类的危险接收点；节点即使上报极端的数值，页面也能正常渲染。唯一没有转义的是 I9，只有管理员能改。
- **节点到主控的证书固定**：校验叶子证书的 SHA-256，空证书链会被拒绝，指纹格式不对时启动失败（fail closed）。令牌只放在 Authorization 头里，不经过代理，跨主机重定向时也不会带上。
- **节点本地文件**：`/etc/keel` 权限 0700；缓存配置、用量状态、私钥都是 0600；`status.json` 逐个字段核对过，不含密码和令牌；`agent update` 的临时文件在 root 拥有的目录里，本地用户无法替换。
- **私网防护的主体**：检查放在 Dialer 的 Control 钩子里，针对每次实际连接的地址。所以 DNS 重绑定、多条 A 记录、Happy Eyeballs、`::ffff:` 映射地址、各种 `localhost` 写法、数字形式的 IP 都会被挡住；UDP 逐包检查；出口节点上同样生效。
- **third_party**：和上游 v0.0.11 / v0.2.8 逐文件 diff，只有 MODIFICATIONS.md 里列出的改动。原子替换用户表的实现是正确的，SS2022 在 TCP（salt 加时间窗）和 UDP（滑动窗口）上的防重放都完好。`go mod verify` 全部通过。
- **ACME**：用的是 `x/crypto/acme` 库，不是自己实现的。http-01 只响应确切的挑战路径；tls-alpn 证书只在挑战进行期间提供，而且只对应本机域名。

## 依赖扫描

- **govulncheck**（带构建标签）：没有可达的漏洞。23 个模块级公告都在没有用到的包里：x/crypto 的 ssh 和 openpgp、klauspost/compress 的 s2、x/sys 的 windows。
- **cargo-audit**：只有 RUSTSEC-2025-0134（rustls-pemfile 停止维护）。
- **扫描器看不到的部分**：`metacubex/utls` 是 crypto/tls 的分叉，没有对应的 OSV 条目。它缺少 Go 标准库近期的修复（L28），Reality 回落的行为也和上游不同（M19）。这两点是人工比对源码发现的。

## 局限

- 所有测试都在 macOS 本机回环上进行。Linux 特有的行为（`/proc` 解析、splice、systemd 沙箱的实际效果、`lo` 投递和各种防火墙规则）是通过读代码和文档判断的。
- 和云平台有关的结论（Azure WireServer 能拿到什么、NAT64 网关的行为）依据的是公开资料，没有在真实的云上测试。
- DoS 只做了小规模复现（几百 MB 内存、几百个连接）再按 1 GB 的 VPS 外推，没有真的把机器打满。
- 第三方协议库（sing、sing-vmess、utls）只审了 keel 实际用到的路径。
- 只审计了 `main` 分支，未合并的分支不在范围内。
- 复现脚本在本次会话的临时目录里，没有放进仓库。
