# keel

自建的轻量代理面板 + 探针，用来替代 3x-ui。只支持三种协议：AnyTLS、VLESS Reality（含 Vision）、Shadowsocks 2022。

- **keel-node**（Go，本仓库 `cmd/keel-node`）：每台服务器一个进程，跑代理、按用户统计流量、在本地执行额度和到期。节点分两种角色，用的是同一个程序：
  - **入口**：用 AnyTLS / VLESS Reality 接客户端，按用户计流量和额度，再按规则把流量分给不同出口（经 SS 2022），或者直连、走 SOCKS。
  - **出口**：只开 SS 2022，每个入口在出口上是一个用户。
- **keel-master**（Rust，本仓库 `master/`）：网页面板 + SQLite + 订阅链接，一个进程一个端口。节点主动用 WebSocket over TLS 连主控，节点自己不开任何管理端口。协议见 [docs/node-protocol.md](docs/node-protocol.md)。

## keel-node

直接用 sing 系列的协议库，不经过 sing-box 的路由、DNS、规则框架，所以程序小、内存低。

| 协议 | 库 |
| --- | --- |
| AnyTLS | `third_party/sing-anytls`（改过的 sing-anytls，改动见其 MODIFICATIONS.md） |
| VLESS + Vision | sing-vmess/vless |
| Reality 服务端 | metacubex/utls（和 sing-box 用的是同一个） |
| SS 2022 多用户服务端和客户端 | `third_party/sing-shadowsocks`（修了多用户表的并发问题） |

### 构建

协议用构建标签挑，没用到的不编进去：

```sh
make node-linux PROTOCOLS=anytls            # 只要 AnyTLS
make node-linux PROTOCOLS=anytls,vless,ss   # 三种都要
```

VLESS 必须同时带 `with_utls` 标签（Vision 靠它识别 Reality 连接），Makefile 会自动加；直接用 `go build -tags vless` 会编译报错提醒。

| 构建 | linux-amd64 大小 | 空闲内存 | 8 路并发下载时 |
| --- | --- | --- | --- |
| 只有 anytls | 7.9 MB | 7.4 MB | 14.1 MB |
| anytls + vless + ss | 9.5 MB | 8.7 MB | 15.2 MB |

大小包含主控连接（WebSocket / HTTP 客户端）、出口健康检测和自动申请证书；最早只有代理功能时分别是 5.7 MB 和 7.9 MB。内存数据来自 `test/bench/mem.sh`（本机回环，AnyTLS，8 个客户端各下 100 MB，每个限速 50 MB/s）。

### 运行

```sh
keel-node -c /etc/keel/node.json -state /var/lib/keel/usage.json
```

接主控时，配置由主控下发，`-c` 只是本地缓存（主控连不上时节点照常用它跑）：

```sh
KEEL_TOKEN=<节点令牌> keel-node -master https://panel.example:8443 \
    -fingerprint <主控证书 SHA-256> -c /etc/keel/node.json -state /var/lib/keel/usage.json
```

节点每 5 秒上报一次每个用户的流量、连接数和整机状态（CPU、内存、硬盘、网速、连接数、TCP 重传率、在线时长），配置了 `probes` 时还会定时对电信、联通、移动的目标做 TCPing（延迟、波动、丢包）。入口的可选参数（AnyTLS 的域名、证书（可以自动向 Let's Encrypt 申请和续期，支持 Cloudflare DNS 验证，NAT 机器也能用）、填充方案，Reality 的 SNI、dest、shortId 等）见 [docs/node-protocol.md](docs/node-protocol.md#入口入站的可选参数)。

配置格式见 [examples/entry.json](examples/entry.json)（入口）和 [examples/exit.json](examples/exit.json)（出口）。

- 配置文件改了会在 2 秒内自动重新加载，`kill -HUP` 可以立刻生效。设置没变的监听保持不动；改了或删掉的监听停止接新连接，已经建立的连接不受影响。
- 每个用户可以有三种凭据（`anytls_password`、`uuid`+`flow`、`ss_key`），缺哪个就不能用哪个协议。SS 2022 客户端的密码写成 `服务端password:用户ss_key`。
- `quota_bytes` 按上行加下行算，超额后 1 秒内断开并拒绝新连接；`expire_at` 是 unix 秒数。`period` 一变，这个用户的计数就从零开始（每月重置就靠主控下发新的 period）。
- 计数每 10 秒和退出时写入 `-state` 文件，重启后同一 period 的计数接着算；`kill -USR1` 立刻写一次。
- 删除用户会断开他所有正在用的连接。
- `outbounds` 里定义出口：`ss2022`（连出口节点，`password` 写 `出口password:入口的ss_key`；`method` 也可以是 aes-128/256-gcm、chacha20-ietf-poly1305 这类普通加密，连第三方 SS，`password` 就是普通密码；`udp_over_tcp` 让 UDP 走 TCP 连接，适合入口到出口之间 UDP 不稳的线路）、`socks`（比如本机 sslocal 走家宽落地）和 `vless`（第三方 VLESS 上游，明文 TCP、不带 TLS，只填 `server` 和 `uuid`，UDP 走 XUDP）。`direct` 是内置的直连。
- `route.rules` 从上往下匹配，第一条命中的规则决定出口，都没命中走 `route.final`（默认 `direct`）。规则的 `outbound` 和 `final` 可以写成有顺序的列表，比如 `["us1", "us2"]`：节点定时经每个出口发一个 HTTP 请求检测，排在前面的出口挂了就自动用下一个，恢复后切回来（细节见 [docs/node-protocol.md](docs/node-protocol.md#出口回退)）。每条规则用 `file`（名单文件，改了自动重新加载）或 `domains`（直接写在配置里）。`route.ipv4_only` 就是原来的 `-4`。用户经直连出站只能访问公网地址，回环、内网、链路本地（含云厂商元数据 169.254.169.254）和 100.64.0.0/10 一律拒绝，免得用户借节点摸到本机服务或背后的局域网；确实要放行时设 `route.allow_private: true`。
- 名单格式，每行一条，`#` 后面是注释：`example.com` 匹配它和所有子域名，`=api.example.com` 只匹配这一个，`~emby` 匹配包含这个词的域名，`91.108.4.0/22` 或单个 IP 匹配目标 IP。原来的 `direct.list` 可以直接用。
- [rules/](rules/) 里有常用名单：`ai.list`（OpenAI、Claude、Gemini 等）、`streaming.list`（Netflix、Disney+、YouTube、日本流媒体等）。

### 测试

```sh
make test                                    # 单元测试（带竞态检测）
BIN=/path/to/clients test/compat/run.sh      # 客户端兼容性
BIN=/path/to/clients test/compat/limits.sh   # 额度、到期、热更新、删用户、重启
BIN=/path/to/clients test/compat/chain.sh    # 入口 → 两个出口的分流，TCP 和 UDP，出口挂掉后回退
PEBBLE_DIR=... PEBBLE_SRC=... go test -tags anytls -run ACME ./cmd/keel-node   # 用 Let's Encrypt 的测试 CA（pebble）走三种验证方式，见 acme_test.go
```

`BIN` 目录里放客户端程序：`xray-<版本>`（可以放多个版本）、`mihomo`、`sing-box`。测试全部在本机回环上跑，不连外网，也不碰任何真实服务器。兼容性测试里每个用例都会：

- 经代理下载 100 MB 文件（HTTP 和 HTTPS 各一次，HTTPS 是为了让 Vision 进入直连模式），校验 sha256；
- 经代理往返 UDP（Vision 走 XUDP，AnyTLS 走 UDP over TCP，SS 2022 走原生 UDP）；
- 核对节点给这个用户记的流量和实际下载量一致（客户端绕过节点直连时也会被这一项抓出来）；
- 记录 Reality 握手用的是 X25519MLKEM768 还是传统 X25519。

最近一次结果（2026-10-22，Linux amd64）：

| 客户端 | VLESS Reality + Vision | VLESS 无 flow | AnyTLS | SS 2022 |
| --- | --- | --- | --- | --- |
| Xray 26.9.30（chrome / firefox / safari / ios / edge 指纹） | 全通 | 全通 | – | 全通 |
| Xray 26.10.21（同上） | 全通 | 全通 | – | 全通 |
| mihomo 1.19.33 | 通 | – | 通 | 通 |
| sing-box 1.14.3 | 通 | – | 通 | 通 |

握手方式：Xray 的 chrome / firefox / safari 指纹用 X25519MLKEM768，ios / edge 指纹、mihomo、sing-box 用传统 X25519，节点两种都接受。另外，没有合法 Reality 凭据的连接（openssl 直连、HTTPS 请求、错误 shortId 的 Xray 客户端）看到的都是 dest 网站本身的证书和内容。

Xray 的 Reality 服务端从 2026 年 9 月起要求客户端带 X25519MLKEM768，所以 sing-box 这类客户端连 Xray 服务端会失败；keel-node 不做这个限制。ML-DSA-65 签名不支持（开了连 Xray 自己的客户端都连不上）。

## keel-master

一个进程：网页面板、SQLite、订阅链接、节点控制通道，全在同一个 HTTPS 端口上。release 构建 3.5 MB，带两个节点、面板每 2 秒刷新时常驻内存约 7 MB。

### 构建和启动

```sh
make master                    # 生成 master/target/release/keel-master
keel-master -data /var/lib/keel-master -listen 0.0.0.0:8443
```

- 面板用用户名 + 密码登录。第一次启动会在日志里打印 `admin` 和一个随机密码，进去后在「设置」里改；也可以在服务器上 `keel-master -data ... -user 用户名 -password -`（密码从标准输入读，不留在命令历史里）。改完所有已登录的会话都会失效。
- 不给证书时会在 `数据目录/tls/` 生成自签证书，节点按指纹认它（安装命令里自动带上），浏览器会提示不安全。有域名证书就用 `-cert fullchain.pem -key key.pem`；放在 Caddy / nginx 后面就用 `-no-tls -listen 127.0.0.1:8080`（反代要转发 WebSocket）。
- 数据库是 `数据目录/keel.db`（WAL 模式，备份时连 `-wal`、`-shm` 一起拷，或者先停服务）。
- 节点安装脚本从主控下载 keel-node：把 `make node-linux` 编出来的文件改名放进 `数据目录/dist/`，叫 `keel-node-linux-amd64`、`keel-node-linux-arm64`。

### 面板

三个页面，每个对象只有一个右侧抽屉，手机上单列、全程不需要左右滑动：

- **探针**：总速率、在线数、本月流量；每台节点的 CPU、内存、硬盘、速率、本月流量、开机时长。点开卡片看到国内三网（电信 / 联通 / 移动）的延迟、波动、重传和近 1 小时曲线（默认测上海三网，用的是 [Zstatic](https://china-tcping-list.vercel.app/) 公开的 TCPing 节点 `sh-ct/cu/cm-v4.ip.zstaticcdn.com:80`，可在「设置」里改；节点每 30 秒 TCPing 一轮）。
- **线路**：入口卡片上点一下出口就是改默认出口；分流按规则集（AI、YouTube、流媒体、Telegram、游戏、Google，名单在 [rules/](rules/)）各选一个出口或直连。下面是出口卡片，显示额度和哪些入口在用。别人的服务器（比如买的家宽落地）点「导入外部出口」，粘贴 `vless://`（明文 TCP）或 `ss://` 分享链接，或者 3x-ui / Xray 的出站 JSON，一行一条；导入后和自建出口一样能设成默认、分流和备用，入口直接连它。商家换了地址就在出口抽屉里粘新链接，线路设置不变。改完立刻下发，节点热更新，现有连接不断。
- **用户**：额度、到期日、每月重置日、可用入口，一个订阅链接。Stash / Clash / mihomo 拿到 Clash 配置，其他客户端拿到 vless:// anytls:// ss:// 通用链接。

### 额度怎么算

- 用户的流量是他在所有入口上的总和。每个入口节点本地按「本期在其他节点用掉的（主控下发的 `used_base`）+ 本机用掉的」卡额度，主控断线也照样生效，误差是两次下发之间别的节点新增的流量（主控至少每分钟更新一次）。
- 重置日按「设置」里的时区算，31 号在小月就是月底。「清零流量」是给这个用户换一个新的计费周期，各节点的计数立即从零开始。
- 出口端口的月额度（比如家宽 900G / 月）用同样的办法：出口节点上每个入口是一个用户，共用这个端口的额度。

## 许可

GPL-3.0，和所依赖的 sing 系列库一致。`third_party/` 下是改过的 sing-anytls 和 sing-shadowsocks，改动各见其 MODIFICATIONS.md。
