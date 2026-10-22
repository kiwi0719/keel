# keel

自建的轻量代理面板 + 探针，用来替代 3x-ui。只支持三种协议：AnyTLS、VLESS Reality（含 Vision）、Shadowsocks 2022。

- **keel-node**（Go，本仓库 `cmd/keel-node`）：每台服务器一个进程，跑代理、按用户统计流量、在本地执行额度和到期。
- **主控**（Rust，网页面板 + SQLite）：还没开始写。节点会主动用 TLS 长连接连主控，节点自己不开任何管理端口。

## keel-node

直接用 sing 系列的协议库，不经过 sing-box 的路由、DNS、规则框架，所以程序小、内存低。

| 协议 | 库 |
| --- | --- |
| AnyTLS | `third_party/sing-anytls`（改过的 sing-anytls，改动见其 MODIFICATIONS.md） |
| VLESS + Vision | sing-vmess/vless |
| Reality 服务端 | metacubex/utls（和 sing-box 用的是同一个） |
| SS 2022 多用户 | sing-shadowsocks/shadowaead_2022 |

### 构建

协议用构建标签挑，没用到的不编进去：

```sh
make node-linux PROTOCOLS=anytls            # 只要 AnyTLS
make node-linux PROTOCOLS=anytls,vless,ss   # 三种都要
```

VLESS 必须同时带 `with_utls` 标签（Vision 靠它识别 Reality 连接），Makefile 会自动加；直接用 `go build -tags vless` 会编译报错提醒。

| 构建 | linux-amd64 大小 | 空闲内存 | 8 路并发下载时 |
| --- | --- | --- | --- |
| 只有 anytls | 5.7 MB | 5.8 MB | 11.9 MB |
| anytls + vless + ss | 7.9 MB | 7.0 MB | 13.4 MB |

内存数据来自 `test/bench/mem.sh`（本机回环，AnyTLS，8 个客户端各下 100 MB，每个限速 50 MB/s）。

### 运行

```sh
keel-node -c /etc/keel/node.json -state /var/lib/keel/usage.json
```

配置格式见 [examples/node.json](examples/node.json)。

- 配置文件改了会在 2 秒内自动重新加载，`kill -HUP` 可以立刻生效。设置没变的监听保持不动；改了或删掉的监听停止接新连接，已经建立的连接不受影响。
- 每个用户可以有三种凭据（`anytls_password`、`uuid`+`flow`、`ss_key`），缺哪个就不能用哪个协议。SS 2022 客户端的密码写成 `服务端password:用户ss_key`。
- `quota_bytes` 按上行加下行算，超额后 1 秒内断开并拒绝新连接；`expire_at` 是 unix 秒数。`period` 一变，这个用户的计数就从零开始（每月重置就靠主控下发新的 period）。
- 计数每 10 秒和退出时写入 `-state` 文件，重启后同一 period 的计数接着算；`kill -USR1` 立刻写一次。
- 删除用户会断开他所有正在用的连接。
- `outbound` 保留了原来 anytls 精简版的功能：`ipv4_only`（原 `-4`）、`socks`（原 `-socks`，走家宽落地）、`socks_domains`、`direct_domains`（后缀 / `=`精确 / `~`关键词，文件改了自动重新加载）。

### 测试

```sh
make test                                    # 单元测试（带竞态检测）
BIN=/path/to/clients test/compat/run.sh      # 客户端兼容性
BIN=/path/to/clients test/compat/limits.sh   # 额度、到期、热更新、删用户、重启
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

## 许可

GPL-3.0，和所依赖的 sing 系列库一致。
