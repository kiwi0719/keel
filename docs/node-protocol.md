# 主控 ↔ 节点协议

节点主动连主控，节点自己不开任何管理端口。连接断了节点照常用本地缓存的配置跑，按 1 秒起、最长 60 秒的退避（带抖动）重连。

## 连接

```sh
keel-node -master https://panel.example:8443 -token <节点令牌> \
          -fingerprint <主控证书 SHA-256> \
          -c /etc/keel/node.json -state /var/lib/keel/usage.json
```

- `-token` 也可以用环境变量 `KEEL_TOKEN` 给，免得出现在 `ps` 里。
- `-master` 只写到端口时，地址是 `wss://host:port/api/node/ws`；写了路径就用那个路径。`http://` 对应 `ws://`，只建议本机调试用。
- 请求头 `Authorization: Bearer <token>`。令牌不对主控直接回 401，节点会按退避重连。
- `-fingerprint`：主控证书（叶子证书 DER）的 SHA-256，十六进制，大小写和冒号都无所谓。给了它就只认这个指纹，不再做 CA 校验，所以主控可以用自签证书；不给就按系统 CA 正常校验。生成方法：`openssl x509 -in cert.pem -outform der | sha256sum`。
- `-c` 是主控下发配置的缓存。有 `-master` 时文件不存在也能启动（空配置，等主控下发）。缓存文件被手动改了照样会自动重新加载，但主控下次下发会覆盖它。
- 节点不走 `HTTP(S)_PROXY` 环境变量。

## 消息

全部是 WebSocket 文本帧，每帧一个 JSON 对象，用 `type` 区分。单帧最大 16 MiB。节点每 30 秒发一次 WebSocket ping，主控的 WebSocket 库正常回 pong 就行。

### 节点 → 主控：`hello`

连上后发的第一帧。

```json
{"type":"hello","node_version":"v0.3.0","protocols":["anytls","vless","ss2022"],
 "hostname":"jp-1","os":"linux","arch":"amd64","config_rev":12}
```

- `protocols`：这个二进制编进了哪些协议。主控别给节点下发它没有的协议，否则整份配置会被拒。
- `config_rev`：节点当前在用的配置版本，没有配置时是 0。和主控的最新版本不一样就下发一次。

### 主控 → 节点：`config`

```json
{"type":"config","rev":13,"config":{ ...完整的节点配置... }}
```

- `config` 是完整配置，格式和 [examples/entry.json](../examples/entry.json)、[examples/exit.json](../examples/exit.json) 一样，不支持增量。节点会和当前配置比较，只动有变化的部分：设置没变的监听不重启，用户表原子替换，已有连接不断（删掉的用户除外）。
- `rev` 必须是正数且单调递增。节点以消息里的 `rev` 为准（覆盖 `config.rev`），并把它写进缓存，重启后 `hello` 里报的还是它。
- 主控下发时字段宽松解析：不认识的字段会被忽略，方便主控先加字段、节点后升级。本地手写的配置文件则严格解析，拼错字段名会报错。

### 节点 → 主控：`applied`

每收到一份 `config` 回一帧。

```json
{"type":"applied","rev":13}
{"type":"applied","rev":13,"error":"listen anytls@0.0.0.0:443: address already in use"}
```

- 没有 `error`：配置已生效并已缓存。
- 有 `error` 有两种情况，主控按 `config_rev` 区分：
  - 配置本身不合法（JSON 错、出口标签不存在、用户重名、协议没编进去……）：整份不生效，节点继续用旧配置，之后的 `report.config_rev` 还是旧版本。
  - 配置生效了，但个别监听起不来（端口被占、证书读不了）：其余部分照常生效，`config_rev` 会变成新版本，`error` 里列出起不来的监听。节点下次收到配置时会重试这些监听。

### 节点 → 主控：`report`

每 5 秒一帧。

```json
{"type":"report","ts":1761100000,"config_rev":13,
 "users":[{"name":"u7","period":"2026-10","up":123456,"down":9876543,"conns":3,"blocked":false}],
 "system":{"cpu_pct":3.2,"load1":0.08,"mem_total":1003520000,"mem_used":312000000,
           "swap_total":0,"swap_used":0,"disk_total":20000000000,"disk_used":4100000000,
           "net_rx":81234567890,"net_tx":79234567890,"rx_rate":152340.5,"tx_rate":148220.1,
           "tcp_conns":42,"udp_conns":5,"uptime_s":864000,"rss":7340032,"tcp_retrans_pct":0.4},
 "probes":[{"name":"ct","host":"203.0.113.1:80","latency_ms":38.2,"jitter_ms":1.7,"loss_pct":0,"samples":10,"at":1761099990},
           {"name":"cu","host":"203.0.113.2:80","latency_ms":45.0,"jitter_ms":3.1,"loss_pct":10,"samples":9,"at":1761099990},
           {"name":"cm","host":"203.0.113.3:80","latency_ms":61.4,"jitter_ms":8.9,"loss_pct":0,"samples":10,"at":1761099990}]}
```

`users`（配置里的每个用户一条）：

- `up` / `down` 是这个用户在**这个节点**、**这个 `period`** 里的累计字节数（绝对值，不是增量），重启后接着算。主控每次直接用最新值覆盖，不用自己累加，丢几帧也不会少算。
- `period` 是用户配置里的 `period` 原样带回。主控改了 `period`（比如每月 1 号换成 `2026-11`），节点上这个用户的计数归零重新开始；主控看到新 `period` 的数据才算换月成功。
- `conns`：当前打开的连接数。
- `blocked`：节点因为超额或到期正在拒绝这个用户。

`system`：

- `net_rx` / `net_tx` 是开机以来除 `lo` 外所有网卡的累计字节；`rx_rate` / `tx_rate` 是和上一帧相比的每秒字节数。
- `rss` 是 keel-node 自己的内存。
- `tcp_retrans_pct`：和上一帧相比，整机重传的 TCP 段占发出段的百分比（来自 `/proc/net/snmp`）。
- 非 Linux 系统上大部分字段是 0。

`probes`（三网 TCPing）：

- 只在有新一轮测完时出现，每一轮只发一次；没有新结果的帧不带这个字段。主控存下来画图就行。
- 同一轮所有目标的 `at` 相同（这一轮测完的时间）。
- 每轮对每个目标做 10 次 TCP 连接，间隔 500 ms，单次超时 2 秒。
- `latency_ms`：成功连接耗时的平均值。`jitter_ms`：相邻两次成功连接耗时之差的平均值。
- `loss_pct`：超时的次数加上耗时 ≥ 1 秒的次数（说明 SYN 重传过）占总次数的百分比。`samples` 是成功次数，为 0 时延迟和波动没有意义。

## 配置里和主控相关的字段

除了 examples 里已有的字段：

```json
{
  "rev": 13,
  "probes": [{"name":"ct","host":"203.0.113.1:80"},{"name":"cu","host":"203.0.113.2:80"},{"name":"cm","host":"203.0.113.3:80"}],
  "probe_interval": "30s",
  "users": [{"name":"u7","anytls_password":"...","quota_bytes":107374182400,
             "expire_at":1767196800,"period":"2026-10","used_base":5368709120}]
}
```

- `probes`：探测目标，`host` 必须是 `IP:端口` 或 `域名:端口`，TCP 可达。不给就不测。`route.ipv4_only` 打开时域名只解析 IPv4。
- `probe_interval`：两轮之间的间隔，默认 `30s`，最小 `5s`。
- `quota_bytes`：0 表示不限。判断条件是 `used_base + up + down >= quota_bytes`，每秒检查一次，超了就断开这个用户所有连接并拒绝新连接（所以会多跑约 1 秒的流量）。
- `used_base`：这个用户本期在**其他节点**上已经用掉的流量，由主控算好下发。一个用户能连多个入口时，靠它让每个节点都按全局用量卡额度。主控更新它不需要很频繁，误差就是两次下发之间其他节点上新增的流量。
- `expire_at`：unix 秒，0 表示不过期。到期即断开并拒绝。
- 删用户：下发的配置里不再有这个用户，节点立刻断开他所有连接。
- 恢复被封的用户：提高 `quota_bytes`、`used_base` 改小、改 `expire_at` 或换 `period`，下发后 1 秒内恢复。

## 主控生成配置的约定

节点不关心名字的含义，下面是主控这边的命名习惯，便于对照日志：

- 出口节点在入口配置里的出站标签：`x<出口id>`，比如 `x3`。
- 入口节点上的用户名：`u<用户id>`。
- 出口节点上的用户名（每个入口一个）：`n<入口id>x<出口id>`。出口按这个名字统计每个入口走了多少流量。
- 分流规则用 `domains` 直接写在配置里，不用 `file`（主控没法往节点上放文件）。顺序：直连名单放第一条（`outbound: "direct"`），然后是 AI、流媒体等规则集，最后 `final` 指向默认出口。
- AnyTLS 入站的 `cert` / `key`：两个文件都不存在时，节点会在那两个路径生成一张自签 ECDSA 证书（AnyTLS 客户端本来就不校验证书）；两个都留空则只在内存里生成。所以主控可以统一写 `/var/lib/keel/anytls.crt` 和 `/var/lib/keel/anytls.key`。
