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

`outbounds`（出口健康状态，入口节点才有，`direct` 不在里面）：

```json
"outbounds":[{"tag":"x3","alive":true,"latency_ms":182.4,"checked_at":1761099998},
             {"tag":"x5","alive":false,"latency_ms":201.0,"checked_at":1761099997,"error":"dial tcp ...: connection refused"}]
```

- `alive`：节点现在是否认为这个出口能用。分流时跳过 `alive: false` 的出口。
- `latency_ms`：最近一次检测成功时，经这个出口完成一次 HTTP 请求的耗时（包括入口到出口、出口到检测网址），不是单纯的入口到出口延迟。
- `checked_at`：最近一次检测的时间，0 表示还没测过。`error` 是最近一次失败的原因，成功后清空。

`certs`（只有用了 `acme` 的入站才有）：

```json
"certs":[{"domain":"a.example.com","issuer":"acme","not_after":1768900000},
         {"domain":"b.example.com","issuer":"self-signed","error":"dns challenge: cloudflare ...: Authentication error","next_try":1761100300}]
```

- `issuer`：`acme` 表示已经在用 CA 签的证书，`self-signed` 表示还没申请下来、在用自签证书。
- `error` / `next_try`：最近一次申请失败的原因和下次重试时间，成功后清空。

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

## 出口回退

规则的 `outbound` 和 `route.final` 可以写一个标签，也可以写一个有顺序的列表：

```json
"route": {
  "rules": [{"name":"ai","domains":["openai.com"],"outbound":["x3","x5"]}],
  "final": ["x1","x2"],
  "health_check": {"url":"http://www.gstatic.com/generate_204","interval":"15s"}
}
```

- 每个连接用列表里第一个活着的出口；全挂了就用第一个（照样尝试）。
- 节点每 `interval`（默认 15 秒，最小 5 秒）经每个出口请求一次 `url`（只支持 `http://`，默认 `http://www.gstatic.com/generate_204`），收到任何 HTTP 响应就算成功，5 秒超时。
- 连续两次失败判为挂了，连续两次成功判为恢复。第一次失败（或挂掉后第一次成功）会在 2 秒后马上复查，所以出口停掉后大约 2 到 20 秒内切走，恢复后大约 2 到 20 秒内切回。本机回环测试里，停掉出口 7 秒后切走，恢复 5 秒后切回。
- 正常连接连不上出口服务器时也会触发一次提前检测。
- 切换只影响新连接，已经建立的连接留在原来的出口上。
- 配置重载时，设置没变的出口保留健康状态。

## 主控生成配置的约定

节点不关心名字的含义，下面是主控这边的命名习惯，便于对照日志：

- 出口节点在入口配置里的出站标签：`x<出口id>`，比如 `x3`。
- 入口节点上的用户名：`u<用户id>`。
- 出口节点上的用户名（每个入口一个）：`n<入口id>x<出口id>`。出口按这个名字统计每个入口走了多少流量。
- 分流规则用 `domains` 直接写在配置里，不用 `file`（主控没法往节点上放文件）。顺序：直连名单放第一条（`outbound: "direct"`），然后是 AI、流媒体等规则集，最后 `final` 指向默认出口。规则和 `final` 选了多个出口时按面板上的顺序写成列表。
- 入口节点只下发 `anytls` 和 `vless`（Reality）入站；`ss2022` 入站只给出口用。

## 入口入站的可选参数

AnyTLS：

```json
{"type":"anytls","listen":"0.0.0.0:443","server_name":"a.example.com",
 "cert":"/etc/letsencrypt/live/a.example.com/fullchain.pem","key":"/etc/letsencrypt/live/a.example.com/privkey.pem",
 "padding_scheme":["stop=8","0=30-30","1=100-400","2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000","3=9-9,500-1000","4=500-1000","5=500-1000","6=500-1000","7=500-1000"]}
```

- `server_name`：客户端连接时用的域名（SNI）。节点不按它拒绝连接，只用来生成自签证书；主控也用它生成订阅里的 `sni`。
- 证书三选一，按顺序：
  1. `cert_pem` + `key_pem`：证书内容直接写在配置里（PEM 文本）。
  2. `cert` + `key`：节点上的证书文件路径，比如 certbot 申请的证书。文件必须存在，不存在或读不了时这个入站起不来，`applied.error` 里写明原因，节点不会自己生成证书去顶替。
  3. 都不给：节点用自签 ECDSA 证书，域名是 `server_name`（没写就是 `localhost`），保存在 `-c` 配置文件所在目录的 `anytls.crt` / `anytls.key`，重启后不变；`server_name` 改了会重新生成。AnyTLS 客户端通常不校验证书（订阅里写 `skip-cert-verify` / `insecure`）。
- 换证书文件后要重新下发配置（或改动这个入站）才会加载新证书。
- `padding_scheme`：可选，覆盖 AnyTLS 默认的填充方案，格式和 sing-box 的 `padding_scheme` 一样，每行一条。服务端会把它推给客户端，客户端不用配置。写错（缺 `stop=`）这个入站起不来。

自动申请证书（ACME）：

```json
{"type":"anytls","listen":"0.0.0.0:443","server_name":"a.example.com",
 "acme":{"email":"me@example.com","challenge":"dns","dns_provider":"cloudflare","dns_token":"<Cloudflare API 令牌>"}}
```

- 写了 `acme` 就不能再写 `cert` / `key` / `cert_pem`，`server_name` 必填，域名要已经解析到这台机器（`dns` 方式除外）。
- 节点先用自签证书把入站开起来，后台向 Let's Encrypt 申请，拿到后直接换上，不用重启、不断连接。证书存在 `-c` 所在目录的 `acme/` 下，重启后直接用；到期前 30 天自动续期。
- `challenge` 验证方式：
  - `dns`：在 Cloudflare 上临时加一条 `_acme-challenge` TXT 记录。不需要开任何端口，NAT 机器、443 被别的程序占着都能用。需要 `dns_provider: "cloudflare"` 和一个有这个域名 DNS 编辑权限的 API 令牌（Cloudflare 后台 → API 令牌 → “编辑区域 DNS” 模板）。
  - `tls-alpn`：Let's Encrypt 连这个域名的 443 端口，由这个 AnyTLS 入站自己应答。要求外网 443 端口通到这个入站（直接监听 443，或 NAT 把公网 443 转到它）。
  - `http`：申请时临时监听 80 端口，申请完就关。要求 80 端口空着、外网能连到。
  - 不写：有 `dns_token` 就用 `dns`，否则入站监听 443 就用 `tls-alpn`，再否则用 `http`。主控知道 NAT 公网端口时最好明确写。
- 失败了 5 分钟后重试，之后每次加倍，最长 6 小时，期间一直用原来的证书（或自签证书）。
- `ca`：可选，ACME 目录地址，默认 Let's Encrypt。`email`：可选。
- 令牌只在主控数据库和节点的缓存配置里，不进仓库。

VLESS Reality：

```json
{"type":"vless","listen":"0.0.0.0:443",
 "reality":{"dest":"www.example.com:443","server_names":["www.example.com","cdn.example.com"],
            "private_key":"<x25519 私钥>","short_ids":["","0123abcd"],"max_time_diff":"1m"}}
```

- `server_names`：客户端可以用的 SNI，可以写多个，必须至少一个。第一个就是订阅里默认的 `sni`。
- `dest`：借用握手的网站，`host:port`；不写端口就是 443，整个不写就用 `server_names` 的第一个加 443。
- `short_ids`：可以写多个，每个 0 到 16 位十六进制（位数为偶数）；空字符串表示允许不带 shortId。整个不写等于只允许空 shortId。
- `max_time_diff`：可选，客户端和服务器允许的最大时间差，不写不检查。
- 用户的 `flow` 为 `xtls-rprx-vision` 或空。客户端指纹（`fp`）只在订阅里，节点不需要。
