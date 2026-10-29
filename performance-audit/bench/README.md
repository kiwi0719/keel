# 性能审计的复现脚本

报告和数据见 [../REPORT.md](../REPORT.md)、[../EVIDENCE.md](../EVIDENCE.md)。脚本只在本机 Docker 里跑，全部走回环，不连外网。

## 准备

- Docker，至少 6 个 CPU（容器按 CPU 0 / 1 / 2-5 分开），本地有 `alpine:latest` 镜像。
- Go、openssl、rsync。
- 一个带 AnyTLS 出站和 socks 入站的 Linux 版 sing-box，架构和 Docker 一致（AnyTLS 的客户端用它；SS2022 和 VLESS Reality 的客户端是 `_go/benchcli`）。

```sh
SINGBOX=/path/to/sing-box-linux-arm64 performance-audit/bench/setup.sh /tmp/keel-bench
```

`setup.sh` 把仓库复制到工作目录、加上 pprof 钩子和测试文件后编译，仓库本身不会被改动。`_go/` 下的源码以下划线开头的目录存放，`go build ./...` 和 `make test` 都不会碰到它们。`cfg/` 里的密钥、UUID 是只给这套测试用的随机值。

## 运行（在工作目录里）

```sh
./bench.sh up        # 起容器：kp-srv（CPU 0，被测节点）、kp-exit（CPU 1，出口）、kp-cli（CPU 2-5，客户端和目标）
./bench.sh keel      # 吞吐和每 GB CPU：AnyTLS / SS2022 / VLESS Reality / Vision
./bench.sh sb        # 同样的 AnyTLS，用 sing-box 做服务端对照
./bench.sh chain     # 入口 AnyTLS → ss2022 出口
./churn.sh           # 新建连接速率、每条连接的 CPU
./hold.sh 1000       # 1000 条打开连接时的内存
./udp-hol.sh         # SS2022 UDP 队头阻塞
./prof.sh 名字 /w/bin/blast get 127.0.0.1:30001 127.0.0.1:18080 /n/40000000000 8   # 下载时采 CPU 和分配剖析，结果在 run/
docker run --rm --ulimit nofile=200000:200000 --cpuset-cpus=0 -v "$PWD/bin":/b alpine /b/procnet 20000   # /proc/net/tcp 的开销
./bench.sh down
```

微基准（`isPublic`、分流匹配、存盘、配置推送、上报体积）：

```sh
cd /tmp/keel-bench/src/cmd/keel-node
go test -tags anytls,vless,with_utls,ss -run 'TestPerfSizes|TestPerUserMemory' -v .
go test -tags anytls,vless,with_utls,ss -run '^$' -bench 'IsPublic|Pick|Usage|QuotaCheck|ConfigPush' -benchmem .
```

## 协议库的微基准

`_go/libtests/` 是协议库子审计写的测试（库内的 `perf_test.go`、`idlemem*_test.go`），`results/` 是它的原始输出。它们要放进仓库副本里、用 `go.work` 让四个库按 keel 的 sing 版本编译：

```sh
W=/tmp/keel-libs && mkdir -p "$W"
rsync -a --exclude .git go.mod go.sum cmd third_party "$W/"
cp -R performance-audit/bench/_go/libtests/third_party performance-audit/bench/_go/libtests/go.work "$W/"
cd "$W"
CONNS=128 go test -count=1 -run TestIdleHeapPerConn -v ./third_party/sing-shadowsocks/shadowaead_2022/      # SS2022 空闲连接内存，加 DOWNLOAD=100000 对比门槛以下
go test -count=1 -run TestUDPStalledSessionBlocksLoop -v ./third_party/sing-shadowsocks/shadowaead_2022/     # UDP 队头阻塞
go test -count=3 -run '^$' -bench 'BenchmarkTCPHandshakeServer|BenchmarkUDPServer|BenchmarkUDPClientWritePacket' -benchmem ./third_party/sing-shadowsocks/shadowaead_2022/
go test -count=1 -tags with_utls -run TestVisionFastPathReachability -v ./third_party/sing-vmess/vless/        # Vision 能否走到 splice
go test -count=3 -run '^$' -bench BenchmarkMuxServerRecv -benchmem ./third_party/sing-vmess/
go test -count=3 -run '^$' -bench 'BenchmarkStreamWrite|BenchmarkRecvLoopToStream|BenchmarkPipeHandoff' -benchmem ./third_party/sing-anytls/session/
go test -count=4 -run '^$' -bench BenchmarkRecordWrite -benchmem ./third_party/utls/
```

`median.sh < 结果文件` 取多次运行的中位数。
