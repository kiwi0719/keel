#!/bin/bash
# setup.sh [WORK]: builds the benchmark into WORK (default: a new temp dir).
# Needs Docker, Go, openssl, rsync, and SINGBOX=<linux sing-box with AnyTLS>
# for the AnyTLS client. Then run the scripts from WORK, e.g.
#   WORK/bench.sh up && WORK/bench.sh keel && WORK/hold.sh 1000
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${1:-$(mktemp -d)}
ARCH=$(docker version --format '{{.Server.Arch}}')
mkdir -p "$WORK/bin" "$WORK/run" "$WORK/src"
cp -R "$HERE/cfg" "$WORK/"
cp "$HERE"/bench.sh "$HERE"/churn.sh "$HERE"/hold.sh "$HERE"/prof.sh "$HERE"/udp-hol.sh "$HERE"/vchain.sh "$WORK/"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 30 -nodes \
  -keyout "$WORK/cfg/key.pem" -out "$WORK/cfg/cert.pem" -subj /CN=bench.test -addext subjectAltName=DNS:bench.test 2>/dev/null
rsync -a --exclude master/target --exclude .git --exclude bin --exclude performance-audit "$REPO/" "$WORK/src/"
cp "$HERE/_go/nodetests/"*.go "$WORK/src/cmd/keel-node/"
mkdir -p "$WORK/src/cmd/benchcli" && cp "$HERE/_go/benchcli/main.go" "$WORK/src/cmd/benchcli/"
export CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH
(cd "$WORK/src" &&
  go build -trimpath -tags anytls,vless,with_utls,ss -o "$WORK/bin/keel-node" ./cmd/keel-node &&
  go build -trimpath -tags anytls,vless,with_utls,ss,pprof -o "$WORK/bin/keel-node-pprof" ./cmd/keel-node &&
  go build -trimpath -o "$WORK/bin/helper" ./test/compat/helper &&
  go build -trimpath -tags with_utls -o "$WORK/bin/benchcli" ./cmd/benchcli)
(cd "$HERE/_go/blast" && go build -o "$WORK/bin/blast" .)
(cd "$HERE/_go/procnet" && go build -o "$WORK/bin/procnet" .)
cp "${SINGBOX:?set SINGBOX to a linux sing-box binary with AnyTLS}" "$WORK/bin/sing-box"
echo "built into $WORK"
