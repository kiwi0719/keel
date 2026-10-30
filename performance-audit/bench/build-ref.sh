#!/bin/bash
# build-ref.sh WORK REF NAME: builds keel-node at git REF into
# WORK/bin/keel-node-NAME and WORK/bin/keel-node-pprof-NAME, for ab.sh.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=$1; REF=$2; NAME=$3
SRC=$(mktemp -d)
git -C "$REPO" archive "$REF" | tar -x -C "$SRC"
cp "$HERE/_go/nodetests/"*.go "$SRC/cmd/keel-node/"
export CGO_ENABLED=0 GOOS=linux GOARCH=$(docker version --format '{{.Server.Arch}}')
(cd "$SRC" &&
  go build -trimpath -tags anytls,vless,with_utls,ss -o "$WORK/bin/keel-node-$NAME" ./cmd/keel-node &&
  go build -trimpath -tags anytls,vless,with_utls,ss,pprof -o "$WORK/bin/keel-node-pprof-$NAME" ./cmd/keel-node)
rm -rf "$SRC"
echo "built $REF as $NAME"
