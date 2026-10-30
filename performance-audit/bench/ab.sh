#!/bin/bash
# ab.sh A B: the TCP suite (throughput, chain, new connections, 1000 open
# connections) with the node built as A, then as B, back to back in fresh
# containers; entry and exit are swapped together. Build them with
# build-ref.sh (or copy bin/keel-node{,-pprof} to bin/keel-node{,-pprof}-NAME).
cd "$(dirname "$0")"
./bench.sh down; ./bench.sh up >/dev/null 2>&1; sleep 2
use() {
  cp "bin/keel-node-pprof-$1" bin/keel-node-pprof; cp "bin/keel-node-$1" bin/keel-node
  docker exec kp-exit sh -c 'pkill keel-node; true'; sleep 0.3
  docker exec -d kp-exit sh -c 'exec /w/bin/keel-node -c /w/cfg/exit/node.json -state /w/run/exit-usage.json > /w/run/exit.log 2>&1'
  sleep 0.5
}
for v in "$1" "$2"; do
  use "$v"; echo "=== $v"
  ./bench.sh keel 2>&1 | grep -v "^$"
  ./bench.sh chain 2>&1 | grep -v "^$"
  ./churn.sh 2>&1 | grep -v "^$"
  ./hold.sh 1000 2>&1 | grep -E "1000 conns|closed"
done
