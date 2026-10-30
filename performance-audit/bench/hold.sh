#!/bin/bash
# hold.sh <n>: memory per open proxied connection, by protocol.
S=$(cd "$(dirname "$0")" && pwd)   # the work dir made by setup.sh
eval "$(sed -n "/^PSK=/,/^PUB=/p" "$S/bench.sh")"; SID=0123456789abcdef
N=${1:-1000}
restart() {
  docker exec kp-cli sh -c 'pkill -f "blast[ ]hold"; pkill -f "benchcl[i]"; true'
  docker exec kp-srv sh -c 'pkill keel-node-pprof; true'; sleep 0.5
  docker exec -d kp-srv sh -c 'KEEL_PPROF=127.0.0.1:6060 exec /w/bin/keel-node-pprof -c /w/cfg/entry/node.json -state /w/run/usage.json > /w/run/srv.log 2>&1'
  docker exec kp-exit sh -c 'pkill keel-node; true'; sleep 0.3
  docker exec -d kp-exit sh -c 'exec /w/bin/keel-node -c /w/cfg/exit/node.json -state /w/run/exit-usage.json > /w/run/exit.log 2>&1'
  sleep 1.5
}
mem() {
  local pid; pid=$(docker exec kp-srv pidof keel-node-pprof)
  local epid; epid=$(docker exec kp-exit pidof keel-node)
  local heap; heap=$(docker exec kp-cli wget -qO- "http://127.0.0.1:6060/debug/pprof/heap?gc=1&debug=1" | awk '/^# HeapInuse/{printf "%.1f", $4/1048576}')
  local gor; gor=$(docker exec kp-cli wget -qO- "http://127.0.0.1:6060/debug/pprof/goroutine?debug=1" | head -1 | awk '{print $4}')
  printf 'entry RSS=%6.1fMB heapInuse=%5sMB goroutines=%5s | exit RSS=%6.1fMB\n' \
    "$(docker exec kp-srv awk '/VmRSS/{print $2/1024}' /proc/$pid/status)" "$heap" "$gor" \
    "$(docker exec kp-exit awk '/VmRSS/{print $2/1024}' /proc/$epid/status)"
}
case_() {
  local label=$1; shift
  restart
  printf '%-22s idle      ' "$label"; mem
  docker exec -d kp-cli "$@"
  for i in $(seq 60); do sleep 1; docker exec kp-cli sh -c 'pgrep -f "blast[ ]hold|benchcl[i]" >/dev/null' || break; [ -n "$(docker exec kp-srv sh -c 'ls /proc/$(pidof keel-node-pprof)/fd | wc -l' | awk -v n=$N '$1>=n')" ] && break; done
  sleep 3
  printf '%-22s %d conns ' "$label" "$N"; mem
  docker exec kp-cli sh -c 'pkill -f "blast[ ]hold"; pkill -f "benchcl[i]"; true'; sleep 3
  printf '%-22s closed    ' "$label"; mem
}
case_ "anytls(1 session)" /w/bin/blast hold 127.0.0.1:30001 127.0.0.1:18080 $N
case_ "ss2022" /w/bin/benchcli hold-ss 127.0.0.1:20002 "$PSK:$K1" 127.0.0.1:18080 $N
case_ "vless-reality" /w/bin/benchcli hold-reality 127.0.0.1:20003 dest.test $PUB $SID $U2 127.0.0.1:18080 $N
case_ "anytls->ss2022 exit" /w/bin/blast hold 127.0.0.1:30001 127.0.0.2:18080 $N
docker exec kp-cli sh -c 'pkill -f "blast[ ]hold"; pkill -f "benchcl[i]"; true'
