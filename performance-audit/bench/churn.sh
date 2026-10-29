#!/bin/bash
# churn.sh: new-connection rate through keel-node (CPU 0), CPU per 1000 connections.
S=$(cd "$(dirname "$0")" && pwd)   # the work dir made by setup.sh
eval "$(sed -n "/^PSK=/,/^PUB=/p" "$S/bench.sh")"; SID=0123456789abcdef
srvpid() { docker exec kp-srv sh -c 'pidof keel-node-pprof || pidof sing-box' | awk '{print $1}'; }
ticks() { docker exec kp-srv awk '{print $14+$15}' /proc/$1/stat; }
one() {
  local label=$1; shift
  local pid; pid=$(srvpid)
  local t0 t1 out
  t0=$(ticks "$pid")
  out=$(docker exec kp-cli "$@" 2>&1 | tail -1)
  t1=$(ticks "$pid")
  local ok; ok=$(echo "$out" | sed -n 's/.*ok=\([0-9]*\).*/\1/p')
  printf '%-28s %s  srv cpu-ms/conn=%s  %s\n' "$label" "$out" "$(awk -v a=$t0 -v b=$t1 -v n=${ok:-0} 'BEGIN{ if(n>0) printf "%.3f", (b-a)*10/n; else print "n/a"}')" \
    "$(docker exec kp-srv awk '/VmRSS|VmHWM|Threads/{printf "%s%s ", $1, $2}' /proc/$pid/status)"
}
C=${C:-32}; T=${T:-8}
one "anytls(stream) c$C" /w/bin/blast conns 127.0.0.1:30001 127.0.0.1:18080 $C $T
one "ss2022 c$C" /w/bin/benchcli conns-ss 127.0.0.1:20002 "$PSK:$K1" 127.0.0.1:18080 $C $T
one "vless-reality c$C" /w/bin/benchcli conns-reality 127.0.0.1:20003 dest.test $PUB $SID $U2 127.0.0.1:18080 $C $T
