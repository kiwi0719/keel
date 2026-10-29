#!/bin/bash
# Throughput / CPU benchmark: keel-node (or sing-box as server) alone on CPU 0.
set -u
S=$(cd "$(dirname "$0")" && pwd)   # the work dir made by setup.sh
cmd=${1:-}

up() {
  docker rm -f kp-srv kp-exit kp-cli >/dev/null 2>&1
  docker run -d --name kp-srv --cpuset-cpus=0 ${SRV_DNS:+--dns $SRV_DNS} -v "$S":/w alpine:latest sleep infinity >/dev/null
  docker run -d --name kp-exit --cpuset-cpus=1 --network container:kp-srv -v "$S":/w alpine:latest sleep infinity >/dev/null
  docker run -d --name kp-cli --cpuset-cpus=2-5 --network container:kp-srv -v "$S":/w alpine:latest sleep infinity >/dev/null
  docker exec -d kp-cli sh -c 'exec /w/bin/blast serve 0.0.0.0:18080 0.0.0.0:18443 > /w/run/blast.log 2>&1'
  docker exec -d kp-cli sh -c 'exec /w/bin/helper dest 127.0.0.1:20443 dest.test > /w/run/dest.log 2>&1'
  docker exec -d kp-cli sh -c 'exec /w/bin/sing-box run -c /w/cfg/client.json > /w/run/client.log 2>&1'
  docker exec -d kp-exit sh -c 'exec /w/bin/keel-node -c /w/cfg/exit/node.json -state /w/run/exit-usage.json > /w/run/exit.log 2>&1'
  sleep 1
}

start_server() {
  docker exec kp-srv sh -c 'pkill keel-node-pprof; pkill sing-box; true'
  sleep 0.5
  case $1 in
    keel) docker exec -d kp-srv sh -c 'KEEL_PPROF=127.0.0.1:6060 exec /w/bin/keel-node-pprof -c /w/cfg/entry/node.json -state /w/run/usage.json > /w/run/srv.log 2>&1' ;;
    sb)   docker exec -d kp-srv sh -c 'exec /w/bin/sing-box run -c /w/cfg/sb/server.json > /w/run/srv.log 2>&1' ;;
  esac
  sleep 1.5
}

srvpid() { docker exec kp-srv sh -c 'pidof keel-node-pprof || pidof sing-box' | awk '{print $1}'; }
exitpid() { docker exec kp-exit pidof keel-node; }
ticks() { docker exec "$1" awk '{print $14+$15}' /proc/$2/stat; }
rss() { docker exec "$1" awk '/VmRSS|VmHWM/{printf "%s=%.1fMB ", $1, $2/1024}' /proc/$2/status; }

PSK=aMACsktAq3rW3WoYP8aPbA==; K1=Dx4NiV8victJxIdnEHdBVA==
U1=80cc6a3a-1514-4342-af5b-78008172e101; U2=745d5d92-0765-4259-825c-c3902a0ddfa2
PUB=IF0ovQ266zFj6WJiqEdVsatmWVs5zDqIV8RILSD8Vnc; SID=0123456789abcdef

# run_case <label> <client command...>: runs the client in kp-cli, reports
# throughput, CPU seconds per GB on the server (and exit) and server RSS.
run_case() {
  local label=$1; shift
  local pid; pid=$(srvpid)
  local epid; epid=$(exitpid)
  local t0 e0 t1 e1 out
  t0=$(ticks kp-srv "$pid"); e0=$(ticks kp-exit "$epid")
  out=$(docker exec kp-cli "$@" 2>&1 | tail -1)
  t1=$(ticks kp-srv "$pid"); e1=$(ticks kp-exit "$epid")
  local bytes; bytes=$(echo "$out" | sed -n 's/.*bytes=\([0-9]*\).*/\1/p')
  local mbps; mbps=$(echo "$out" | sed -n 's/.*MBps=\([0-9]*\).*/\1/p')
  local cpu; cpu=$(awk -v a="$t0" -v b="$t1" -v n="${bytes:-0}" 'BEGIN{ if (n>0) printf "%.2f", (b-a)/100/(n/1e9); else print "n/a" }')
  local ecpu; ecpu=$(awk -v a="$e0" -v b="$e1" -v n="${bytes:-0}" 'BEGIN{ if (n>0) printf "%.2f", (b-a)/100/(n/1e9); else print "n/a" }')
  printf '%-34s %6s MB/s  srv %5s cpu-s/GB  exit %5s cpu-s/GB  %s\n' "$label" "${mbps:-ERR}" "$cpu" "$ecpu" "$(rss kp-srv "$pid")"
  [ -z "$bytes" ] && echo "   -> $out"
}

G=3000000000; P=500000000
anytls() { run_case "$1 anytls x$2" /w/bin/blast get 127.0.0.1:30001 "${3:-127.0.0.1:18080}" /n/$4 "$2"; }
ss() { run_case "keel ss2022 x$1" /w/bin/benchcli ss 127.0.0.1:20002 "$PSK:$K1" 127.0.0.1:18080 /n/$2 "$1"; }
vless() { run_case "keel vless-reality x$1" /w/bin/benchcli reality 127.0.0.1:20003 dest.test $PUB $SID $U2 - 127.0.0.1:18080 /n/$2 "$1"; }
vision() { run_case "keel vision $1 x$2" /w/bin/benchcli reality 127.0.0.1:20003 dest.test $PUB $SID $U1 xtls-rprx-vision "$3" /n/$4 "$2" $5; }

suite_keel() {
  anytls keel 1 127.0.0.1:18080 $G
  anytls keel 8 127.0.0.1:18080 $P
  ss 1 $G
  ss 8 $P
  vless 1 $G
  vless 8 $P
  vision http 1 127.0.0.1:18080 $G ""
  vision https 1 127.0.0.1:18443 $G tls
  vision https 8 127.0.0.1:18443 $P tls
}

case $cmd in
  up) up ;;
  keel) start_server keel; suite_keel ;;
  sb) start_server sb; anytls sing-box 1 127.0.0.1:18080 $G; anytls sing-box 8 127.0.0.1:18080 $P ;;
  chain) start_server keel; anytls "keel->exit" 1 127.0.0.2:18080 2000000000; anytls "keel->exit" 8 127.0.0.2:18080 300000000 ;;
  down) docker rm -f kp-srv kp-exit kp-cli >/dev/null 2>&1 ;;
  *) echo "usage: $0 up|keel|sb|chain|down" >&2; exit 2 ;;
esac
