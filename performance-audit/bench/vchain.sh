#!/bin/bash
# vchain.sh: client -> entry Vision inbound -> VLESS+REALITY+Vision outbound
# -> second keel-node's Vision inbound (kp-exit) -> HTTPS target 127.0.0.3.
cd "$(dirname "$0")"
PUB=IF0ovQ266zFj6WJiqEdVsatmWVs5zDqIV8RILSD8Vnc; SID=0123456789abcdef; U1=80cc6a3a-1514-4342-af5b-78008172e101
docker exec kp-srv sh -c 'pkill keel-node-pprof; true'
docker exec kp-exit sh -c 'pkill -f "vchain/exit.jso[n]"; true'
sleep 0.5
docker exec -d kp-exit sh -c 'exec /w/bin/keel-node -c /w/cfg/vchain/exit.json -state /w/run/usage-vexit.json > /w/run/vexit.log 2>&1'
docker exec -d kp-srv sh -c 'KEEL_PPROF=127.0.0.1:6060 exec /w/bin/keel-node-pprof -c /w/cfg/vchain/entry.json -state /w/run/usage-ventry.json > /w/run/ventry.log 2>&1'
sleep 1.5
ticks() { docker exec "$1" awk '{print $14+$15}' /proc/$2/stat; }
spid=$(docker exec kp-srv pidof keel-node-pprof); xpid=$(docker exec kp-exit sh -c 'pgrep -f "vchain/exit.jso[n]"')
for streams in 1 8; do
  n=$([ $streams = 1 ] && echo 3000000000 || echo 500000000)
  s0=$(ticks kp-srv $spid); x0=$(ticks kp-exit $xpid)
  out=$(docker exec kp-cli /w/bin/benchcli reality 127.0.0.1:20003 dest.test $PUB $SID $U1 xtls-rprx-vision 127.0.0.3:18443 /n/$n $streams tls 2>&1 | tail -1)
  s1=$(ticks kp-srv $spid); x1=$(ticks kp-exit $xpid)
  bytes=$(echo "$out" | sed -n 's/.*bytes=\([0-9]*\).*/\1/p')
  echo "vision->vision x$streams: $out  entry $(awk -v a=$s0 -v b=$s1 -v n=${bytes:-0} 'BEGIN{if(n>0)printf "%.2f",(b-a)/100/(n/1e9); else print "n/a"}') cpu-s/GB  exit $(awk -v a=$x0 -v b=$x1 -v n=${bytes:-0} 'BEGIN{if(n>0)printf "%.2f",(b-a)/100/(n/1e9); else print "n/a"}') cpu-s/GB"
done
