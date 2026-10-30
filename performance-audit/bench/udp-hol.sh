#!/bin/bash
# udp-hol.sh: one SS2022 UDP session whose destination name never resolves
# stalls every other UDP session on the same inbound. Run `./bench.sh up`
# first; this script points the node at a DNS server that never answers.
S=$(cd "$(dirname "$0")" && pwd)
eval "$(sed -n "/^PSK=/,/^PUB=/p" "$S/bench.sh")"
docker exec -d kp-cli sh -c 'exec /w/bin/blast blackhole 127.0.0.53:53 > /w/run/bh.log 2>&1'
docker exec -d kp-cli sh -c 'exec /w/bin/blast udpecho 127.0.0.1:19000 > /w/run/udpecho.log 2>&1'
docker exec kp-srv sh -c 'echo "nameserver 127.0.0.53" > /etc/resolv.conf'
docker exec kp-srv sh -c 'pkill keel-node-pprof; true'; sleep 0.5
docker exec -d kp-srv sh -c 'KEEL_PPROF=127.0.0.1:6060 exec /w/bin/keel-node-pprof -c /w/cfg/entry/node.json -state /w/run/usage.json > /w/run/srv.log 2>&1'
sleep 1.5
# victim: ping-pong to an IP through SS2022 UDP for 16 s
docker exec kp-cli /w/bin/benchcli udp-ss 127.0.0.1:20002 "$PSK:$K1" 127.0.0.1:19000 ping 16 &
sleep 4
# another session: 6 s of packets to a name whose lookup hangs
docker exec kp-cli /w/bin/benchcli udp-ss 127.0.0.1:20002 "$PSK:$K1" slow-dns.test:9 flood 6 2000
wait
