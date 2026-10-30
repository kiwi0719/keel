#!/bin/bash
# interop.sh: keel's SS 2022 against the unmodified upstream libraries
# (_go/interop): their clients through keel's inbound, and keel's outbound
# to their server. Run `./bench.sh up` first.
cd "$(dirname "$0")"
PSK=aMACsktAq3rW3WoYP8aPbA==; K1=Dx4NiV8victJxIdnEHdBVA==; KX=P9jV5FlpdIv3IRqhtEhI5A==
docker exec kp-srv sh -c 'pkill keel-node-pprof; true'
docker exec kp-exit sh -c 'pkill -f "interop serve-ss[1]"; pkill -f "vchain/exit.jso[n]"; true'
docker exec kp-cli sh -c 'pkill -f "interop ech[o] 0.0.0.0:19002"; true'
sleep 0.5
docker exec -d kp-cli /w/bin/interop echo 0.0.0.0:19002
docker exec -d kp-exit /w/bin/interop serve-ss1 127.0.0.1:20111 $PSK $KX
docker exec -d kp-srv sh -c 'KEEL_PPROF=127.0.0.1:6060 exec /w/bin/keel-node-pprof -c /w/cfg/interop-entry.json -state /w/run/usage-interop.json > /w/run/interop-entry.log 2>&1'
sleep 1.5
for client in ss1 ss2; do
  echo "upstream $client client -> keel inbound: $(docker exec kp-cli /w/bin/interop echoes $client 127.0.0.1:20002 "$PSK:$K1" 127.0.0.1:19002 3000000 8 2>&1 | tail -1)"
done
echo "upstream ss1 client -> keel inbound -> keel outbound -> upstream server: $(docker exec kp-cli /w/bin/interop echoes ss1 127.0.0.1:20002 "$PSK:$K1" 127.0.0.4:19002 3000000 8 2>&1 | tail -1)"
for client in ss1 ss2; do
  echo "upstream $client client, 100 MB download: $(docker exec kp-cli /w/bin/interop get $client 127.0.0.1:20002 "$PSK:$K1" 127.0.0.1:18080 /n/100000000 2>&1 | tail -1)"
done
echo "same through keel's outbound and the upstream server: $(docker exec kp-cli /w/bin/interop get ss1 127.0.0.1:20002 "$PSK:$K1" 127.0.0.4:18080 /n/100000000 2>&1 | tail -1)"
