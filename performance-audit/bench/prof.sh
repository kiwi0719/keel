#!/bin/bash
# prof.sh <name> <client command...>: CPU profile keel-node during a long download.
name=$1; shift
docker exec kp-cli sh -c 'pkill -f "blast[ ]get"; pkill -f "benchcl[i]"; true'
sleep 0.5
docker exec -d kp-cli "$@"
sleep 1.5
echo "$name: running clients: $(docker exec kp-cli sh -c 'pgrep -f "blast[ ]get|benchcl[i]" | wc -l')"
docker exec kp-cli wget -qO /w/run/cpu-$name.pprof "http://127.0.0.1:6060/debug/pprof/profile?seconds=4"
docker exec kp-cli wget -qO /w/run/allocs-$name.pprof "http://127.0.0.1:6060/debug/pprof/allocs"
docker exec kp-cli sh -c 'pkill -f "blast[ ]get"; pkill -f "benchcl[i]"; true'
sleep 1
