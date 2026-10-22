#!/usr/bin/env bash
# Memory of keel-node builds serving AnyTLS: RSS idle, while 8 clients
# download 100 MB each in parallel, peak, and 10 s after the load.
#
#   BIN=/path/to/clients test/bench/mem.sh bin/keel-node-anytls-linux-amd64 bin/keel-node-anytls-vless-ss-linux-amd64
set -uo pipefail
BIN=${BIN:?set BIN to the directory with sing-box}
WORK=$(mktemp -d)
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$WORK"' EXIT
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 1 -nodes \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=bench.test" 2>/dev/null
mkdir -p "$WORK/www" && head -c 100M /dev/urandom > "$WORK/www/f"
(cd "$WORK/www" && exec python3 -m http.server -b 127.0.0.1 38080 >/dev/null 2>&1) & PIDS+=($!)
cat > "$WORK/node.json" <<JSON
{"inbounds": [{"type": "anytls", "listen": "127.0.0.1:38443", "cert": "$WORK/cert.pem", "key": "$WORK/key.pem"}],
 "users": [{"name": "u", "anytls_password": "pw"}]}
JSON
cat > "$WORK/sb.json" <<JSON
{"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 38090}],
 "outbounds": [{"type": "anytls", "server": "127.0.0.1", "server_port": 38443, "password": "pw",
   "tls": {"enabled": true, "server_name": "bench.test", "insecure": true}}]}
JSON
"$BIN/sing-box" run -c "$WORK/sb.json" >/dev/null 2>&1 & PIDS+=($!)

rss() { awk "/$2/{print \$2}" "/proc/$1/status"; }
printf '%-40s %8s %8s %8s %8s %8s\n' BINARY SIZE IDLE LOAD PEAK AFTER
for node in "$@"; do
  "$node" -c "$WORK/node.json" -state "$WORK/usage.json" >/dev/null 2>&1 &
  N=$!
  sleep 2
  idle=$(rss $N VmRSS)
  loads=()
  for i in $(seq 8); do curl -s --limit-rate 50M --socks5 127.0.0.1:38090 http://127.0.0.1:38080/f -o /dev/null & loads+=($!); done
  sleep 1.5
  load=$(rss $N VmRSS)
  wait "${loads[@]}"
  peak=$(rss $N VmHWM)
  sleep 10
  after=$(rss $N VmRSS)
  kill $N; wait $N 2>/dev/null
  printf '%-40s %7.1fM %7.1fM %7.1fM %7.1fM %7.1fM\n' "$(basename "$node")" \
    "$(echo "$(stat -c %s "$node")/1048576" | bc -l)" "$(echo "$idle/1024" | bc -l)" "$(echo "$load/1024" | bc -l)" \
    "$(echo "$peak/1024" | bc -l)" "$(echo "$after/1024" | bc -l)"
done
