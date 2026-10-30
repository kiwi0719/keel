#!/bin/sh
# usage: bench_http.sh PORT DATA_DIR PID [N_STATE]
# Latency/throughput of /api/state, /api/public and /s/{token} in every format.
PORT=$1; DATA=$2; PID=$3; NS=${4:-50}
SCR=$(cd "$(dirname "$0")" && pwd)
COOKIE=$(cat "$SCR/cookie-$PORT.txt")
B="https://127.0.0.1:$PORT"
TOK=$(sqlite3 "$DATA/keel.db" "select sub_token from users where id=2")
abs() { # label, ab args...
  label=$1; shift
  /usr/sbin/ab -q -f TLS1.2 "$@" 2>&1 | awk -v l="$label" '
    /Requests per second/ {rps=$4} /Time per request:.*\(mean\)$/ {mean=$4}
    /Failed requests/ {fail=$3} /Non-2xx/ {non2xx=$3}
    /^  50%/ {p50=$2} /^  95%/ {p95=$2} /^  99%/ {p99=$2} /^ 100%/ {pmax=$2}
    END {printf "%-34s rps=%-8s mean=%-7sms p50=%-5s p95=%-5s p99=%-5s max=%-5s failed=%s non2xx=%s\n", l, rps, mean, p50, p95, p99, pmax, fail, (non2xx==""?0:non2xx)}'
}
echo "RSS before: $(ps -o rss= -p $PID) KB"
printf 'sizes: state=%s public=%s' \
  "$(curl -sk -o /dev/null -w '%{size_download}' -H "Cookie: $COOKIE" $B/api/state)" \
  "$(curl -sk -o /dev/null -w '%{size_download}' $B/api/public)"
for f in clash stash singbox surge links; do printf ' sub_%s=%s' $f "$(curl -sk -o /dev/null -w '%{size_download}' "$B/s/$TOK?format=$f")"; done; echo
abs "/api/state c=1" -n "$NS" -c 1 -k -H "Cookie: $COOKIE" "$B/api/state"
abs "/api/state c=4" -n "$NS" -c 4 -k -H "Cookie: $COOKIE" "$B/api/state"
abs "/api/public c=8 (cached)" -n 2000 -c 8 -k "$B/api/public"
printf '/api/public rebuild (cache expired):'
for i in 1 2 3 4 5; do sleep 2.2; printf ' %s' "$(curl -sk -o /dev/null -w '%{time_total}' $B/api/public)"; done; echo ' s'
for f in clash stash singbox surge links; do
  abs "/s/{token}?format=$f c=1" -n 200 -c 1 -k "$B/s/$TOK?format=$f"
done
abs "/s/{token}?format=clash c=8" -n 1000 -c 8 -k "$B/s/$TOK?format=clash"
echo "RSS after: $(ps -o rss= -p $PID) KB"
