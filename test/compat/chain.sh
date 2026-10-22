#!/usr/bin/env bash
# Entry -> exit chaining and rule routing, all on localhost:
#
#   Xray client --Reality+Vision--> entry keel-node --SS 2022--> exit1 / exit2 keel-node --> target
#
# The entry routes by rules: "localhost" (domain rule) and 127.0.0.2 (IP rule)
# go to exit2, whose SS outbound carries UDP over TCP; 127.0.0.3 goes direct;
# everything else goes to exit1 (final) with native SS 2022 UDP. Each check
# reads the exits' per-user counters to prove which way the traffic went.
# 127.0.0.4 goes to a third-party style upstream: an Xray VLESS server over
# plain TCP (UDP as XUDP), checked through Xray's access log.
# Finally exit1 is stopped and started again: final is [exit1, exit2], so
# traffic must fall back to exit2 and come back to exit1.
#
#   BIN=/path/to/clients test/compat/chain.sh      (needs xray-*)
set -uo pipefail
cd "$(dirname "$0")/../.."
BIN=${BIN:?set BIN to the directory with client binaries}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "work dir kept: $WORK" || rm -rf "$WORK"' EXIT

go build ${RACE:+-race -gcflags=all=-d=checkptr=0} -o "$WORK/keel-node" -tags anytls,vless,with_utls,ss ./cmd/keel-node || exit 1
go build -o "$WORK/helper" ./test/compat/helper || exit 1
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

SNI=www.example.com DEST=127.0.0.1:48443 PORT=48080 ECHO_PORT=49000
ENTRY_PORT=48501 EXIT1_PORT=48601 EXIT2_PORT=48602 UPSTREAM_PORT=48701 SOCKS=127.0.0.1:1280
MB=1048576

"$WORK/helper" dest "$DEST" "$SNI" 2>/dev/null &
"$WORK/helper" udpecho "0.0.0.0:$ECHO_PORT" &
mkdir -p "$WORK/www" && head -c 20M /dev/urandom > "$WORK/www/20m.bin" && echo ok > "$WORK/www/ok"
WANT_SHA=$(sha256sum "$WORK/www/20m.bin" | cut -d' ' -f1)
(cd "$WORK/www" && exec python3 -m http.server -b 0.0.0.0 $PORT >/dev/null 2>&1) &

XRAY=$(ls "$BIN"/xray-* | sort -V | tail -1)
KEYS=$("$XRAY" x25519)
PRIV=$(echo "$KEYS" | awk -F': ' '/^Private/{print $2}')
PUB=$(echo "$KEYS" | awk -F': ' '/^(Public|Password)/{print $2}' | head -1)
UUID=$("$XRAY" uuid) UPSTREAM_UUID=$("$XRAY" uuid)
PSK1=$(openssl rand -base64 16) KEY1=$(openssl rand -base64 16)
PSK2=$(openssl rand -base64 16) KEY2=$(openssl rand -base64 16)

start_exit() {
  "$WORK/keel-node" -v -c "$WORK/exit$1/node.json" -state "$WORK/exit$1/usage.json" >> "$WORK/exit$1/node.log" 2>&1 &
  eval "EXIT$1_PID=$!"
}
for i in 1 2; do
  psk=PSK$i key=KEY$i port=EXIT${i}_PORT
  mkdir -p "$WORK/exit$i"
  cat > "$WORK/exit$i/node.json" <<JSON
{"inbounds": [{"type": "ss2022", "listen": "127.0.0.1:${!port}", "password": "${!psk}"}],
 "users": [{"name": "entry", "ss_key": "${!key}"}]}
JSON
  start_exit $i
done
mkdir -p "$WORK/entry"
cat > "$WORK/entry/node.json" <<JSON
{
  "route": {
    "rules": [
      {"name": "ai", "domains": ["=localhost", "127.0.0.2/32"], "outbound": "exit2"},
      {"name": "direct", "domains": ["127.0.0.3"], "outbound": "direct"},
      {"name": "upstream", "domains": ["127.0.0.4"], "outbound": "upstream"}
    ],
    "final": ["exit1", "exit2"],
    "health_check": {"url": "http://127.0.0.1:$PORT/ok", "interval": "5s"}
  },
  "outbounds": [
    {"tag": "exit1", "type": "ss2022", "server": "127.0.0.1:$EXIT1_PORT", "password": "$PSK1:$KEY1"},
    {"tag": "exit2", "type": "ss2022", "server": "127.0.0.1:$EXIT2_PORT", "password": "$PSK2:$KEY2", "udp_over_tcp": true},
    {"tag": "upstream", "type": "vless", "server": "127.0.0.1:$UPSTREAM_PORT", "uuid": "$UPSTREAM_UUID"}
  ],
  "inbounds": [
    {"type": "vless", "listen": "127.0.0.1:$ENTRY_PORT",
     "reality": {"dest": "$DEST", "server_names": ["$SNI"], "private_key": "$PRIV"}}
  ],
  "users": [{"name": "alice", "uuid": "$UUID", "flow": "xtls-rprx-vision"}]
}
JSON
"$WORK/keel-node" -v -c "$WORK/entry/node.json" -state "$WORK/entry/usage.json" > "$WORK/entry/node.log" 2>&1 &
ENTRY_PID=$!
cat > "$WORK/xray.json" <<JSON
{"log": {"loglevel": "warning"},
 "inbounds": [{"listen": "127.0.0.1", "port": ${SOCKS#*:}, "protocol": "socks", "settings": {"udp": true}}],
 "outbounds": [{"protocol": "vless",
   "settings": {"vnext": [{"address": "127.0.0.1", "port": $ENTRY_PORT, "users": [{"id": "$UUID", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
   "streamSettings": {"network": "tcp", "security": "reality",
     "realitySettings": {"serverName": "$SNI", "fingerprint": "chrome", "publicKey": "$PUB", "shortId": ""}}}]}
JSON
"$XRAY" run -c "$WORK/xray.json" > "$WORK/xray.log" 2>&1 &
cat > "$WORK/upstream.json" <<JSON
{"log": {"loglevel": "warning", "access": "$WORK/upstream-access.log"},
 "inbounds": [{"listen": "127.0.0.1", "port": $UPSTREAM_PORT, "protocol": "vless",
   "settings": {"clients": [{"id": "$UPSTREAM_UUID"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "none"}}],
 "outbounds": [{"protocol": "freedom"}]}
JSON
"$XRAY" run -c "$WORK/upstream.json" > "$WORK/upstream.log" 2>&1 &
sleep 2

# down <dir>: bytes the node in <dir> counted as sent to its user.
down() {
  local pid_var=$(echo "$1" | tr a-z A-Z)_PID
  kill -USR1 "${!pid_var}" 2>/dev/null; sleep 0.3
  python3 -c "import json; u=json.load(open('$WORK/$1/usage.json'))['users']; print(sum(x['down'] for x in u.values()))"
}
PASS=0 FAIL=0
check() { if [ "$2" = 0 ]; then PASS=$((PASS+1)); printf 'ok    %s %s\n' "$1" "${3:-}"; else FAIL=$((FAIL+1)); printf 'FAIL  %s %s\n' "$1" "${3:-}"; fi; }

# route_check <description> <want: exit1|exit2|direct> <command...>
route_check() {
  local desc=$1 want=$2; shift 2
  local e1 e2 n1 n2 out
  e1=$(down exit1); e2=$(down exit2)
  out=$("$@" 2>&1); local rc=$?
  n1=$(( $(down exit1) - e1 )); n2=$(( $(down exit2) - e2 ))
  local got=direct
  if [ $n1 -gt 1000 ] && [ $n1 -ge $n2 ]; then got=exit1; elif [ $n2 -gt 1000 ]; then got=exit2; fi
  check "$desc" $([ $rc = 0 ] && [ "$got" = "$want" ] && echo 0 || echo 1) "(via $got: exit1 +$n1 B, exit2 +$n2 B; $out)"
}
fetch() { # <host>
  local sha; sha=$(curl -s --max-time 30 --socks5-hostname "$SOCKS" "http://$1:$PORT/20m.bin" | sha256sum | cut -d' ' -f1)
  [ "$sha" = "$WANT_SHA" ] && echo "sha ok" || { echo "download failed"; return 1; }
}

route_check "tcp, no rule -> final exit1" exit1 fetch 127.0.0.1
route_check "tcp, domain rule -> exit2" exit2 fetch localhost
route_check "tcp, ip rule -> exit2" exit2 fetch 127.0.0.2
route_check "tcp, ip rule -> direct" direct fetch 127.0.0.3
# upstream_check <description> <access log pattern> <command...>
upstream_check() {
  local desc=$1 pattern=$2; shift 2
  local out; out=$("$@" 2>&1); local rc=$?
  sleep 0.3
  check "$desc" $([ $rc = 0 ] && grep -q "$pattern" "$WORK/upstream-access.log" && echo 0 || echo 1) "($out)"
}
upstream_check "tcp, ip rule -> vless upstream" "accepted tcp:127.0.0.4:$PORT" fetch 127.0.0.4
upstream_check "udp, ip rule -> vless upstream (XUDP)" "accepted udp:127.0.0.4:$ECHO_PORT" "$WORK/helper" socksudp "$SOCKS" 127.0.0.4:$ECHO_PORT
route_check "udp, no rule -> exit1 (native SS UDP)" exit1 "$WORK/helper" socksudp "$SOCKS" 127.0.0.1:$ECHO_PORT
route_check "udp, ip rule -> exit2 (UDP over TCP)" exit2 "$WORK/helper" socksudp "$SOCKS" 127.0.0.2:$ECHO_PORT

# The entry still counts everything for its own user.
kill -USR1 $ENTRY_PID; sleep 0.3
alice=$(python3 -c "import json; print(json.load(open('$WORK/entry/usage.json'))['users']['alice']['down'])")
check "entry counts the user's traffic" $([ "$alice" -ge $((100*MB)) ] && echo 0 || echo 1) "(alice down $((alice/MB)) MB for 5 x 20 MB)"

# Fallback: stop exit1, wait for the entry to notice, then bring it back.
# wait_log <pattern> <seconds>: seconds it took for pattern to show up in the entry log.
wait_log() {
  local start=$SECONDS
  until grep -q "$1" "$WORK/entry/node.log"; do
    [ $((SECONDS - start)) -ge "$2" ] && { echo "timeout"; return 1; }
    sleep 0.5
  done
  echo "$((SECONDS - start)) s"
}
kill -USR1 $EXIT1_PID; sleep 0.3; kill $EXIT1_PID; wait $EXIT1_PID 2>/dev/null
took=$(wait_log "outbound exit1 is dead" 40); check "exit1 stopped: entry marks it dead" $? "($took)"
route_check "tcp, final falls back to exit2" exit2 fetch 127.0.0.1
route_check "udp, final falls back to exit2" exit2 "$WORK/helper" socksudp "$SOCKS" 127.0.0.1:$ECHO_PORT
start_exit 1
took=$(wait_log "outbound exit1 is alive again" 40); check "exit1 back: entry marks it alive" $? "($took)"
route_check "tcp, final returns to exit1" exit1 fetch 127.0.0.1

echo
echo "passed $PASS, failed $FAIL"
grep -hiE "panic|fatal|DATA RACE" "$WORK"/*/node.log && echo "node logs have errors above"
[ "$FAIL" = 0 ]
