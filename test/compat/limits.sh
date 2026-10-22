#!/usr/bin/env bash
# Quota, expiry, hot reload and restart behaviour of keel-node on localhost:
#   - a user over quota is cut off within about a second and cannot reconnect
#   - reloading the config (new user, new inbound, new period) does not break
#     a download that is already running
#   - removing a user closes that user's open connections
#   - an expired user is blocked
#   - counters survive a restart
#
#   BIN=/path/to/clients test/compat/limits.sh     (needs xray-* and sing-box)
set -uo pipefail
cd "$(dirname "$0")/../.."
BIN=${BIN:?set BIN to the directory with client binaries}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "work dir kept: $WORK" || rm -rf "$WORK"' EXIT

go build ${RACE:+-race -gcflags=all=-d=checkptr=0} -o "$WORK/keel-node" -tags anytls,vless,with_utls,ss ./cmd/keel-node || exit 1
go build -o "$WORK/helper" ./test/compat/helper || exit 1
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

SNI=www.example.com DEST=127.0.0.1:28443 HTTP=127.0.0.1:28080
VLESS_PORT=28501 ANYTLS_PORT=28502 SS_PORT=28503
SOCKS_A=127.0.0.1:1180 SOCKS_B=127.0.0.1:1181
MB=1048576

"$WORK/helper" dest "$DEST" "$SNI" 2>/dev/null &
mkdir -p "$WORK/www" && head -c 100M /dev/urandom > "$WORK/www/100m.bin"
WANT_SHA=$(sha256sum "$WORK/www/100m.bin" | cut -d' ' -f1)
(cd "$WORK/www" && exec python3 -m http.server -b 127.0.0.1 28080 >/dev/null 2>&1) &

XRAY=$(ls "$BIN"/xray-* | sort -V | tail -1)
KEYS=$("$XRAY" x25519)
PRIV=$(echo "$KEYS" | awk -F': ' '/^Private/{print $2}')
PUB=$(echo "$KEYS" | awk -F': ' '/^(Public|Password)/{print $2}' | head -1)
UUID_A=$("$XRAY" uuid)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 1 -nodes \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=anytls.test" 2>/dev/null

# write_config <b quota bytes> <b period> <b expire_at> <include user a: yes|no> <extra inbound json or "">
write_config() {
  local users="" extra=""
  [ "$4" = yes ] && users="{\"name\": \"a\", \"uuid\": \"$UUID_A\", \"flow\": \"xtls-rprx-vision\"},"
  [ -n "$5" ] && extra=",$5"
  cat > "$WORK/node.json.tmp" <<JSON
{
  "inbounds": [
    {"type": "vless", "listen": "127.0.0.1:$VLESS_PORT",
     "reality": {"dest": "$DEST", "server_names": ["$SNI"], "private_key": "$PRIV"}},
    {"type": "anytls", "listen": "127.0.0.1:$ANYTLS_PORT", "cert": "$WORK/cert.pem", "key": "$WORK/key.pem"}$extra
  ],
  "users": [
    $users
    {"name": "b", "anytls_password": "pw-b", "quota_bytes": $1, "period": "$2", "expire_at": $3}
  ]
}
JSON
  mv "$WORK/node.json.tmp" "$WORK/node.json"
}

start_node() {
  "$WORK/keel-node" -c "$WORK/node.json" -state "$WORK/usage.json" >> "$WORK/node.log" 2>&1 &
  NODE_PID=$!
  sleep 1
}

# reload: the node polls the config every 2s; SIGHUP makes it immediate.
reload() { kill -HUP "$NODE_PID"; sleep 1; }

cat > "$WORK/xray.json" <<JSON
{"log": {"loglevel": "warning"},
 "inbounds": [{"listen": "127.0.0.1", "port": ${SOCKS_A#*:}, "protocol": "socks"}],
 "outbounds": [{"protocol": "vless",
   "settings": {"vnext": [{"address": "127.0.0.1", "port": $VLESS_PORT, "users": [{"id": "$UUID_A", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
   "streamSettings": {"network": "tcp", "security": "reality",
     "realitySettings": {"serverName": "$SNI", "fingerprint": "chrome", "publicKey": "$PUB", "shortId": ""}}}]}
JSON
cat > "$WORK/sing-box.json" <<JSON
{"log": {"level": "warn"},
 "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": ${SOCKS_B#*:}}],
 "outbounds": [{"type": "anytls", "server": "127.0.0.1", "server_port": $ANYTLS_PORT, "password": "pw-b",
   "tls": {"enabled": true, "server_name": "anytls.test", "insecure": true}}]}
JSON

PASS=0 FAIL=0
check() { # <description> <condition result 0/1> [detail]
  if [ "$2" = 0 ]; then PASS=$((PASS+1)); printf 'ok    %s %s\n' "$1" "${3:-}"; else FAIL=$((FAIL+1)); printf 'FAIL  %s %s\n' "$1" "${3:-}"; fi
}
# fetch <socks> <rate> -> prints "<bytes> <sha-ok:0|1>"
fetch() {
  curl -s --max-time 60 --limit-rate "$2" --socks5 "$1" "http://$HTTP/100m.bin" -o "$WORK/dl.$$" 
  local size; size=$(stat -c %s "$WORK/dl.$$" 2>/dev/null || echo 0)
  local sha; sha=$(sha256sum "$WORK/dl.$$" 2>/dev/null | cut -d' ' -f1); rm -f "$WORK/dl.$$"
  [ "$sha" = "$WANT_SHA" ] && echo "$size 0" || echo "$size 1"
}
used_b() { python3 -c "import json; u=json.load(open('$WORK/usage.json'))['users']['b']; print(u['up']+u['down'])"; }

write_config $((30*MB)) p1 0 yes ""
start_node
"$XRAY" run -c "$WORK/xray.json" > "$WORK/xray.log" 2>&1 &
"$BIN/sing-box" run -c "$WORK/sing-box.json" > "$WORK/sing-box.log" 2>&1 &
sleep 1.5

# 1. Quota: b may use 30 MB; a 100 MB download at 40 MB/s is cut after ~30 MB.
read -r size ok < <(fetch "$SOCKS_B" 40M)
check "quota: download cut off" $([ "$ok" = 1 ] && [ "$size" -lt $((80*MB)) ] && echo 0 || echo 1) "(got $((size/MB)) MB of 100 with a 30 MB quota)"
grep -q "user b blocked: quota used up" "$WORK/node.log"; check "quota: logged as blocked" $?
read -r size ok < <(fetch "$SOCKS_B" 40M)
check "quota: blocked user cannot reconnect" $([ "$size" -lt $MB ] && echo 0 || echo 1) "(got $size bytes)"

# 2. Hot reload during a running download: a fetches 100 MB at 20 MB/s (~5 s);
#    meanwhile add an ss2022 inbound and start a new period for b.
fetch "$SOCKS_A" 20M > "$WORK/a1" &
FETCH=$!
sleep 1.5
write_config $((300*MB)) p2 0 yes "{\"type\": \"ss2022\", \"listen\": \"127.0.0.1:$SS_PORT\", \"password\": \"$(openssl rand -base64 16)\"}"
reload
wait $FETCH
read -r size ok < "$WORK/a1"
check "reload: running download unaffected" "$ok" "($((size/MB)) MB)"
grep -q "started ss2022@127.0.0.1:$SS_PORT" "$WORK/node.log"; check "reload: new inbound started" $?
read -r size ok < <(fetch "$SOCKS_B" 0)
check "reload: new period unblocks b" "$ok"

# 3. Removing a user closes their connections.
fetch "$SOCKS_A" 20M > "$WORK/a2" &
FETCH=$!
sleep 1.5
write_config $((300*MB)) p2 0 no ""
reload
wait $FETCH
read -r size ok < "$WORK/a2"
check "remove: download of removed user cut" $([ "$ok" = 1 ] && echo 0 || echo 1) "(got $((size/MB)) MB)"
grep -q "user a removed, closed" "$WORK/node.log"; check "remove: logged" $?
grep -q "stopped ss2022@127.0.0.1:$SS_PORT" "$WORK/node.log"; check "reload: removed inbound stopped" $?

# 4. Restart keeps counters of the current period.
sleep 11
before=$(used_b)
kill -TERM "$NODE_PID"; wait "$NODE_PID" 2>/dev/null
start_node
sleep 11
after=$(used_b)
check "restart: counters kept" $([ "$after" -ge "$before" ] && [ "$before" -gt $((50*MB)) ] && echo 0 || echo 1) "(before $((before/MB)) MB, after $((after/MB)) MB)"

# 5. Expiry blocks the user.
write_config $((300*MB)) p2 $(( $(date +%s) - 1 )) no ""
reload
read -r size ok < <(fetch "$SOCKS_B" 0)
check "expiry: expired user blocked" $([ "$size" -lt $MB ] && echo 0 || echo 1) "(got $size bytes)"
grep -q "user b blocked: expired" "$WORK/node.log"; check "expiry: logged" $?

echo
echo "passed $PASS, failed $FAIL"
grep -iE "panic|fatal|DATA RACE" "$WORK/node.log" && echo "node log has errors above"
[ "$FAIL" = 0 ]
