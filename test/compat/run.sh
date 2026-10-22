#!/usr/bin/env bash
# Compatibility test: runs keel-node with every protocol on localhost and
# drives it with real clients (Xray, mihomo, sing-box). Each case downloads a
# 100 MB file (sha256 checked) and, where the client supports it, round-trips
# UDP through the proxy. Nothing leaves this machine.
#
#   BIN=/path/to/clients test/compat/run.sh
#
# BIN must hold the client binaries: xray-<version> (any number of them),
# mihomo and sing-box. Missing clients are skipped. ONLY=<regex> runs only the
# matching cases.
#
# The COUNTED column checks the node's per-user traffic accounting: a case
# fails if the node counted less than the payload, which also catches a client
# that quietly sent traffic around the node.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
BIN=${BIN:?set BIN to the directory with client binaries}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "work dir kept: $WORK" || rm -rf "$WORK"' EXIT

SNI=www.example.com
DEST=127.0.0.1:18443
HTTP=127.0.0.1:18080
HTTPS=127.0.0.1:18444
ECHO=127.0.0.1:19000
VLESS_PORT=20443 ANYTLS_PORT=20445 SS_PORT=20446
SOCKS=127.0.0.1:1080

go build ${RACE:+-race -gcflags=all=-d=checkptr=0} -o "$WORK/keel-node" -tags anytls,vless,with_utls,ss ./cmd/keel-node || exit 1
go build -o "$WORK/helper" ./test/compat/helper || exit 1
# Everything below talks to localhost only; a proxy from the environment would
# let curl bypass the node and make every case pass.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

"$WORK/helper" dest "$DEST" "$SNI" 2>/dev/null &
"$WORK/helper" udpecho "$ECHO" &
mkdir -p "$WORK/www" && head -c 100M /dev/urandom > "$WORK/www/100m.bin"
WANT_SHA=$(sha256sum "$WORK/www/100m.bin" | cut -d' ' -f1)
(cd "$WORK/www" && exec python3 -m http.server -b 127.0.0.1 18080 >/dev/null 2>&1) &
"$WORK/helper" dest "$HTTPS" files.test "$WORK/www" 2>/dev/null &

XRAY=$(ls "$BIN"/xray-* | sort -V | tail -1)
KEYS=$("$XRAY" x25519)
PRIV=$(echo "$KEYS" | awk -F': ' '/^Private/{print $2}')
PUB=$(echo "$KEYS" | awk -F': ' '/^(Public|Password)/{print $2}' | head -1)
SID=$(openssl rand -hex 8)
UUID_VISION=$("$XRAY" uuid)
UUID_PLAIN=$("$XRAY" uuid)
ANYTLS_PW=$(openssl rand -hex 12)
SS_PSK=$(openssl rand -base64 16)
SS_KEY=$(openssl rand -base64 16)

cat > "$WORK/node.json" <<JSON
{
  "inbounds": [
    {"type": "vless", "listen": "127.0.0.1:$VLESS_PORT",
     "reality": {"dest": "$DEST", "server_names": ["$SNI"], "private_key": "$PRIV", "short_ids": ["$SID"]}},
    {"type": "anytls", "listen": "127.0.0.1:$ANYTLS_PORT", "server_name": "anytls.test",
     "padding_scheme": ["stop=8", "0=30-30", "1=100-400", "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000", "3=9-9,500-1000", "4=500-1000", "5=500-1000", "6=500-1000", "7=500-1000"]},
    {"type": "ss2022", "listen": "127.0.0.1:$SS_PORT", "method": "2022-blake3-aes-128-gcm", "password": "$SS_PSK"}
  ],
  "users": [
    {"name": "vision", "uuid": "$UUID_VISION", "flow": "xtls-rprx-vision", "anytls_password": "$ANYTLS_PW", "ss_key": "$SS_KEY"},
    {"name": "plain", "uuid": "$UUID_PLAIN"}
  ]
}
JSON
"$WORK/keel-node" -v -c "$WORK/node.json" -state "$WORK/usage.json" > "$WORK/node.log" 2>&1 &
NODE_PID=$!
sleep 1

RESULTS=()
record() { RESULTS+=("$(printf '%-44s %-6s %-6s %-8s %-7s %s' "$1" "$2" "$3" "$4" "${6:--}" "$5")"); }

# kex_count: Reality handshakes so far that used X25519MLKEM768 / classic X25519.
kex_count() { echo "$(grep -c 'using X25519MLKEM768: true' "$WORK/node.log") $(grep -c 'using X25519MLKEM768: false' "$WORK/node.log")"; }

# counted_down <user>: bytes the node has counted toward the user so far.
counted_down() {
  kill -USR1 "$NODE_PID"; sleep 0.3
  python3 -c "import json; print(json.load(open('$WORK/usage.json'))['users'].get('$1', {}).get('down', 0))"
}

wait_port() { for _ in $(seq 50); do (exec 3<>/dev/tcp/${1%:*}/${1#*:}) 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# run_case <name> <user> <udp:yes|no> <command...>: start a client exposing SOCKS
# on $SOCKS, download the file over HTTP and HTTPS (TLS inside the tunnel is what
# makes Vision switch to direct copy), and test UDP.
run_case() {
  local name=$1 user=$2 udp=$3; shift 3
  [[ "$name" =~ ${ONLY:-.} ]] || return
  "$@" > "$WORK/client.log" 2>&1 &
  local pid=$!
  if ! wait_port "$SOCKS"; then
    record "$name" "FAIL" "-" "-" "client did not start: $(tail -1 "$WORK/client.log")"
    kill $pid 2>/dev/null; wait $pid 2>/dev/null; return
  fi
  local tcp=ok udpres=- note="" got url payload=0 before
  before=$(counted_down "$user")
  local kex_before; kex_before=$(kex_count)
  for url in "http://$HTTP/100m.bin" "https://$HTTPS/100m.bin"; do
    got=$(curl -sk --max-time 60 --socks5 "$SOCKS" "$url" | sha256sum | cut -d' ' -f1)
    if [ "$got" = "$WANT_SHA" ]; then
      payload=$(( payload + 104857600 ))
    else
      tcp=FAIL; note="$note ${url%%:*} download failed"
    fi
  done
  if [ "$udp" = yes ]; then
    if "$WORK/helper" socksudp "$SOCKS" "$ECHO" >/dev/null 2>"$WORK/udp.err"; then udpres=ok; else udpres=FAIL; note="$note $(tail -1 "$WORK/udp.err")"; fi
  fi
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  sleep 0.3
  # The node must count at least the payload, and at most 2% + 1 MB more
  # (HTTP and TLS overhead, UDP probes).
  local delta=$(( $(counted_down "$user") - before )) count=ok
  if [ "$delta" -lt "$payload" ] || [ "$delta" -gt $(( payload + payload / 50 + 1048576 )) ]; then
    count=FAIL; note="$note counted $((delta / 1048576)) MB for $((payload / 1048576)) MB"
  fi
  local kex=- m0 c0 m1 c1
  read -r m0 c0 <<< "$kex_before"; read -r m1 c1 <<< "$(kex_count)"
  if [ "$m1" -gt "$m0" ] && [ "$c1" -gt "$c0" ]; then kex=mixed
  elif [ "$m1" -gt "$m0" ]; then kex=mlkem
  elif [ "$c1" -gt "$c0" ]; then kex=x25519; fi
  record "$name" "$tcp" "$udpres" "$count" "$note" "$kex"
  sleep 0.3
}

xray_vless() { # <xray> <uuid> <flow> <fingerprint> [shortId]
  cat > "$WORK/xray.json" <<JSON
{"log": {"loglevel": "warning"},
 "inbounds": [{"listen": "127.0.0.1", "port": ${SOCKS#*:}, "protocol": "socks", "settings": {"udp": true}}],
 "outbounds": [{"protocol": "vless",
   "settings": {"vnext": [{"address": "127.0.0.1", "port": $VLESS_PORT, "users": [{"id": "$2", "encryption": "none", "flow": "$3"}]}]},
   "streamSettings": {"network": "tcp", "security": "reality",
     "realitySettings": {"serverName": "$SNI", "fingerprint": "$4", "publicKey": "$PUB", "shortId": "${5:-$SID}"}}}]}
JSON
  exec "$1" run -c "$WORK/xray.json"
}

xray_ss() {
  cat > "$WORK/xray-ss.json" <<JSON
{"log": {"loglevel": "warning"},
 "inbounds": [{"listen": "127.0.0.1", "port": ${SOCKS#*:}, "protocol": "socks", "settings": {"udp": true}}],
 "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": $SS_PORT, "method": "2022-blake3-aes-128-gcm", "password": "$SS_PSK:$SS_KEY"}]}}]}
JSON
  exec "$1" run -c "$WORK/xray-ss.json"
}

mihomo_case() { # <proxy yaml>
  mkdir -p "$WORK/mihomo"
  cat > "$WORK/mihomo/config.yaml" <<YAML
socks-port: ${SOCKS#*:}
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: warning
ipv6: false
proxies:
$1
proxy-groups: []
rules:
  - MATCH,p
YAML
  exec "$BIN/mihomo" -d "$WORK/mihomo"
}

singbox_case() { # <outbound json>
  cat > "$WORK/sing-box.json" <<JSON
{"log": {"level": "warn"},
 "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": ${SOCKS#*:}}],
 "outbounds": [$1]}
JSON
  exec "$BIN/sing-box" run -c "$WORK/sing-box.json"
}

for x in $(ls "$BIN"/xray-* | sort -V); do
  v=${x##*/}
  for fp in chrome firefox safari ios edge; do
    run_case "$v vless+vision reality fp=$fp" vision yes xray_vless "$x" "$UUID_VISION" xtls-rprx-vision "$fp"
  done
  run_case "$v vless (no flow) reality fp=chrome" plain yes xray_vless "$x" "$UUID_PLAIN" "" chrome
  run_case "$v ss2022" vision yes xray_ss "$x"
done

if [ -x "$BIN/mihomo" ]; then
  run_case "mihomo vless+vision reality" vision yes mihomo_case "  - {name: p, type: vless, server: 127.0.0.1, port: $VLESS_PORT, uuid: $UUID_VISION, network: tcp, tls: true, udp: true, flow: xtls-rprx-vision, servername: $SNI, client-fingerprint: chrome, reality-opts: {public-key: $PUB, short-id: $SID}}"
  run_case "mihomo anytls" vision yes mihomo_case "  - {name: p, type: anytls, server: 127.0.0.1, port: $ANYTLS_PORT, password: $ANYTLS_PW, sni: anytls.test, skip-cert-verify: true, udp: true}"
  run_case "mihomo ss2022" vision yes mihomo_case "  - {name: p, type: ss, server: 127.0.0.1, port: $SS_PORT, cipher: 2022-blake3-aes-128-gcm, password: '$SS_PSK:$SS_KEY', udp: true}"
fi

if [ -x "$BIN/sing-box" ]; then
  run_case "sing-box vless+vision reality" vision yes singbox_case "{\"type\": \"vless\", \"server\": \"127.0.0.1\", \"server_port\": $VLESS_PORT, \"uuid\": \"$UUID_VISION\", \"flow\": \"xtls-rprx-vision\", \"packet_encoding\": \"xudp\", \"tls\": {\"enabled\": true, \"server_name\": \"$SNI\", \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"}, \"reality\": {\"enabled\": true, \"public_key\": \"$PUB\", \"short_id\": \"$SID\"}}}"
  run_case "sing-box anytls" vision yes singbox_case "{\"type\": \"anytls\", \"server\": \"127.0.0.1\", \"server_port\": $ANYTLS_PORT, \"password\": \"$ANYTLS_PW\", \"tls\": {\"enabled\": true, \"server_name\": \"anytls.test\", \"insecure\": true}}"
  run_case "sing-box ss2022" vision yes singbox_case "{\"type\": \"shadowsocks\", \"server\": \"127.0.0.1\", \"server_port\": $SS_PORT, \"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS_PSK:$SS_KEY\"}"
fi

# Probes: without valid Reality credentials the node must look like the dest site.
probe_cn=$(echo | openssl s_client -connect 127.0.0.1:$VLESS_PORT -servername $SNI 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
case "$probe_cn" in *"$SNI"*) record "probe: openssl sees dest certificate" ok - - "$probe_cn" ;; *) record "probe: openssl sees dest certificate" FAIL - - "$probe_cn" ;; esac
probe_body=$(curl -sk --max-time 10 --resolve "$SNI:$VLESS_PORT:127.0.0.1" "https://$SNI:$VLESS_PORT/")
[ "$probe_body" = "dest-ok" ] && record "probe: https request served by dest" ok - - "" || record "probe: https request served by dest" FAIL - - "$probe_body"
run_case "negative: xray wrong shortId must fail" vision no xray_vless "$XRAY" "$UUID_VISION" xtls-rprx-vision chrome 0123456789abcdef
[[ "${RESULTS[-1]}" == negative* ]] && RESULTS[-1]=$(echo "${RESULTS[-1]}" | sed 's/ FAIL / ok(expected fail) /; t; s/ ok / FAIL(should not connect) /')

mlkem=$(grep -c "using X25519MLKEM768: true" "$WORK/node.log")
x25519=$(grep -c "using X25519MLKEM768: false" "$WORK/node.log")
echo
printf '%-44s %-6s %-6s %-8s %-7s %s\n' CASE TCP UDP COUNTED KEX NOTE
printf '%s\n' "${RESULTS[@]}"
echo
echo "Reality handshakes: X25519MLKEM768=$mlkem, classic X25519=$x25519"
echo
grep -iE "panic|fatal|race" "$WORK/node.log" && echo "node log has errors above"
