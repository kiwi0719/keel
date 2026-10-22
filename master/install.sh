#!/bin/sh
# keel-node installer, served by keel-master at /install.sh. The panel shows
# the full command; it downloads keel-node from the master and runs it as a
# service (systemd or OpenRC) that dials back to the master.
set -eu

MASTER="" TOKEN="" FINGERPRINT="" PIN=""
while [ $# -gt 0 ]; do
	case "$1" in
	--master) MASTER=$2; shift 2 ;;
	--token) TOKEN=$2; shift 2 ;;
	--fingerprint) FINGERPRINT=$2; shift 2 ;;
	--pin) PIN=$2; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 1 ;;
	esac
done
if [ -z "$MASTER" ] || [ -z "$TOKEN" ]; then
	echo "usage: install.sh --master URL --token TOKEN [--fingerprint HEX --pin SPKI]" >&2
	exit 1
fi
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

# A self-signed master is reached by pinning its public key instead of CA checks.
if [ -n "$PIN" ]; then
	fetch() { curl -fsSLk --pinnedpubkey "sha256//$PIN" -o "$2" "$1"; }
else
	fetch() { curl -fsSL -o "$2" "$1"; }
fi

mkdir -p /etc/keel /var/lib/keel
chmod 700 /etc/keel /var/lib/keel
fetch "$MASTER/dl/keel-node-linux-$ARCH" /usr/local/bin/keel-node.new
chmod 755 /usr/local/bin/keel-node.new
mv /usr/local/bin/keel-node.new /usr/local/bin/keel-node

umask 077
printf 'KEEL_TOKEN=%s\n' "$TOKEN" >/etc/keel/token.env
ARGS="-master $MASTER -c /etc/keel/node.json -state /var/lib/keel/usage.json"
[ -n "$FINGERPRINT" ] && ARGS="$ARGS -fingerprint $FINGERPRINT"
umask 022

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	cat >/etc/systemd/system/keel-node.service <<UNIT
[Unit]
Description=keel-node
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
EnvironmentFile=/etc/keel/token.env
ExecStart=/usr/local/bin/keel-node $ARGS
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
	systemctl daemon-reload
	systemctl enable keel-node >/dev/null 2>&1
	systemctl restart keel-node
elif command -v rc-service >/dev/null 2>&1; then
	cat >/etc/init.d/keel-node <<RC
#!/sbin/openrc-run
name=keel-node
supervisor=supervise-daemon
command=/usr/local/bin/keel-node
command_args="$ARGS"
output_log=/var/log/keel-node.log
error_log=/var/log/keel-node.log
respawn_delay=3
respawn_max=0
rc_ulimit="-n 1048576"
depend() { need net; }
start_pre() {
	# Keep the log bounded even without logrotate.
	if [ -f /var/log/keel-node.log ] && [ "\$(wc -c </var/log/keel-node.log)" -gt 10485760 ]; then : >/var/log/keel-node.log; fi
	set -a; . /etc/keel/token.env; set +a
}
RC
	chmod 755 /etc/init.d/keel-node
	if [ -d /etc/logrotate.d ]; then
		cat >/etc/logrotate.d/keel-node <<'LR'
/var/log/keel-node.log {
	size 5M
	rotate 2
	compress
	missingok
	notifempty
	copytruncate
}
LR
	fi
	rc-update add keel-node default >/dev/null 2>&1
	rc-service keel-node restart
else
	echo "no systemd or OpenRC; start it yourself:" >&2
	echo "  KEEL_TOKEN=... /usr/local/bin/keel-node $ARGS" >&2
	exit 1
fi
echo "keel-node installed; it should show up as online in the panel within a few seconds."
# Ports to open or map at the provider (NAT boxes: public -> listen).
if [ -n "$PIN" ]; then
	PORTS=$(curl -fsSk --pinnedpubkey "sha256//$PIN" -H "Authorization: Bearer $TOKEN" "$MASTER/api/node/ports" 2>/dev/null || true)
else
	PORTS=$(curl -fsS -H "Authorization: Bearer $TOKEN" "$MASTER/api/node/ports" 2>/dev/null || true)
fi
if [ -n "$PORTS" ]; then
	echo
	echo "ports (open TCP+UDP; on a NAT box map public -> listen):"
	echo "$PORTS" | while read -r what listen public; do
		if [ "$listen" = "$public" ]; then printf '  %-24s %s\n' "$what" "$listen"
		else printf '  %-24s listen %s, public %s\n' "$what" "$listen" "$public"; fi
	done
	echo "change them in the panel; the node picks up new ports by itself."
fi
