#!/bin/sh
# usage: login.sh DATA_DIR PORT  -> writes DATA_DIR/../cookie-<port>.txt with "__Host-keel_session=..."
DATA=$1; PORT=$2
USER=$(sed 's| / .*||' "$DATA/initial-password")
PW=$(sed 's|^[^/]* / ||' "$DATA/initial-password")
printf '{"username":"%s","password":"%s"}' "$USER" "$PW" > "$DATA/.login.json"
curl -sk -D - -o /dev/null -H 'content-type: application/json' --data-binary @"$DATA/.login.json" "https://127.0.0.1:$PORT/api/login" \
  | tr -d '\r' | sed -n 's/^set-cookie: \(__Host-keel_session=[^;]*\).*/\1/ip' > "$(dirname $DATA)/cookie-$PORT.txt"
rm -f "$DATA/.login.json"
wc -c < "$(dirname $DATA)/cookie-$PORT.txt"
