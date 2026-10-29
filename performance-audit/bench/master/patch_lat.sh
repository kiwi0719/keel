#!/bin/sh
# usage: patch_lat.sh PORT N  -> N timed PATCH /api/users/2 (each edit runs App::sync before answering)
PORT=$1; N=${2:-3}
SCR=$(cd "$(dirname "$0")" && pwd)
COOKIE=$(cat "$SCR/cookie-$PORT.txt")
i=0
while [ $i -lt $N ]; do
  i=$((i+1))
  curl -sk -o /dev/null -w "PATCH /api/users/2: %{http_code} %{time_total}s\n" -X PATCH -H "Cookie: $COOKIE" -H 'x-keel: 1' \
    -H 'content-type: application/json' --data "{\"plan\":\"p$i$$\"}" "https://127.0.0.1:$PORT/api/users/2"
done
