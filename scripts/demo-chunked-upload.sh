#!/usr/bin/env bash
# Chunked upload walkthrough: init → send two chunks → resume → merge → verify.
# Requires the server on :8080 and jq-free parsing via grep, so it runs anywhere.
set -euo pipefail

BASE=${BASE:-http://127.0.0.1:8080}
TENANT=${TENANT:-east}
# Git Bash exports USERNAME as the Windows account name, so reading it here would
# sign in as the local user and the demo would die at login on this machine.
USER=${DEMO_USER:-alice}
PASS=${PASSWORD:-passw0rd}
FILE=${FILE:-./tmp-demo.bin}
CHUNK=${CHUNK:-1048576}

command -v curl >/dev/null || { echo "curl is required"; exit 1; }

if [ ! -f "$FILE" ]; then
    echo "creating a $CHUNK byte demo file at $FILE"
    head -c "$CHUNK" /dev/urandom > "$FILE"
fi

echo "== login =="
TOKEN=$(curl -s -X POST "$BASE/api/v1/login" -H 'Content-Type: application/json' \
    -d "{\"tenant_code\":\"$TENANT\",\"username\":\"$USER\",\"password\":\"$PASS\"}" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "login failed"; exit 1; }

SIZE=$(wc -c < "$FILE" | tr -d ' ')
SHA=$(sha256sum "$FILE" | cut -d' ' -f1)

echo "== init ($SIZE bytes, sha $SHA) =="
INIT=$(curl -s -X POST "$BASE/api/v1/uploads" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"dir\":\"/demo\",\"name\":\"$(basename "$FILE")\",\"size\":$SIZE,\"chunk_size\":$CHUNK,\"sha256\":\"$SHA\"}")
echo "$INIT"

if echo "$INIT" | grep -q '"instant":true'; then
    echo "== 秒传 hit: the server already had these bytes, nothing was transferred =="
    exit 0
fi

UID_=$(echo "$INIT" | sed -n 's/.*"upload_id":\([0-9]*\).*/\1/p')
COUNT=$(echo "$INIT" | sed -n 's/.*"chunk_count":\([0-9]*\).*/\1/p')

echo "== upload every chunk except the first, then resume =="
for ((i=1; i<COUNT; i++)); do
    dd if="$FILE" of=/tmp/chunk.bin bs="$CHUNK" skip="$i" count=1 status=none
    CSHA=$(sha256sum /tmp/chunk.bin | cut -d' ' -f1)
    curl -s -X PUT "$BASE/api/v1/uploads/$UID_/chunks/$i" \
        -H "Authorization: Bearer $TOKEN" -H "X-Chunk-SHA256: $CSHA" \
        --data-binary @/tmp/chunk.bin > /dev/null
done

echo "== status after the simulated interruption =="
curl -s "$BASE/api/v1/uploads/$UID_" -H "Authorization: Bearer $TOKEN"; echo

echo "== send only the missing chunk 0 =="
dd if="$FILE" of=/tmp/chunk.bin bs="$CHUNK" count=1 status=none
CSHA=$(sha256sum /tmp/chunk.bin | cut -d' ' -f1)
curl -s -X PUT "$BASE/api/v1/uploads/$UID_/chunks/0" \
    -H "Authorization: Bearer $TOKEN" -H "X-Chunk-SHA256: $CSHA" \
    --data-binary @/tmp/chunk.bin; echo

echo "== merge =="
DONE=$(curl -s -X POST "$BASE/api/v1/uploads/$UID_/complete" -H "Authorization: Bearer $TOKEN")
echo "$DONE"
FID=$(echo "$DONE" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')

echo "== download and compare =="
curl -s "$BASE/api/v1/files/$FID/download" -H "Authorization: Bearer $TOKEN" -o /tmp/roundtrip.bin
SHA2=$(sha256sum /tmp/roundtrip.bin | cut -d' ' -f1)
echo "original: $SHA"
echo "returned: $SHA2"
[ "$SHA" = "$SHA2" ] && echo "OK: byte identical" || { echo "MISMATCH"; exit 1; }
