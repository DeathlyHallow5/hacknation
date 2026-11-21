#!/usr/bin/env bash
# Run one scan of the local lab (172.30.0.0/24) and print a short summary.
# Usage: scripts/lab-scan.sh [name] [extra JSON fields, e.g. '"window_minutes":1']
# Needs: docker compose --profile lab up -d, curl, python3.
set -euo pipefail
API=${API:-http://127.0.0.1:8000/api}
. "$(dirname "$0")/_auth.sh"
NAME=${1:-lab $(date +%H:%M:%S)}
EXTRA=${2:-}

body=$(python3 -c 'import json,sys; d={"name":sys.argv[1],"targets":"172.30.0.0/24","batch_size":64,"rate_limit_pps":200,"ports":"100"}; d.update(json.loads("{"+sys.argv[2]+"}")); print(json.dumps(d))' "$NAME" "$EXTRA")
scan=$(curl -sf "$API/scans" -H 'Content-Type: application/json' -d "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "scan $scan created"

run=""
for _ in $(seq 1 30); do
  run=$(curl -sf "$API/scans/$scan/runs" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["id"] if r else "")')
  [ -n "$run" ] && break
  sleep 2
done
[ -n "$run" ] || { echo "scheduler did not start a run"; exit 1; }
echo "run  $run started"

while true; do
  state=$(curl -sf "$API/runs/$run" | python3 -c 'import json,sys; r=json.load(sys.stdin); s=r["stats"]; print(r["status"], "%s/%s hosts" % (s.get("hosts_done",0), s.get("hosts_total","?")), "alive=%s open=%s http=%s" % (s.get("alive",0), s.get("open_ports",0), s.get("http",0)))')
  echo "  $state"
  case $state in done*|failed*|cancelled*|paused*) break ;; esac
  sleep 5
done

curl -sf "$API/runs/$run" | python3 -m json.tool
echo "--- findings"
curl -sf "$API/runs/$run/findings" | python3 -c '
import json, sys
for h in json.load(sys.stdin)["hosts"]:
    print(h["address"], h["state"])
    for s in h["services"]:
        print("  %s/%s %s %s %s conf=%s" % (s["port"], s["protocol"], s["service"], s["product"] or "", s["version"] or "", s["confidence"]))
        for f in s["http"]:
            flags = [n for n in ("is_admin", "is_staging") if f[n]]
            print("    %s %r tech=%s %s" % (f["status_code"], f["title"], f["technologies"], flags))
            print("    headers: %s" % sorted((f["headers"] or {}).keys()))
'
