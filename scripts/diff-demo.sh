#!/usr/bin/env bash
# Diff Engine demo on the local lab: 4 runs of one scan with infrastructure changes
# between them, then a comparison of two arbitrary runs.
#   1 baseline          nginx .10 + Apache .11
#   2 change            Apache down, new admin panel on staging (.12)
#   3 no change         Apache still down -> confirmed Inactive (inactive_after_misses=2)
#   4 Apache is back    -> reappeared, counted as a flap (unstable host)
# Needs: docker compose stack running, curl, python3.
set -euo pipefail
API=${API:-http://127.0.0.1:8000/api}
cd "$(dirname "$0")/.."

dc() { docker compose "$@" >/dev/null 2>&1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

latest_run() {
  curl -sf "$API/scans/$1/runs" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["id"] if r else "")'
}

# Wait for a run of scan $1 different from $2 to finish; print its id.
wait_run() {
  local run=""
  for _ in $(seq 1 60); do
    run=$(latest_run "$1")
    [ -n "$run" ] && [ "$run" != "${2:-}" ] && break
    sleep 2
  done
  until curl -sf "$API/runs/$run" | grep -qE '"status":"(done|partial|failed|cancelled)"'; do sleep 3; done
  echo "$run"
}

show() {
  curl -sf "$API/runs/$1" | python3 -c '
import json, sys
r = json.load(sys.stdin); s = r["stats"]
print("run %s: %s | alive=%s rechecked=%s recovered=%s | %.0fs" % (r["id"][:8], r["status"], s.get("alive"), s.get("rechecked", 0), s.get("recovered", 0), s.get("elapsed_secs", 0)))'
  curl -sf "$API/runs/$1/diff${2:+?against=$2}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if not d["run_a"]:
    print("  (first run: baseline, nothing to compare)"); sys.exit()
print("  vs %s: %s" % (d["run_a"][:8], d["summary"]))
for e in d["entries"]:
    what = "%s %s" % (e["field"] + ":" if e["field"] else "", " -> ".join(str(v) for v in (e["old_value"], e["new_value"]) if v is not None))
    print("  [%s] %-7s %-7s %-28s %s (conf %.2f)" % ("!" * e["interest"], e["change"], e["kind"], e["entity"], what.strip(), e["confidence"]))'
}

run_now() { curl -sf -XPOST "$API/scans/$1/run" >/dev/null; }

step "1/4 baseline: nginx .10 + Apache .11"
dc --profile lab2 stop lab-admin
dc --profile lab up -d lab-nginx lab-httpd
scan=$(curl -sf "$API/scans" -H 'Content-Type: application/json' -d '{
  "name": "diff demo", "targets": "172.30.0.8/29", "batch_size": 64, "rate_limit_pps": 200,
  "ports": "100", "inactive_after_misses": 2 }' | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
r1=$(wait_run "$scan"); show "$r1"

step "2/4 Apache stopped, new host with an admin login on staging (.12)"
dc --profile lab stop lab-httpd
dc --profile lab2 up -d lab-admin
run_now "$scan"; r2=$(wait_run "$scan" "$r1"); show "$r2"

step "3/4 nothing changed: Apache still down -> confirmed Inactive"
run_now "$scan"; r3=$(wait_run "$scan" "$r2"); show "$r3"

step "4/4 Apache is back -> reappeared (flap)"
dc --profile lab start lab-httpd
run_now "$scan"; r4=$(wait_run "$scan" "$r3"); show "$r4"

step "any two runs: run 1 vs run 4"
show "$r4" "$r1"
echo; echo "scan id: $scan"
