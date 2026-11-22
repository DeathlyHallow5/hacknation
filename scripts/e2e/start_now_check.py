"""'Teraz' outside the clock window runs at once; 'W najbliższym oknie' waits; estimate; logs.
Usage: python -I -X utf8 scripts/e2e/start_now_check.py <.env> [base]"""
import datetime, sys, time

exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_client.py"), encoding="utf-8").read())
admin = login(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])
targets = admin.call("GET", "/targets?page_size=200")[1]["items"]
lab = next(t for t in targets if t["value"] == "172.30.0.0/28")
prof = next(p for p in admin.call("GET", "/profiles")[1] if p["name"] == "Laboratorium")
# A window that is closed now: opens in 3 h, lasts 1 h (Europe/Warsaw).
now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=1)))
ws = (now + datetime.timedelta(hours=3)).strftime("%H:00")
we = (now + datetime.timedelta(hours=4)).strftime("%H:00")
win = {"start": ws, "end": we, "timezone": "Europe/Warsaw"}

st, est = admin.call("POST", "/scans/estimate", {"target_ids": [lab["id"]], "profile_id": prof["id"], "window": win})
check("estimate /28 Laboratorium (8 ports @100/s) ≈ 14*16/100+6+20 ≈ 28 s", st == 200 and 20 <= est["est_duration_s"] <= 40, est)

st, r = admin.call("POST", "/scans", {"name": "Teraz poza oknem", "target_ids": [lab["id"]], "profile_id": prof["id"], "start": "now", "window": win})
check("create 'now' outside window", st == 201, (st, r))
check("address_count known before start", r.get("address_count") == 14, r.get("address_count"))
logs = admin.call("GET", f"/scans/{r['id']}/logs")[1]
check("no 'Okno zamknięte' while queued", not any("Okno zamknięte" in l["message"] for l in logs), [l["message"] for l in logs])
t0 = time.time()
seen = set()
while time.time() - t0 < 240:
    s = admin.call("GET", f"/scans/{r['id']}")[1]
    seen.add(s["status"])
    if s["status"] in ("completed", "failed", "cancelled"):
        break
    time.sleep(3)
check("'now' outside window ran to completion", s["status"] == "completed", (s["status"], seen))
check("never waited for the window", "paused_window" not in seen, seen)
print("  took", round(time.time() - t0), "s; estimate", est["est_duration_s"], "s; hosts", s["stats"]["hosts_alive"])

st, w = admin.call("POST", "/scans", {"name": "W oknie", "target_ids": [lab["id"]], "profile_id": prof["id"], "start": "window", "window": win})
time.sleep(8)
s2 = admin.call("GET", f"/scans/{w['id']}")[1]
logs2 = admin.call("GET", f"/scans/{w['id']}/logs")[1]
check("'window' waits for the window", s2["status"] == "paused_window", s2["status"])
check("log says it waits for the window", any("Czeka na okno" in l["message"] for l in logs2), [l["message"] for l in logs2])
admin.call("POST", f"/scans/{w['id']}/cancel", {})
print(f"\n{sum(results)}/{len(results)} passed")
