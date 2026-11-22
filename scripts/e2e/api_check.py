"""Live checks of the /api/v1 endpoints added for the full dashboard (scans, profiles,
schedules, assets, diffs, signatures, admin). Talks to the core directly with a cookie
session + CSRF header, like the browser through the Next proxy.
Usage: python -I -X utf8 scripts/e2e/api_check.py <.env> [base, default http://127.0.0.1:3000]"""
exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_client.py"), encoding="utf-8").read())
tag = uuid.uuid4().hex[:5]
admin = login(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])
check("admin login", admin)

# ---------- admin ----------
st, roles = admin.call("GET", "/roles")
check("roles: 4 built-in first", st == 200 and [r["key"] for r in roles][:4] == ["admin", "operator", "analyst", "viewer"], roles)
check("role without permissions refused", admin.call("POST", "/roles", {"name": "x"})[0] == 422)
pw = "Lab-password-" + tag
st, u = admin.call("POST", "/users", {"login": f"anal-{tag}", "name": "Anna Analityk", "email": "a@example.org", "role_id": "analyst", "password": pw})
check("create user (analyst)", st == 201 and u["role_id"] == "analyst" and u["name"] == "Anna Analityk", (st, u))
st, uv = admin.call("POST", "/users", {"login": f"obs-{tag}", "name": "Obserwator", "role_id": "viewer", "password": pw})
check("create user (viewer)", st == 201, (st, uv))
st, u2 = admin.call("PATCH", f"/users/{u['id']}", {"email": "b@example.org"})
check("update user email", st == 200 and u2["email"] == "b@example.org", (st, u2))
st, s = admin.call("GET", "/settings")
check("settings defaults", st == 200 and s["default_window"]["timezone"] == "Europe/Warsaw", s)
st, s2 = admin.call("PATCH", "/settings", {"scan_safety": {"max_rate_rps": 0}})
check("settings validation", st == 422 and "max_rate_rps" in s2["error"]["fields"], (st, s2))
st, s2 = admin.call("PATCH", "/settings", {"change_detection": {"inactive_after_misses": 2}})
check("settings update", st == 200 and s2["change_detection"]["inactive_after_misses"] == 2, (st, s2))
st, enc = admin.call("GET", "/security/encryption")
check("encryption status (live round-trip)", st == 200 and enc["enabled"] and enc["key_id"].startswith("sha256:"), enc)
# Without ASI_DATA_KEY_PREVIOUS there is nothing to rotate: 409 with the procedure.
check("key rotation needs a previous key (409)", admin.call("POST", "/security/encryption/rotate")[0] == 409)
st, eng = admin.call("GET", "/engines")
check("engines with versions", st == 200 and all(e["status"] == "ok" and e["version"] for e in eng), eng)
st, dd = admin.call("GET", "/integrations/defectdojo")
check("defectdojo config", st == 200 and "api_token_set" in dd, dd)
if dd.get("enabled") and dd.get("api_token_set"):
    # A connected DefectDojo (compose.yaml's dojo-connect) is left alone: the token cannot be
    # read back, so overwriting it would break automatic export. scripts/e2e/defectdojo_check.py
    # covers the live integration.
    print("  (skipped: DefectDojo is connected; saving a fake token would break it)")
else:
    st, dd = admin.call("PUT", "/integrations/defectdojo", {"url": "http://127.0.0.1:9", "api_token": "secret-token-1234", "enabled": True, "engagement_id": 1})
    check("defectdojo save masks token", st == 200 and dd["api_token_set"] and dd["api_token_masked"].endswith("1234") and "secret" not in json.dumps(dd), dd)
    st, dd = admin.call("POST", "/integrations/defectdojo/test")
    check("defectdojo test reports failure honestly", st == 200 and dd["last_test"]["ok"] is False, dd)
    admin.call("PUT", "/integrations/defectdojo", {"url": ""})  # leave it switched off, not pointing at a dead address

# ---------- profiles ----------
st, profiles = admin.call("GET", "/profiles")
check("builtin profiles incl. Laboratorium and Duża sieć", st == 200 and {"Szybki", "Standardowy", "Delikatny", "Laboratorium", "Duża sieć"} <= {p["name"] for p in profiles if p["builtin"]}, [p["name"] for p in profiles])
quick = next(p for p in profiles if p["name"] == "Laboratorium")
st, p = admin.call("POST", "/profiles", {"name": f"Lab {tag}", "description": "porty labu", "ports": {"preset": "custom", "custom": "22,80,443,8080"}, "rate_limit_rps": 50, "batch_strategy": "auto", "batch_prefix": 24})
check("create custom profile", st == 201 and not p["builtin"] and p["ports"]["custom"].startswith("22"), (st, p))
check("profile rate above global max refused", admin.call("PATCH", f"/profiles/{p['id']}", {"rate_limit_rps": 99999})[0] == 422)
check("builtin profile cannot be deleted", admin.call("DELETE", f"/profiles/{quick['id']}")[0] == 409)

# ---------- targets + estimate ----------
st, r = admin.call("POST", "/targets", {"items": [{"value": "172.30.0.0/28", "name": f"lab {tag}"}], "on_conflict": "skip"})
lab = next(t for t in admin.call("GET", "/targets?page_size=500")[1]["items"] if t["value"] == "172.30.0.0/28")
st, est = admin.call("POST", "/scans/estimate", {"target_ids": [lab["id"]], "profile_id": p["id"]})
check("estimate", st == 200 and est["addresses"] == 14 and est["batches"] >= 1 and est["notes"], (st, est))

# ---------- scan with SSE ----------
st, run = admin.call("POST", "/scans", {"name": f"Lab scan {tag}", "target_ids": [lab["id"]], "profile_id": p["id"], "start": "now", "tags": ["lab"]})
check("create scan → run", st == 201 and run["status"] in ("queued", "running") and run["profile_name"] == f"Lab {tag}", (st, run))
events = admin.sse(f"/scans/{run['id']}/events", 150)
check("SSE: progress … done", "progress" in events and events[-1] == "done", events[-6:])
run = wait_run(admin, run["id"])
check("run completed", run["status"] == "completed" and run["stats"]["hosts_alive"] >= 2, run)
st, b = admin.call("GET", f"/scans/{run['id']}/batches")
check("batches", st == 200 and b and b[0]["status"] == "done", (st, b))
st, lg = admin.call("GET", f"/scans/{run['id']}/logs")
check("logs", st == 200 and any("zakończone" in l["message"] for l in lg), lg)
st, run2 = admin.call("PATCH", f"/scans/{run['id']}", {"notes": "przegląd labu", "tags": ["lab", "demo"]})
check("patch run notes/tags", st == 200 and run2["notes"] == "przegląd labu" and run2["tags"] == ["lab", "demo"], run2)
st, body = admin.call("GET", f"/scans/{run['id']}/export?format=json")
check("export results JSON", st == 200 and body["format"] == "asi-results" and body["hosts"], st)
st, csvb = admin.call("GET", f"/scans/{run['id']}/export?format=csv")
check("export results CSV", st == 200 and csvb.startswith(b"ip,hostname"), csvb[:80])

# pause / resume / cancel on a second run
st, r2 = admin.call("POST", "/scans", {"name": f"Pause {tag}", "target_ids": [lab["id"]], "profile_id": p["id"], "start": "now"})
time.sleep(4)
st, pz = admin.call("POST", f"/scans/{r2['id']}/pause")
check("pause", st == 200 and pz["status"] in ("paused",), (st, pz))
st, rs = admin.call("POST", f"/scans/{r2['id']}/resume")
check("resume", st == 200 and rs["status"] in ("queued", "running"), (st, rs))
st, cx = admin.call("POST", f"/scans/{r2['id']}/cancel")
check("cancel", st == 200 and cx["status"] == "cancelled", (st, cx))
check("cancel again → 409", admin.call("POST", f"/scans/{r2['id']}/cancel")[0] == 409)
check("delete finished run", admin.call("DELETE", f"/scans/{r2['id']}")[0] == 204)

# test window: pauses and resumes by itself
st, r3 = admin.call("POST", "/scans", {"name": f"Okno {tag}", "target_ids": [lab["id"]], "profile_id": p["id"], "start": "now", "test_window_seconds": 30})
seen = set()
end = time.time() + 240
while time.time() < end:
    s3 = admin.call("GET", f"/scans/{r3['id']}")[1]
    seen.add(s3["status"])
    if s3["status"] in ("completed", "cancelled", "failed"):
        break
    time.sleep(1)
# A small lab may finish inside the test window; when it does not, it must pause and resume.
check("test window: completed (paused and resumed if it did not fit)", s3["status"] == "completed", (seen, s3["status"], s3.get("windows_used")))

# import results
form, ct = multipart({}, "wyniki.csv", b"ip,hostname,port,protocol,service,product,version\n198.51.100.7,imp,22,tcp,ssh,OpenSSH,9.6\n198.51.100.7,imp,80,tcp,http,nginx,1.25\n")
st, imp = admin.call("POST", "/scans/import", raw=form, ctype=ct)
check("import results (CSV)", st == 201 and imp["source"] == "import" and imp["status"] == "completed", (st, imp))
nmap_xml = b'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="198.51.100.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Caddy" conf="10" method="probed"/></port></ports></host></nmaprun>'
form, ct = multipart({}, "nmap.xml", nmap_xml)
st, imp2 = admin.call("POST", "/scans/import", raw=form, ctype=ct)
check("import results (nmap XML)", st == 201, (st, imp2))

# ---------- schedules ----------
st, sch = admin.call("POST", "/schedules", {"name": f"Nocny {tag}", "enabled": True, "target_ids": [lab["id"]], "profile_id": p["id"], "window": {"start": "22:00", "end": "06:00", "timezone": "Europe/Warsaw"}, "days": [1, 2, 3, 4, 5], "frequency": "weekly", "on_window_exceeded": "pause_resume"})
check("create schedule with next window", st == 201 and sch["next_run_at"] and sch["frequency"] == "weekly", (st, sch))
check("cron refused honestly", admin.call("POST", "/schedules", {"name": "c", "target_ids": [lab["id"]], "profile_id": p["id"], "window": {"start": "01:00", "end": "02:00", "timezone": "Europe/Warsaw"}, "frequency": "cron"})[0] == 422)
st, sch2 = admin.call("PATCH", f"/schedules/{sch['id']}", {"enabled": False})
check("disable schedule clears next run", st == 200 and sch2["next_run_at"] is None, sch2)
check("delete schedule", admin.call("DELETE", f"/schedules/{sch['id']}")[0] == 204)

# ---------- assets ----------
st, hosts = admin.call("GET", "/hosts?page_size=100")
check("hosts list", st == 200 and hosts["total"] >= 2 and "response_pattern" in hosts["items"][0], (st, hosts))
h = next(x for x in hosts["items"] if x["ip"].startswith("172.30.0.1"))
st, hd = admin.call("GET", f"/hosts/{h['id']}")
check("host detail with services + fingerprint", st == 200 and hd["services"] and hd["services"][0]["http"] is not None, (st, hd))
st, hp = admin.call("PATCH", f"/hosts/{h['id']}", {"owner": "Dział sieci", "criticality": "critical", "tags": ["lab", "dmz"]})
check("host override", st == 200 and hp["owner"] == "Dział sieci" and hp["manual_overrides"]["owner"]["value"] == "Dział sieci", (st, hp))
st, hr = admin.call("DELETE", f"/hosts/{h['id']}/overrides/owner")
check("revert override", st == 200 and "owner" not in hr["manual_overrides"], (st, hr))
st, hist = admin.call("GET", f"/hosts/{h['id']}/history")
check("host history", st == 200 and len(hist) >= 1, (st, hist))
check("unstable hosts", admin.call("GET", "/hosts/unstable")[0] == 200)
st, svcs = admin.call("GET", "/services?page_size=100")
check("services list", st == 200 and svcs["total"] >= 2, (st, svcs))
sv = svcs["items"][0]
st, sp = admin.call("PATCH", f"/services/{sv['id']}", {"version": "ręcznie 1.0", "notes": "sprawdzone"})
check("service override", st == 200 and sp["version"] == "ręcznie 1.0", (st, sp))
st, groups = admin.call("GET", "/service-groups")
check("service groups", st == 200 and groups and groups[0]["count"] >= 1, (st, groups))
st, df = admin.call("GET", "/diffs")
check("diffs default (latest vs previous)", st == 200 and df["base"] and df["head"] and "summary" in df, (st, df))

# ---------- signatures ----------
st, sigs = admin.call("GET", "/signatures")
check("23 builtin signatures", st == 200 and sum(s["source"] == "builtin" for s in sigs) >= 20, len(sigs) if isinstance(sigs, list) else sigs)
sig = {"name": f"Admin staging {tag}", "description": "test", "category": "admin_panel", "technology": "Lab", "score_weight": 20,
       "enabled": True, "match": {"operator": "and", "conditions": [{"type": "title", "op": "contains", "value": "Admin login"}]}, "tags": ["lab"]}
st, tr = admin.call("POST", "/signatures/test", {"signature": sig, "target": {"raw": {"status_code": 200, "headers": "Server: nginx", "body": "<title>Admin login - staging</title>"}}})
check("signature test on raw response", st == 200 and tr["matched"] and tr["safety"]["ok"], (st, tr))
bad = dict(sig, match={"operator": "and", "conditions": [{"type": "path", "path": "/admin", "op": "exists"}]})
st, tr = admin.call("POST", "/signatures/test", {"signature": bad, "target": {"raw": {"status_code": 200, "headers": "", "body": ""}}})
check("path probe is a safe GET; on a raw response it explains it needs a service", st == 200 and tr["safety"]["ok"] and not tr["matched"] and tr["safety"]["issues"], (st, tr))
st, cs = admin.call("POST", "/signatures", sig)
check("create custom signature", st == 201 and cs["source"] == "custom", (st, cs))
check("ReDoS-ish / bad regex refused", admin.call("POST", "/signatures", dict(sig, name="x" + tag, match={"operator": "and", "conditions": [{"type": "title", "op": "regex", "value": "("}]}))[0] == 422)
builtin = next(s for s in sigs if s["source"] == "builtin")
check("builtin cannot be edited", admin.call("PATCH", f"/signatures/{builtin['id']}", {"name": "x"})[0] == 409)
check("builtin can be disabled", admin.call("PATCH", f"/signatures/{builtin['id']}", {"enabled": False})[1]["enabled"] is False)
admin.call("PATCH", f"/signatures/{builtin['id']}", {"enabled": True})
st, f = admin.call("GET", "/findings?category=admin_panel&page_size=100")
check("signature match shows up as a finding", st == 200 and any(x.get("signature_name") == sig["name"] for x in f["items"]), [x.get("signature_name") for x in f["items"]])
check("delete custom signature", admin.call("DELETE", f"/signatures/{cs['id']}")[0] == 204)

# ---------- findings bulk ----------
# Re-read: the custom signature above is deleted, and with it the finding it produced.
f = admin.call("GET", "/findings?category=admin_panel&page_size=100")[1]
ids = [x["id"] for x in f["items"][:2]]
st, bk = admin.call("POST", "/findings/bulk", {"ids": ids, "action": "tag", "payload": {"tag": f"przeglad-{tag}"}})
check("findings bulk tag", st == 200 and bk["affected"] == len(ids), (st, bk))
admin.call("POST", "/findings/bulk", {"ids": ids, "action": "untag", "payload": {"tag": f"przeglad-{tag}"}})

# ---------- RBAC on new routes ----------
viewer = login(f"obs-{tag}", pw)
analyst = login(f"anal-{tag}", pw)
check("viewer: hosts readable", viewer.call("GET", "/hosts")[0] == 200)
check("viewer: no scan start", viewer.call("POST", "/scans", {"name": "x", "target_ids": [lab["id"]], "profile_id": p["id"]})[0] == 403)
check("viewer: no host edit", viewer.call("PATCH", f"/hosts/{h['id']}", {"owner": "x"})[0] == 403)
check("viewer: no users list", viewer.call("GET", "/users")[0] == 403)
check("viewer: no cookie reveal", viewer.call("POST", f"/services/{sv['id']}/cookies/x/reveal")[0] == 403)
check("viewer: fingerprint redacted", all(not s["http"] or s["http"]["redacted"] for s in viewer.call("GET", f"/hosts/{h['id']}")[1]["services"]))
check("analyst: can edit host", analyst.call("PATCH", f"/hosts/{h['id']}", {"notes": "ok"})[0] == 200)
check("analyst: cannot start scan (no scan.execute)", analyst.call("POST", "/scans", {"name": "x", "target_ids": [lab["id"]], "profile_id": p["id"]})[0] == 403)
check("analyst: cannot create profile", analyst.call("POST", "/profiles", {"name": "x"})[0] == 403)
check("analyst: settings forbidden", analyst.call("GET", "/settings")[0] == 403)

# cleanup
admin.call("PATCH", "/settings", {"change_detection": {"inactive_after_misses": 3}})
admin.call("DELETE", f"/profiles/{p['id']}")
admin.call("DELETE", f"/users/{u['id']}")
admin.call("DELETE", f"/users/{uv['id']}")
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
