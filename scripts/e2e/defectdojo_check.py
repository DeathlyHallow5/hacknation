"""ASI -> DefectDojo end to end: lab scan -> automatic export; manual 'evidence' export; check
everything on DefectDojo's own API. Usage: python -I -X utf8 scripts/e2e/defectdojo_check.py <.env> http://127.0.0.1:3000"""
import json, sys, time, urllib.request

exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_client.py"), encoding="utf-8").read())
asi = login(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])


def dd(path, method="GET", body=None, token=None):
    h = {"Accept": "application/json"}
    if token:
        h["Authorization"] = f"Token {token}"
    data = None
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8081" + path, data=data, method=method, headers=h), timeout=60) as r:
        return json.loads(r.read())


tok = dd("/api/v2/api-token-auth/", "POST", {"username": "admin", "password": ENV["DD_ADMIN_PASSWORD"]})["token"]
cfg = asi.call("GET", "/integrations/defectdojo")[1]
check("ASI integration enabled, auto export on", cfg["enabled"] and cfg["auto_export"] and cfg["engagement_id"], cfg)
eng = cfg["engagement_id"]
tests_before = dd(f"/api/v2/tests/?engagement={eng}&limit=100", token=tok)["count"]

lab = next(t for t in asi.call("GET", "/targets?page_size=100")[1]["items"] if t["value"] == "172.30.0.0/28")
prof = next(p for p in asi.call("GET", "/profiles")[1] if p["name"] == "Laboratorium")
st, run = asi.call("POST", "/scans", {"name": "DefectDojo e2e", "target_ids": [lab["id"]], "profile_id": prof["id"], "start": "now"})
check("lab scan started", st == 201, (st, run))
t0 = time.time()
while time.time() - t0 < 300:
    r = asi.call("GET", f"/scans/{run['id']}")[1]
    if r["status"] in ("completed", "failed", "cancelled"):
        break
    time.sleep(3)
check("lab scan completed", r["status"] == "completed", r["status"])
time.sleep(8)  # auto export runs right after the run is closed

exports = asi.call("GET", "/integrations/defectdojo/exports")[1]
auto = next((e for e in exports if e["by"] in ("", "automatycznie (po skanie)")), None)
check("automatic export recorded in ASI", auto is not None and auto["status"] == "success", exports[:3])
tests = dd(f"/api/v2/tests/?engagement={eng}&limit=100", token=tok)
check("DefectDojo: a new test in the engagement", tests["count"] > tests_before, tests["count"])
newest = max(tests["results"], key=lambda t: t["id"])
fnd = dd(f"/api/v2/findings/?test={newest['id']}&limit=100", token=tok)["results"]
print("  DefectDojo findings:", [(f["title"][:50], f["severity"]) for f in fnd])
check("DefectDojo: findings imported", len(fnd) >= 1, fnd)
check("DefectDojo: admin panel on .12 as Medium/High", any("172.30.0.12" in f["description"] and f["severity"] in ("Medium", "High") for f in fnd),
      [(f["title"], f["severity"]) for f in fnd])
check("DefectDojo: ASI score explained in description", all("Ocena ASI" in f["description"] for f in fnd))

findings = asi.call("GET", "/findings?page_size=100")[1]["items"]
exported = [f for f in findings if f.get("defectdojo")]
check("ASI marks exported findings", len(exported) >= len(fnd), (len(exported), len(fnd)))
one = next(f for f in findings if not f.get("defectdojo")) if any(not f.get("defectdojo") for f in findings) else findings[0]
st, ev = asi.call("POST", "/findings/defectdojo", {"ids": [one["id"]], "as": "evidence"})
check("manual export as evidence", st == 200 and ev["exported"] == 1, (st, ev))
files = dd(f"/api/v2/engagements/{eng}/files/", token=tok)
items = files.get("results", files) if isinstance(files, dict) else files
check("DefectDojo: evidence file attached to the engagement", len(items) >= 1, files)
check("links point at the browser address", ev["links"][0]["url"].startswith("http://localhost:8081/"), ev["links"][0])
print(f"\n{sum(results)}/{len(results)} passed")
