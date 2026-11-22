"""Domains as targets + path/html signatures, through the dashboard proxy.
Usage: python -I -X utf8 scripts/e2e/signatures_domains_check.py <.env> http://127.0.0.1:3000"""
import sys, time

exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_client.py"), encoding="utf-8").read())
a = login(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])
prof = next(p for p in a.call("GET", "/profiles")[1] if p["name"] == "Laboratorium")

for v in ("blog.asi.test", "example.com", "nope.asi.test"):
    a.call("POST", "/targets", {"items": [{"value": v, "name": v}], "on_conflict": "skip"})
ts = {t["value"]: t for t in a.call("GET", "/targets?page_size=200")[1]["items"]}
check("domain target stored as domain", ts["blog.asi.test"]["type"] == "domain", ts["blog.asi.test"])

st, e = a.call("POST", "/scans/estimate", {"target_ids": [ts["example.com"]["id"]], "profile_id": prof["id"]})
check("domain outside ASI_ALLOWED_DOMAINS refused", st == 422 and "ASI_ALLOWED_DOMAINS" in e["error"]["message"], (st, e))
st, e = a.call("POST", "/scans/estimate", {"target_ids": [ts["nope.asi.test"]["id"]], "profile_id": prof["id"]})
check("unresolvable approved domain refused with a reason", st == 422 and "rozwiązać" in e["error"]["message"], (st, e))
st, e = a.call("POST", "/scans/estimate", {"target_ids": [ts["blog.asi.test"]["id"]], "profile_id": prof["id"]})
check("approved domain estimates", st == 200 and e["addresses"] == 1, (st, e))


def scan(name, ids):
    st, r = a.call("POST", "/scans", {"name": name, "target_ids": ids, "profile_id": prof["id"], "start": "now"})
    assert st == 201, (st, r)
    t0 = time.time()
    while time.time() - t0 < 300:
        s = a.call("GET", f"/scans/{r['id']}")[1]
        if s["status"] in ("completed", "failed", "cancelled"):
            return s
        time.sleep(3)
    return s


s = scan("Domena blog.asi.test", [ts["blog.asi.test"]["id"]])
check("domain scan completed", s["status"] == "completed" and s["stats"]["hosts_alive"] >= 1, (s["status"], s["stats"], s.get("error")))
hosts = a.call("GET", "/hosts?page_size=100&q=172.30.0.13")[1]["items"]
check("host found via the domain, name kept", any(h["ip"] == "172.30.0.13" and "blog.asi.test" in (h.get("hostnames") or [h.get("hostname")]) for h in hosts),
      [(h["ip"], h.get("hostname"), h.get("hostnames")) for h in hosts])

time.sleep(2)
f = a.call("GET", "/findings?page_size=200")[1]["items"]
on_blog = [x for x in f if x["ip"] == "172.30.0.13"]
names = {x.get("signature_name"): x for x in on_blog if x.get("signature_name")}
print("  signatures on 172.30.0.13:", sorted(names))
for n in ("Repozytorium .git dostępne z sieci", "Strona logowania (/login)", "Panel /admin/", "Endpoint /version",
          "Wersja w stopce strony", "Meta generator (CMS i wersja)"):
    check(f"signature: {n}", n in names, sorted(names))
ev = " ".join(f'{x["title"]} {x.get("evidence")}' for x in on_blog)  # the extracted version is part of the title
check("path evidence shows the GET and status", "GET /.git/HEAD" in ev, ev[:400])
check("versions extracted (1.4.2 / WordPress 6.4.2)", "1.4.2" in ev and "WordPress 6.4.2" in ev, ev[:600])

# custom signature on a header the scanner now keeps (X-Powered-By)
st, sig = a.call("POST", "/signatures", {"name": "X-Powered-By PHP (test)", "description": "", "category": "technology", "technology": "PHP",
    "score_weight": 5, "enabled": True, "tags": [], "match": {"operator": "and", "conditions": [{"type": "header", "name": "X-Powered-By", "op": "regex", "value": "PHP/", "extract": "PHP/([\\d.]+)"}]}})
if st == 409:
    sig = next(x for x in a.call("GET", "/signatures")[1] if x["name"] == "X-Powered-By PHP (test)")
    st = 201
check("custom header signature created", st == 201, (st, sig))
svc = next((x for x in on_blog if x.get("service_id")), None)
st, t = a.call("POST", "/signatures/test", {"signature": {k: sig[k] for k in ("name", "description", "category", "technology", "score_weight", "enabled", "tags", "match")},
                                             "target": {"service_id": svc["service_id"]}})
check("header signature matches the stored scan data", st == 200 and t["matched"] and t["extracted_version"] == "8.1.2", (st, t))
st, t = a.call("POST", "/signatures/test", {"signature": {"name": "git", "description": "", "category": "exposure", "technology": None, "score_weight": 5, "enabled": True, "tags": [],
    "match": {"operator": "and", "conditions": [{"type": "path", "path": "/.git/HEAD", "op": "contains", "value": "ref:"}]}}, "target": {"service_id": svc["service_id"]}})
check("path signature test on a service uses the probe", st == 200 and t["matched"], (st, t))
a.call("DELETE", f"/signatures/{sig['id']}")
for v in ("example.com", "nope.asi.test"):
    a.call("DELETE", f"/targets/{ts[v]['id']}")
print(f"\n{sum(results)}/{len(results)} passed")
