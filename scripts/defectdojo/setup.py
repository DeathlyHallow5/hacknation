"""Connect ASI to the local DefectDojo (compose.defectdojo.yaml) — the same steps as
Administracja → Integracje in the dashboard, done once from the command line.

1. API token of the DefectDojo admin (password DD_ADMIN_PASSWORD from .env);
2. ASI settings: URL http://dojo-nginx:8080 (how the core reaches it), the token (stored
   encrypted, never printed), automatic export of findings with score >= --min-score;
3. "Test połączenia": the core finds or creates product "ASI — CBI AGH" and engagement
   "ASI — skanowanie ciągłe" in DefectDojo.

Usage: python -I scripts/defectdojo/setup.py .env [--min-score 60] [--no-auto]
       [--dojo http://localhost:8081] [--asi http://localhost:3000]"""
import argparse, http.cookiejar, json, sys, urllib.error, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("env")
ap.add_argument("--dojo", default="http://localhost:8081")
ap.add_argument("--asi", default="http://localhost:3000")
ap.add_argument("--min-score", type=int, default=60)
ap.add_argument("--no-auto", action="store_true", help="do not export automatically after each scan")
a = ap.parse_args()
ENV = dict(l.strip().split("=", 1) for l in open(a.env, encoding="utf-8") if "=" in l and not l.startswith("#"))
for k in ("DD_ADMIN_PASSWORD", "ASI_ADMIN_PASSWORD"):
    if not ENV.get(k):
        sys.exit(f"{k} is not set in {a.env}")

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(method, url, body=None, headers=None):
    h = {"Accept": "application/json", **(headers or {})}
    data = None
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with opener.open(req, timeout=60) as r:
            b = r.read()
            return r.status, (json.loads(b) if b else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300]


st, tok = call("POST", f"{a.dojo}/api/v2/api-token-auth/", {"username": "admin", "password": ENV["DD_ADMIN_PASSWORD"]})
if st != 200:
    sys.exit(f"DefectDojo token: HTTP {st} — is it up? (docker compose ... --profile dojo up -d)")
print("DefectDojo: API token received")

asi = a.asi.rstrip("/") + "/api/v1"
write = {"X-ASI-CSRF": "1", "Origin": a.asi.rstrip("/")}
st, _ = call("POST", f"{asi}/auth/login", {"login": ENV.get("ASI_ADMIN_USER", "admin"), "password": ENV["ASI_ADMIN_PASSWORD"]}, write)
if st != 200:
    sys.exit(f"ASI login: HTTP {st}")
cfg = {"url": "http://dojo-nginx:8080", "api_token": tok["token"], "auto_export": not a.no_auto,
       "min_score": a.min_score, "export_as": "finding", "verify_tls": True}
st, saved = call("PUT", f"{asi}/integrations/defectdojo", cfg, write)
if st != 200:
    sys.exit(f"ASI settings: HTTP {st} {saved}")
print(f"ASI: DefectDojo set (enabled={saved['enabled']}, auto export={saved['auto_export']}, min score={saved['min_score']})")
st, tested = call("POST", f"{asi}/integrations/defectdojo/test", {}, write)
t = (tested or {}).get("last_test") or {}
print(("OK: " if t.get("ok") else "FAILED: ") + str(t.get("message")))
sys.exit(0 if t.get("ok") else 1)
