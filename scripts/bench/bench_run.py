"""Run the 10k+ benchmark scan and check accuracy against the plan.
Usage: BENCH_NOTE="what changed" python -I -X utf8 bench_run.py <.env> <plan.json> <label> <ports> <rate> <batch_prefix> [api base]
The result is recorded in docs/benchmarks/ (history.csv + full JSON)."""
import http.cookiejar, json, os, subprocess, sys, time, urllib.error, urllib.request

env_path, plan_path, label, ports, rate, prefix = sys.argv[1:7]
ENV = dict(l.strip().split("=", 1) for l in open(env_path, encoding="utf-8") if "=" in l and not l.startswith("#"))
BASE = (sys.argv[7] if len(sys.argv) > 7 else "http://127.0.0.1:3000") + "/api/v1"
ORIGIN = "http://localhost:3000"


class Api:
    """Cookie session + CSRF header, like the browser through the Next proxy."""

    def __init__(self, user, password):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        st, _ = self.call("POST", "/auth/login", {"login": user, "password": password})
        if st != 200:
            sys.exit(f"login failed: HTTP {st}")

    def call(self, method, path, body=None, timeout=60):
        h = {"Accept": "application/json"}
        data = None
        if body is not None:
            data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
        if method != "GET":
            h["X-ASI-CSRF"] = "1"
            h["Origin"] = ORIGIN  # the core checks it with the CSRF header (ASI_ALLOWED_ORIGINS)
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
        try:
            with self.op.open(req, timeout=timeout) as r:
                b = r.read()
                return r.status, (json.loads(b) if b else None)
        except urllib.error.HTTPError as e:
            b = e.read()
            try:
                return e.code, json.loads(b)
            except ValueError:
                return e.code, b


plan = json.load(open(plan_path))
admin = Api(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])

admin.call("POST", "/targets", {"items": [{"value": plan["net"], "name": "Benchmark /18", "tags": ["bench"]}]})
target = next(t for t in admin.call("GET", "/targets?page_size=500")[1]["items"] if t["value"] == plan["net"])
name = f"Bench {label}"
prof = next((p for p in admin.call("GET", "/profiles")[1] if p["name"] == name), None)
body = {"name": name, "description": "benchmark", "ports": {"preset": "custom", "custom": ports} if "," in ports or ports.isdigit() else {"preset": ports, "custom": ""},
        "rate_limit_rps": int(rate), "batch_strategy": "fixed", "batch_prefix": int(prefix)}
if prof:
    st, prof = admin.call("PATCH", f"/profiles/{prof['id']}", body)
else:
    st, prof = admin.call("POST", "/profiles", body)
st, est = admin.call("POST", "/scans/estimate", {"target_ids": [target["id"]], "profile_id": prof["id"]})
print("estimate:", {k: est[k] for k in ("addresses", "batches", "batch_size", "rate_rps", "est_duration_s")})

st, run = admin.call("POST", "/scans", {"name": f"Benchmark {label}", "target_ids": [target["id"]], "profile_id": prof["id"], "start": "now", "tags": ["bench"]})
t0 = time.time()
samples = []
while True:
    st, r = admin.call("GET", f"/scans/{run['id']}")
    s = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}", "asi-core-1"], capture_output=True, text=True).stdout.strip()
    cpu = float(s.split("%")[0]) if s else 0.0
    mem = s.split()[1] if s else "?"
    el = time.time() - t0
    samples.append((el, r["progress"], r["stats"]["hosts_alive"], cpu, mem))
    if len(samples) % 6 == 1:
        print(f"  t={el:5.0f}s progress={r['progress']*100:5.1f}% batches={r['batches_done']}/{r['batches_total']} alive={r['stats']['hosts_alive']} cpu={cpu:.0f}% mem={mem}", flush=True)
    if r["status"] in ("completed", "cancelled", "failed"):
        break
    time.sleep(10)
total = time.time() - t0
print(f"RESULT {label}: status={r['status']} wall={total:.0f}s active={r['duration_s']}s addresses={r['address_count']} "
      f"rate={r['address_count']/max(total,1):.1f} addr/s alive={r['stats']['hosts_alive']} services={r['stats']['services']} "
      f"http={r['stats']['http_services']} batches={r['batches_done']} cpu_max={max(x[3] for x in samples):.0f}% "
      f"mem_max={max(x[4] for x in samples)}")

# accuracy against the plan
st, body = admin.call("GET", f"/scans/{run['id']}/export?format=json", timeout=300)
found = {h["ip"]: h for h in body["hosts"]}
expected = {ip: kind for ip, _, kind in plan["hosts"]}
want_port = {"nginx": 80, "httpd": 80, "redis": 6379}
missing = [ip for ip in expected if ip not in found]
extra = [ip for ip in found if ip not in expected and ip != plan["scanner"]]
svc_ok = sum(1 for ip, kind in expected.items() if ip in found and any(s["port"] == want_port[kind] for s in found[ip]["services"]))
ver_ok = sum(1 for ip, kind in expected.items() if ip in found and any(s["port"] == want_port[kind] and s.get("product") for s in found[ip]["services"]))
http_ok = sum(1 for ip, kind in expected.items() if kind != "redis" and ip in found and any(s["http"] for s in found[ip]["services"]))
web = sum(1 for k in expected.values() if k != "redis")
print(f"ACCURACY {label}: hosts found {len(expected)-len(missing)}/{len(expected)}, extra (not planned) {len(extra)} {extra[:5]}, "
      f"expected port open {svc_ok}/{len(expected)}, product identified {ver_ok}/{len(expected)}, http fingerprint {http_ok}/{web}")
result = {"label": label, "ports": ports, "rate": int(rate), "run": r, "samples": samples, "missing": missing, "extra": extra,
          "svc_ok": svc_ok, "ver_ok": ver_ok, "http_ok": http_ok, "wall": total}
# Every run goes to the journal (docs/benchmarks/), so we can show how the scanner changed.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from record import record  # noqa: E402

record(plan, result, ports, int(rate), os.environ.get("BENCH_NOTE", ""))
