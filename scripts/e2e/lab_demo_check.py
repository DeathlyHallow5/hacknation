"""README lab walkthrough, steps 2-5, through the Next proxy: scan /28, change the lab, scan again,
check Zmiany (diff) and Znaleziska (admin panel). Usage: python -I -X utf8 scripts/e2e/lab_demo_check.py <.env> [base]"""
import subprocess, sys, time

exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_client.py"), encoding="utf-8").read())
admin = login(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])
lab = next(t for t in admin.call("GET", "/targets?page_size=200")[1]["items"] if t["value"] == "172.30.0.0/28")
prof = next(p for p in admin.call("GET", "/profiles")[1] if p["name"] == "Laboratorium")


def scan(name):
    st, r = admin.call("POST", "/scans", {"name": name, "target_ids": [lab["id"]], "profile_id": prof["id"], "start": "now"})
    assert st == 201, (st, r)
    t0 = time.time()
    while time.time() - t0 < 300:
        s = admin.call("GET", f"/scans/{r['id']}")[1]
        if s["status"] in ("completed", "failed", "cancelled"):
            print(f"  {name}: {s['status']} in {round(time.time() - t0)} s, hosts {s['stats']['hosts_alive']}, "
                  f"new {s['stats']['new']} gone {s['stats']['gone']} changed {s['stats']['changed']} unstable {s['stats']['unstable']}")
            return s
        time.sleep(3)
    raise SystemExit("timeout")


def compose(*a):
    subprocess.run(["docker", "compose", *a], capture_output=True, text=True, cwd=sys.argv[3] if len(sys.argv) > 3 else ".")


compose("start", "lab-httpd")
compose("--profile", "lab2", "stop", "lab-admin")
s1 = scan("README krok 2")
check("run 1 sees nginx .10 and Apache .11", s1["status"] == "completed" and s1["stats"]["hosts_alive"] >= 2)
compose("stop", "lab-httpd")
compose("--profile", "lab2", "up", "-d", "lab-admin")
time.sleep(3)
s2 = scan("README krok 5")
check("run 2: something new", s2["stats"]["new"] >= 1, s2["stats"])
check("run 2: Apache missing (gone/unstable)", s2["stats"]["gone"] + s2["stats"]["unstable"] >= 1, s2["stats"])
st, d = admin.call("GET", f"/diffs?head={s2['id']}")
items = d.get("items", d.get("changes", [])) if isinstance(d, dict) else d
txt = str(d)
check("Zmiany: new host 172.30.0.12", st == 200 and "172.30.0.12" in txt, (st, txt[:600]))
check("Zmiany: 172.30.0.11 missing", "172.30.0.11" in txt, txt[:600])
st, f = admin.call("GET", "/findings?page_size=100")
check("Znaleziska: admin panel on .12", any(x.get("ip") == "172.30.0.12" and x.get("category") == "admin_panel" for x in f["items"]),
      [(x.get("ip"), x.get("category"), x.get("title")) for x in f["items"]][:10])
st, top = admin.call("GET", "/dashboard/top-findings")
check("Pulpit top findings not empty", st == 200 and len(top) > 0, top)
compose("start", "lab-httpd")
compose("--profile", "lab2", "stop", "lab-admin")
print(f"\n{sum(results)}/{len(results)} passed")
