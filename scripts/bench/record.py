"""Benchmark journal: every run goes to docs/benchmarks/ so we can show how the scanner changed.

- docs/benchmarks/history.csv — one row per run (date, commit, settings, speed, accuracy, resources);
- docs/benchmarks/<date>-<label>.json — the full result (run, progress samples, missed hosts).

`python -I scripts/bench/record.py <result.json> [note]` adds an existing result by hand."""
import csv, datetime, ipaddress, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIR = ROOT / "docs" / "benchmarks"
FIELDS = ["date", "commit", "label", "note", "status", "addresses", "covered_pct", "ports", "rate_pps",
          "wall_s", "addr_per_s", "hosts_planned", "hosts_found", "port_ok", "product_ok", "http_ok", "http_planned",
          "extra_hosts", "cpu_max_pct", "mem_max", "file"]


def commit():
    r = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", "core"], capture_output=True, text=True).stdout.strip()
    return r.stdout.strip() + ("+dirty" if dirty else "")


def covered(plan, result):
    """Planned hosts inside the part of the range the run got through (all of them unless cancelled)."""
    run = result["run"]
    hosts = [(ip, kind) for ip, _, kind in plan["hosts"]]
    if run["status"] == "completed":
        return hosts
    first = ipaddress.ip_network(plan["net"]).network_address + 1
    limit = first + round(run["progress"] * run["address_count"])
    return [(ip, kind) for ip, kind in hosts if ipaddress.ip_address(ip) < limit]


def record(plan, result, ports, rate, note="", when=None, rev=None):
    DIR.mkdir(parents=True, exist_ok=True)
    run = result["run"]
    when = when or datetime.datetime.now()
    name = f"{when:%Y-%m-%d-%H%M}-{result['label']}.json"
    json.dump(result, open(DIR / name, "w", encoding="utf-8", newline="\n"), indent=1, default=str)
    inside = covered(plan, result)
    missing = set(result["missing"])
    samples = result["samples"]
    row = {
        "date": f"{when:%Y-%m-%d %H:%M}", "commit": rev or commit(), "label": result["label"], "note": note,
        "status": run["status"], "addresses": run["address_count"], "covered_pct": round(run["progress"] * 100, 1),
        "ports": ports, "rate_pps": rate, "wall_s": round(result["wall"]),
        "addr_per_s": round(run["address_count"] * run["progress"] / max(result["wall"], 1), 1),
        "hosts_planned": len(inside), "hosts_found": sum(1 for ip, _ in inside if ip not in missing),
        "port_ok": result["svc_ok"], "product_ok": result["ver_ok"], "http_ok": result["http_ok"],
        "http_planned": sum(1 for _, k in inside if k != "redis"), "extra_hosts": " ".join(result["extra"]),
        "cpu_max_pct": round(max(s[3] for s in samples)), "mem_max": max((s[4] for s in samples), key=mem_mib), "file": name,
    }
    path = DIR / "history.csv"
    new = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"recorded {path.relative_to(ROOT)} + {name}")
    return row


def mem_mib(text):
    units = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024}
    for u, k in units.items():
        if text.endswith(u):
            return float(text[: -len(u)]) * k
    return 0.0


if __name__ == "__main__":
    res = json.load(open(sys.argv[1], encoding="utf-8"))
    plan = json.load(open(pathlib.Path(sys.argv[1]).with_name("bench_plan.json")))
    record(plan, res, res.get("ports", "?"), res.get("rate", "?"), sys.argv[2] if len(sys.argv) > 2 else "")
