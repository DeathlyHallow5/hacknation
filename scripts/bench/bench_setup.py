"""Benchmark network: 10.77.0.0/18 (16 382 addresses) with live hosts spread over it.
Usage: python -I -X utf8 bench_setup.py up [plan.json] | down
Needs the stack running (docker compose up -d): core joins the bench network."""
import ipaddress, json, random, subprocess, sys

NET, NAME = "10.77.0.0/18", "asi-bench"
random.seed(2026)
hosts = list(ipaddress.ip_network(NET).hosts())
# Scanner at the top of the range; live hosts drawn from the rest.
scanner_ip = str(hosts[-1])
chosen = sorted(random.sample(hosts[:-1], 160))
plan = []
for i, ip in enumerate(chosen):
    if i % 8 == 0:
        plan.append((str(ip), "mirror.gcr.io/library/redis:7-alpine", "redis"))
    elif i % 4 == 0:
        plan.append((str(ip), "httpd:2.4-alpine", "httpd"))
    else:
        plan.append((str(ip), "nginx:1.27-alpine", "nginx"))


def run(*a):
    return subprocess.run(list(a), capture_output=True, text=True)


if sys.argv[1] == "up":
    run("docker", "network", "create", "--subnet", NET, "--internal", NAME)
    for n, (ip, image, kind) in enumerate(plan):
        r = run("docker", "run", "-d", "--name", f"bench-{n:03d}", "--network", NAME, "--ip", ip,
                "--memory", "32m", "--label", "asi-bench=1", image)
        if r.returncode:
            print("fail", ip, r.stderr.strip()[:200])
    r = run("docker", "network", "connect", "--ip", scanner_ip, NAME, "asi-core-1")
    print("core connect:", r.returncode, r.stderr.strip()[:200])
    json.dump({"net": NET, "scanner": scanner_ip, "hosts": plan}, open(sys.argv[2] if len(sys.argv) > 2 else "bench_plan.json", "w"))
    kinds = {}
    for _, _, k in plan:
        kinds[k] = kinds.get(k, 0) + 1
    print(f"{len(plan)} live hosts in {NET} ({len(hosts)} addresses):", kinds, "scanner", scanner_ip)
else:
    ids = run("docker", "ps", "-aq", "--filter", "label=asi-bench=1").stdout.split()
    if ids:
        run("docker", "rm", "-f", *ids)
    run("docker", "network", "disconnect", "-f", NAME, "asi-core-1")
    run("docker", "network", "rm", NAME)
    print("removed", len(ids))
