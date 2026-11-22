"""Shared client for the end-to-end checks: session cookie, CSRF header and Origin, like the
dashboard. Every script runs against the dashboard proxy (http://127.0.0.1:3000 by default):
    python -I -X utf8 scripts/e2e/<check>.py .env [http://127.0.0.1:3000]
Scripts load this file with exec() because `python -I` leaves the script folder off sys.path."""
import http.cookiejar, json, sys, time, urllib.request, urllib.error, uuid

ENV = dict(l.strip().split("=", 1) for l in open(sys.argv[1], encoding="utf-8") if "=" in l and not l.startswith("#"))
BASE = (sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3000") + "/api/v1"
ORIGIN = "http://localhost:3000"
results = []


class C:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None, raw=None, ctype=None, timeout=60):
        h = {"Accept": "application/json"}
        data = None
        if raw is not None:
            data, h["Content-Type"] = raw, ctype
        elif body is not None:
            data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
        if method != "GET":
            h["X-ASI-CSRF"] = "1"
            h["Origin"] = ORIGIN  # the core checks it with the CSRF header (ASI_ALLOWED_ORIGINS)
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
        try:
            with self.op.open(req, timeout=timeout) as r:
                b = r.read()
                ct = r.headers.get("content-type", "")
                return r.status, (json.loads(b) if b and "json" in ct else b)
        except urllib.error.HTTPError as e:
            b = e.read()
            try:
                return e.code, json.loads(b)
            except Exception:
                return e.code, b

    def sse(self, path, seconds):
        req = urllib.request.Request(BASE + path, headers={"Accept": "text/event-stream"})
        events = []
        end = time.time() + seconds
        try:
            with self.op.open(req, timeout=seconds + 5) as r:
                buf = b""
                while time.time() < end:
                    line = r.readline()
                    if not line:
                        break
                    if line.startswith(b"event:"):
                        events.append(line[6:].strip().decode())
                        if events[-1] == "done":
                            break
        except Exception as e:
            events.append(f"error:{e}")
        return events


def check(name, cond, extra=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{str(extra)[:400]}]" if extra and not cond else ""))


def login(user, pw):
    c = C()
    st, b = c.call("POST", "/auth/login", {"login": user, "password": pw})
    return c if st == 200 else None


def multipart(fields, filename, content):
    b = uuid.uuid4().hex
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n\r\n'.encode() + content + b"\r\n")
    parts.append(f"--{b}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={b}"


def wait_run(c, rid, statuses=("completed", "cancelled", "failed"), limit=240):
    end = time.time() + limit
    while time.time() < end:
        st, r = c.call("GET", f"/scans/{rid}")
        if st == 200 and r["status"] in statuses:
            return r
        time.sleep(3)
    return c.call("GET", f"/scans/{rid}")[1]


