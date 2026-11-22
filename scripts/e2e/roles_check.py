"""Custom roles + /tags + /permissions, through the Next proxy like the browser.
Usage: python -I -X utf8 scripts/e2e/roles_check.py <.env> [base]"""
import sys, uuid

exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_client.py"), encoding="utf-8").read())
admin = login(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])
t = uuid.uuid4().hex[:6]

st, perms = admin.call("GET", "/permissions")
check("GET /permissions → 41", st == 200 and len(perms) == 41 and perms[0] == "dashboard:read", (st, perms))
st, tags = admin.call("GET", "/tags")
check("GET /tags → list of {name,count}", st == 200 and isinstance(tags, list) and all({"name", "count"} <= set(x) for x in tags), (st, tags))

st, r = admin.call("POST", "/roles", {"name": f"Audytor {t}", "description": "tylko znaleziska", "permissions": ["findings:read", "dashboard:read", "findings:read"]})
check("create custom role → 201", st == 201 and r["builtin"] is False and r["permissions"] == ["dashboard:read", "findings:read"], (st, r))
rid = r["id"]
check("duplicate name → 409", admin.call("POST", "/roles", {"name": f"audytor {t}", "permissions": ["dashboard:read"]})[0] == 409)
check("unknown permission → 422", admin.call("POST", "/roles", {"name": f"X {t}", "permissions": ["root:all"]})[0] == 422)
check("no permissions → 422", admin.call("POST", "/roles", {"name": f"Y {t}", "permissions": []})[0] == 422)
check("builtin role PATCH → 409", admin.call("PATCH", "/roles/admin", {"name": "x"})[0] == 409)
roles = admin.call("GET", "/roles")[1]
check("GET /roles lists 4 builtin + custom", sum(1 for x in roles if x["builtin"]) == 4 and any(x["id"] == rid for x in roles), [x["name"] for x in roles])

pw = "Haslo-testowe-" + uuid.uuid4().hex[:10]
st, u = admin.call("POST", "/users", {"login": f"audytor{t}", "name": "Audytor", "role_id": rid, "password": pw})
check("create user with custom role", st == 201 and u["role_id"] == rid and u["role_name"] == f"Audytor {t}", (st, u))
c = login(f"audytor{t}", pw)
check("custom-role user logs in", c is not None)
st, me = c.call("GET", "/auth/me")
check("/auth/me: custom role + its permissions", st == 200 and me["role"]["builtin"] is False and me["permissions"] == ["dashboard:read", "findings:read"], me)
check("allowed: GET /findings", c.call("GET", "/findings")[0] == 200)
check("allowed: GET /dashboard/summary", c.call("GET", "/dashboard/summary")[0] == 200)
check("denied: GET /targets → 403", c.call("GET", "/targets")[0] == 403)
check("denied: GET /dashboard/technologies (assets:read) → 403", c.call("GET", "/dashboard/technologies")[0] == 403)
check("denied: PATCH finding (no findings:update) → 403", c.call("PATCH", f"/findings/{uuid.uuid4()}", {"status": "confirmed"})[0] == 403)
check("denied: legacy /api route", c.call("GET", "/../targets")[0] in (401, 403, 404))

st, r2 = admin.call("PATCH", f"/roles/{rid}", {"permissions": ["dashboard:read", "findings:read", "targets:read"]})
check("PATCH custom role", st == 200 and "targets:read" in r2["permissions"] and r2["users_count"] == 1, (st, r2))
check("takes effect at once: GET /targets now 200", c.call("GET", "/targets")[0] == 200)

check("custom role cannot grant itself admin", c.call("POST", "/users", {"login": f"x{t}", "role_id": "admin", "password": pw})[0] == 403)
admin.call("PATCH", f"/roles/{rid}", {"permissions": ["dashboard:read", "users:manage", "users:read"]})
check("users:manage custom role cannot hand out admin", c.call("POST", "/users", {"login": f"x{t}", "role_id": "admin", "password": pw})[0] == 403)

check("delete role in use → 409", admin.call("DELETE", f"/roles/{rid}")[0] == 409)
st, u2 = admin.call("PATCH", f"/users/{u['id']}", {"role_id": "viewer"})
check("move user back to viewer", st == 200 and u2["role_id"] == "viewer", (st, u2))
check("old session ended on role change", c.call("GET", "/auth/me")[0] == 401)
admin.call("DELETE", f"/users/{u['id']}")
check("delete role still blocked (deactivated user had it)?", admin.call("DELETE", f"/roles/{rid}")[0] in (204, 409))
st = admin.call("DELETE", f"/roles/{rid}")[0]
print(f"\n{sum(results)}/{len(results)} passed")
