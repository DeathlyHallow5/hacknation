import sys
exec(open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "_client.py"), encoding="utf-8").read())
a = login(ENV.get("ASI_ADMIN_USER", "admin"), ENV["ASI_ADMIN_PASSWORD"])
profs = {p["name"]: p for p in a.call("GET", "/profiles")[1]}
check("built-in profile Laboratorium exists", "Laboratorium" in profs, list(profs))
a.call("POST", "/targets", {"items": [{"value": "10.9.9.0/24", "name": "poza zakresem"}]})
ts = {t["value"]: t for t in a.call("GET", "/targets?page_size=200")[1]["items"]}
st, e = a.call("POST", "/scans/estimate", {"target_ids": [ts["172.30.0.0/28"]["id"]], "profile_id": profs["Laboratorium"]["id"]})
check("Laboratorium estimate ok, 8 approved ports", st == 200, (st, e))
st, e = a.call("POST", "/scans/estimate", {"target_ids": [ts["172.30.0.0/28"]["id"]], "profile_id": profs["Szybki"]["id"]})
check("Szybki (top-100) narrowed to approved ports, with a note", st == 200 and any("zatwierdzone" in n for n in e["notes"]), (st, e))
st, e = a.call("POST", "/scans", {"name": "x", "target_ids": [ts["10.9.9.0/24"]["id"]], "profile_id": profs["Laboratorium"]["id"], "start": "now"})
check("target outside ASI_ALLOWED_CIDRS refused", st == 422 and "ASI_ALLOWED_CIDRS" in e["error"]["message"], (st, e))
a.call("DELETE", f"/targets/{ts['10.9.9.0/24']['id']}")
print(f"\n{sum(results)}/{len(results)} passed")
