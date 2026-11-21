import type {
  AddressMap,
  AvailabilityHeatmap,
  DashboardSummary,
  LoginRequest,
  ScanRun,
  SearchResult,
  TagStat,
  TechStat,
} from "@/lib/api/types";
import { AddressStatus } from "@/lib/api/types";
import { parseCidr } from "@/lib/net";
import { PLAIN, WEB_APPS } from "@/mock/catalog";
import { resetDB, type MockDB } from "@/mock/db";
import type { RouteFn } from "@/mock/router";
import { SESSION_COOKIE } from "@/mock/router";
import { effectiveScore, settleRecheck } from "@/mock/serialize";
import { headOffset, refreshScan } from "@/mock/sim";
import { iso, nextWindowStart, windowAround } from "@/mock/time";
import { apiError, audit, badRequest, json, matchesText, sessionFor } from "@/mock/util";

export function liveScans(db: MockDB): ScanRun[] {
  const out: ScanRun[] = [];
  for (const s of db.scans) {
    if (db.sims.has(s.id) && !["completed", "cancelled", "failed"].includes(s.status)) {
      refreshScan(db, s);
      if (!["completed", "cancelled", "failed"].includes(s.status)) out.push(s);
    }
  }
  return out;
}

export function lastCompleted(db: MockDB): ScanRun | null {
  for (let i = db.scans.length - 1; i >= 0; i--) {
    const s = db.scans[i];
    if (s.source === "scanner" && s.status === "completed") return s;
  }
  return null;
}

export function excludedRanges(db: MockDB) {
  const list = [...db.settings.scan_safety.excluded_cidrs, ...db.targets.filter((t) => t.excluded && t.type === "cidr").map((t) => t.value)];
  return Array.from(new Set(list))
    .map((c) => parseCidr(c))
    .filter((c): c is NonNullable<typeof c> => Boolean(c));
}

export function coreRoutes(route: RouteFn) {
  /* ---------------- auth ---------------- */
  route("POST", "/auth/login", null, async (ctx) => {
    const body = await ctx.body<LoginRequest>();
    const login = String(body.login ?? "").trim().toLowerCase();
    const user = ctx.db.users.find((u) => u.login === login || u.email === login);
    if (!user || String(body.password ?? "") !== user.password)
      return apiError(401, "invalid_credentials", "Nieprawidłowy login lub hasło.");
    if (!user.active) return apiError(403, "account_disabled", "Konto jest nieaktywne. Skontaktuj się z administratorem.");
    user.last_login_at = iso(Date.now());
    audit(ctx.db, user, "login", "session", null, "Zalogowano do systemu");
    const token = `mock.${user.id}.${Math.random().toString(36).slice(2)}`;
    return json(sessionFor(ctx.db, user), {
      headers: { "Set-Cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200` },
    });
  });

  route("POST", "/auth/logout", undefined, (ctx) => {
    audit(ctx.db, ctx.user, "logout", "session", null, "Wylogowano");
    return new Response(null, {
      status: 204,
      headers: { "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` },
    });
  });

  route("GET", "/auth/me", undefined, (ctx) => json(sessionFor(ctx.db, ctx.user!)));

  route("POST", "/_mock/reset", "settings:manage", () => {
    resetDB();
    return json({ ok: true });
  });

  /* ---------------- dashboard ---------------- */
  route("GET", "/dashboard/summary", "dashboard:read", (ctx) => {
    const db = ctx.db;
    const now = new Date();
    const running = liveScans(db);
    const last = lastCompleted(db);
    const win = db.settings.default_window;
    const w = windowAround(now, win.start, win.end);
    const summary = { new: 0, changed: 0, gone: 0, unstable: 0 };
    for (const c of db.latestDiff.changes) summary[c.kind] += 1;
    const base = db.scans.find((s) => s.id === db.latestDiff.baseId);
    const head = db.scans.find((s) => s.id === db.latestDiff.headId);
    const trend = db.trend.slice(-30);
    const active = db.hosts.filter((h) => h.responded).length;
    const prev = trend.length > 1 ? trend[trend.length - 2].value : active;
    const open = db.findings.filter((f) => f.status === "open" || f.status === "in_review");
    const body: DashboardSummary = {
      active_hosts: active,
      active_hosts_delta: active - prev,
      active_trend: trend,
      monitored_addresses: db.targets.filter((t) => !t.excluded && t.type === "cidr").reduce((n, t) => n + t.address_count, 0),
      targets_count: db.targets.length,
      services_count: db.hosts.reduce((n, h) => n + (h.responded ? h.services.length : 0), 0),
      web_services_count: db.hosts.reduce((n, h) => n + (h.responded ? h.services.filter((s) => s.web && !s.redirectTo).length : 0), 0),
      findings_open: open.length,
      findings_high: open.filter((f) => effectiveScore(f) >= 70).length,
      changes: summary,
      changes_base_scan: base?.number ?? null,
      changes_head_scan: head?.number ?? null,
      last_scan: last,
      running_scan: running[0] ?? null,
      window: win,
      window_open: w.open,
      window_progress: w.open ? (now.getTime() - w.startAt.getTime()) / (w.endAt.getTime() - w.startAt.getTime()) : 1,
      next_window_at: iso(nextWindowStart(now, win.start, win.end)),
      rate_limit_rps: db.settings.scan_safety.max_rate_rps,
    };
    return json(body);
  });

  route("GET", "/dashboard/top-findings", "findings:read", (ctx) => {
    const limit = Math.min(50, Number(ctx.query.get("limit") ?? 10));
    const q = ctx.query.get("q");
    const change = ctx.query.get("change");
    const category = ctx.query.get("category");
    const rank = { new: 3, changed: 2, unstable: 1, gone: 0, unchanged: 0 } as const;
    const sorted = ctx.db.findings
      .filter((f) => f.status !== "false_positive" && f.status !== "accepted")
      .filter((f) => (change ? f.change === change : true))
      .filter((f) => (category ? f.category === category : true))
      .filter((f) => matchesText(q, f.title, f.ip, f.hostname, ...f.technologies))
      .sort((a, b) => effectiveScore(b) - effectiveScore(a) || rank[b.change] - rank[a.change]);
    // Diversify the headline list: at most 2 findings per (category, main technology).
    const seen = new Map<string, number>();
    const items = [];
    for (const f of sorted) {
      const key = `${f.category}|${(f.technologies[0] ?? "").split(" ")[0]}`;
      if ((seen.get(key) ?? 0) >= 2 && !q) continue;
      seen.set(key, (seen.get(key) ?? 0) + 1);
      items.push(f);
      if (items.length >= limit) break;
    }
    return json(items);
  });

  route("GET", "/dashboard/changes-timeline", "changes:read", (ctx) => {
    const limit = Math.min(90, Number(ctx.query.get("limit") ?? 30));
    return json(ctx.db.timeline.slice(-limit));
  });

  route("GET", "/dashboard/availability", "changes:read", (ctx) => {
    const hosts = ctx.db.hosts.filter((h) => h.availability === "unstable" && h.byHour);
    for (const h of hosts) settleRecheck(ctx.db, h);
    const matrix: (number | null)[][] = [];
    for (let d = 0; d < 7; d++) {
      const row: (number | null)[] = [];
      for (let hour = 0; hour < 24; hour++) {
        let sum = 0;
        let n = 0;
        for (const h of hosts) {
          const v = h.byHour![hour];
          if (v === null) continue;
          const office = ["office", "dorm", "wifi", "lab"].includes(h.blockType);
          const weekend = d >= 5;
          sum += weekend && office ? v * (h.blockType === "dorm" ? 0.95 : 0.42) : v;
          n++;
        }
        row.push(n ? Math.round((sum / n) * 100) / 100 : null);
      }
      matrix.push(row);
    }
    const body: AvailabilityHeatmap = { matrix, hosts_considered: hosts.length, samples: hosts.length * 24 * 4 };
    return json(body);
  });

  route("GET", "/dashboard/technologies", "assets:read", (ctx) => {
    const limit = Math.min(40, Number(ctx.query.get("limit") ?? 12));
    const counts = new Map<string, TechStat>();
    for (const h of ctx.db.hosts) {
      if (!h.responded) continue;
      for (const s of h.services) {
        if (s.redirectTo) continue;
        let name: string | null = null;
        let category: TechStat["category"] = "other";
        if (s.web) {
          const t = WEB_APPS[s.web].techs[0];
          name = t.name;
          category = t.category;
        } else if (s.plain && PLAIN[s.plain].tech) {
          name = PLAIN[s.plain].tech!.name;
          category = PLAIN[s.plain].tech!.category;
        }
        if (!name) continue;
        const cur = counts.get(name) ?? { name, category, count: 0, delta: 0 };
        cur.count += 1;
        if (s.change === "new") cur.delta += 1;
        counts.set(name, cur);
      }
    }
    return json([...counts.values()].sort((a, b) => b.count - a.count).slice(0, limit));
  });

  route("GET", "/dashboard/address-map", "assets:read", (ctx) => {
    const db = ctx.db;
    const c = parseCidr(ctx.query.get("cidr") ?? "10.0.0.0/16");
    if (!c || c.prefix < 16 || c.prefix > 24) return badRequest("Obsługiwane są zakresy od /16 do /24.");
    const netBase = (10 << 24) >>> 0;
    const first = c.network - netBase;
    if (first < 0 || first >= 65536) return badRequest("Zakres spoza monitorowanej sieci 10.0.0.0/16.");
    const excluded = excludedRanges(db);
    const bytes = new Uint8Array(Math.ceil(c.size / 2));
    const counts: AddressMap["counts"] = { none: 0, active: 0, new: 0, changed: 0, gone: 0, unstable: 0, inactive: 0, excluded: 0 };
    const names = ["none", "active", "new", "changed", "gone", "unstable", "inactive", "excluded"] as const;
    for (let i = 0; i < c.size; i++) {
      const off = first + i;
      const ipNum = (netBase + off) >>> 0;
      let code: AddressStatus = AddressStatus.None;
      if (excluded.some((e) => ipNum >= e.network && ipNum < e.network + e.size)) code = AddressStatus.Excluded;
      else {
        const h = db.hostByOff.get(off);
        if (h) {
          if (h.change === "gone") code = AddressStatus.Gone;
          else if (h.change === "new") code = AddressStatus.New;
          else if (h.change === "changed") code = AddressStatus.Changed;
          else if (h.availability === "unstable" || h.change === "unstable") code = AddressStatus.Unstable;
          else if (h.availability === "inactive") code = AddressStatus.Inactive;
          else if (h.responded) code = AddressStatus.Active;
        }
      }
      counts[names[code]] += 1;
      bytes[i >> 1] |= i % 2 === 0 ? code << 4 : code;
    }
    const running = liveScans(db)[0];
    const head = running ? headOffset(db, running) : null;
    const body: AddressMap = {
      cidr: c.cidr,
      prefix: c.prefix,
      size: c.size,
      data: Buffer.from(bytes).toString("base64"),
      counts,
      scan_head: head !== null && head >= first && head < first + c.size ? head - first : null,
      generated_at: iso(Date.now()),
    };
    return json(body);
  });

  /* ---------------- search & tags ---------------- */
  route("GET", "/search", undefined, (ctx) => {
    const q = (ctx.query.get("q") ?? "").trim().toLowerCase();
    const res: SearchResult = { hosts: [], targets: [], findings: [] };
    if (q.length >= 2) {
      for (const h of ctx.db.hosts) {
        if (h.ip.startsWith(q) || h.hostnames.some((n) => n.includes(q))) {
          res.hosts.push({ id: h.id, ip: h.ip, hostname: h.hostnames[0] ?? null });
          if (res.hosts.length >= 6) break;
        }
      }
      res.targets = ctx.db.targets
        .filter((t) => t.value.includes(q) || (t.name ?? "").toLowerCase().includes(q))
        .slice(0, 5)
        .map((t) => ({ id: t.id, value: t.value, name: t.name }));
      res.findings = ctx.db.findings
        .filter((f) => f.title.toLowerCase().includes(q) || f.ip.startsWith(q))
        .slice(0, 5)
        .map((f) => ({ id: f.id, title: f.title, ip: f.ip }));
    }
    return json(res);
  });

  route("GET", "/tags", undefined, (ctx) => {
    const m = new Map<string, number>();
    const add = (t: string) => m.set(t, (m.get(t) ?? 0) + 1);
    ctx.db.targets.forEach((t) => t.tags.forEach(add));
    ctx.db.hosts.forEach((h) => h.tags.forEach(add));
    ctx.db.findings.forEach((f) => f.tags.forEach(add));
    const out: TagStat[] = [...m.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
    return json(out.slice(0, 60));
  });
}
