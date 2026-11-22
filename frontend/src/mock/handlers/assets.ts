import type {
  Criticality,
  DeviceType,
  HostHistoryEntry,
  HostPatch,
  ServiceGroup,
  ServicePatch,
  UnstableHost,
} from "@/lib/api/types";
import { CRITICALITY_LABEL, DEVICE_LABEL } from "@/lib/labels";
import { parseCidr } from "@/lib/net";
import { PLAIN, WEB_APPS } from "@/mock/catalog";
import type { HostRec, MockDB } from "@/mock/db";
import { cookieValue } from "@/mock/http";
import type { RouteFn } from "@/mock/router";
import {
  findHostByService,
  findingIndex,
  hostDetail,
  hostSummary,
  serviceFull,
  serviceSummary,
  settleRecheck,
  techNames,
} from "@/mock/serialize";
import { iso } from "@/mock/time";
import { audit, badRequest, json, list, matchesText, notFound, paginate, sortBy, str } from "@/mock/util";

const HOST_FIELDS: Record<keyof HostPatch, string> = {
  owner: "Właściciel",
  criticality: "Krytyczność",
  tags: "Tagi",
  notes: "Notatki",
  device_type: "Typ urządzenia",
  hostnames: "Nazwy hosta",
};

const FIELD_TO_REC: Record<keyof HostPatch, keyof HostRec> = {
  owner: "owner",
  criticality: "criticality",
  tags: "tags",
  notes: "notes",
  device_type: "device",
  hostnames: "hostnames",
};

function fmtField(key: string, v: unknown): string | null {
  if (key === "criticality") return CRITICALITY_LABEL[v as Criticality] ?? str(v);
  if (key === "device_type") return DEVICE_LABEL[v as DeviceType] ?? str(v);
  return str(v);
}

function filterHosts(db: MockDB, q: URLSearchParams) {
  const text = q.get("q");
  const avail = list(q, "availability");
  const change = list(q, "change");
  const device = list(q, "device");
  const tags = list(q, "tag");
  const crit = list(q, "criticality");
  const tech = q.get("tech")?.toLowerCase();
  const port = q.get("port") ? Number(q.get("port")) : null;
  const cidr = q.get("cidr") ? parseCidr(q.get("cidr")!) : null;
  const owner = q.get("owner");
  const overrides = q.get("has_overrides") === "true";
  const showInactive = q.get("include_inactive") !== "false";
  return db.hosts.filter((h) => {
    if (!showInactive && h.availability === "inactive") return false;
    if (avail.length && !avail.includes(h.availability)) return false;
    if (change.length && !change.includes(h.change)) return false;
    if (device.length && !device.includes(h.device)) return false;
    if (crit.length && !crit.includes(h.criticality)) return false;
    if (tags.length && !tags.some((t) => h.tags.includes(t))) return false;
    if (owner && h.owner !== owner) return false;
    if (port !== null && !h.services.some((s) => s.port === port)) return false;
    if (cidr && !(h.ipInt >= cidr.network && h.ipInt < cidr.network + cidr.size)) return false;
    if (overrides && !Object.keys(h.overrides).length && !h.services.some((s) => Object.keys(s.overrides).length)) return false;
    if (tech && !techNames(h).some((t) => t.toLowerCase().includes(tech))) return false;
    if (text) {
      const t = text.trim().toLowerCase();
      if (!(h.ip.startsWith(t) || h.hostnames.some((n) => n.includes(t)) || (h.owner ?? "").toLowerCase().includes(t) || h.tags.includes(t))) return false;
    }
    return true;
  });
}

export function assetRoutes(route: RouteFn) {
  route("GET", "/hosts", "assets:read", (ctx) => {
    const idx = findingIndex(ctx.db);
    let hosts = filterHosts(ctx.db, ctx.query);
    const sort = ctx.query.get("sort") ?? "ip";
    if (sort.replace("-", "") === "score") {
      const score = (h: HostRec) => (idx.get(h.id) ?? []).reduce((m, f) => Math.max(m, f.score_override ?? f.score), 0);
      hosts = sortBy(hosts, sort, { score });
    } else
      hosts = sortBy(hosts, sort, {
        ip: (h) => h.ipInt,
        hostname: (h) => h.hostnames[0] ?? "~",
        last_seen: (h) => h.lastSeen,
        first_seen: (h) => h.firstSeen,
        services: (h) => h.services.length,
        availability: (h) => ["active", "unstable", "inactive"].indexOf(h.availability),
        owner: (h) => h.owner,
      });
    const page = paginate(hosts, ctx.query, 50);
    return json({ ...page, items: page.items.map((h) => hostSummary(h, idx)) });
  });

  route("GET", "/hosts/unstable", "changes:read", (ctx) => {
    const out: UnstableHost[] = ctx.db.hosts
      .filter((h) => h.availability === "unstable")
      .map((h) => {
        settleRecheck(ctx.db, h);
        const responded = h.pattern.filter(Boolean).length;
        return {
          host_id: h.id,
          ip: h.ip,
          hostname: h.hostnames[0] ?? null,
          pattern: h.pattern,
          response_rate: Math.round((responded / h.pattern.length) * 100) / 100,
          by_hour: h.byHour ?? Array(24).fill(null),
          last_recheck_at: h.lastRecheckAt,
          recheck_pending: Boolean(h.recheckRequestedAt),
          time_pattern: null,
        };
      })
      .sort((a, b) => Number(b.recheck_pending) - Number(a.recheck_pending) || a.response_rate - b.response_rate)
      .slice(0, Number(ctx.query.get("limit") ?? 80));
    return json(out);
  });

  route("GET", "/hosts/:id", "assets:read", (ctx) => {
    const h = ctx.db.hostById.get(ctx.params.id) ?? ctx.db.hosts.find((x) => x.ip === ctx.params.id);
    if (!h) return notFound("Host");
    settleRecheck(ctx.db, h);
    return json(hostDetail(ctx.db, h, findingIndex(ctx.db)));
  });

  route("PATCH", "/hosts/:id", "assets:update", async (ctx) => {
    const h = ctx.db.hostById.get(ctx.params.id);
    if (!h) return notFound("Host");
    const patch = await ctx.body<HostPatch>();
    if (patch.criticality && !["low", "medium", "high", "critical"].includes(patch.criticality))
      return badRequest("Nieprawidłowa krytyczność.", { criticality: "Dozwolone: low, medium, high, critical" });
    const changes = [];
    for (const key of Object.keys(HOST_FIELDS) as (keyof HostPatch)[]) {
      if (!(key in patch)) continue;
      const recKey = FIELD_TO_REC[key];
      const before = h[recKey];
      const after = patch[key];
      if (JSON.stringify(before) === JSON.stringify(after)) continue;
      const scannerValue = h.overrides[key]?.scanner_value ?? before;
      (h as unknown as Record<string, unknown>)[recKey] = after;
      h.overrides[key] = { value: after, scanner_value: scannerValue, by: ctx.user!.name, at: iso(Date.now()) };
      changes.push({ field: key, label: HOST_FIELDS[key], before: fmtField(key, before), after: fmtField(key, after) });
    }
    if (changes.length) audit(ctx.db, ctx.user, "update", "host", h.ip, "Edytowano dane hosta (zachowane przy kolejnych skanach)", changes, h.id);
    return json(hostDetail(ctx.db, h, findingIndex(ctx.db)));
  });

  route("DELETE", "/hosts/:id/overrides/:field", "assets:update", (ctx) => {
    const h = ctx.db.hostById.get(ctx.params.id);
    if (!h) return notFound("Host");
    const key = ctx.params.field as keyof HostPatch;
    const o = h.overrides[key];
    if (!o) return notFound("Ręczna zmiana");
    const recKey = FIELD_TO_REC[key];
    const before = h[recKey];
    (h as unknown as Record<string, unknown>)[recKey] = o.scanner_value ?? null;
    delete h.overrides[key];
    audit(ctx.db, ctx.user, "update", "host", h.ip, "Przywrócono wartość ze skanu", [{ field: key, label: HOST_FIELDS[key], before: fmtField(key, before), after: fmtField(key, o.scanner_value) }], h.id);
    return json(hostDetail(ctx.db, h, findingIndex(ctx.db)));
  });

  route("GET", "/hosts/:id/history", "assets:read", (ctx) => {
    const h = ctx.db.hostById.get(ctx.params.id);
    if (!h) return notFound("Host");
    const runs = ctx.db.scans.filter((s) => s.source === "scanner" && s.status === "completed").slice(-h.pattern.length);
    const latest = ctx.db.latestDiff;
    const out: HostHistoryEntry[] = runs.map((s, i) => {
      const responded = h.pattern[h.pattern.length - runs.length + i] ?? true;
      const ch = s.id === latest.headId ? latest.changes.filter((c) => c.host_id === h.id).flatMap((c) => c.fields) : [];
      return {
        scan_id: s.id,
        scan_number: s.number,
        at: s.finished_at ?? s.started_at ?? iso(Date.now()),
        responded,
        open_ports: responded ? h.services.filter((sv) => sv.firstSeen <= (s.finished_at ?? "")).map((sv) => sv.port) : [],
        changes: ch,
      };
    });
    return json(out.reverse());
  });

  route("POST", "/hosts/:id/recheck", "assets:recheck", (ctx) => {
    const h = ctx.db.hostById.get(ctx.params.id);
    if (!h) return notFound("Host");
    h.recheckRequestedAt = Date.now();
    audit(ctx.db, ctx.user, "recheck", "host", h.ip, "Zlecono ponowny pomiar hosta (poza oknem nocnym)", [], h.id);
    return json({ queued: true }, { status: 202 });
  });

  route("GET", "/services", "assets:read", (ctx) => {
    const text = ctx.query.get("q");
    const port = ctx.query.get("port") ? Number(ctx.query.get("port")) : null;
    const product = ctx.query.get("product")?.toLowerCase();
    const group = ctx.query.get("group");
    const change = list(ctx.query, "change");
    const web = ctx.query.get("web") === "true";
    const out = [];
    for (const h of ctx.db.hosts) {
      if (!h.responded) continue;
      for (const s of h.services) {
        if (s.redirectTo && web) continue;
        if (port !== null && s.port !== port) continue;
        if (web && !s.web) continue;
        if (change.length && !change.includes(s.change)) continue;
        if (group && (s.web ?? s.plain) !== group) continue;
        if (product && !(s.product ?? "").toLowerCase().includes(product) && !(s.web && WEB_APPS[s.web].label.toLowerCase().includes(product))) continue;
        if (!matchesText(text, h.ip, h.hostnames[0], s.product, s.name, s.version, s.web ? WEB_APPS[s.web].label : null)) continue;
        out.push({ h, s });
      }
    }
    const sorted = sortBy(out, ctx.query.get("sort") ?? "ip", {
      ip: (x) => x.h.ipInt * 100000 + x.s.port,
      port: (x) => x.s.port,
      product: (x) => x.s.product,
      confidence: (x) => x.s.confidence,
    });
    const page = paginate(sorted, ctx.query, 50);
    return json({ ...page, items: page.items.map(({ h, s }) => serviceSummary(h, s)) });
  });

  route("GET", "/services/:id", "assets:read", (ctx) => {
    const r = findHostByService(ctx.db, ctx.params.id);
    if (!r) return notFound("Usługa");
    return json(serviceFull(ctx.db, r.h, r.s));
  });

  route("PATCH", "/services/:id", "assets:update", async (ctx) => {
    const r = findHostByService(ctx.db, ctx.params.id);
    if (!r) return notFound("Usługa");
    const { h, s } = r;
    const patch = await ctx.body<ServicePatch>();
    const labels: Record<keyof ServicePatch, string> = { product: "Produkt", version: "Wersja", tags: "Tagi", notes: "Notatki" };
    const changes = [];
    for (const key of Object.keys(labels) as (keyof ServicePatch)[]) {
      if (!(key in patch)) continue;
      const before = s[key];
      const after = patch[key];
      if (JSON.stringify(before) === JSON.stringify(after)) continue;
      if (key === "product" || key === "version")
        s.overrides[key] = { value: after, scanner_value: s.overrides[key]?.scanner_value ?? before, by: ctx.user!.name, at: iso(Date.now()) };
      (s as unknown as Record<string, unknown>)[key] = after;
      changes.push({ field: key, label: labels[key], before: str(before), after: str(after) });
    }
    if (changes.length) audit(ctx.db, ctx.user, "update", "service", `${h.ip}:${s.port}`, "Poprawiono identyfikację usługi", changes, s.id);
    return json(serviceFull(ctx.db, h, s));
  });

  route("POST", "/services/:id/cookies/:name/reveal", "sensitive:reveal", (ctx) => {
    const r = findHostByService(ctx.db, ctx.params.id);
    if (!r) return notFound("Usługa");
    audit(ctx.db, ctx.user, "reveal", "service", `${r.h.ip}:${r.s.port} ${ctx.params.name}`, "Odsłonięto wartość ciasteczka (dane wrażliwe, szyfrowane w spoczynku)", [], r.s.id);
    return json({ value: cookieValue(r.h.ip, r.s.port, ctx.params.name) });
  });

  route("GET", "/service-groups", "assets:read", (ctx) => {
    const q = ctx.query.get("q");
    const groups = new Map<string, ServiceGroup & { _versions: Map<string, number>; _ports: Set<number> }>();
    for (const h of ctx.db.hosts) {
      if (!h.responded) continue;
      for (const s of h.services) {
        if (s.redirectTo) continue;
        const key = s.web ?? s.plain ?? `${s.name}:${s.product ?? "?"}`;
        const label = s.web ? WEB_APPS[s.web].label : s.plain ? (PLAIN[s.plain].product ?? s.name) : `${s.product ?? s.name}`;
        const version = s.web ? (s.appVersion && s.appVersion !== "-" ? s.appVersion : s.serverVersion) : s.version;
        let g = groups.get(key);
        if (!g) {
          g = { key, label, product: s.product ?? label, versions: [], port_set: [], count: 0, hosts_sample: [], outdated: false, _versions: new Map(), _ports: new Set() };
          groups.set(key, g);
        }
        g.count++;
        g._versions.set(version ?? "nieznana", (g._versions.get(version ?? "nieznana") ?? 0) + 1);
        g._ports.add(s.port);
        if (s.old) g.outdated = true;
        if (g.hosts_sample.length < 5) g.hosts_sample.push({ id: h.id, ip: h.ip });
      }
    }
    const out: ServiceGroup[] = [...groups.values()]
      .filter((g) => matchesText(q, g.label, g.product))
      .map(({ _versions, _ports, ...g }) => ({
        ...g,
        versions: [..._versions.entries()].map(([version, count]) => ({ version, count })).sort((a, b) => b.count - a.count),
        port_set: [..._ports].sort((a, b) => a - b),
      }))
      .sort((a, b) => b.count - a.count);
    return json(out);
  });
}
