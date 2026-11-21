/** Convert internal mock records into API contract shapes. */
import type { Finding, Host, HostSummary, ScanRef, ScanRun, Service, ServiceSummary } from "@/lib/api/types";
import { PLAIN, WEB_APPS } from "@/mock/catalog";
import type { HostRec, MockDB, ServiceRec } from "@/mock/db";
import { buildHttp, technologiesFor, titleFor } from "@/mock/http";
import { rngFor } from "@/mock/rng";
import { iso } from "@/mock/time";

export function techNames(h: HostRec): string[] {
  const names: string[] = [];
  for (const s of h.services) {
    if (s.redirectTo) continue;
    if (s.web) {
      const t = WEB_APPS[s.web].techs[0];
      const v = t.version === "app" ? s.appVersion : t.version === "server" ? s.serverVersion : t.version;
      names.push(v && v !== "-" ? `${t.name} ${v}` : t.name);
    } else if (s.plain && PLAIN[s.plain].tech) {
      names.push(`${PLAIN[s.plain].tech!.name}${s.version ? ` ${s.version}` : ""}`);
    }
  }
  return Array.from(new Set(names));
}

export function findingIndex(db: MockDB) {
  const byHost = new Map<string, Finding[]>();
  for (const f of db.findings) {
    const arr = byHost.get(f.host_id);
    if (arr) arr.push(f);
    else byHost.set(f.host_id, [f]);
  }
  return byHost;
}

export const effectiveScore = (f: Finding) => f.score_override ?? f.score;

/** Apply a pending daytime re-measurement (POST /hosts/{id}/recheck). */
export function settleRecheck(db: MockDB, h: HostRec, now = Date.now()) {
  if (!h.recheckRequestedAt || now - h.recheckRequestedAt < 6000) return;
  const hour = new Date(now).getUTCHours() + 1;
  const rate = h.byHour?.[hour % 24] ?? (h.availability === "inactive" ? 0.15 : 0.8);
  const r = rngFor("recheck", h.off, Math.floor(now / 1000));
  const responded = r() < rate;
  h.pattern = [...h.pattern.slice(1), responded];
  h.lastRecheckAt = iso(now);
  h.recheckRequestedAt = null;
  if (responded) {
    h.lastSeen = iso(now);
    h.missCount = 0;
    if (h.availability === "inactive") h.availability = "unstable";
  }
  if (h.byHour) h.byHour[hour % 24] = Math.round(((h.byHour[hour % 24] ?? rate) * 0.7 + (responded ? 1 : 0) * 0.3) * 100) / 100;
  void db;
}

export function hostSummary(h: HostRec, byHost: Map<string, Finding[]>): HostSummary {
  const fs = byHost.get(h.id) ?? [];
  return {
    id: h.id,
    ip: h.ip,
    hostnames: h.hostnames,
    availability: h.availability,
    change: h.change,
    response_pattern: h.pattern,
    miss_count: h.missCount,
    open_ports: h.services.map((s) => s.port),
    services_count: h.services.length,
    technologies: techNames(h).slice(0, 4),
    device_type: h.device,
    subnet: `10.0.${h.block}.0/24`,
    owner: h.owner,
    criticality: h.criticality,
    tags: h.tags,
    score: fs.reduce((m, f) => Math.max(m, effectiveScore(f)), 0),
    findings_count: fs.length,
    has_manual_overrides: Object.keys(h.overrides).length > 0 || h.services.some((s) => Object.keys(s.overrides).length > 0),
    first_seen: h.firstSeen,
    last_seen: h.lastSeen,
  };
}

export function serviceFull(db: MockDB, h: HostRec, s: ServiceRec): Service {
  return {
    id: s.id,
    host_id: h.id,
    ip: h.ip,
    port: s.port,
    protocol: s.protocol,
    name: s.name,
    product: s.product,
    version: s.version,
    confidence: s.confidence,
    tls: s.tls,
    banner: s.banner,
    change: s.change,
    http: buildHttp(h, s, db.seededAt, Date.now()),
    tags: s.tags,
    notes: s.notes,
    manual_overrides: s.overrides,
    first_seen: s.firstSeen,
    last_seen: s.lastSeen,
  };
}

export function serviceSummary(h: HostRec, s: ServiceRec): ServiceSummary {
  return {
    id: s.id,
    host_id: h.id,
    ip: h.ip,
    hostname: h.hostnames[0] ?? null,
    port: s.port,
    protocol: s.protocol,
    name: s.name,
    product: s.product,
    version: s.version,
    confidence: s.confidence,
    tls: s.tls,
    banner: s.banner,
    change: s.change,
    title: titleFor(h, s),
    technologies: technologiesFor(h, s).map((t) => (t.version ? `${t.name} ${t.version}` : t.name)),
    tags: s.tags,
    notes: s.notes,
    has_manual_overrides: Object.keys(s.overrides).length > 0,
    first_seen: s.firstSeen,
    last_seen: s.lastSeen,
  };
}

export function hostDetail(db: MockDB, h: HostRec, byHost: Map<string, Finding[]>): Host {
  return {
    ...hostSummary(h, byHost),
    os_guess: h.osGuess,
    notes: h.notes,
    services: h.services.map((s) => serviceFull(db, h, s)),
    manual_overrides: h.overrides,
  };
}

export function scanRef(s: ScanRun): ScanRef {
  return { id: s.id, number: s.number, name: s.name, started_at: s.started_at, finished_at: s.finished_at, status: s.status };
}

export function findHostByService(db: MockDB, serviceId: string): { h: HostRec; s: ServiceRec } | null {
  const m = /^s-(\d+)-/.exec(serviceId);
  if (!m) return null;
  const h = db.hostByOff.get(Number(m[1]));
  const s = h?.services.find((x) => x.id === serviceId);
  return h && s ? { h, s } : null;
}
