/**
 * Accelerated scan simulation. State is a pure function of timestamps, so it
 * works without timers: every read calls advance() which applies window
 * pauses/resumes and finalises the scan when its time is up.
 */
import type { Change, Finding, ScanBatch, ScanLogLine, ScanPhase, ScanRun } from "@/lib/api/types";
import { BLOCK_DENSITY, blockType } from "@/mock/catalog";
import type { HostRec, MockDB, SimState } from "@/mock/db";
import { findingsForHost } from "@/mock/findings";
import { chance, int, rngFor, shuffle } from "@/mock/rng";
import { bumpVersion, spawnHost } from "@/mock/seed";
import { iso } from "@/mock/time";
import { audit } from "@/mock/util";

const PHASES: [ScanPhase, number][] = [
  ["preflight", 0.05],
  ["discovery", 0.4],
  ["services", 0.7],
  ["http", 0.88],
  ["signatures", 0.95],
  ["diff", 1.0001],
];
const PHASE_LOG: Record<ScanPhase, string> = {
  preflight: "Pre-flight: odsiew adresów bez odpowiedzi (ICMP/TCP SYN 80,443)",
  discovery: "Wykrywanie hostów: nmap -sn, naabu (limit zapytań aktywny)",
  services: "Identyfikacja usług: nmap -sV --version-intensity 5",
  http: "Odcisk HTTP/HTTPS: httpx -title -tech-detect -tls-grab",
  signatures: "Sygnatury: tylko bezpieczne sprawdzenia GET/HEAD, bez logowania",
  diff: "Porównanie z poprzednim przebiegiem i ocena pewności zmian",
};
const RESUME_GAP_MS = 20_000;

const clamp01 = (n: number) => Math.min(1, Math.max(0, n));

export function phaseAt(p: number): ScanPhase {
  for (const [ph, end] of PHASES) if (p < end) return ph;
  return "diff";
}

const batchProgress = (p: number) => clamp01((p - 0.05) / 0.83);

export function progressOf(sim: SimState, now: number): number {
  const active = sim.activeMs + (sim.lastResumeMs !== null ? now - sim.lastResumeMs : 0);
  return clamp01(active / sim.totalMs);
}

function log(sim: SimState, at: number, level: "info" | "warn" | "error", message: string) {
  sim.logs.push({ at: iso(at), level, message });
  if (sim.logs.length > 400) sim.logs.splice(0, sim.logs.length - 400);
}

export function addressSpan(db: MockDB, targetIds: string[]): { first: number; size: number } | null {
  let lo = Infinity;
  let hi = -Infinity;
  for (const id of targetIds) {
    const t = db.targets.find((x) => x.id === id);
    if (!t || t.excluded) continue;
    let first: number | null = null;
    let size = 1;
    if (t.type === "cidr" || t.type === "ip") {
      const [ip, pfx] = t.value.split("/");
      const parts = ip.split(".").map(Number);
      if (parts[0] !== 10 || parts[1] !== 0) continue;
      first = parts[2] * 256 + parts[3];
      size = pfx ? 2 ** (32 - Number(pfx)) : 1;
    } else {
      const h = db.hosts.find((x) => x.hostnames.includes(t.value));
      if (h) first = h.off;
    }
    if (first === null) continue;
    lo = Math.min(lo, first);
    hi = Math.max(hi, first + size);
  }
  if (!Number.isFinite(lo)) return null;
  return { first: lo, size: Math.min(65536, hi - lo) };
}

export function startSim(
  db: MockDB,
  scan: ScanRun,
  opts: { totalMs: number; testWindowMs: number | null; waitForWindowUntil: number | null },
) {
  const now = Date.now();
  const waiting = opts.waitForWindowUntil !== null;
  const sim: SimState = {
    scanId: scan.id,
    totalMs: opts.totalMs,
    activeMs: 0,
    lastResumeMs: waiting ? null : now,
    pausedReason: waiting ? "window" : null,
    testWindowMs: opts.testWindowMs,
    windowStartMs: now,
    resumeAtMs: waiting ? opts.waitForWindowUntil : null,
    windowsUsed: waiting ? 0 : 1,
    cancelled: false,
    finalized: false,
    logs: [],
    lastLoggedBatch: -1,
    lastPhase: null,
    span: addressSpan(db, scan.target_ids),
    waitingForWindow: waiting,
  };
  if (waiting) log(sim, now, "info", `Skan zaplanowany — oczekuje na okno (${scan.window?.start}–${scan.window?.end}).`);
  else
    log(
      sim,
      now,
      "info",
      `Start skanowania #${scan.number}: ${scan.address_count.toLocaleString("pl-PL")} adresów w ${scan.batches_total} podgrupach, limit ${scan.rate_limit_rps} zapytań/s.`,
    );
  db.sims.set(scan.id, sim);
  return sim;
}

/** Apply all state transitions due up to `now`. */
export function advance(db: MockDB, sim: SimState, now = Date.now()) {
  for (let guard = 0; guard < 20; guard++) {
    if (sim.finalized || sim.cancelled) return;
    if (sim.lastResumeMs !== null) {
      const doneAt = sim.lastResumeMs + (sim.totalMs - sim.activeMs);
      if (sim.testWindowMs !== null) {
        const closeAt = sim.windowStartMs + sim.testWindowMs;
        if (closeAt <= now && closeAt < doneAt) {
          sim.activeMs += closeAt - sim.lastResumeMs;
          sim.lastResumeMs = null;
          sim.pausedReason = "window";
          sim.resumeAtMs = closeAt + RESUME_GAP_MS;
          const p = Math.round(progressOf(sim, closeAt) * 100);
          log(sim, closeAt, "warn", `Koniec okna czasowego przy ${p}% — skan wstrzymany, punkt kontrolny zapisany. Wznowienie w kolejnym oknie.`);
          const scan = db.scans.find((s) => s.id === sim.scanId);
          if (scan) audit(db, null, "scan_pause", "scan", `#${scan.number}`, `Skan #${scan.number} wstrzymany: przekroczono okno czasowe (${p}%)`, [], scan.id);
          continue;
        }
      }
      if (doneAt <= now) {
        sim.activeMs = sim.totalMs;
        sim.lastResumeMs = null;
        finalize(db, sim, doneAt);
        return;
      }
      return;
    }
    if (sim.pausedReason === "window" && sim.resumeAtMs !== null && sim.resumeAtMs <= now) {
      const at = sim.resumeAtMs;
      sim.lastResumeMs = at;
      sim.windowStartMs = at;
      sim.pausedReason = null;
      sim.resumeAtMs = null;
      sim.windowsUsed += 1;
      const first = sim.waitingForWindow;
      sim.waitingForWindow = false;
      log(sim, at, "info", first ? "Otwarto okno skanowania — start." : `Nowe okno — wznowienie od punktu kontrolnego (okno ${sim.windowsUsed}).`);
      const scan = db.scans.find((s) => s.id === sim.scanId);
      if (scan && !first) audit(db, null, "scan_resume", "scan", `#${scan.number}`, `Skan #${scan.number} wznowiony w kolejnym oknie`, [], scan.id);
      continue;
    }
    return;
  }
}

/** Refresh the dynamic fields of a live scan record. */
export function refreshScan(db: MockDB, scan: ScanRun, now = Date.now()): ScanRun {
  const sim = db.sims.get(scan.id);
  if (!sim) return scan;
  advance(db, sim, now);
  if (sim.finalized || sim.cancelled) return scan;
  const p = progressOf(sim, now);
  const phase = phaseAt(p);
  const bp = batchProgress(p);
  const done = Math.min(scan.batches_total, Math.floor(bp * scan.batches_total));
  // logs for phases / batches crossed since last refresh
  if (sim.lastPhase !== phase) {
    sim.lastPhase = phase;
    log(sim, now, "info", PHASE_LOG[phase]);
  }
  const batches = batchesFor(db, scan);
  for (let i = sim.lastLoggedBatch + 1; i < done; i++) {
    const b = batches[i];
    if (b && (i % 4 === 0 || i === scan.batches_total - 1))
      log(sim, now, "info", `Podgrupa ${i + 1}/${scan.batches_total} (${b.cidr}): ${b.hosts_alive} aktywnych hostów, ${b.addresses} adresów.`);
    sim.lastLoggedBatch = i;
  }
  const running = sim.lastResumeMs !== null;
  const rate = running ? Math.round(scan.rate_limit_rps * (0.86 + 0.12 * Math.sin(now / 2300))) : 0;
  const remainingMs = sim.totalMs - (sim.activeMs + (running ? now - sim.lastResumeMs! : 0));
  Object.assign(scan, {
    status: sim.cancelled ? "cancelled" : running ? "running" : sim.pausedReason === "window" ? "paused_window" : "paused",
    phase,
    progress: Math.round(p * 1000) / 1000,
    batches_done: done,
    rate_rps: rate,
    duration_s: Math.round((sim.activeMs + (running ? now - sim.lastResumeMs! : 0)) / 1000),
    eta_s: running ? Math.round(remainingMs / 1000) : null,
    window_ends_at: running && sim.testWindowMs !== null ? iso(sim.windowStartMs + sim.testWindowMs) : null,
    resume_at: sim.resumeAtMs ? iso(sim.resumeAtMs) : null,
    windows_used: sim.windowsUsed,
    stats: {
      ...scan.stats,
      hosts_alive: Math.round(bp * expectedAlive(db, sim)),
    },
  } satisfies Partial<ScanRun>);
  return scan;
}

function expectedAlive(db: MockDB, sim: SimState): number {
  if (!sim.span) return 1;
  let n = 0;
  for (const h of db.hosts) if (h.responded && h.off >= sim.span.first && h.off < sim.span.first + sim.span.size) n++;
  return n;
}

export function headOffset(db: MockDB, scan: ScanRun, now = Date.now()): number | null {
  const sim = db.sims.get(scan.id);
  if (!sim || !sim.span || sim.finalized || sim.cancelled) return null;
  return sim.span.first + Math.floor(batchProgress(progressOf(sim, now)) * (sim.span.size - 1));
}

/** Batches (address sub-groups) for any scan: live ones from the sim, finished ones deterministically. */
export function batchesFor(db: MockDB, scan: ScanRun, now = Date.now()): ScanBatch[] {
  const sim = db.sims.get(scan.id);
  const span = sim?.span ?? (scan.address_count >= 65536 ? { first: 0, size: 65536 } : null);
  const total = scan.batches_total;
  const size = span ? Math.max(1, Math.ceil(span.size / total)) : 1;
  const r = rngFor("batches", scan.id);
  const started = scan.started_at ? new Date(scan.started_at).getTime() : now;
  const p = sim && !sim.finalized ? batchProgress(progressOf(sim, now)) : scan.status === "completed" ? 1 : scan.progress;
  const doneCount = Math.floor(p * total);
  const perBatchMs = sim ? sim.totalMs * 0.83 / total : (scan.duration_s * 1000 * 0.83) / Math.max(1, total);
  const out: ScanBatch[] = [];
  for (let i = 0; i < total; i++) {
    const first = span ? span.first + i * size : 0;
    let alive = 0;
    if (span) for (let o = first; o < first + size; o++) if (db.hostByOff.get(o)?.responded) alive++;
    const prefix = 32 - Math.round(Math.log2(size));
    const cidr = span ? `10.0.${first >> 8}.${first & 255}/${prefix}` : `domena ${i + 1}`;
    const status: ScanBatch["status"] =
      i < doneCount ? "done" : i === doneCount && scan.status === "running" ? "running" : i === doneCount && (scan.status === "paused" || scan.status === "paused_window") ? "paused" : scan.status === "cancelled" && i >= doneCount ? "failed" : "pending";
    const dur = Math.round((perBatchMs * (0.7 + r() * 0.6)) / 1000);
    const bStart = started + i * perBatchMs;
    out.push({
      id: `${scan.id}-b${i}`,
      index: i,
      cidr,
      addresses: span ? size : 1,
      status,
      started_at: status === "pending" ? null : iso(bStart),
      finished_at: status === "done" ? iso(bStart + dur * 1000) : null,
      duration_s: status === "done" ? dur : null,
      hosts_alive: status === "pending" ? 0 : alive,
      rate_rps: status === "pending" ? 0 : Math.round(scan.rate_limit_rps * (0.8 + r() * 0.18)),
      retries: chance(r, 0.06) ? int(r, 1, 2) : 0,
    });
  }
  return out;
}

export function logsFor(db: MockDB, scan: ScanRun) {
  const sim = db.sims.get(scan.id);
  if (sim) return sim.logs;
  if (!scan.started_at) return [];
  const s = new Date(scan.started_at).getTime();
  const lines: ScanLogLine[] = [
    { at: iso(s), level: "info" as const, message: `Start skanowania #${scan.number} z harmonogramu (${scan.address_count.toLocaleString("pl-PL")} adresów, ${scan.batches_total} podgrup).` },
    { at: iso(s + 60_000), level: "info" as const, message: PHASE_LOG.preflight },
    { at: iso(s + 22 * 60_000), level: "info" as const, message: PHASE_LOG.discovery },
    { at: iso(s + 3 * 3_600_000), level: "info" as const, message: PHASE_LOG.services },
    { at: iso(s + 5 * 3_600_000), level: "info" as const, message: PHASE_LOG.http },
    { at: iso(s + 6.4 * 3_600_000), level: "info" as const, message: PHASE_LOG.signatures },
  ];
  if (scan.windows_used > 1)
    lines.push({ at: iso(s + 8 * 3_600_000), level: "warn" as const, message: "Koniec okna 06:00 — skan wstrzymany, punkt kontrolny zapisany." }, { at: iso(s + 24 * 3_600_000), level: "info" as const, message: "Nowe okno 22:00 — wznowienie od punktu kontrolnego." });
  if (scan.status === "cancelled") lines.push({ at: scan.finished_at!, level: "warn" as const, message: "Skan przerwany przez użytkownika." });
  else if (scan.finished_at)
    lines.push({ at: scan.finished_at, level: "info" as const, message: `Zakończono: ${scan.stats.new} nowych, ${scan.stats.changed} zmienionych, ${scan.stats.gone} zniknęło, ${scan.stats.unstable} niestabilnych.` });
  return lines;
}

/* ------------------------------------------------------------------ */
/* Finalisation: produce a new snapshot + diff                         */
/* ------------------------------------------------------------------ */

function finalize(db: MockDB, sim: SimState, doneAt: number) {
  sim.finalized = true;
  const scan = db.scans.find((s) => s.id === sim.scanId);
  if (!scan) return;
  const at = iso(doneAt);
  const r = rngFor("finalize", scan.number);
  const span = sim.span ?? { first: 0, size: 0 };
  const inSpan = (h: HostRec) => h.off >= span.first && h.off < span.first + span.size;

  // Change state is relative to the previous run: reset everything first.
  for (const h of db.hosts) {
    h.change = "unchanged";
    for (const s of h.services) s.change = "unchanged";
  }

  const changes: Change[] = [];
  const cid = () => `c-${scan.number}-${changes.length}`;
  const responded = db.hosts.filter((h) => h.responded && inSpan(h));
  const scale = Math.max(0.15, span.size / 65536);

  // new hosts
  const nNew = Math.max(2, Math.round(26 * scale));
  const free: number[] = [];
  for (let o = span.first; o < span.first + span.size && free.length < 4000; o += 1 + int(r, 0, 40)) {
    const b = o >> 8;
    if ((o & 255) === 0 || (o & 255) === 255) continue;
    if (!db.hostByOff.has(o) && BLOCK_DENSITY[blockType(b)] > 0.05) free.push(o);
  }
  for (const off of shuffle(r, free).slice(0, nNew)) {
    const h = spawnHost(off, at, rngFor("spawn", off, scan.number));
    db.hosts.push(h);
    db.hostById.set(h.id, h);
    db.hostByOff.set(off, h);
    changes.push({
      id: cid(),
      kind: "new",
      entity: "host",
      host_id: h.id,
      ip: h.ip,
      hostname: h.hostnames[0] ?? null,
      port: null,
      summary: h.services.length ? `Nowy host z usługami: ${h.services.slice(0, 3).map((s) => `${s.port}/${s.name}`).join(", ")}` : "Nowy host odpowiada na ping (brak otwartych portów)",
      fields: h.services.slice(0, 4).map((s) => ({ field: `service.${s.port}`, label: `Port ${s.port}/${s.protocol}`, before: null, after: `${s.port}/${s.name} ${s.product ?? ""}`.trim() })),
      confidence: Math.round((0.9 + r() * 0.09) * 100) / 100,
      measurements: { responded: 3, total: 3 },
      detected_at: at,
    });
  }
  db.hosts.sort((a, b) => a.off - b.off);

  // gone
  const nGone = Math.max(1, Math.round(6 * scale));
  for (const h of shuffle(r, responded.filter((x) => x.availability === "active")).slice(0, nGone)) {
    h.responded = false;
    h.change = "gone";
    h.availability = "unstable";
    h.missCount = 1;
    changes.push({
      id: cid(),
      kind: "gone",
      entity: "host",
      host_id: h.id,
      ip: h.ip,
      hostname: h.hostnames[0] ?? null,
      port: null,
      summary: "Host przestał odpowiadać (1 skan bez odpowiedzi)",
      fields: [{ field: "host.responded", label: "Odpowiada", before: "tak", after: "nie (1 skan bez odpowiedzi)" }],
      confidence: Math.round((0.6 + r() * 0.25) * 100) / 100,
      measurements: { responded: 0, total: 3 },
      detected_at: at,
    });
  }

  // changed: version bumps (manual overrides are kept!)
  const nChanged = Math.max(2, Math.round(15 * scale));
  let keptOverrides = 0;
  for (const h of shuffle(r, responded.filter((x) => x.responded && x.change === "unchanged" && x.services.some((s) => s.web || s.plain === "ssh"))).slice(0, nChanged)) {
    const s = h.services.find((x) => x.web && !x.redirectTo) ?? h.services.find((x) => x.plain === "ssh")!;
    const before = (s.web ? s.serverVersion : s.version) ?? "";
    const after = bumpVersion(before);
    if (s.web) s.serverVersion = after;
    if (s.overrides.version) {
      s.overrides.version.scanner_value = after;
      keptOverrides++;
    } else if (!s.web || ["Apache httpd", "nginx", "Apache Tomcat", "Microsoft IIS httpd", "Jetty"].includes(s.product ?? "")) s.version = after;
    s.change = "changed";
    h.change = "changed";
    changes.push({
      id: cid(),
      kind: "changed",
      entity: "service",
      host_id: h.id,
      ip: h.ip,
      hostname: h.hostnames[0] ?? null,
      port: s.port,
      summary: `Zmiana wersji ${s.product ?? s.name}: ${before} → ${after}`,
      fields: [{ field: `service.${s.port}.version`, label: `Wersja (${s.port}/${s.name})`, before, after }],
      confidence: Math.round((0.82 + r() * 0.16) * 100) / 100,
      measurements: { responded: 3, total: 3 },
      detected_at: at,
    });
  }

  // unstable
  const nUnstable = Math.max(1, Math.round(9 * scale));
  for (const h of shuffle(r, db.hosts.filter((x) => inSpan(x) && x.availability === "unstable" && x.change === "unchanged")).slice(0, nUnstable)) {
    h.change = "unstable";
    changes.push({
      id: cid(),
      kind: "unstable",
      entity: "host",
      host_id: h.id,
      ip: h.ip,
      hostname: h.hostnames[0] ?? null,
      port: h.services[0]?.port ?? null,
      summary: "Host odpowiada nieregularnie — 2 z 3 ostatnich pomiarów",
      fields: [{ field: "host.pattern", label: "Ostatnie pomiary", before: "3/3", after: "2/3" }],
      confidence: Math.round((0.55 + r() * 0.3) * 100) / 100,
      measurements: { responded: 2, total: 3 },
      detected_at: at,
    });
  }

  // measurement history + inactive policy
  const inactiveAfter = db.settings.change_detection.inactive_after_misses;
  for (const h of db.hosts) {
    if (!inSpan(h) || h.change === "new") continue;
    const respondedNow = h.change === "gone" ? false : h.availability === "unstable" ? chance(r, 0.66) : h.responded;
    h.pattern = [...h.pattern.slice(1), respondedNow];
    if (respondedNow) {
      h.missCount = 0;
      h.lastSeen = at;
      h.responded = true;
      for (const s of h.services) s.lastSeen = at;
    } else if (h.change !== "gone") {
      h.missCount += 1;
      if (h.missCount >= inactiveAfter) h.availability = "inactive";
    }
  }
  for (const h of db.hosts) for (const k of Object.keys(h.overrides)) if (inSpan(h)) keptOverrides += k ? 1 : 0;

  // findings for affected hosts — keep analyst edits
  const affected = new Set(changes.map((c) => c.host_id));
  const previous = new Map(db.findings.filter((f) => affected.has(f.host_id)).map((f) => [f.id, f]));
  db.findings = db.findings.filter((f) => !affected.has(f.host_id));
  for (const id of affected) {
    const h = db.hostById.get(id);
    if (!h) continue;
    for (const f of findingsForHost(h, db.seededAt, doneAt)) {
      const old = previous.get(f.id);
      db.findings.push(old ? mergeFinding(f, old) : f);
    }
  }

  // counts, timeline, diff
  const summary = { new: 0, changed: 0, gone: 0, unstable: 0 };
  for (const c of changes) summary[c.kind] += 1;
  const prevHead = db.latestDiff.headId;
  db.latestDiff = { baseId: prevHead, headId: scan.id, changes };
  const alive = db.hosts.filter((h) => h.responded).length;
  db.timeline.push({ scan_id: scan.id, scan_number: scan.number, at, ...summary });
  db.trend.push({ scan_number: scan.number, at, value: alive });
  for (const t of db.targets) if (scan.target_ids.includes(t.id) && !t.excluded) t.last_scanned_at = at;

  Object.assign(scan, {
    status: "completed",
    phase: null,
    progress: 1,
    batches_done: scan.batches_total,
    rate_rps: Math.round(scan.rate_limit_rps * 0.93),
    duration_s: Math.round(sim.totalMs / 1000),
    eta_s: null,
    finished_at: at,
    window_ends_at: null,
    resume_at: null,
    windows_used: sim.windowsUsed,
    stats: {
      hosts_alive: db.hosts.filter((h) => h.responded && inSpan(h)).length,
      services: db.hosts.reduce((n, h) => n + (inSpan(h) && h.responded ? h.services.length : 0), 0),
      http_services: db.hosts.reduce((n, h) => n + (inSpan(h) && h.responded ? h.services.filter((s) => s.web && !s.redirectTo).length : 0), 0),
      findings: db.findings.length,
      ...summary,
    },
  } satisfies Partial<ScanRun>);
  log(sim, doneAt, "info", `Zakończono: ${summary.new} nowych, ${summary.changed} zmienionych, ${summary.gone} zniknęło, ${summary.unstable} niestabilnych.`);
  if (keptOverrides) log(sim, doneAt, "info", `Zachowano ${keptOverrides} ręcznych zmian — wartości ze skanu nie nadpisały edycji użytkowników.`);
  audit(db, null, "scan_start", "scan", `#${scan.number}`, `Zakończono skan #${scan.number}: ${summary.new} nowe, ${summary.changed} zmienione, ${summary.gone} zniknęło, ${summary.unstable} niestabilne`, [], scan.id);
}

function mergeFinding(fresh: Finding, old: Finding): Finding {
  return {
    ...fresh,
    status: old.status,
    score_override: old.score_override,
    assignee: old.assignee,
    tags: old.tags,
    notes: old.notes,
    manual_overrides: old.manual_overrides,
    defectdojo: old.defectdojo,
    first_seen: old.first_seen,
  };
}

export function cancelSim(db: MockDB, scan: ScanRun) {
  const sim = db.sims.get(scan.id);
  const now = Date.now();
  if (!sim) return;
  advance(db, sim, now);
  if (sim.finalized) return;
  if (sim.lastResumeMs !== null) sim.activeMs += now - sim.lastResumeMs;
  sim.lastResumeMs = null;
  sim.cancelled = true;
  log(sim, now, "warn", "Skan przerwany przez użytkownika — wyniki częściowe zachowane.");
  Object.assign(scan, { status: "cancelled", phase: null, rate_rps: 0, eta_s: null, finished_at: iso(now), window_ends_at: null, resume_at: null });
}

export function pauseSim(db: MockDB, scan: ScanRun) {
  const sim = db.sims.get(scan.id);
  const now = Date.now();
  if (!sim) return;
  advance(db, sim, now);
  if (sim.finalized || sim.cancelled || sim.lastResumeMs === null) return;
  sim.activeMs += now - sim.lastResumeMs;
  sim.lastResumeMs = null;
  sim.pausedReason = "user";
  log(sim, now, "info", "Skan wstrzymany przez użytkownika.");
}

export function resumeSim(db: MockDB, scan: ScanRun) {
  const sim = db.sims.get(scan.id);
  const now = Date.now();
  if (!sim) return;
  advance(db, sim, now);
  if (sim.finalized || sim.cancelled || sim.lastResumeMs !== null) return;
  sim.lastResumeMs = now;
  sim.windowStartMs = now;
  sim.pausedReason = null;
  sim.resumeAtMs = null;
  if (sim.waitingForWindow) {
    sim.waitingForWindow = false;
    sim.windowsUsed += 1;
  }
  log(sim, now, "info", "Skan wznowiony ręcznie.");
}
