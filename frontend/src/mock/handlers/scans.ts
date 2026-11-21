import Papa from "papaparse";
import type {
  ScanCreateRequest,
  ScanEstimate,
  ScanEstimateRequest,
  ScanEvent,
  ScanPatch,
  ScanProfile,
  ScanProfileInput,
  ScanRun,
  Schedule,
  ScheduleInput,
} from "@/lib/api/types";
import type { HostRec, MockDB } from "@/mock/db";
import { nextId } from "@/mock/db";
import { blockType } from "@/mock/catalog";
import type { RouteFn } from "@/mock/router";
import { scanRef } from "@/mock/serialize";
import { addressSpan, batchesFor, cancelSim, logsFor, pauseSim, refreshScan, resumeSim, startSim } from "@/mock/sim";
import { iso, nextScheduleRun, nextWindowStart, parseHM, windowAround } from "@/mock/time";
import { apiError, audit, badRequest, file, json, list, matchesText, notFound, paginate, toCsv } from "@/mock/util";
import { liveScans } from "@/mock/handlers/core";

function portCount(db: MockDB, p: ScanProfile): number {
  const spec = p.ports.preset === "top100" ? null : p.ports.preset === "top1000" ? null : p.ports.preset === "allowed" ? db.settings.scan_safety.allowed_ports : p.ports.custom;
  if (p.ports.preset === "top100") return 100;
  if (p.ports.preset === "top1000") return 1000;
  let n = 0;
  for (const part of (spec ?? "").split(",")) {
    const [a, b] = part.split("-").map((x) => Number(x.trim()));
    if (!a) continue;
    n += b ? Math.max(1, b - a + 1) : 1;
  }
  return Math.max(1, n);
}

function windowSeconds(start: string, end: string) {
  const [sh, sm] = parseHM(start);
  const [eh, em] = parseHM(end);
  let mins = eh * 60 + em - (sh * 60 + sm);
  if (mins <= 0) mins += 24 * 60;
  return mins * 60;
}

export function estimate(db: MockDB, req: ScanEstimateRequest): ScanEstimate | string {
  const profile = db.profiles.find((p) => p.id === req.profile_id);
  if (!profile) return "Wybierz profil skanowania.";
  const targets = db.targets.filter((t) => req.target_ids.includes(t.id));
  if (!targets.length) return "Wybierz co najmniej jeden cel.";
  const addresses = targets.filter((t) => !t.excluded).reduce((n, t) => n + t.address_count, 0);
  const excluded = targets.filter((t) => t.excluded).reduce((n, t) => n + t.address_count, 0);
  const rate = Math.min(profile.rate_limit_rps, db.settings.scan_safety.max_rate_rps);
  const estAlive = Math.max(1, Math.round(addresses * 0.19));
  const ports = portCount(db, profile);
  const seconds = Math.round(
    (addresses * 2) / rate + (estAlive * ports * 0.9) / rate + (profile.http_probe ? (estAlive * 0.4 * 6) / rate : 0) + (profile.signatures !== "none" ? (estAlive * 0.4 * 4) / rate : 0),
  );
  const span = addressSpan(db, req.target_ids);
  let batchPrefix = profile.batch_prefix;
  let batches = 1;
  if (span && span.size > 1) {
    if (profile.batch_strategy === "auto") {
      const wanted = Math.max(1, Math.ceil(seconds / 400));
      const pow = 2 ** Math.round(Math.log2(wanted));
      batchPrefix = Math.max(17, Math.min(26, 32 - Math.round(Math.log2(Math.max(1, span.size / pow)))));
    }
    batches = Math.max(1, Math.ceil(span.size / 2 ** (32 - batchPrefix)));
  } else batches = Math.max(1, targets.length);
  const win = req.window ?? db.settings.default_window;
  const ws = windowSeconds(win.start, win.end);
  const notes: string[] = [];
  if (excluded) notes.push(`Pominięto ${excluded.toLocaleString("pl-PL")} adresów z celów wykluczonych.`);
  if (profile.rate_limit_rps > db.settings.scan_safety.max_rate_rps)
    notes.push(`Limit profilu obniżono do globalnego maksimum ${db.settings.scan_safety.max_rate_rps} zapytań/s.`);
  notes.push(`Podział na ${batches} podgrup /${batchPrefix} (ok. ${Math.max(1, Math.round(seconds / batches / 60))} min każda) — po przekroczeniu okna skan wznowi się od ostatniej ukończonej podgrupy.`);
  return {
    addresses,
    excluded,
    est_alive: estAlive,
    batch_prefix: batchPrefix,
    batch_size: 2 ** (32 - batchPrefix),
    batches,
    rate_rps: rate,
    est_duration_s: seconds,
    window_seconds: ws,
    fits_window: seconds <= ws,
    windows_needed: Math.max(1, Math.ceil(seconds / ws)),
    notes,
  };
}

function scanList(db: MockDB) {
  liveScans(db);
  return db.scans;
}

export function scanRoutes(route: RouteFn) {
  route("GET", "/scans", "scans:read", (ctx) => {
    const statuses = list(ctx.query, "status");
    const source = ctx.query.get("source");
    const q = ctx.query.get("q");
    const items = scanList(ctx.db)
      .filter((s) => (!statuses.length || statuses.includes(s.status)) && (!source || s.source === source) && matchesText(q, s.name, `#${s.number}`, s.targets_label))
      .slice()
      .sort((a, b) => b.number - a.number);
    return json(paginate(items, ctx.query, 20));
  });

  route("POST", "/scans/estimate", "scans:read", async (ctx) => {
    const res = estimate(ctx.db, await ctx.body<ScanEstimateRequest>());
    return typeof res === "string" ? badRequest(res) : json(res);
  });

  route("POST", "/scans", "scans:create", async (ctx) => {
    const db = ctx.db;
    const body = await ctx.body<ScanCreateRequest>();
    if (!body.name?.trim()) return badRequest("Podaj nazwę skanowania.", { name: "Pole wymagane" });
    const est = estimate(db, { target_ids: body.target_ids ?? [], profile_id: body.profile_id, window: body.window });
    if (typeof est === "string") return badRequest(est);
    if (!est.addresses) return badRequest("Wszystkie wybrane cele są wykluczone ze skanowania.");
    const profile = db.profiles.find((p) => p.id === body.profile_id)!;
    const number = Math.max(...db.scans.map((s) => s.number)) + 1;
    const targets = db.targets.filter((t) => body.target_ids.includes(t.id) && !t.excluded);
    const win = body.window ?? db.settings.default_window;
    const now = new Date();
    const scan: ScanRun = {
      id: `scan-${number}`,
      number,
      name: body.name.trim(),
      status: "running",
      phase: "preflight",
      source: "scanner",
      profile_id: profile.id,
      profile_name: profile.name,
      schedule_id: null,
      target_ids: targets.map((t) => t.id),
      targets_label:
        targets.length === 1
          ? targets[0].value
          : `${targets.filter((t) => t.type !== "domain").length} zakr., ${targets.filter((t) => t.type === "domain").length} dom. (${est.addresses.toLocaleString("pl-PL")} adresów)`,
      address_count: est.addresses,
      progress: 0,
      batches_total: est.batches,
      batches_done: 0,
      rate_rps: 0,
      rate_limit_rps: est.rate_rps,
      window: win,
      window_ends_at: null,
      resume_at: null,
      windows_used: 1,
      started_at: iso(now),
      finished_at: null,
      duration_s: 0,
      eta_s: null,
      stats: { hosts_alive: 0, services: 0, http_services: 0, findings: 0, new: 0, changed: 0, gone: 0, unstable: 0 },
      error: null,
      tags: body.tags ?? [],
      notes: body.notes ?? null,
      created_by: ctx.user!.name,
    };
    const w = windowAround(now, win.start, win.end);
    const waitUntil = body.start === "window" && !w.open ? nextWindowStart(now, win.start, win.end).getTime() : null;
    if (waitUntil) scan.status = "paused_window";
    db.scans.push(scan);
    const totalMs = Math.round(Math.min(90_000, Math.max(24_000, 24_000 + (est.addresses / 65536) * 60_000)));
    startSim(db, scan, {
      totalMs,
      testWindowMs: body.test_window_seconds ? body.test_window_seconds * 1000 : null,
      waitForWindowUntil: waitUntil,
    });
    refreshScan(db, scan);
    audit(db, ctx.user, "scan_start", "scan", `#${number}`, `Uruchomiono skanowanie #${number} „${scan.name}” (${est.addresses.toLocaleString("pl-PL")} adresów)`, [], scan.id);
    return json(scan, { status: 201 });
  });

  route("POST", "/scans/import", "scans:import", async (ctx) => {
    const db = ctx.db;
    const form = await ctx.form();
    const f = form.get("file");
    if (!(f instanceof Blob)) return badRequest("Dołącz plik w polu „file”.");
    const name = f instanceof File ? f.name : "wyniki";
    const text = await f.text();
    type Row = { ip: string; hostname?: string; port?: number; protocol?: string; service?: string; product?: string; version?: string };
    const rows: Row[] = [];
    if (name.toLowerCase().endsWith(".json") || /^\s*[[{]/.test(text)) {
      let data: unknown;
      try {
        data = JSON.parse(text);
      } catch (e) {
        return badRequest(`Niepoprawny JSON: ${(e as Error).message}`);
      }
      const hosts = (Array.isArray(data) ? data : (data as { hosts?: unknown[] }).hosts) ?? [];
      for (const h of hosts as { ip: string; hostnames?: string[]; services?: { port: number; protocol?: string; name?: string; product?: string; version?: string }[] }[]) {
        if (!h?.ip) continue;
        if (!h.services?.length) rows.push({ ip: h.ip, hostname: h.hostnames?.[0] });
        for (const s of h.services ?? []) rows.push({ ip: h.ip, hostname: h.hostnames?.[0], port: s.port, protocol: s.protocol, service: s.name, product: s.product, version: s.version });
      }
    } else {
      const res = Papa.parse<Record<string, string>>(text.trim(), { header: true, skipEmptyLines: true, transformHeader: (h) => h.trim().toLowerCase() });
      for (const r of res.data) if (r.ip) rows.push({ ip: r.ip.trim(), hostname: r.hostname, port: r.port ? Number(r.port) : undefined, protocol: r.protocol, service: r.service, product: r.product, version: r.version });
    }
    if (!rows.length) return badRequest("Plik nie zawiera żadnych hostów (oczekiwano kolumny „ip”).");
    const ips = new Set(rows.map((r) => r.ip));
    let created = 0;
    let servicesAdded = 0;
    const at = iso(Date.now());
    for (const r of rows) {
      const p = r.ip.split(".").map(Number);
      if (p.length !== 4 || p[0] !== 10 || p[1] !== 0) continue;
      const off = p[2] * 256 + p[3];
      let h = db.hostByOff.get(off);
      if (!h) {
        h = {
          id: `h-${off}`, ipInt: (10 << 24) + off, ip: r.ip, off, block: p[2], blockType: blockType(p[2]),
          hostnames: r.hostname ? [r.hostname] : [], device: "unknown", osGuess: null, services: [], responded: true,
          availability: "active", change: "new", pattern: [false, false, false, false, false, false, false, true], missCount: 0,
          firstSeen: at, lastSeen: at, owner: null, criticality: "medium", tags: ["import"], notes: null, overrides: {},
          recheckRequestedAt: null, lastRecheckAt: null, byHour: null,
        } satisfies HostRec;
        db.hosts.push(h);
        db.hostById.set(h.id, h);
        db.hostByOff.set(off, h);
        created++;
      }
      if (r.port && !h.services.some((s) => s.port === r.port)) {
        h.services.push({
          id: `s-${off}-${r.port}`, port: r.port, protocol: r.protocol === "udp" ? "udp" : "tcp", name: r.service ?? "unknown",
          product: r.product ?? null, version: r.version ?? null, confidence: 0.7, tls: r.port === 443, banner: null, web: null,
          appVersion: null, serverVersion: null, plain: null, old: false, redirectTo: null, certDays: null, certRenewedAt: null,
          change: "new", firstSeen: at, lastSeen: at, tags: ["import"], notes: null, overrides: {},
        });
        servicesAdded++;
      }
    }
    db.hosts.sort((a, b) => a.off - b.off);
    const number = Math.max(...db.scans.map((s) => s.number)) + 1;
    const scan: ScanRun = {
      id: `scan-${number}`, number, name: `Import: ${name}`, status: "completed", phase: null, source: "import", profile_id: null,
      profile_name: null, schedule_id: null, target_ids: [], targets_label: `${ips.size} hostów z pliku`, address_count: ips.size,
      progress: 1, batches_total: 1, batches_done: 1, rate_rps: 0, rate_limit_rps: 0, window: null, window_ends_at: null,
      resume_at: null, windows_used: 0, started_at: at, finished_at: at, duration_s: 1, eta_s: null,
      stats: { hosts_alive: ips.size, services: rows.filter((r) => r.port).length, http_services: rows.filter((r) => r.port === 80 || r.port === 443).length, findings: 0, new: created, changed: 0, gone: 0, unstable: 0 },
      error: null, tags: ["import"], notes: `Zaimportowano ${rows.length} wierszy: ${created} nowych hostów, ${servicesAdded} nowych usług.`, created_by: ctx.user!.name,
    };
    db.scans.push(scan);
    audit(db, ctx.user, "import", "scan", `#${number}`, `Zaimportowano wyniki skanu z pliku ${name} (${ips.size} hostów)`, [], scan.id);
    return json(scan, { status: 201 });
  });

  route("GET", "/scans/:id", "scans:read", (ctx) => {
    const s = ctx.db.scans.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Skanowanie");
    return json(refreshScan(ctx.db, s));
  });

  route("PATCH", "/scans/:id", "scans:update", async (ctx) => {
    const s = ctx.db.scans.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Skanowanie");
    const patch = await ctx.body<ScanPatch>();
    const changes = [];
    if (patch.name !== undefined && patch.name !== s.name) {
      changes.push({ field: "name", label: "Nazwa", before: s.name, after: patch.name });
      s.name = patch.name;
    }
    if (patch.notes !== undefined && patch.notes !== s.notes) {
      changes.push({ field: "notes", label: "Notatki", before: s.notes, after: patch.notes });
      s.notes = patch.notes;
    }
    if (patch.tags !== undefined) {
      changes.push({ field: "tags", label: "Tagi", before: s.tags.join(", "), after: patch.tags.join(", ") });
      s.tags = patch.tags;
    }
    if (changes.length) audit(ctx.db, ctx.user, "update", "scan", `#${s.number}`, "Edytowano skanowanie", changes, s.id);
    return json(refreshScan(ctx.db, s));
  });

  route("DELETE", "/scans/:id", "scans:delete", (ctx) => {
    const i = ctx.db.scans.findIndex((x) => x.id === ctx.params.id);
    if (i < 0) return notFound("Skanowanie");
    const s = ctx.db.scans[i];
    if (s.id === ctx.db.latestDiff.headId || s.id === ctx.db.latestDiff.baseId)
      return apiError(409, "conflict", "Nie można usunąć skanów, które tworzą bieżące porównanie zmian.");
    if (["running", "paused", "paused_window"].includes(s.status)) cancelSim(ctx.db, s);
    ctx.db.scans.splice(i, 1);
    ctx.db.timeline = ctx.db.timeline.filter((p) => p.scan_id !== s.id);
    audit(ctx.db, ctx.user, "delete", "scan", `#${s.number}`, `Usunięto skanowanie #${s.number}`, [], s.id);
    return new Response(null, { status: 204 });
  });

  for (const action of ["pause", "resume", "cancel"] as const) {
    route("POST", `/scans/:id/${action}`, "scans:control", (ctx) => {
      const s = ctx.db.scans.find((x) => x.id === ctx.params.id);
      if (!s) return notFound("Skanowanie");
      if (!ctx.db.sims.has(s.id) || ["completed", "cancelled", "failed"].includes(s.status))
        return apiError(409, "conflict", "To skanowanie już się zakończyło.");
      if (action === "pause") pauseSim(ctx.db, s);
      if (action === "resume") resumeSim(ctx.db, s);
      if (action === "cancel") cancelSim(ctx.db, s);
      audit(ctx.db, ctx.user, action === "pause" ? "scan_pause" : action === "resume" ? "scan_resume" : "scan_cancel", "scan", `#${s.number}`, action === "pause" ? `Wstrzymano skanowanie #${s.number}` : action === "resume" ? `Wznowiono skanowanie #${s.number}` : `Przerwano skanowanie #${s.number}`, [], s.id);
      return json(refreshScan(ctx.db, s));
    });
  }

  route("GET", "/scans/:id/batches", "scans:read", (ctx) => {
    const s = ctx.db.scans.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Skanowanie");
    refreshScan(ctx.db, s);
    return json(batchesFor(ctx.db, s));
  });

  route("GET", "/scans/:id/logs", "scans:read", (ctx) => {
    const s = ctx.db.scans.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Skanowanie");
    refreshScan(ctx.db, s);
    return json(logsFor(ctx.db, s));
  });

  route("GET", "/scans/:id/events", "scans:read", (ctx) => {
    const db = ctx.db;
    const s = db.scans.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Skanowanie");
    const enc = new TextEncoder();
    let timer: ReturnType<typeof setInterval> | null = null;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        let logCount = 0;
        let lastStatus = "";
        let lastDone = -1;
        const startedAt = Date.now();
        const send = (e: ScanEvent) => {
          if (!closed) controller.enqueue(enc.encode(`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`));
        };
        const close = () => {
          if (closed) return;
          closed = true;
          if (timer) clearInterval(timer);
          try {
            controller.close();
          } catch {
            /* already closed */
          }
        };
        controller.enqueue(enc.encode("retry: 3000\n\n"));
        const tick = () => {
          if (closed) return;
          const scan = refreshScan(db, s);
          send({ type: "progress", scan });
          const logs = logsFor(db, scan);
          for (const l of logs.slice(logCount)) send({ type: "log", ...l });
          logCount = logs.length;
          if (scan.status === "paused_window" && lastStatus !== "paused_window") send({ type: "window", state: "paused", resume_at: scan.resume_at });
          if (lastStatus === "paused_window" && scan.status === "running") send({ type: "window", state: "resumed", resume_at: null });
          if (scan.batches_done !== lastDone) {
            const batches = batchesFor(db, scan);
            for (let i = Math.max(0, lastDone); i <= Math.min(scan.batches_done, batches.length - 1); i++) send({ type: "batch", batch: batches[i] });
            lastDone = scan.batches_done;
          }
          lastStatus = scan.status;
          if (["completed", "cancelled", "failed"].includes(scan.status) || Date.now() - startedAt > 15 * 60_000) {
            send({ type: "done", scan });
            close();
          }
        };
        tick();
        timer = setInterval(tick, 1000);
        ctx.req.signal.addEventListener("abort", close);
      },
      cancel() {
        if (timer) clearInterval(timer);
      },
    });
    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
      },
    });
  });

  route("GET", "/scans/:id/export", "scans:export", (ctx) => {
    const db = ctx.db;
    const s = db.scans.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Skanowanie");
    const span = addressSpan(db, s.target_ids) ?? (s.address_count >= 65536 ? { first: 0, size: 65536 } : { first: 0, size: 0 });
    const hosts = db.hosts.filter((h) => h.responded && h.off >= span.first && h.off < span.first + span.size);
    const format = ctx.query.get("format") === "csv" ? "csv" : "json";
    audit(db, ctx.user, "export", "scan", `#${s.number}`, `Wyeksportowano wyniki skanu #${s.number} (${format.toUpperCase()}, ${hosts.length} hostów)`, [], s.id);
    if (format === "csv") {
      const rows: Record<string, unknown>[] = [];
      for (const h of hosts) for (const sv of h.services) rows.push({ ip: h.ip, hostname: h.hostnames[0] ?? "", port: sv.port, protocol: sv.protocol, service: sv.name, product: sv.product, version: sv.version, change: sv.change });
      return file(toCsv(rows, ["ip", "hostname", "port", "protocol", "service", "product", "version", "change"]), `skan-${s.number}.csv`, "text/csv");
    }
    const data = {
      scan: scanRef(s),
      scanner: "asi-mock",
      hosts: hosts.map((h) => ({
        ip: h.ip,
        hostnames: h.hostnames,
        availability: h.availability,
        change: h.change,
        services: h.services.map((sv) => ({ port: sv.port, protocol: sv.protocol, name: sv.name, product: sv.product, version: sv.version, change: sv.change })),
      })),
    };
    return file(JSON.stringify(data), `skan-${s.number}.json`, "application/json");
  });

  /* ---------------- profiles ---------------- */
  route("GET", "/profiles", "scans:read", (ctx) => json(ctx.db.profiles));
  route("POST", "/profiles", "scans:create", async (ctx) => {
    const body = await ctx.body<ScanProfileInput>();
    if (!body.name?.trim()) return badRequest("Podaj nazwę profilu.", { name: "Pole wymagane" });
    if (body.rate_limit_rps > ctx.db.settings.scan_safety.max_rate_rps)
      return badRequest(`Limit nie może przekraczać ${ctx.db.settings.scan_safety.max_rate_rps} zapytań/s.`, { rate_limit_rps: "Powyżej limitu globalnego" });
    const p: ScanProfile = { ...body, id: nextId(ctx.db, "p"), builtin: false };
    ctx.db.profiles.push(p);
    audit(ctx.db, ctx.user, "create", "profile", p.name, "Utworzono profil skanowania", [], p.id);
    return json(p, { status: 201 });
  });
  route("PATCH", "/profiles/:id", "scans:update", async (ctx) => {
    const p = ctx.db.profiles.find((x) => x.id === ctx.params.id);
    if (!p) return notFound("Profil");
    const body = await ctx.body<Partial<ScanProfileInput>>();
    if (body.rate_limit_rps && body.rate_limit_rps > ctx.db.settings.scan_safety.max_rate_rps)
      return badRequest(`Limit nie może przekraczać ${ctx.db.settings.scan_safety.max_rate_rps} zapytań/s.`, { rate_limit_rps: "Powyżej limitu globalnego" });
    Object.assign(p, body, { id: p.id, builtin: p.builtin });
    audit(ctx.db, ctx.user, "update", "profile", p.name, "Edytowano profil skanowania", [], p.id);
    return json(p);
  });
  route("DELETE", "/profiles/:id", "scans:delete", (ctx) => {
    const p = ctx.db.profiles.find((x) => x.id === ctx.params.id);
    if (!p) return notFound("Profil");
    if (p.builtin) return apiError(409, "conflict", "Profili wbudowanych nie można usuwać.");
    if (ctx.db.schedules.some((s) => s.profile_id === p.id)) return apiError(409, "conflict", "Profil jest używany przez harmonogram.");
    ctx.db.profiles = ctx.db.profiles.filter((x) => x.id !== p.id);
    audit(ctx.db, ctx.user, "delete", "profile", p.name, "Usunięto profil skanowania", [], p.id);
    return new Response(null, { status: 204 });
  });

  /* ---------------- schedules ---------------- */
  const CRON_INVALID = "Wyrażenie cron jest niepoprawne albo nie wypada w ciągu najbliższego roku.";
  const validateSchedule = (body: Partial<ScheduleInput>) => {
    if (body.window && (!/^\d{2}:\d{2}$/.test(body.window.start) || !/^\d{2}:\d{2}$/.test(body.window.end)))
      return "Okno musi mieć format GG:MM.";
    if (body.frequency === "cron" && !(body.cron ?? "").trim().match(/^(\S+\s+){4}\S+$/)) return "Wyrażenie cron musi mieć 5 pól.";
    if (body.days && !body.days.length) return "Wybierz co najmniej jeden dzień tygodnia.";
    return null;
  };
  route("GET", "/schedules", "schedules:read", (ctx) => json(ctx.db.schedules));
  route("POST", "/schedules", "schedules:create", async (ctx) => {
    const body = await ctx.body<ScheduleInput>();
    const err = validateSchedule(body) ?? (!body.name?.trim() ? "Podaj nazwę harmonogramu." : null);
    if (err) return badRequest(err);
    const now = new Date();
    const next = nextScheduleRun(body, now);
    if (body.frequency === "cron" && !next) return badRequest(CRON_INVALID, { cron: CRON_INVALID });
    const s: Schedule = { ...body, id: nextId(ctx.db, "sch"), next_run_at: body.enabled && next ? iso(next) : null, last_run_id: null, created_at: iso(now) };
    ctx.db.schedules.push(s);
    audit(ctx.db, ctx.user, "create", "schedule", s.name, "Utworzono harmonogram", [], s.id);
    return json(s, { status: 201 });
  });
  route("PATCH", "/schedules/:id", "schedules:update", async (ctx) => {
    const s = ctx.db.schedules.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Harmonogram");
    const body = await ctx.body<Partial<ScheduleInput>>();
    const err = validateSchedule(body);
    if (err) return badRequest(err);
    const merged = { ...s, ...body };
    const next = nextScheduleRun(merged, new Date());
    if (merged.frequency === "cron" && !next) return badRequest(CRON_INVALID, { cron: CRON_INVALID });
    const before = { enabled: s.enabled, window: `${s.window.start}–${s.window.end}` };
    Object.assign(s, body, { id: s.id });
    s.next_run_at = s.enabled && next ? iso(next) : null;
    audit(ctx.db, ctx.user, "update", "schedule", s.name, "Edytowano harmonogram", [
      ...(before.enabled !== s.enabled ? [{ field: "enabled", label: "Aktywny", before: before.enabled ? "tak" : "nie", after: s.enabled ? "tak" : "nie" }] : []),
      ...(before.window !== `${s.window.start}–${s.window.end}` ? [{ field: "window", label: "Okno", before: before.window, after: `${s.window.start}–${s.window.end}` }] : []),
    ], s.id);
    return json(s);
  });
  route("DELETE", "/schedules/:id", "schedules:delete", (ctx) => {
    const s = ctx.db.schedules.find((x) => x.id === ctx.params.id);
    if (!s) return notFound("Harmonogram");
    ctx.db.schedules = ctx.db.schedules.filter((x) => x.id !== s.id);
    audit(ctx.db, ctx.user, "delete", "schedule", s.name, "Usunięto harmonogram", [], s.id);
    return new Response(null, { status: 204 });
  });
}
