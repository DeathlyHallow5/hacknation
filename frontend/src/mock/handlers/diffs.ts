import type { Change, ChangeKind, DiffResponse, ScanRun } from "@/lib/api/types";
import type { MockDB } from "@/mock/db";
import type { RouteFn } from "@/mock/router";
import { scanRef } from "@/mock/serialize";
import { pick, rngFor, shuffle } from "@/mock/rng";
import { badRequest, json, list, matchesText, notFound, paginate, sortBy } from "@/mock/util";

/** Synthetic but deterministic changes for older scan pairs. */
function syntheticChanges(db: MockDB, base: ScanRun, head: ScanRun): Change[] {
  const points = db.timeline.filter((p) => p.scan_number > base.number && p.scan_number <= head.number);
  const want: Record<ChangeKind, number> = { new: 0, changed: 0, gone: 0, unstable: 0 };
  for (const p of points) {
    want.new += p.new;
    want.changed += p.changed;
    want.gone += p.gone;
    want.unstable += p.unstable;
  }
  for (const k of Object.keys(want) as ChangeKind[]) want[k] = Math.min(want[k], 400);
  const r = rngFor("diff", base.number, head.number);
  const pool = shuffle(r, db.hosts.filter((h) => h.services.length > 0));
  const out: Change[] = [];
  let i = 0;
  const at = head.finished_at ?? head.started_at ?? new Date().toISOString();
  for (const kind of ["new", "changed", "gone", "unstable"] as ChangeKind[]) {
    for (let n = 0; n < want[kind]; n++) {
      const h = pool[i++ % pool.length];
      const s = h.services[0];
      const ver = s.version ?? "1.0";
      const summary =
        kind === "new"
          ? `Nowa usługa: ${s.port}/${s.name}${s.product ? ` (${s.product})` : ""}`
          : kind === "changed"
            ? pick(r, [`Zmiana wersji ${s.product ?? s.name}`, "Zmiana tytułu strony", "Odnowiony certyfikat TLS", `Nowy nagłówek Server`])
            : kind === "gone"
              ? "Host przestał odpowiadać"
              : "Host odpowiada nieregularnie";
      out.push({
        id: `c-${base.number}-${head.number}-${out.length}`,
        kind,
        entity: kind === "changed" ? "service" : "host",
        host_id: h.id,
        ip: h.ip,
        hostname: h.hostnames[0] ?? null,
        port: kind === "gone" ? null : s.port,
        summary,
        fields:
          kind === "changed"
            ? [{ field: `service.${s.port}.version`, label: `Wersja (${s.port}/${s.name})`, before: ver, after: `${ver}+` }]
            : kind === "new"
              ? [{ field: `service.${s.port}`, label: `Port ${s.port}/${s.protocol}`, before: null, after: `${s.name} ${s.product ?? ""}`.trim() }]
              : [{ field: "host.responded", label: "Odpowiada", before: kind === "gone" ? "tak" : "3/3", after: kind === "gone" ? "nie" : "2/3" }],
        confidence: Math.round((kind === "unstable" ? 0.55 + r() * 0.3 : 0.75 + r() * 0.24) * 100) / 100,
        measurements: kind === "unstable" ? { responded: 2, total: 3 } : kind === "gone" ? { responded: 0, total: 3 } : { responded: 3, total: 3 },
        detected_at: at,
      });
    }
  }
  return out;
}

export function diffRoutes(route: RouteFn) {
  route("GET", "/diffs", "changes:read", (ctx) => {
    const db = ctx.db;
    const runs = db.scans.filter((s) => s.source === "scanner" && s.status === "completed");
    const headId = ctx.query.get("head") ?? db.latestDiff.headId;
    const head = runs.find((s) => s.id === headId);
    if (!head) return notFound("Skan (head)");
    const prevOfHead = runs.filter((s) => s.number < head.number).at(-1);
    const baseId = ctx.query.get("base") ?? (head.id === db.latestDiff.headId ? db.latestDiff.baseId : prevOfHead?.id);
    const base = runs.find((s) => s.id === baseId);
    if (!base) return notFound("Skan (base)");
    if (base.number >= head.number) return badRequest("Skan bazowy musi być starszy niż porównywany.");

    const all = head.id === db.latestDiff.headId && base.id === db.latestDiff.baseId ? db.latestDiff.changes : syntheticChanges(db, base, head);
    const summary: Record<ChangeKind, number> = { new: 0, changed: 0, gone: 0, unstable: 0 };
    for (const c of all) summary[c.kind] += 1;
    const kinds = list(ctx.query, "kind");
    const q = ctx.query.get("q");
    const minConf = ctx.query.get("min_confidence") ? Number(ctx.query.get("min_confidence")) : null;
    const filtered = sortBy(
      all.filter((c) => (!kinds.length || kinds.includes(c.kind)) && (minConf === null || c.confidence >= minConf) && matchesText(q, c.ip, c.hostname, c.summary)),
      ctx.query.get("sort") ?? "kind_rank,-confidence",
      {
        kind_rank: (c) => ["new", "changed", "gone", "unstable"].indexOf(c.kind),
        confidence: (c) => c.confidence,
        ip: (c) => c.ip.split(".").reduce((a, p) => a * 256 + Number(p), 0),
      },
    );
    const page = paginate(filtered, ctx.query, 50);
    const body: DiffResponse = { ...page, base: scanRef(base), head: scanRef(head), summary };
    return json(body);
  });
}
