import type { BulkRequest, DefectDojoExportRequest, DefectDojoExportResult, Finding, FindingPatch, FindingStatus } from "@/lib/api/types";
import { FINDING_STATUS_LABEL } from "@/lib/labels";
import type { MockDB } from "@/mock/db";
import type { RouteFn } from "@/mock/router";
import { effectiveScore } from "@/mock/serialize";
import { iso } from "@/mock/time";
import { apiError, audit, badRequest, file, json, list, matchesText, notFound, paginate, sortBy, str, toCsv } from "@/mock/util";

const STATUSES: FindingStatus[] = ["open", "in_review", "confirmed", "false_positive", "accepted"];

function filterFindings(db: MockDB, q: URLSearchParams): Finding[] {
  const text = q.get("q");
  const cats = list(q, "category");
  const changes = list(q, "change");
  const statuses = list(q, "status");
  const tags = list(q, "tag");
  const minScore = q.get("min_score") ? Number(q.get("min_score")) : null;
  const host = q.get("host_id");
  const ids = list(q, "ids");
  return db.findings.filter(
    (f) =>
      (!ids.length || ids.includes(f.id)) &&
      (!cats.length || cats.includes(f.category)) &&
      (!changes.length || changes.includes(f.change)) &&
      (!statuses.length || statuses.includes(f.status)) &&
      (!tags.length || tags.some((t) => f.tags.includes(t))) &&
      (minScore === null || effectiveScore(f) >= minScore) &&
      (!host || f.host_id === host) &&
      matchesText(text, f.title, f.ip, f.hostname, f.service_label, ...f.technologies, ...f.tags),
  );
}

const getters = {
  score: (f: Finding) => effectiveScore(f),
  ip: (f: Finding) => f.ip.split(".").reduce((a, p) => a * 256 + Number(p), 0),
  title: (f: Finding) => f.title,
  category: (f: Finding) => f.category,
  status: (f: Finding) => STATUSES.indexOf(f.status),
  confidence: (f: Finding) => f.confidence,
  last_seen: (f: Finding) => f.last_seen,
  first_seen: (f: Finding) => f.first_seen,
  change: (f: Finding) => ["new", "changed", "unstable", "gone", "unchanged"].indexOf(f.change),
};

function applyFindingPatch(f: Finding, patch: FindingPatch, by: string) {
  const labels: Record<keyof FindingPatch, string> = {
    status: "Status",
    score_override: "Priorytet (ręcznie)",
    assignee: "Przypisano",
    tags: "Tagi",
    notes: "Notatki",
  };
  const changes = [];
  for (const key of Object.keys(labels) as (keyof FindingPatch)[]) {
    if (!(key in patch)) continue;
    const before = f[key];
    const after = patch[key];
    if (JSON.stringify(before) === JSON.stringify(after)) continue;
    (f as unknown as Record<string, unknown>)[key] = after;
    f.manual_overrides[key] = { value: after, scanner_value: f.manual_overrides[key]?.scanner_value ?? before, by, at: iso(Date.now()) };
    const fmt = (v: unknown) => (key === "status" ? FINDING_STATUS_LABEL[v as FindingStatus] : str(v));
    changes.push({ field: key, label: labels[key], before: fmt(before), after: fmt(after) });
  }
  return changes;
}

export function findingRoutes(route: RouteFn) {
  route("GET", "/findings", "findings:read", (ctx) => {
    const items = sortBy(filterFindings(ctx.db, ctx.query), ctx.query.get("sort") ?? "-score,change", getters);
    return json(paginate(items, ctx.query, 25));
  });

  route("GET", "/findings/export", "findings:export", (ctx) => {
    const format = ctx.query.get("format") === "csv" ? "csv" : "json";
    const items = sortBy(filterFindings(ctx.db, ctx.query), "-score", getters);
    audit(ctx.db, ctx.user, "export", "finding", `znaleziska.${format}`, `Pobrano raport znalezisk (${format.toUpperCase()}, ${items.length} wierszy)`);
    if (format === "csv") {
      const rows = items.map((f) => ({
        id: f.id,
        title: f.title,
        category: f.category,
        ip: f.ip,
        hostname: f.hostname,
        port: f.port,
        service: f.service_label,
        technologies: f.technologies,
        change: f.change,
        status: f.status,
        score: effectiveScore(f),
        confidence: f.confidence,
        first_seen: f.first_seen,
        last_seen: f.last_seen,
        assignee: f.assignee,
        tags: f.tags,
        notes: f.notes,
      }));
      return file(
        toCsv(rows, ["id", "title", "category", "ip", "hostname", "port", "service", "technologies", "change", "status", "score", "confidence", "first_seen", "last_seen", "assignee", "tags", "notes"]),
        "znaleziska.csv",
        "text/csv",
      );
    }
    return file(JSON.stringify({ generated_at: iso(Date.now()), findings: items }, null, 2), "znaleziska.json", "application/json");
  });

  route("GET", "/findings/:id", "findings:read", (ctx) => {
    const f = ctx.db.findings.find((x) => x.id === ctx.params.id);
    return f ? json(f) : notFound("Znalezisko");
  });

  route("PATCH", "/findings/:id", "findings:update", async (ctx) => {
    const f = ctx.db.findings.find((x) => x.id === ctx.params.id);
    if (!f) return notFound("Znalezisko");
    const patch = await ctx.body<FindingPatch>();
    if (patch.status && !STATUSES.includes(patch.status)) return badRequest("Nieznany status.", { status: STATUSES.join(", ") });
    if (patch.score_override !== undefined && patch.score_override !== null && (patch.score_override < 0 || patch.score_override > 100))
      return badRequest("Priorytet musi mieścić się w zakresie 0–100.", { score_override: "0–100" });
    const changes = applyFindingPatch(f, patch, ctx.user!.name);
    if (changes.length) audit(ctx.db, ctx.user, "update", "finding", `${f.title} (${f.ip})`, "Edytowano znalezisko", changes, f.id);
    return json(f);
  });

  route("POST", "/findings/bulk", "findings:update", async (ctx) => {
    const body = await ctx.body<BulkRequest>();
    const ids = new Set(body.ids ?? []);
    let affected = 0;
    for (const f of ctx.db.findings) {
      if (!ids.has(f.id)) continue;
      const p = body.payload ?? {};
      if (body.action === "set_status" && STATUSES.includes(p.status as FindingStatus)) applyFindingPatch(f, { status: p.status as FindingStatus }, ctx.user!.name);
      else if (body.action === "tag" && p.tag) applyFindingPatch(f, { tags: Array.from(new Set([...f.tags, String(p.tag)])) }, ctx.user!.name);
      else if (body.action === "untag") applyFindingPatch(f, { tags: f.tags.filter((t) => t !== p.tag) }, ctx.user!.name);
      else if (body.action === "assign") applyFindingPatch(f, { assignee: (p.assignee as string) ?? null }, ctx.user!.name);
      else continue;
      affected++;
    }
    audit(ctx.db, ctx.user, "update", "finding", `${affected} znalezisk`, `Operacja zbiorcza „${body.action}” na ${affected} znaleziskach`);
    return json({ affected });
  });

  route("POST", "/findings/defectdojo", "findings:defectdojo", async (ctx) => {
    const db = ctx.db;
    if (!db.defectdojo.enabled || !db.defectdojo.api_token_set)
      return apiError(409, "conflict", "Integracja z DefectDojo jest wyłączona. Skonfiguruj ją w Administracja → Integracje.");
    const body = await ctx.body<DefectDojoExportRequest>();
    const items = db.findings.filter((f) => body.ids?.includes(f.id));
    if (!items.length) return badRequest("Zaznacz co najmniej jedno znalezisko.");
    const at = iso(Date.now());
    const links: DefectDojoExportResult["links"] = [];
    for (const f of items) {
      db.seq += 1;
      const ddId = f.defectdojo?.finding_id ?? 5000 + db.seq;
      f.defectdojo = { exported_at: at, finding_id: ddId, url: `${db.defectdojo.url}/finding/${ddId}` };
      links.push({ finding_id: f.id, url: f.defectdojo.url });
    }
    db.seq += 1;
    const exportId = `dd-${db.seq}`;
    db.ddExports.unshift({
      id: exportId,
      at,
      by: ctx.user!.name,
      count: items.length,
      as: body.as === "evidence" ? "evidence" : "finding",
      status: "success",
      message:
        body.as === "evidence"
          ? `Dodano ${items.length} załączników (evidence) do „${db.defectdojo.engagement_name}”`
          : `Utworzono ${items.length} findingów (severity: Info) w „${db.defectdojo.engagement_name}”`,
    });
    audit(db, ctx.user, "defectdojo_export", "finding", `${items.length} znalezisk`, `Wysłano ${items.length} znalezisk do DefectDojo (${body.as === "evidence" ? "evidence" : "finding informacyjny"})`);
    const res: DefectDojoExportResult = { exported: items.length, failed: 0, export_id: exportId, links };
    return json(res);
  });
}
