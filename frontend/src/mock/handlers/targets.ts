import Papa from "papaparse";
import type {
  BulkRequest,
  Criticality,
  ImportReport,
  ImportRowReport,
  Target,
  TargetCreateRequest,
  TargetCreateResult,
  TargetInput,
  TargetPatch,
} from "@/lib/api/types";
import { CRITICALITY_LABEL } from "@/lib/labels";
import { checkTarget } from "@/lib/net";
import { nextId, type MockDB } from "@/mock/db";
import type { RouteFn } from "@/mock/router";
import { iso } from "@/mock/time";
import {
  audit,
  badRequest,
  file,
  json,
  list,
  matchesText,
  notFound,
  paginate,
  sortBy,
  str,
  toCsv,
} from "@/mock/util";

const CRIT_ALIASES: Record<string, Criticality> = {
  low: "low",
  niska: "low",
  medium: "medium",
  srednia: "medium",
  średnia: "medium",
  high: "high",
  wysoka: "high",
  critical: "critical",
  krytyczna: "critical",
};

export function normCriticality(v: unknown): Criticality {
  return CRIT_ALIASES[String(v ?? "").trim().toLowerCase()] ?? "medium";
}

function activeHostsFor(db: MockDB, t: Pick<Target, "type" | "value">): number {
  if (t.type === "domain") return db.hosts.some((h) => h.responded && h.hostnames.includes(t.value)) ? 1 : 0;
  const c = checkTarget(t.value);
  if (!c.ok) return 0;
  const [ip, pfx] = t.value.split("/");
  const p = ip.split(".").map(Number);
  if (p[0] !== 10 || p[1] !== 0) return 0;
  const first = p[2] * 256 + p[3];
  const size = pfx ? 2 ** (32 - Number(pfx)) : 1;
  let n = 0;
  for (const h of db.hosts) if (h.responded && h.off >= first && h.off < first + size) n++;
  return n;
}

function createTarget(db: MockDB, input: TargetInput, source: "manual" | "import", by: string): Target {
  const c = checkTarget(input.value);
  const now = iso(Date.now());
  const t: Target = {
    id: nextId(db, "t"),
    value: c.value!,
    type: c.type!,
    address_count: c.address_count!,
    name: input.name ?? null,
    owner: input.owner ?? null,
    criticality: input.criticality ?? "medium",
    tags: input.tags ?? [],
    notes: input.notes ?? null,
    excluded: Boolean(input.excluded),
    source,
    active_hosts: 0,
    last_scanned_at: null,
    created_at: now,
    updated_at: now,
    updated_by: by,
  };
  t.active_hosts = activeHostsFor(db, t);
  return t;
}

function applyPatch(t: Target, patch: TargetPatch, by: string) {
  const changes: { field: string; label: string; before: string | null; after: string | null }[] = [];
  const labels: Record<string, string> = {
    name: "Nazwa",
    owner: "Właściciel",
    criticality: "Krytyczność",
    tags: "Tagi",
    notes: "Notatki",
    excluded: "Wykluczony",
  };
  for (const key of Object.keys(labels) as (keyof TargetPatch)[]) {
    if (!(key in patch)) continue;
    const before = t[key as keyof Target];
    const after = patch[key];
    if (JSON.stringify(before) === JSON.stringify(after)) continue;
    const fmt = (v: unknown) =>
      key === "criticality" ? CRITICALITY_LABEL[v as Criticality] : key === "excluded" ? (v ? "tak" : "nie") : str(v);
    changes.push({ field: key, label: labels[key], before: fmt(before), after: fmt(after) });
    (t as unknown as Record<string, unknown>)[key] = after;
  }
  if (changes.length) {
    t.updated_at = iso(Date.now());
    t.updated_by = by;
  }
  return changes;
}

function parseRows(text: string, format: "csv" | "json"): { rows: Record<string, unknown>[]; error?: string } {
  if (format === "json") {
    try {
      const data = JSON.parse(text);
      const arr = Array.isArray(data) ? data : Array.isArray(data?.targets) ? data.targets : null;
      if (!arr) return { rows: [], error: "Oczekiwano tablicy obiektów lub obiektu z polem „targets”." };
      return { rows: arr.map((x: unknown) => (typeof x === "string" ? { value: x } : (x as Record<string, unknown>))) };
    } catch (e) {
      return { rows: [], error: `Niepoprawny JSON: ${(e as Error).message}` };
    }
  }
  const res = Papa.parse<Record<string, string>>(text.trim(), { header: true, skipEmptyLines: true, transformHeader: (h) => h.trim().toLowerCase() });
  if (!res.meta.fields?.length) return { rows: [], error: "Plik CSV nie ma wiersza nagłówka." };
  return { rows: res.data };
}

function rowToInput(r: Record<string, unknown>): TargetInput {
  const value = String(r.value ?? r.target ?? r.cel ?? r.ip ?? r.cidr ?? r.domain ?? r.domena ?? "").trim();
  const tags = Array.isArray(r.tags)
    ? (r.tags as unknown[]).map(String)
    : String(r.tags ?? r.tagi ?? "")
        .split(/[|;]/)
        .map((s) => s.trim())
        .filter(Boolean);
  const excludedRaw = String(r.excluded ?? r.wykluczony ?? "").toLowerCase();
  return {
    value,
    name: (r.name ?? r.nazwa ?? null) as string | null,
    owner: (r.owner ?? r.wlasciciel ?? r["właściciel"] ?? null) as string | null,
    criticality: normCriticality(r.criticality ?? r.krytycznosc ?? r["krytyczność"]),
    tags,
    notes: (r.notes ?? r.notatki ?? null) as string | null,
    excluded: ["true", "1", "tak", "yes"].includes(excludedRaw) || r.excluded === true,
  };
}

export function targetRoutes(route: RouteFn) {
  route("GET", "/targets", "targets:read", (ctx) => {
    const q = ctx.query.get("q");
    const types = list(ctx.query, "type");
    const tags = list(ctx.query, "tag");
    const crit = list(ctx.query, "criticality");
    const excluded = ctx.query.get("excluded");
    let items = ctx.db.targets.filter(
      (t) =>
        matchesText(q, t.value, t.name, t.owner, t.notes, ...t.tags) &&
        (!types.length || types.includes(t.type)) &&
        (!tags.length || tags.some((x) => t.tags.includes(x))) &&
        (!crit.length || crit.includes(t.criticality)) &&
        (excluded === null || excluded === "" || String(t.excluded) === excluded),
    );
    items = sortBy(items, ctx.query.get("sort") ?? "-criticality_rank,value", {
      value: (t) => t.value,
      name: (t) => t.name,
      owner: (t) => t.owner,
      type: (t) => t.type,
      address_count: (t) => t.address_count,
      active_hosts: (t) => t.active_hosts,
      criticality_rank: (t) => ["low", "medium", "high", "critical"].indexOf(t.criticality),
      updated_at: (t) => t.updated_at,
      last_scanned_at: (t) => t.last_scanned_at,
    });
    return json(paginate(items, ctx.query, 50));
  });

  route("GET", "/targets/export", "targets:export", (ctx) => {
    const format = ctx.query.get("format") === "csv" ? "csv" : "json";
    const rows = ctx.db.targets.map((t) => ({
      value: t.value,
      type: t.type,
      name: t.name,
      owner: t.owner,
      criticality: t.criticality,
      tags: t.tags,
      notes: t.notes,
      excluded: t.excluded,
      address_count: t.address_count,
    }));
    audit(ctx.db, ctx.user, "export", "target", `cele.${format}`, `Wyeksportowano ${rows.length} celów (${format.toUpperCase()})`);
    return format === "csv"
      ? file(toCsv(rows, ["value", "type", "name", "owner", "criticality", "tags", "notes", "excluded", "address_count"]), "cele.csv", "text/csv")
      : file(JSON.stringify({ targets: rows }, null, 2), "cele.json", "application/json");
  });

  route("GET", "/targets/:id", "targets:read", (ctx) => {
    const t = ctx.db.targets.find((x) => x.id === ctx.params.id);
    return t ? json(t) : notFound("Cel");
  });

  route("POST", "/targets", "targets:create", async (ctx) => {
    const body = await ctx.body<TargetCreateRequest>();
    if (!Array.isArray(body.items) || !body.items.length) return badRequest("Podaj co najmniej jeden cel.");
    const res: TargetCreateResult = { created: [], updated: [], skipped: [], errors: [] };
    const seen = new Set<string>();
    for (const item of body.items) {
      const c = checkTarget(String(item.value ?? ""));
      if (!c.ok) {
        res.errors.push({ value: String(item.value ?? ""), error: c.error! });
        continue;
      }
      if (seen.has(c.value!)) {
        res.skipped.push({ value: c.value!, reason: "Powtórzony w tym samym zgłoszeniu" });
        continue;
      }
      seen.add(c.value!);
      const existing = ctx.db.targets.find((t) => t.value === c.value);
      if (existing) {
        if (body.on_conflict === "update") {
          applyPatch(existing, { ...item, value: undefined } as TargetPatch, ctx.user!.name);
          res.updated.push(existing);
        } else res.skipped.push({ value: c.value!, reason: "Cel już istnieje" });
        continue;
      }
      const t = createTarget(ctx.db, { ...item, value: c.value! }, "manual", ctx.user!.name);
      ctx.db.targets.push(t);
      res.created.push(t);
    }
    if (res.created.length || res.updated.length)
      audit(ctx.db, ctx.user, "create", "target", res.created.map((t) => t.value).slice(0, 3).join(", ") || null, `Dodano ${res.created.length} celów ręcznie${res.updated.length ? `, zaktualizowano ${res.updated.length}` : ""}`);
    return json(res, { status: res.created.length ? 201 : 200 });
  });

  route("PATCH", "/targets/:id", "targets:update", async (ctx) => {
    const t = ctx.db.targets.find((x) => x.id === ctx.params.id);
    if (!t) return notFound("Cel");
    const patch = await ctx.body<TargetPatch>();
    if (patch.criticality && !["low", "medium", "high", "critical"].includes(patch.criticality))
      return badRequest("Nieprawidłowa krytyczność.", { criticality: "Dozwolone: low, medium, high, critical" });
    const changes = applyPatch(t, patch, ctx.user!.name);
    if (changes.length) audit(ctx.db, ctx.user, "update", "target", t.value, "Edytowano cel", changes, t.id);
    return json(t);
  });

  route("DELETE", "/targets/:id", "targets:delete", (ctx) => {
    const i = ctx.db.targets.findIndex((x) => x.id === ctx.params.id);
    if (i < 0) return notFound("Cel");
    const [t] = ctx.db.targets.splice(i, 1);
    audit(ctx.db, ctx.user, "delete", "target", t.value, "Usunięto cel", [], t.id);
    return new Response(null, { status: 204 });
  });

  route("POST", "/targets/bulk", "targets:update", async (ctx) => {
    const body = await ctx.body<BulkRequest>();
    const ids = new Set(body.ids ?? []);
    if (body.action === "delete" && !ctx.perms.has("targets:delete"))
      return json({ error: { code: "forbidden", message: "Twoja rola nie pozwala usuwać celów.", required_permission: "targets:delete" } }, { status: 403 });
    let affected = 0;
    if (body.action === "delete") {
      const before = ctx.db.targets.length;
      ctx.db.targets = ctx.db.targets.filter((t) => !ids.has(t.id));
      affected = before - ctx.db.targets.length;
    } else {
      for (const t of ctx.db.targets) {
        if (!ids.has(t.id)) continue;
        const p = body.payload ?? {};
        if (body.action === "tag" && p.tag && !t.tags.includes(String(p.tag))) t.tags = [...t.tags, String(p.tag)];
        else if (body.action === "untag") t.tags = t.tags.filter((x) => x !== p.tag);
        else if (body.action === "exclude") t.excluded = true;
        else if (body.action === "include") t.excluded = false;
        else if (body.action === "set_owner") t.owner = (p.owner as string) ?? null;
        else if (body.action === "set_criticality") t.criticality = normCriticality(p.criticality);
        else continue;
        t.updated_at = iso(Date.now());
        t.updated_by = ctx.user!.name;
        affected++;
      }
    }
    audit(ctx.db, ctx.user, body.action === "delete" ? "delete" : "update", "target", `${affected} celów`, `Operacja zbiorcza „${body.action}” na ${affected} celach`);
    return json({ affected });
  });

  route("POST", "/targets/import", "targets:import", async (ctx) => {
    const form = await ctx.form();
    const f = form.get("file");
    if (!(f instanceof Blob)) return badRequest("Dołącz plik w polu „file”.");
    const name = f instanceof File ? f.name.toLowerCase() : "";
    const text = await f.text();
    const fmtField = String(form.get("format") ?? "");
    const format: "csv" | "json" =
      fmtField === "csv" || fmtField === "json" ? fmtField : name.endsWith(".json") || /^\s*[[{]/.test(text) ? "json" : "csv";
    const dryRun = String(form.get("dry_run") ?? "false") === "true";
    const onConflict = String(form.get("on_conflict") ?? "skip") === "update" ? "update" : "skip";
    const { rows, error } = parseRows(text, format);
    if (error) return badRequest(error);
    const report: ImportReport = { format, dry_run: dryRun, total_rows: rows.length, valid: 0, invalid: 0, duplicates: 0, created: 0, updated: 0, rows: [] };
    const seen = new Set<string>();
    const toCreate: TargetInput[] = [];
    rows.forEach((r, idx) => {
      const input = rowToInput(r);
      const c = checkTarget(input.value);
      const row: ImportRowReport = { row: idx + 2 - (format === "json" ? 1 : 0), value: input.value, status: "ok" };
      if (!c.ok) {
        row.status = "invalid";
        row.error = c.error;
        report.invalid++;
      } else {
        row.type = c.type;
        row.address_count = c.address_count;
        const dupInFile = seen.has(c.value!);
        const existing = ctx.db.targets.find((t) => t.value === c.value);
        seen.add(c.value!);
        if (dupInFile || (existing && onConflict === "skip")) {
          row.status = "duplicate";
          row.error = dupInFile ? "Powtórzony w pliku" : "Cel już istnieje";
          report.duplicates++;
        } else {
          report.valid++;
          if (existing) {
            if (!dryRun) applyPatch(existing, { ...input, value: undefined } as TargetPatch, ctx.user!.name);
            report.updated++;
          } else toCreate.push({ ...input, value: c.value! });
        }
      }
      if (report.rows.length < 500) report.rows.push(row);
    });
    if (!dryRun) {
      for (const input of toCreate) ctx.db.targets.push(createTarget(ctx.db, input, "import", ctx.user!.name));
      report.created = toCreate.length;
      audit(ctx.db, ctx.user, "import", "target", name || "plik", `Zaimportowano cele z pliku ${name || ""} (${report.created} nowych, ${report.updated} zaktualizowanych, ${report.invalid} błędnych)`);
    } else report.created = toCreate.length;
    return json(report);
  });
}
