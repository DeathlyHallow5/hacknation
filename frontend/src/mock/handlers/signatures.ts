import YAML from "yaml";
import type { Signature, SignatureCondition, SignatureInput, SignatureTestRequest, SignatureTestResult } from "@/lib/api/types";
import { WEB_APPS } from "@/mock/catalog";
import { nextId, type MockDB } from "@/mock/db";
import { buildHttp } from "@/mock/http";
import type { RouteFn } from "@/mock/router";
import { findHostByService } from "@/mock/serialize";
import { iso } from "@/mock/time";
import { apiError, audit, badRequest, file, json, list, matchesText, notFound } from "@/mock/util";

/* ------------------------------------------------------------------ */
/* Safety: signatures detect, they never attack                        */
/* ------------------------------------------------------------------ */

const FORBIDDEN_PATH = /(\.\.|%2e%2e|[\s'"<>;`]|\bunion\b|\bselect\b|\bor\s+1=1|\bsleep\(|\$\{|\{\{)/i;
const CREDENTIAL_PARAM = /(pass(word|wd)?|pwd|token|login|user(name)?|auth|session)=/i;

export function signatureSafety(input: Partial<SignatureInput>): string[] {
  const issues: string[] = [];
  if (!input.name || input.name.trim().length < 3) issues.push("Nazwa sygnatury musi mieć co najmniej 3 znaki.");
  const conds = input.match?.conditions ?? [];
  if (!conds.length) issues.push("Dodaj co najmniej jeden warunek.");
  if (conds.length > 10) issues.push("Sygnatura może mieć najwyżej 10 warunków.");
  conds.forEach((c, i) => {
    const n = i + 1;
    if ((c.type === "header" || c.type === "cookie") && !/^[A-Za-z0-9_.\-]+$/.test(c.name ?? ""))
      issues.push(`Warunek ${n}: podaj poprawną nazwę ${c.type === "header" ? "nagłówka" : "ciasteczka"}.`);
    if (c.type === "path") {
      const p = c.path ?? "";
      if (!p.startsWith("/")) issues.push(`Warunek ${n}: ścieżka musi zaczynać się od „/”.`);
      if (p.includes("?")) issues.push(`Warunek ${n}: ścieżka nie może zawierać parametrów — sygnatury wykonują tylko proste żądania GET.`);
      if (FORBIDDEN_PATH.test(p)) issues.push(`Warunek ${n}: ścieżka zawiera znaki typowe dla ataku (np. „..”, cudzysłów, SQL) — niedozwolone.`);
      if (CREDENTIAL_PARAM.test(p)) issues.push(`Warunek ${n}: ścieżka nie może przekazywać danych logowania.`);
      if (p.length > 200) issues.push(`Warunek ${n}: ścieżka jest za długa (maks. 200 znaków).`);
      if (c.expect_status !== null && c.expect_status !== undefined && (c.expect_status < 100 || c.expect_status > 599))
        issues.push(`Warunek ${n}: kod odpowiedzi musi być z zakresu 100–599.`);
    }
    if (c.type === "favicon_hash" && !/^-?\d+$/.test(String(c.value ?? ""))) issues.push(`Warunek ${n}: hash favicony musi być liczbą całkowitą (mmh3).`);
    if ((c.value ?? "").length > 300) issues.push(`Warunek ${n}: wartość jest za długa (maks. 300 znaków).`);
    for (const re of [c.op === "regex" ? c.value : null, c.extract]) {
      if (!re) continue;
      try {
        new RegExp(re, "i");
      } catch {
        issues.push(`Warunek ${n}: niepoprawne wyrażenie regularne.`);
      }
    }
    if (c.op !== "exists" && c.type !== "path" && !(c.value ?? "").trim() && c.type !== "version")
      issues.push(`Warunek ${n}: podaj wartość do porównania.`);
  });
  return issues;
}

/* ------------------------------------------------------------------ */
/* Evaluation                                                          */
/* ------------------------------------------------------------------ */

interface Probe {
  label: string;
  status: number;
  headers: { name: string; value: string }[];
  cookies: string[];
  title: string;
  body: string;
  favicon: number | null;
  paths: Record<string, { status: number; body: string }>;
}

function probeFromService(db: MockDB, serviceId: string): Probe | null {
  const r = findHostByService(db, serviceId);
  if (!r) return null;
  const http = buildHttp(r.h, r.s, db.seededAt, Date.now());
  if (!http) return null;
  const app = WEB_APPS[r.s.web!];
  const paths: Probe["paths"] = { "/": { status: http.status_code, body: http.body_excerpt ?? "" } };
  if (app.admin) paths[app.admin.path] = { status: /tomcat|cisco/.test(app.key) ? 401 : 200, body: `<title>${app.admin.title}</title> ${http.body_excerpt ?? ""}` };
  if (app.redirectPath) paths[app.redirectPath.split("?")[0]] = { status: 200, body: http.body_excerpt ?? "" };
  if (app.key === "wordpress") paths["/wp-login.php"] = { status: 200, body: "<title>Logowanie ‹ WordPress</title>" };
  return {
    label: `${r.h.ip}:${r.s.port} (${app.label})`,
    status: http.status_code,
    headers: [...http.headers.map((h) => ({ name: h.name, value: h.value })), ...http.cookies.map((c) => ({ name: "Set-Cookie", value: `${c.name}=${c.value_masked}` }))],
    cookies: http.cookies.map((c) => c.name),
    title: http.title ?? "",
    body: `${http.title ? `<title>${http.title}</title>` : ""} ${http.body_excerpt ?? ""}`,
    favicon: http.favicon_hash,
    paths,
  };
}

function probeFromRaw(raw: { status_code: number; headers: string; body: string; favicon_hash?: number | null }): Probe {
  const headers = raw.headers
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.includes(":") && !/^HTTP\//i.test(l))
    .map((l) => ({ name: l.slice(0, l.indexOf(":")).trim(), value: l.slice(l.indexOf(":") + 1).trim() }));
  const cookies = headers.filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value.split("=")[0].trim());
  const title = /<title[^>]*>([^<]*)<\/title>/i.exec(raw.body)?.[1]?.trim() ?? "";
  return {
    label: "wklejona odpowiedź HTTP",
    status: raw.status_code,
    headers,
    cookies,
    title,
    body: raw.body,
    favicon: raw.favicon_hash ?? null,
    paths: { "/": { status: raw.status_code, body: raw.body } },
  };
}

function compare(op: SignatureCondition["op"], subject: string | null, value: string | null | undefined): string | null {
  if (subject === null) return null;
  const v = value ?? "";
  if (op === "exists") return subject;
  if (op === "equals") return subject.toLowerCase() === v.toLowerCase() ? subject : null;
  if (op === "contains") {
    const i = subject.toLowerCase().indexOf(v.toLowerCase());
    return i >= 0 ? subject.slice(Math.max(0, i - 30), i + v.length + 30) : null;
  }
  try {
    const m = new RegExp(v, "i").exec(subject);
    return m ? m[0] : null;
  } catch {
    return null;
  }
}

export function evaluate(sig: Pick<SignatureInput, "match">, p: Probe) {
  let version: string | null = null;
  const results = sig.match.conditions.map((c, index) => {
    let evidence: string | null = null;
    switch (c.type) {
      case "header": {
        const h = p.headers.find((x) => x.name.toLowerCase() === (c.name ?? "").toLowerCase());
        evidence = h ? compare(c.op, h.value, c.value) : null;
        if (evidence !== null) evidence = `${h!.name}: ${h!.value}`;
        break;
      }
      case "cookie": {
        const name = p.cookies.find((x) => x.toLowerCase() === (c.name ?? "").toLowerCase());
        evidence = name ? compare(c.op === "exists" ? "exists" : c.op, name, c.value) : null;
        if (evidence !== null) evidence = `Set-Cookie: ${name}=…`;
        break;
      }
      case "favicon_hash":
        evidence = p.favicon !== null && String(p.favicon) === String(c.value ?? "").trim() ? `favicon mmh3 = ${p.favicon}` : null;
        break;
      case "html":
        evidence = compare(c.op, p.body, c.value);
        break;
      case "title":
        evidence = compare(c.op, p.title || null, c.value);
        break;
      case "status":
        evidence = compare(c.op === "exists" ? "exists" : c.op, String(p.status), c.value);
        break;
      case "path": {
        const r = p.paths[c.path ?? ""] ?? { status: 404, body: "" };
        const statusOk = c.expect_status ? r.status === c.expect_status : r.status >= 200 && r.status < 400;
        const bodyOk = c.op === "exists" || !c.value ? true : compare(c.op, r.body, c.value) !== null;
        evidence = statusOk && bodyOk ? `GET ${c.path} → ${r.status}` : null;
        break;
      }
      case "version": {
        const text = `${p.headers.map((h) => `${h.name}: ${h.value}`).join("\n")}\n${p.body}`;
        try {
          const m = new RegExp(c.extract || c.value || "", "i").exec(text);
          if (m) {
            version = m[1] ?? m[0];
            evidence = `wersja: ${version}`;
          }
        } catch {
          evidence = null;
        }
        break;
      }
    }
    return { index, matched: evidence !== null, evidence };
  });
  const matched = (sig.match.operator === "or" ? results.some((r) => r.matched) : results.every((r) => r.matched)) && results.length > 0;
  return { matched, conditions: results, extracted_version: version as string | null };
}

function countMatches(db: MockDB, sig: Pick<SignatureInput, "match">): number {
  let n = 0;
  let probed = 0;
  for (const h of db.hosts) {
    if (!h.responded) continue;
    for (const s of h.services) {
      if (!s.web || s.redirectTo) continue;
      if (++probed > 8000) return n;
      const p = probeFromService(db, s.id);
      if (p && evaluate(sig, p).matched) n++;
    }
  }
  return n;
}

function normalize(input: Partial<SignatureInput>): SignatureInput {
  return {
    name: String(input.name ?? "").trim(),
    description: String(input.description ?? ""),
    category: input.category ?? "technology",
    technology: input.technology ?? null,
    score_weight: Math.max(0, Math.min(50, Number(input.score_weight ?? 10))),
    enabled: input.enabled ?? true,
    match: {
      operator: input.match?.operator === "or" ? "or" : "and",
      conditions: (input.match?.conditions ?? []).map((c) => ({
        type: c.type,
        name: c.name ?? null,
        path: c.path ?? null,
        op: c.op ?? "contains",
        value: c.value ?? null,
        expect_status: c.expect_status ?? null,
        extract: c.extract ?? null,
      })),
    },
    tags: input.tags ?? [],
  };
}

export function signatureRoutes(route: RouteFn) {
  route("GET", "/signatures", "signatures:read", (ctx) => {
    const q = ctx.query.get("q");
    const source = ctx.query.get("source");
    const cats = list(ctx.query, "category");
    const enabled = ctx.query.get("enabled");
    return json(
      ctx.db.signatures.filter(
        (s) =>
          matchesText(q, s.name, s.description, s.technology, ...s.tags) &&
          (!source || s.source === source) &&
          (!cats.length || cats.includes(s.category)) &&
          (enabled === null || String(s.enabled) === enabled),
      ),
    );
  });

  route("GET", "/signatures/export", "signatures:read", (ctx) => {
    const format = ctx.query.get("format") === "json" ? "json" : "yaml";
    const data = ctx.db.signatures.map((s) => ({
      name: s.name,
      description: s.description,
      category: s.category,
      technology: s.technology,
      score_weight: s.score_weight,
      enabled: s.enabled,
      tags: s.tags,
      match: s.match,
    }));
    return format === "json"
      ? file(JSON.stringify({ signatures: data }, null, 2), "sygnatury.json", "application/json")
      : file(YAML.stringify({ signatures: data }), "sygnatury.yaml", "application/yaml");
  });

  route("POST", "/signatures/test", "signatures:test", async (ctx) => {
    const body = await ctx.body<SignatureTestRequest>();
    const input = normalize(body.signature ?? {});
    const issues = signatureSafety(input);
    const probe =
      "service_id" in (body.target ?? {})
        ? probeFromService(ctx.db, (body.target as { service_id: string }).service_id)
        : "raw" in (body.target ?? {})
          ? probeFromRaw((body.target as { raw: Parameters<typeof probeFromRaw>[0] }).raw)
          : null;
    if (!probe) return badRequest("Wybierz usługę WWW lub wklej odpowiedź HTTP do testu.");
    const r = evaluate(input, probe);
    const res: SignatureTestResult = { ...r, safety: { ok: issues.length === 0, issues }, target_label: probe.label };
    return json(res);
  });

  route("POST", "/signatures/import", "signatures:create", async (ctx) => {
    const form = await ctx.form();
    const f = form.get("file");
    if (!(f instanceof Blob)) return badRequest("Dołącz plik w polu „file”.");
    let data: unknown;
    try {
      data = YAML.parse(await f.text());
    } catch (e) {
      return badRequest(`Nie udało się odczytać pliku YAML/JSON: ${(e as Error).message}`);
    }
    const arr = (Array.isArray(data) ? data : (data as { signatures?: unknown[] })?.signatures) ?? [];
    let created = 0;
    let updated = 0;
    const errors: string[] = [];
    for (const raw of arr as Partial<SignatureInput>[]) {
      const input = normalize(raw);
      const issues = signatureSafety(input);
      if (issues.length) {
        errors.push(`${input.name || "(bez nazwy)"}: ${issues[0]}`);
        continue;
      }
      const existing = ctx.db.signatures.find((s) => s.source === "custom" && s.name === input.name);
      if (existing) {
        Object.assign(existing, input, { updated_at: iso(Date.now()), version: existing.version + 1 });
        updated++;
      } else {
        ctx.db.signatures.push({ ...input, id: nextId(ctx.db, "sig"), source: "custom", severity: "info", author: ctx.user!.name, created_at: iso(Date.now()), updated_at: iso(Date.now()), matches_last_scan: countMatches(ctx.db, input), version: 1 });
        created++;
      }
    }
    audit(ctx.db, ctx.user, "import", "signature", f instanceof File ? f.name : "plik", `Zaimportowano sygnatury: ${created} nowych, ${updated} zaktualizowanych, ${errors.length} odrzuconych`);
    return json({ created, updated, errors });
  });

  route("GET", "/signatures/:id", "signatures:read", (ctx) => {
    const s = ctx.db.signatures.find((x) => x.id === ctx.params.id);
    return s ? json(s) : notFound("Sygnatura");
  });

  route("POST", "/signatures", "signatures:create", async (ctx) => {
    const input = normalize(await ctx.body<Partial<SignatureInput>>());
    const issues = signatureSafety(input);
    if (issues.length) return apiError(422, "validation", issues[0], { fields: { match: issues.join(" ") } });
    const now = iso(Date.now());
    const sig: Signature = { ...input, id: nextId(ctx.db, "sig"), source: "custom", severity: "info", author: ctx.user!.name, created_at: now, updated_at: now, matches_last_scan: countMatches(ctx.db, input), version: 1 };
    ctx.db.signatures.push(sig);
    audit(ctx.db, ctx.user, "create", "signature", sig.name, "Utworzono sygnaturę własną", [], sig.id);
    return json(sig, { status: 201 });
  });

  route("PATCH", "/signatures/:id", "signatures:update", async (ctx) => {
    const sig = ctx.db.signatures.find((x) => x.id === ctx.params.id);
    if (!sig) return notFound("Sygnatura");
    const patch = await ctx.body<Partial<SignatureInput>>();
    if (sig.source === "builtin" && Object.keys(patch).some((k) => k !== "enabled"))
      return apiError(409, "conflict", "Sygnatury wbudowane można tylko włączać i wyłączać. Utwórz kopię jako sygnaturę własną.");
    const merged = normalize({ ...sig, ...patch, match: patch.match ?? sig.match });
    const issues = signatureSafety(merged);
    if (issues.length) return apiError(422, "validation", issues[0], { fields: { match: issues.join(" ") } });
    const before = sig.enabled;
    Object.assign(sig, merged, { updated_at: iso(Date.now()), version: sig.version + (patch.match ? 1 : 0) });
    if (patch.match) sig.matches_last_scan = countMatches(ctx.db, sig);
    audit(ctx.db, ctx.user, "update", "signature", sig.name, patch.enabled !== undefined && Object.keys(patch).length === 1 ? (sig.enabled ? "Włączono sygnaturę" : "Wyłączono sygnaturę") : "Edytowano sygnaturę", patch.enabled !== undefined ? [{ field: "enabled", label: "Aktywna", before: before ? "tak" : "nie", after: sig.enabled ? "tak" : "nie" }] : [], sig.id);
    return json(sig);
  });

  route("DELETE", "/signatures/:id", "signatures:delete", (ctx) => {
    const sig = ctx.db.signatures.find((x) => x.id === ctx.params.id);
    if (!sig) return notFound("Sygnatura");
    if (sig.source === "builtin") return apiError(409, "conflict", "Sygnatur wbudowanych nie można usuwać — możesz je wyłączyć.");
    ctx.db.signatures = ctx.db.signatures.filter((x) => x.id !== sig.id);
    audit(ctx.db, ctx.user, "delete", "signature", sig.name, "Usunięto sygnaturę własną", [], sig.id);
    return new Response(null, { status: 204 });
  });
}
