import type { AuditEvent, Paginated, Permission, Session, User } from "@/lib/api/types";
import type { MockDB } from "@/mock/db";
import { iso } from "@/mock/time";

export type Json = Record<string, unknown> | unknown[] | string | number | boolean | null;

export function json(data: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: { "Content-Type": "application/json; charset=utf-8", ...(init.headers ?? {}) },
  });
}

export function apiError(
  status: number,
  code: string,
  message: string,
  extra: { required_permission?: Permission; fields?: Record<string, string> } = {},
): Response {
  return json({ error: { code, message, ...extra } }, { status });
}

export const notFound = (what = "Zasób") => apiError(404, "not_found", `${what} nie istnieje.`);
export const badRequest = (message: string, fields?: Record<string, string>) =>
  apiError(fields ? 422 : 400, fields ? "validation" : "bad_request", message, { fields });

export function file(content: string, filename: string, contentType: string): Response {
  return new Response(content, {
    headers: {
      "Content-Type": `${contentType}; charset=utf-8`,
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}

export function paginate<T>(items: T[], q: URLSearchParams, defaultSize = 25): Paginated<T> {
  const page = Math.max(1, Number(q.get("page") ?? 1) || 1);
  const pageSize = Math.min(500, Math.max(1, Number(q.get("page_size") ?? defaultSize) || defaultSize));
  return { items: items.slice((page - 1) * pageSize, page * pageSize), page, page_size: pageSize, total: items.length };
}

/** sort=-score,ip  (prefix "-" = descending). */
export function sortBy<T>(items: T[], sort: string | null, getters: Record<string, (x: T) => unknown>): T[] {
  if (!sort) return items;
  const keys = sort.split(",").filter(Boolean);
  const out = items.slice();
  out.sort((a, b) => {
    for (const k of keys) {
      const desc = k.startsWith("-");
      const g = getters[desc ? k.slice(1) : k];
      if (!g) continue;
      const va = g(a);
      const vb = g(b);
      let c = 0;
      if (typeof va === "number" && typeof vb === "number") c = va - vb;
      else c = String(va ?? "").localeCompare(String(vb ?? ""), "pl", { numeric: true });
      if (c !== 0) return desc ? -c : c;
    }
    return 0;
  });
  return out;
}

export function list(q: URLSearchParams, key: string): string[] {
  const v = q.get(key);
  return v ? v.split(",").map((s) => s.trim()).filter(Boolean) : [];
}

export function matchesText(q: string | null, ...values: (string | null | undefined)[]): boolean {
  if (!q) return true;
  const needle = q.toLowerCase().trim();
  if (!needle) return true;
  return values.some((v) => v?.toLowerCase().includes(needle));
}

export function audit(
  db: MockDB,
  user: User | null,
  action: AuditEvent["action"],
  resource: string,
  label: string | null,
  summary: string,
  changes: AuditEvent["changes"] = [],
  resourceId: string | null = null,
) {
  db.seq += 1;
  db.audit.unshift({
    id: `a-${db.seq}`,
    at: iso(Date.now()),
    actor: user ? { id: user.id, name: user.name, role: user.role_name } : { id: "system", name: "System", role: "System" },
    action,
    resource,
    resource_id: resourceId,
    resource_label: label,
    summary,
    changes,
  });
  if (db.audit.length > 2000) db.audit.length = 2000;
}

export function sessionFor(db: MockDB, user: User): Session {
  const role = db.roles.find((r) => r.id === user.role_id)!;
  return { user: publicUser(user), role, permissions: role.permissions };
}

export function publicUser(u: User & { password?: string }): User {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, ...rest } = u as User & { password?: string };
  return rest;
}

export function str(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (Array.isArray(v)) return v.join(", ");
  return String(v);
}

export function toCsv(rows: Record<string, unknown>[], columns: string[]): string {
  const esc = (v: unknown) => {
    const s = v === null || v === undefined ? "" : Array.isArray(v) ? v.join("|") : String(v);
    return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [columns.join(","), ...rows.map((r) => columns.map((c) => esc(r[c])).join(","))].join("\n");
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
