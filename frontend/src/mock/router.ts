/**
 * Tiny router for the mock backend: method + path pattern -> handler,
 * with session lookup and RBAC enforcement (403 + required_permission),
 * exactly like the Rust backend is expected to behave.
 */
import type { Permission, User } from "@/lib/api/types";
import { getDB, type MockDB } from "@/mock/db";
import { apiError, sleep } from "@/mock/util";

export interface Ctx {
  req: Request;
  db: MockDB;
  params: Record<string, string>;
  query: URLSearchParams;
  user: (User & { password: string }) | null;
  perms: Set<Permission>;
  body<T>(): Promise<T>;
  form(): Promise<FormData>;
}

export type Handler = (ctx: Ctx) => Response | Promise<Response>;

interface Route {
  method: string;
  pattern: string;
  /** undefined = any logged-in user, null = public */
  perm: Permission | null | undefined;
  handler: Handler;
  re: RegExp;
  keys: string[];
}

const routes: Route[] = [];

export type RouteFn = (method: string, pattern: string, perm: Permission | null | undefined, handler: Handler) => void;

export const route: RouteFn = (method, pattern, perm, handler) => {
  const keys: string[] = [];
  const re = new RegExp(
    `^${pattern.replace(/\/:([a-zA-Z_]+)/g, (_, k: string) => {
      keys.push(k);
      return "/([^/]+)";
    })}$`,
  );
  routes.push({ method, pattern, perm, handler, re, keys });
};

export const SESSION_COOKIE = "asi_session";

function sessionUser(db: MockDB, req: Request) {
  const cookie = req.headers.get("cookie") ?? "";
  const m = new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`).exec(cookie);
  if (!m) return null;
  // Mock token: "mock.<userId>.<random>" — stateless so it survives dev-server reloads.
  const [, userId] = decodeURIComponent(m[1]).split(".");
  const user = db.users.find((u) => u.id === userId && u.active);
  return user ?? null;
}

let registered = false;

export async function handleMock(req: Request, subpath: string): Promise<Response> {
  if (!registered) {
    registered = true;
    const { registerAll } = await import("@/mock/handlers");
    registerAll(route);
  }
  const db = getDB();
  const url = new URL(req.url);
  const candidates = routes.filter((r) => r.re.test(subpath));
  if (!candidates.length) return apiError(404, "not_found", `Nieznany endpoint: ${req.method} /api/v1${subpath}`);
  const r = candidates.find((c) => c.method === req.method);
  if (!r) return apiError(405, "method_not_allowed", `Metoda ${req.method} nie jest obsługiwana dla /api/v1${subpath}`);

  const params: Record<string, string> = {};
  const m = r.re.exec(subpath)!;
  r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));

  const user = sessionUser(db, req);
  const role = user ? db.roles.find((x) => x.id === user.role_id) : null;
  const perms = new Set<Permission>(role?.permissions ?? []);

  if (r.perm !== null && !user) return apiError(401, "unauthorized", "Sesja wygasła lub nie jesteś zalogowany.");
  if (r.perm && !perms.has(r.perm))
    return apiError(403, "forbidden", `Twoja rola (${role?.name ?? "brak"}) nie ma uprawnienia do tej operacji.`, {
      required_permission: r.perm,
    });

  const latency = Number(process.env.ASI_MOCK_LATENCY_MS ?? 140);
  if (latency > 0 && !subpath.endsWith("/events")) await sleep(latency * (0.5 + Math.random()));

  let bodyCache: unknown;
  const ctx: Ctx = {
    req,
    db,
    params,
    query: url.searchParams,
    user,
    perms,
    async body<T>() {
      if (bodyCache === undefined) bodyCache = await req.json().catch(() => ({}));
      return bodyCache as T;
    },
    form: () => req.formData(),
  };
  try {
    return await r.handler(ctx);
  } catch (e) {
    console.error("[mock]", req.method, subpath, e);
    return apiError(500, "internal", `Błąd mock-serwera: ${e instanceof Error ? e.message : String(e)}`);
  }
}
