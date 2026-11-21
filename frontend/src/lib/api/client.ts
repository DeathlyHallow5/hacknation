import type { ApiErrorBody, Permission } from "@/lib/api/types";
import { toQuery } from "@/lib/utils";

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;
  requiredPermission?: Permission;
  fields?: Record<string, string>;

  constructor(status: number, body: Partial<ApiErrorBody["error"]> | undefined) {
    super(body?.message ?? `Błąd serwera (${status})`);
    this.status = status;
    this.code = body?.code ?? "internal";
    this.requiredPermission = body?.required_permission;
    this.fields = body?.fields;
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  query?: Record<string, unknown>;
  signal?: AbortSignal;
}

function redirectToLogin() {
  if (typeof window === "undefined") return;
  if (window.location.pathname.startsWith("/login")) return;
  const next = encodeURIComponent(window.location.pathname + window.location.search);
  // Full reload on purpose: drop every cached query of the expired session.
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination
  window.location.href = `/login?next=${next}`;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, query, signal } = opts;
  const headers: Record<string, string> = { Accept: "application/json" };
  let payload: BodyInit | undefined;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  const res = await fetch(`${API_BASE}${path}${toQuery(query)}`, {
    method,
    headers,
    body: payload,
    signal,
    credentials: "same-origin",
    cache: "no-store",
  });

  if (res.status === 204) return undefined as T;

  const isJson = res.headers.get("content-type")?.includes("application/json");
  const data = isJson ? await res.json().catch(() => undefined) : undefined;

  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/auth/")) redirectToLogin();
    throw new ApiError(res.status, (data as ApiErrorBody | undefined)?.error);
  }
  return data as T;
}

/** Fetch a file (CSV/JSON export) and return it as a Blob + filename. */
export async function requestFile(path: string, query?: Record<string, unknown>) {
  const res = await fetch(`${API_BASE}${path}${toQuery(query)}`, { credentials: "same-origin", cache: "no-store" });
  if (!res.ok) {
    const data = await res.json().catch(() => undefined);
    throw new ApiError(res.status, (data as ApiErrorBody | undefined)?.error);
  }
  const cd = res.headers.get("content-disposition") ?? "";
  const m = /filename="?([^"]+)"?/.exec(cd);
  return { blob: await res.blob(), filename: m?.[1] ?? "eksport" };
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return "Nieznany błąd";
}
