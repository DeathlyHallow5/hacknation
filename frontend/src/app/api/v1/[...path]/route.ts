/**
 * Single entry point for /api/v1/*.
 *
 * ASI_API_MODE (read at runtime, no rebuild needed):
 *   mock   (default) — built-in mock backend from src/mock
 *   proxy            — transparent proxy to ASI_API_URL (Rust/axum), incl. SSE and cookies
 *   hybrid           — proxy first; falls back to the mock when the upstream route is not
 *                      implemented yet (501, or 404 without a JSON body) or unreachable
 *
 * Every response carries `x-asi-source: mock | upstream`.
 */
import type { NextRequest } from "next/server";
import type { ApiMeta } from "@/lib/api/types";
import { handleMock } from "@/mock/router";

export const dynamic = "force-dynamic";

type Mode = ApiMeta["mode"];

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "proxy-connection",
  "te",
  "trailer",
  "host",
  "content-length",
  "content-encoding",
]);

function mode(): Mode {
  const m = (process.env.ASI_API_MODE ?? "mock").toLowerCase();
  return m === "proxy" || m === "hybrid" ? m : "mock";
}

function upstreamUrl(): string | null {
  return process.env.ASI_API_URL?.replace(/\/+$/, "") || null;
}

function tag(res: Response, source: "mock" | "upstream"): Response {
  const headers = new Headers();
  res.headers.forEach((v, k) => {
    if (!HOP_BY_HOP.has(k.toLowerCase()) && k.toLowerCase() !== "set-cookie") headers.set(k, v);
  });
  for (const c of res.headers.getSetCookie()) headers.append("set-cookie", c);
  headers.set("x-asi-source", source);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

function errorJson(status: number, code: string, message: string) {
  return Response.json({ error: { code, message } }, { status, headers: { "x-asi-source": "proxy" } });
}

async function forward(req: NextRequest, base: string, subpath: string, body: ArrayBuffer | undefined) {
  const headers = new Headers();
  req.headers.forEach((v, k) => {
    if (!HOP_BY_HOP.has(k.toLowerCase())) headers.set(k, v);
  });
  headers.set("x-forwarded-host", req.headers.get("host") ?? "");
  headers.set("x-forwarded-proto", req.nextUrl.protocol.replace(":", ""));
  return fetch(`${base}/api/v1${subpath}${req.nextUrl.search}`, {
    method: req.method,
    headers,
    body,
    redirect: "manual",
    cache: "no-store",
    signal: req.signal,
  });
}

function rebuild(req: NextRequest, body: ArrayBuffer | undefined): Request {
  return new Request(req.url, { method: req.method, headers: req.headers, body, signal: req.signal });
}

async function dispatch(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const subpath = `/${path.map(encodeURIComponent).join("/")}`;
  const m = mode();
  const upstream = upstreamUrl();

  if (subpath === "/_meta") {
    const meta: ApiMeta = { mode: m, upstream: m === "mock" ? null : upstream, version: "0.1.0" };
    return Response.json(meta, { headers: { "x-asi-source": "mock" } });
  }

  if (m === "mock") return tag(await handleMock(req, subpath), "mock");

  if (!upstream) return errorJson(500, "misconfigured", "Ustaw ASI_API_URL (adres backendu Rust), aby używać trybu proxy/hybrid.");

  const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer();
  try {
    const res = await forward(req, upstream, subpath, body);
    const notImplemented =
      res.status === 501 || (res.status === 404 && !(res.headers.get("content-type") ?? "").includes("application/json"));
    if (m === "hybrid" && notImplemented) {
      await res.body?.cancel();
      return tag(await handleMock(rebuild(req, body), subpath), "mock");
    }
    return tag(res, "upstream");
  } catch (e) {
    if (m === "hybrid") return tag(await handleMock(rebuild(req, body), subpath), "mock");
    return errorJson(502, "upstream_unreachable", `Backend ${upstream} nie odpowiada: ${e instanceof Error ? e.message : e}`);
  }
}

export { dispatch as GET, dispatch as POST, dispatch as PATCH, dispatch as PUT, dispatch as DELETE };
