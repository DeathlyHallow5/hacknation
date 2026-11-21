// Runtime proxy keeps the browser on the same origin in local and Docker setups.
import type { NextRequest } from "next/server";

async function proxy(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  const route = path.join("/");
  if (
    // Allow-list of core API routes (UUID ids). Extend as core/src/api.rs grows.
    !/^(health|tools|targets|scans(?:\/[0-9a-f-]{36}\/(run|runs))?|runs\/[0-9a-f-]{36}(?:\/(findings|cancel|diff))?)$/.test(
      route,
    )
  ) {
    return Response.json({ detail: "Unknown API route" }, { status: 404 });
  }
  const base = process.env.ASI_API_INTERNAL_URL ?? "http://127.0.0.1:8000";
  try {
    const upstream = await fetch(
      `${base}/api/${route}${request.nextUrl.search}`,
      {
        method: request.method,
        headers: {
          "Content-Type": "application/json",
          ...(request.headers.get("last-event-id")
            ? { "Last-Event-ID": request.headers.get("last-event-id")! }
            : {}),
        },
        body: request.method === "POST" ? await request.text() : undefined,
        cache: "no-store",
        signal: request.signal,
      },
    );
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "Content-Type":
          upstream.headers.get("content-type") ?? "application/json",
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
      },
    });
  } catch {
    return Response.json(
      { detail: "API is unavailable. Check the backend service." },
      { status: 502 },
    );
  }
}
export const GET = proxy;
export const POST = proxy;
