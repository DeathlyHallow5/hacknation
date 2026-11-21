/** Deterministic HTTP/HTTPS fingerprints for mock services. */
import type { HttpCookie, HttpFingerprint, HttpHeader, Technology, TlsInfo } from "@/lib/api/types";
import { WEB_APPS, type WebApp } from "@/mock/catalog";
import type { HostRec, ServiceRec } from "@/mock/db";
import { chance, hex, int, pick, rngFor } from "@/mock/rng";
import { DAY, iso } from "@/mock/time";

const SOURCE_WEIGHT = {
  header: 0.8,
  cookie: 0.55,
  html: 0.85,
  favicon: 0.9,
  path: 0.7,
  title: 0.6,
  banner: 0.75,
  signature: 0.9,
} as const;

interface Ctx {
  v: string;
  sv: string;
  major: string;
  host: string;
  token: string;
}

export function fill(s: string, ctx: Ctx): string {
  return s
    .replace(/\{v\}/g, ctx.v)
    .replace(/\{sv\}/g, ctx.sv)
    .replace(/\{major\}/g, ctx.major)
    .replace(/\{host\}/g, ctx.host)
    .replace(/\{token\}/g, ctx.token);
}

export function cookieValue(ip: string, port: number, name: string): string {
  return hex(rngFor("cookie", ip, port, name), 32);
}

function ctxFor(h: HostRec, s: ServiceRec): Ctx {
  const v = s.appVersion && s.appVersion !== "-" ? s.appVersion : "";
  return {
    v,
    sv: s.serverVersion ?? "",
    major: v.split(".")[0] ?? "",
    host: h.hostnames[0] ?? h.ip,
    token: hex(rngFor("token", h.ip, s.port), 6),
  };
}

export function titleFor(h: HostRec, s: ServiceRec): string | null {
  if (!s.web) return null;
  if (s.redirectTo) return "301 Moved Permanently";
  const app = WEB_APPS[s.web];
  const t = fill(app.title, ctxFor(h, s)).trim();
  return t || null;
}

export function environmentFor(h: HostRec, app: WebApp): HttpFingerprint["environment"] {
  if (app.env) return app.env;
  const name = h.hostnames.join(" ");
  if (/\bstaging|stg-/.test(name)) return "staging";
  if (/\btest|-test\b/.test(name)) return "test";
  if (/\bdev\b|dev-/.test(name)) return "dev";
  return null;
}

export function buildTls(h: HostRec, s: ServiceRec, base: number, now: number): TlsInfo {
  const rng = rngFor("tls", h.ip, s.port);
  const device = ["bmc", "camera", "printer", "storage", "network", "iot"].includes(h.device);
  const selfSigned = device || chance(rng, 0.03);
  const host = h.hostnames[0] ?? h.ip;
  const days = s.certDays ?? int(rng, 40, 330);
  const notAfter = base + days * DAY;
  const lifetime = selfSigned ? 3650 : pick(rng, [90, 365, 397]);
  const notBefore = s.certRenewedAt ?? notAfter - lifetime * DAY;
  const version = device ? (s.old ? "TLS 1.0" : "TLS 1.2") : pick(rng, ["TLS 1.3", "TLS 1.3", "TLS 1.3", "TLS 1.2"]);
  const cipher =
    version === "TLS 1.3"
      ? pick(rng, ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"])
      : version === "TLS 1.2"
        ? "ECDHE-RSA-AES256-GCM-SHA384"
        : "AES128-SHA";
  const cn = selfSigned ? (h.device === "bmc" ? `idrac-${hex(rng, 7).toUpperCase()}` : host) : host;
  const daysLeft = Math.floor((notAfter - now) / DAY);
  return {
    version,
    cipher,
    subject_cn: cn,
    issuer: selfSigned
      ? `CN=${cn} (samopodpisany)`
      : pick(rng, ["GEANT TLS RSA 1", "HARICA GEANT TLS R1", "Certum Domain Validation CA SHA2", "R11 (Let's Encrypt)"]),
    san: selfSigned ? [cn] : Array.from(new Set([host, ...h.hostnames.slice(1, 3)])),
    not_before: iso(notBefore),
    not_after: iso(notAfter),
    days_left: daysLeft,
    self_signed: selfSigned,
    expired: daysLeft < 0,
    sha256: hex(rng, 64).toUpperCase(),
  };
}

/** Header that actually reveals a given technology. */
const TECH_HEADER: Record<string, RegExp> = {
  Jenkins: /^x-jenkins$/i,
  Drupal: /^x-generator$/i,
  Kibana: /^kbn-name$/i,
  Elasticsearch: /^x-elastic-product$/i,
  "ASP.NET": /^x-aspnet-version$/i,
};

function sourceDetail(
  type: keyof typeof SOURCE_WEIGHT,
  app: WebApp,
  ctx: Ctx,
  server: string,
  title: string | null,
  tech: { name: string; category: string },
): string {
  switch (type) {
    case "header": {
      const re = TECH_HEADER[tech.name];
      const specific = re ? app.headers?.find(([n]) => re.test(n)) : undefined;
      if (specific) return `${specific[0]}: ${fill(specific[1], ctx)}`;
      if (app.poweredBy && (/php|asp\.net|python/i.test(tech.name) || !server)) return `X-Powered-By: ${app.poweredBy}`;
      if (server && (tech.category === "web_server" || tech.category === "app_server" || server.toLowerCase().includes(tech.name.split(" ")[0].toLowerCase())))
        return `Server: ${server}`;
      const any = app.headers?.find(([n]) => /generator|jenkins|kbn|elastic|aspnet/i.test(n));
      if (any) return `${any[0]}: ${fill(any[1], ctx)}`;
      return server ? `Server: ${server}` : `X-Powered-By: ${app.poweredBy ?? "—"}`;
    }
    case "cookie":
      return `Ciasteczko ${app.cookies?.[0]?.name ?? "sesji"}`;
    case "html":
      return `Fragment HTML: ${fill(app.body, ctx).slice(0, 80)}`;
    case "favicon":
      return `Hash favicony ${app.favicon ?? "—"}`;
    case "path":
      return `GET ${app.admin?.path ?? "/"} → 200`;
    case "title":
      return `Tytuł strony: „${title ?? ""}”`;
    case "banner":
      return "Baner usługi";
    default:
      return "Sygnatura";
  }
}

export function technologiesFor(h: HostRec, s: ServiceRec): Technology[] {
  if (!s.web) return [];
  const app = WEB_APPS[s.web];
  const ctx = ctxFor(h, s);
  const server = app.server(ctx.sv);
  const title = titleFor(h, s);
  const unstablePenalty = h.availability === "unstable" ? 0.9 : 1;
  return app.techs.map((t) => {
    const version =
      t.version === "app" ? ctx.v || null : t.version === "server" ? ctx.sv || null : t.version;
    const sources = t.via.map((type) => ({ type, detail: sourceDetail(type, app, ctx, server, title, t) }));
    const miss = sources.reduce((acc, src) => acc * (1 - SOURCE_WEIGHT[src.type]), 1);
    const confidence = Math.min(0.99, Math.round((1 - miss) * unstablePenalty * 100) / 100);
    return { name: t.name, version, category: t.category, confidence, sources };
  });
}

export function buildHttp(h: HostRec, s: ServiceRec, base: number, now: number): HttpFingerprint | null {
  if (!s.web) return null;
  const app = WEB_APPS[s.web];
  const rng = rngFor("http", h.ip, s.port);
  const ctx = ctxFor(h, s);
  const scheme = s.tls ? "https" : "http";
  const defaultPort = (s.tls && s.port === 443) || (!s.tls && s.port === 80);
  const origin = `${scheme}://${ctx.host}${defaultPort ? "" : `:${s.port}`}`;
  const server = app.server(ctx.sv);

  if (s.redirectTo) {
    const target = `https://${ctx.host}${s.redirectTo === 443 ? "" : `:${s.redirectTo}`}/`;
    const headers: HttpHeader[] = [];
    if (server) headers.push({ name: "Server", value: server, note: /\d/.test(server) ? "Ujawnia nazwę i wersję serwera" : null });
    headers.push({ name: "Location", value: target, note: "Przekierowanie na HTTPS" });
    headers.push({ name: "Content-Type", value: "text/html; charset=iso-8859-1", note: null });
    return {
      url: `${origin}/`,
      status_code: 301,
      title: "301 Moved Permanently",
      content_type: "text/html",
      content_length: 162 + int(rng, 0, 80),
      response_time_ms: int(rng, 3, 35),
      headers,
      cookies: [],
      tls: null,
      redirects: [],
      favicon_hash: null,
      technologies: technologiesFor(h, s).filter((t) => t.category === "web_server"),
      environment: environmentFor(h, app),
      admin_panel: null,
      body_excerpt: `<p>The document has moved <a href="${target}">here</a>.</p>`,
    };
  }

  const headers: HttpHeader[] = [];
  if (server) headers.push({ name: "Server", value: server, note: /\d/.test(server) ? "Ujawnia nazwę i wersję serwera" : null });
  if (app.poweredBy) headers.push({ name: "X-Powered-By", value: app.poweredBy, note: "Ujawnia technologię i jej wersję" });
  headers.push({
    name: "Content-Type",
    value: app.key === "elastic" ? "application/json; charset=UTF-8" : "text/html; charset=UTF-8",
    note: null,
  });
  for (const [name, value, note] of app.headers ?? []) headers.push({ name, value: fill(value, ctx), note });
  if (s.tls && !app.env && chance(rng, 0.7))
    headers.push({ name: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains", note: null });
  if (chance(rng, 0.5)) headers.push({ name: "X-Content-Type-Options", value: "nosniff", note: null });

  const cookies: HttpCookie[] = (app.cookies ?? []).map((c) => {
    let note: string | null = null;
    if (s.tls && !c.secure) note = "Brak flagi Secure mimo HTTPS";
    else if (!c.httpOnly && /sess|xsrf|token/i.test(c.name)) note = "Brak HttpOnly — wartość dostępna dla JavaScriptu";
    else if (!s.tls && /sess|jsession|phpmyadmin|grafana/i.test(c.name)) note = "Sesja przesyłana bez szyfrowania (HTTP)";
    return {
      name: c.name,
      value_masked: `${cookieValue(h.ip, s.port, c.name).slice(0, 4)}••••••••`,
      domain: null,
      path: "/",
      secure: c.secure,
      http_only: c.httpOnly,
      same_site: c.sameSite,
      expires: null,
      note,
    };
  });

  const title = titleFor(h, s);
  const redirects = app.redirectPath ? [{ url: `${origin}/`, status_code: 302 }] : [];
  return {
    url: `${origin}${app.redirectPath ?? "/"}`,
    status_code: app.key === "cisco_http" ? 401 : app.key === "dev_app" ? 404 : 200,
    title,
    content_type: app.key === "elastic" ? "application/json" : "text/html",
    content_length: int(rng, 1800, 64000),
    response_time_ms: int(rng, 12, h.availability === "unstable" ? 1400 : 380),
    headers,
    cookies,
    tls: s.tls ? buildTls(h, s, base, now) : null,
    redirects,
    favicon_hash: app.favicon ?? null,
    technologies: technologiesFor(h, s),
    environment: environmentFor(h, app),
    admin_panel: app.admin ? { path: app.admin.path, title: app.admin.title } : null,
    body_excerpt: fill(app.body, ctx),
  };
}
