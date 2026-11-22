/** Derive findings (observations worth a look) from hosts and score them. */
import type { ChangeState, Criticality, Evidence, Finding, FindingCategory, FindingStatus } from "@/lib/api/types";
import { DEVICE_LABEL } from "@/lib/labels";
import { PLAIN, WEB_APPS } from "@/mock/catalog";
import type { HostRec, ServiceRec } from "@/mock/db";
import { buildHttp } from "@/mock/http";
import { chance, pick, pickWeighted, rngFor } from "@/mock/rng";
import { DAY, iso } from "@/mock/time";

const BASE: Record<FindingCategory, number> = {
  admin_panel: 40,
  staging: 36,
  exposure: 44,
  outdated: 26,
  iot: 22,
  tls: 16,
  cookie: 10,
  header: 8,
  signature: 20,
};

const FACTOR: Record<FindingCategory, string> = {
  admin_panel: "Panel administracyjny dostępny w sieci",
  staging: "Środowisko testowe widoczne obok produkcji",
  exposure: "Usługa dostępna bez uwierzytelnienia",
  outdated: "Komponent nieaktualny lub bez wsparcia",
  iot: "Urządzenie IoT z interfejsem WWW",
  tls: "Problem z certyfikatem TLS",
  cookie: "Słabe ustawienia ciasteczka",
  header: "Ujawnienie wersji w nagłówkach",
  signature: "Dopasowanie sygnatury własnej",
};

export function scoreFinding(
  category: FindingCategory,
  opts: { change: ChangeState; criticality: Criticality; plainHttpLogin?: boolean; eol?: boolean },
) {
  const breakdown: { factor: string; points: number }[] = [{ factor: FACTOR[category], points: BASE[category] }];
  if (opts.change === "new") breakdown.push({ factor: "Pojawiło się w ostatnim skanie", points: 15 });
  if (opts.change === "changed") breakdown.push({ factor: "Zmieniło się w ostatnim skanie", points: 8 });
  if (opts.change === "unstable") breakdown.push({ factor: "Host widoczny tylko okresowo", points: 6 });
  if (opts.criticality === "critical") breakdown.push({ factor: "Zasób o krytycznym znaczeniu", points: 15 });
  if (opts.criticality === "high") breakdown.push({ factor: "Zasób o wysokiej krytyczności", points: 10 });
  if (opts.plainHttpLogin) breakdown.push({ factor: "Logowanie przez nieszyfrowane HTTP", points: 10 });
  if (opts.eol) breakdown.push({ factor: "Wersja bez wsparcia producenta (EOL)", points: 12 });
  const score = Math.max(3, Math.min(99, breakdown.reduce((s, b) => s + b.points, 0)));
  return { score, breakdown };
}

const ANALYSTS = ["Anna Nowak", "Piotr Wiśniewski", "Katarzyna Zielińska", "Jan Kowalski"];

function serviceLabel(s: ServiceRec): string {
  if (s.web) return `${s.port}/${s.tls ? "HTTPS" : "HTTP"}`;
  return `${s.port}/${s.name.toUpperCase()}`;
}

function effectiveChange(h: HostRec, s: ServiceRec): ChangeState {
  if (s.change !== "unchanged") return s.change;
  if (h.change !== "unchanged") return h.change;
  if (h.availability === "unstable") return "unstable";
  return "unchanged";
}

const SIGNATURE_BY_KEY: Record<string, { id: string; name: string }> = {
  staging_portal: { id: "sig-c1", name: "Nagłówek X-Environment: staging" },
  apache22: { id: "sig-c2", name: "Stary Apache 2.2" },
  joomla3: { id: "sig-c3", name: "Stopka „Powered by Joomla! 3”" },
  apc: { id: "sig-c5", name: "APC RomPager 4.01" },
};

export function findingsForHost(h: HostRec, base: number, now: number): Finding[] {
  const out: Finding[] = [];
  const hostname = h.hostnames[0] ?? null;
  const measurements =
    h.availability === "unstable" ? { responded: 2, total: 3 } : h.responded ? { responded: 3, total: 3 } : { responded: 0, total: 3 };
  const device = ["printer", "camera", "bmc", "network", "iot", "storage"].includes(h.device);

  const push = (
    s: ServiceRec,
    category: FindingCategory,
    title: string,
    evidence: Evidence[],
    technologies: string[],
    confidence: number,
    extra: { plainHttpLogin?: boolean; eol?: boolean; signature?: { id: string; name: string } } = {},
  ) => {
    const rng = rngFor("fstatus", h.ip, s.port, category);
    const change = effectiveChange(h, s);
    const { score, breakdown } = scoreFinding(category, {
      change,
      criticality: h.criticality,
      plainHttpLogin: extra.plainHttpLogin,
      eol: extra.eol,
    });
    const status: FindingStatus =
      change === "new"
        ? "open"
        : pickWeighted(rng, [
            ["open", 70],
            ["in_review", 12],
            ["confirmed", 8],
            ["false_positive", 5],
            ["accepted", 5],
          ] as const);
    const exported = status === "confirmed" && chance(rng, 0.6);
    const firstSeen = change === "new" ? h.lastSeen : s.firstSeen;
    out.push({
      id: `f-${h.off}-${s.port}-${category}`,
      title,
      category,
      host_id: h.id,
      ip: h.ip,
      hostname,
      port: s.port,
      service_id: s.id,
      service_label: serviceLabel(s),
      technologies,
      change,
      status,
      score,
      score_override: null,
      score_breakdown: breakdown,
      confidence: Math.round(confidence * (h.availability === "unstable" ? 0.88 : 1) * 100) / 100,
      measurements,
      evidence,
      signature_id: extra.signature?.id ?? null,
      signature_name: extra.signature?.name ?? null,
      assignee: status === "open" ? null : pick(rng, ANALYSTS),
      tags: device ? ["urządzenia"] : [],
      notes: null,
      manual_overrides: {},
      defectdojo: exported
        ? {
            exported_at: iso(base - Math.floor(rng() * 9) * DAY),
            finding_id: 4100 + (h.off % 900),
            url: `https://defectdojo.cbi.uczelnia.example/finding/${4100 + (h.off % 900)}`,
          }
        : null,
      first_seen: firstSeen,
      last_seen: h.lastSeen,
      occurrences: measurements.total,
    });
  };

  for (const s of h.services) {
    if (s.redirectTo) continue;
    const rng = rngFor("finding", h.ip, s.port);

    if (s.web) {
      const app = WEB_APPS[s.web];
      const http = buildHttp(h, s, base, now);
      if (!http) continue;
      const techs = http.technologies.map((t) => (t.version ? `${t.name} ${t.version}` : t.name)).slice(0, 3);
      const conf = Math.max(0.5, ...http.technologies.map((t) => t.confidence));
      const titleEv: Evidence[] = http.title
        ? [{ type: "title", label: "Tytuł strony", snippet: http.title, highlight: http.title }]
        : [];

      if (app.admin && (!device || chance(rng, 0.2))) {
        push(
          s,
          device ? "iot" : "admin_panel",
          device
            ? `${DEVICE_LABEL[h.device]} z panelem logowania: ${app.label}`
            : `Panel administracyjny: ${app.label}`,
          [
            { type: "path", label: "Ścieżka (GET, bez logowania)", snippet: `GET ${app.admin.path} → ${http.status_code === 401 ? 401 : 200}`, highlight: app.admin.path },
            ...titleEv,
          ],
          techs,
          conf,
          { plainHttpLogin: !s.tls },
        );
      } else if (app.iot && !app.admin && chance(rng, 0.12)) {
        push(s, "iot", `${DEVICE_LABEL[h.device]} z interfejsem WWW: ${app.label}`, [...titleEv], techs, conf);
      }

      if (http.environment) {
        const envHeader = http.headers.find((x) => /environment|debug/i.test(x.name));
        const label =
          http.environment === "staging" ? "testowe (staging)" : http.environment === "dev" ? "deweloperskie" : "testowe";
        push(
          s,
          "staging",
          `Środowisko ${label}: ${hostname ?? h.ip}`,
          [
            envHeader
              ? { type: "header", label: "Nagłówek", snippet: `${envHeader.name}: ${envHeader.value}`, highlight: envHeader.value }
              : { type: "title", label: "Nazwa hosta", snippet: hostname ?? h.ip, highlight: http.environment },
            ...(http.body_excerpt ? [{ type: "html" as const, label: "Fragment HTML", snippet: http.body_excerpt, highlight: null }] : []),
          ],
          techs,
          conf,
          { signature: s.web === "staging_portal" ? SIGNATURE_BY_KEY.staging_portal : undefined },
        );
      }

      if (s.old) {
        const server = http.headers.find((x) => x.name === "Server");
        const appVer = s.appVersion && s.appVersion !== "-" ? s.appVersion : s.serverVersion;
        const sig =
          s.web === "apache_default" && s.serverVersion?.startsWith("2.2")
            ? SIGNATURE_BY_KEY.apache22
            : s.web === "joomla"
              ? SIGNATURE_BY_KEY.joomla3
              : s.web === "apc_ups"
                ? SIGNATURE_BY_KEY.apc
                : undefined;
        push(
          s,
          "outdated",
          `Nieaktualna wersja: ${app.label} ${appVer ?? ""}`.trim(),
          [
            server
              ? { type: "header", label: "Nagłówek", snippet: `Server: ${server.value}`, highlight: server.value }
              : { type: "html", label: "Fragment HTML", snippet: http.body_excerpt ?? "", highlight: appVer },
          ],
          techs,
          conf,
          { eol: true, signature: sig },
        );
      }

      if (app.exposure) {
        push(s, "exposure", app.exposure, [
          ...titleEv,
          ...(http.body_excerpt ? [{ type: "html" as const, label: "Odpowiedź", snippet: http.body_excerpt, highlight: null }] : []),
        ], techs, conf);
      }

      if (http.tls && (http.tls.expired || http.tls.days_left < 21 || (http.tls.self_signed && !device))) {
        const t = http.tls;
        push(
          s,
          "tls",
          t.expired ? "Wygasły certyfikat TLS" : t.days_left < 21 ? `Certyfikat TLS wygasa za ${t.days_left} dni` : "Certyfikat TLS samopodpisany",
          [{ type: "tls", label: "Certyfikat", snippet: `CN=${t.subject_cn}, wystawca: ${t.issuer}, ważny do ${t.not_after.slice(0, 10)}`, highlight: t.not_after.slice(0, 10) }],
          techs,
          0.99,
        );
      }

      const weakCookie = http.cookies.find((c) => c.note);
      if (weakCookie && chance(rng, 0.35)) {
        push(
          s,
          "cookie",
          `Ciasteczko ${weakCookie.name}: ${weakCookie.note!.charAt(0).toLowerCase()}${weakCookie.note!.slice(1)}`,
          [
            {
              type: "cookie",
              label: "Set-Cookie",
              snippet: `Set-Cookie: ${weakCookie.name}=${weakCookie.value_masked}; Path=/${weakCookie.http_only ? "; HttpOnly" : ""}${weakCookie.secure ? "; Secure" : ""}`,
              highlight: weakCookie.name,
            },
          ],
          techs,
          0.97,
        );
      }

      const leaky = http.headers.find((x) => /x-powered-by|x-aspnet-version|x-jenkins/i.test(x.name));
      if (leaky && chance(rng, 0.25)) {
        push(
          s,
          "header",
          `Ujawnienie wersji w nagłówku ${leaky.name}`,
          [{ type: "header", label: "Nagłówek", snippet: `${leaky.name}: ${leaky.value}`, highlight: leaky.value }],
          techs,
          0.98,
        );
      }
    } else if (s.plain) {
      const p = PLAIN[s.plain];
      const product = s.product ?? s.name;
      if (p.exposure && (!device || chance(rng, 0.3))) {
        push(
          s,
          "exposure",
          `${p.exposure} (${s.port}/${s.protocol})`,
          [{ type: "banner", label: "Baner", snippet: s.banner ?? `${s.port}/${s.protocol} open ${s.name} ${product} ${s.version ?? ""}`, highlight: product }],
          p.tech ? [`${p.tech.name} ${s.version ?? ""}`.trim()] : [product],
          s.confidence,
        );
      }
      if (s.old) {
        push(
          s,
          "outdated",
          `Nieaktualna wersja: ${product} ${s.version ?? ""}`.trim(),
          [{ type: "banner", label: "Baner", snippet: s.banner ?? `${product} ${s.version ?? ""}`, highlight: s.version }],
          [`${product} ${s.version ?? ""}`.trim()],
          s.confidence,
          { eol: true },
        );
      }
    }
  }
  return out;
}
