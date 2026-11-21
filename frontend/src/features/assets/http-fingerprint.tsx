"use client";

import { Eye, EyeOff, Lock, ShieldAlert, TriangleAlert } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { Guard } from "@/components/data/bits";
import { Button } from "@/components/ui/button";
import { Chip, DefinitionList } from "@/components/ui/misc";
import { Tooltip } from "@/components/ui/overlays";
import { RedirectChain } from "@/components/viz/bits";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { HttpFingerprint } from "@/lib/api/types";
import { fmtDate } from "@/lib/format";
import { TECH_CATEGORY_LABEL } from "@/lib/labels";
import { cn } from "@/lib/utils";

function CookieValue({ serviceId, name, masked }: { serviceId: string; name: string; masked: string }) {
  const [value, setValue] = React.useState<string | null>(null);
  return (
    <span className="flex items-center gap-1.5">
      <code className="mono max-w-56 truncate text-sm">{value ?? masked}</code>
      <Guard permission="sensitive:reveal">
        <Button
          size="icon-sm"
          variant="ghost"
          aria-label={value ? "Ukryj wartość" : "Pokaż wartość (zapisywane w dzienniku zdarzeń)"}
          onClick={async () => {
            if (value) return setValue(null);
            try {
              const r = await api.hosts.revealCookie(serviceId, name);
              setValue(r.value);
              toast("Odsłonięto wartość ciasteczka", { description: "Operacja została zapisana w dzienniku zdarzeń." });
            } catch (e) {
              toast.error("Nie udało się odsłonić wartości", { description: errorMessage(e) });
            }
          }}
        >
          {value ? <EyeOff /> : <Eye />}
        </Button>
      </Guard>
    </span>
  );
}

function Flag({ on, label }: { on: boolean; label: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-bold", on ? "bg-success-soft text-success" : "bg-surface-3 text-ink-3 line-through decoration-1")}>
      {label}
    </span>
  );
}

export function HttpFingerprintView({ http, serviceId }: { http: HttpFingerprint; serviceId: string }) {
  return (
    <div className="grid gap-5">
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone={http.status_code < 300 ? "success" : http.status_code < 400 ? "warning" : "danger"} className="tabular">
          HTTP {http.status_code}
        </Chip>
        {http.environment ? (
          <Chip tone="warning">
            <TriangleAlert className="size-3" aria-hidden /> Środowisko: {http.environment === "staging" ? "staging" : http.environment === "dev" ? "deweloperskie" : "testowe"}
          </Chip>
        ) : null}
        {http.admin_panel ? (
          <Chip tone="danger">
            <ShieldAlert className="size-3" aria-hidden /> Panel administracyjny: <span className="mono">{http.admin_panel.path}</span>
          </Chip>
        ) : null}
        <Chip tone="outline">{http.response_time_ms} ms</Chip>
        {http.favicon_hash !== null ? (
          <Tooltip content="MurmurHash3 favicony — zgodny z wyszukiwarkami typu Shodan">
            <Chip tone="outline" className="mono">favicon {http.favicon_hash}</Chip>
          </Tooltip>
        ) : null}
      </div>

      <DefinitionList
        items={[
          { label: "Tytuł strony", value: http.title ?? "—" },
          { label: "Adres końcowy", value: <span className="mono text-sm break-all">{http.url}</span> },
          { label: "Typ treści", value: http.content_type ?? "—" },
        ]}
      />

      {http.redirects.length ? (
        <section className="grid gap-2">
          <h4 className="text-sm font-bold text-ink-2">Przekierowania</h4>
          <RedirectChain hops={http.redirects} finalUrl={http.url} finalStatus={http.status_code} />
        </section>
      ) : null}

      <section className="grid gap-2">
        <h4 className="text-sm font-bold text-ink-2">Technologie</h4>
        <ul className="grid gap-2">
          {http.technologies.map((t) => (
            <li key={t.name} className="grid gap-1 rounded-lg border border-line p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold">
                  {t.name} {t.version ? <span className="mono font-normal text-ink-2">{t.version}</span> : null}
                </span>
                <span className="flex items-center gap-2">
                  <Chip tone="outline">{TECH_CATEGORY_LABEL[t.category]}</Chip>
                  <span className="tabular text-sm font-bold">{Math.round(t.confidence * 100)}%</span>
                </span>
              </div>
              <ul className="grid gap-0.5 text-xs text-ink-2">
                {t.sources.map((s, i) => (
                  <li key={i} className="mono break-all">
                    · {s.detail}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </section>

      <section className="grid gap-2">
        <h4 className="text-sm font-bold text-ink-2">Nagłówki odpowiedzi</h4>
        <div className="overflow-hidden rounded-lg border border-line">
          <table className="w-full text-sm">
            <tbody>
              {http.headers.map((h, i) => (
                <tr key={i} className={cn("border-b border-line last:border-0", h.note && "bg-unstable-soft/60")}>
                  <th scope="row" className="mono w-56 px-3 py-1.5 text-left align-top font-semibold">
                    {h.name}
                  </th>
                  <td className="px-3 py-1.5 align-top">
                    <span className="mono break-all">{h.value}</span>
                    {h.note ? <span className="mt-0.5 block text-xs font-semibold text-unstable-ink">{h.note}</span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {http.cookies.length ? (
        <section className="grid gap-2">
          <h4 className="flex items-center gap-1.5 text-sm font-bold text-ink-2">
            Ciasteczka <Lock className="size-3.5" aria-label="wartości szyfrowane w bazie" />
          </h4>
          <ul className="grid gap-2">
            {http.cookies.map((c) => (
              <li key={c.name} className={cn("grid gap-1.5 rounded-lg border p-3", c.note ? "border-unstable/50" : "border-line")}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="mono font-semibold">{c.name}</span>
                  <span className="flex flex-wrap gap-1">
                    <Flag on={c.secure} label="Secure" />
                    <Flag on={c.http_only} label="HttpOnly" />
                    <Flag on={Boolean(c.same_site)} label={`SameSite${c.same_site ? `=${c.same_site}` : ""}`} />
                  </span>
                </div>
                <CookieValue serviceId={serviceId} name={c.name} masked={c.value_masked} />
                {c.note ? <span className="text-xs font-semibold text-unstable-ink">{c.note}</span> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {http.tls ? (
        <section className="grid gap-2">
          <h4 className="text-sm font-bold text-ink-2">Certyfikat TLS</h4>
          <div className={cn("rounded-lg border p-3", http.tls.expired || http.tls.days_left < 21 ? "border-danger/50" : "border-line")}>
            <DefinitionList
              items={[
                { label: "Podmiot (CN)", value: <span className="mono">{http.tls.subject_cn}</span> },
                { label: "Wystawca", value: http.tls.issuer },
                { label: "Nazwy (SAN)", value: <span className="mono text-sm">{http.tls.san.join(", ")}</span> },
                {
                  label: "Ważność",
                  value: (
                    <span className={cn(http.tls.expired ? "font-bold text-danger" : http.tls.days_left < 21 ? "font-bold text-unstable-ink" : undefined)}>
                      {fmtDate(http.tls.not_before)} – {fmtDate(http.tls.not_after)} ({http.tls.expired ? "wygasł" : `${http.tls.days_left} dni`})
                    </span>
                  ),
                },
                { label: "Protokół", value: `${http.tls.version}, ${http.tls.cipher}` },
                { label: "SHA-256", value: <span className="mono text-xs break-all">{http.tls.sha256}</span> },
              ]}
            />
          </div>
        </section>
      ) : null}

      {http.body_excerpt ? (
        <section className="grid gap-2">
          <h4 className="text-sm font-bold text-ink-2">Fragment treści</h4>
          <pre className="mono overflow-x-auto rounded-lg bg-surface-2 p-3 text-xs leading-relaxed whitespace-pre-wrap">{http.body_excerpt}</pre>
        </section>
      ) : null}
    </div>
  );
}
