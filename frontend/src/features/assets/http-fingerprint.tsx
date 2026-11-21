"use client";

import { Check, Eye, EyeOff, Lock, ShieldAlert, TriangleAlert, X } from "lucide-react";
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
import { countLabel, fmtDate } from "@/lib/format";
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

/** Cookie attribute: set = check, missing = cross and struck through. Icon + text, never colour alone. */
function Flag({ on, label }: { on: boolean; label: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-xs text-ink-2">
      {on ? <Check className="size-3.5" aria-hidden /> : <X className="size-3.5" aria-hidden />}
      <span className={cn("mono", !on && "line-through decoration-1")}>{label}</span>
      <span className="sr-only">{on ? "(ustawiona)" : "(brak)"}</span>
    </span>
  );
}

const HEADING = "text-sm font-semibold text-ink";

/**
 * HTTP fingerprint inside a service row. No frames of its own: sections are separated
 * by spacing and rows by hairlines, so the host panel stays the only container.
 */
export function HttpFingerprintView({ http, serviceId }: { http: HttpFingerprint; serviceId: string }) {
  return (
    <div className="grid gap-5">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm text-ink-2">
        {/* Only the flags that need attention are chips: an error code, a test environment, an admin panel. */}
        {http.status_code >= 400 ? (
          <Chip tone="danger" className="tabular">
            <TriangleAlert className="size-3" aria-hidden /> HTTP {http.status_code}
          </Chip>
        ) : (
          <span className="tabular">HTTP {http.status_code}</span>
        )}
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
        <span className="tabular">{http.response_time_ms} ms</span>
        {http.favicon_hash !== null ? (
          <Tooltip content="MurmurHash3 favicony, zgodny z wyszukiwarkami typu Shodan">
            <span tabIndex={0} className="rounded-sm">
              favicon <span className="mono text-ink">{http.favicon_hash}</span>
            </span>
          </Tooltip>
        ) : null}
      </div>

      <DefinitionList
        items={[
          { label: "Tytuł strony", value: http.title ?? "—" },
          { label: "Adres końcowy", value: <span className="mono text-sm break-all">{http.url}</span> },
          { label: "Typ treści", value: http.content_type ? <span className="mono text-sm">{http.content_type}</span> : "—" },
        ]}
      />

      {http.redirects.length ? (
        <section className="grid gap-2">
          <h4 className={HEADING}>Przekierowania</h4>
          <RedirectChain hops={http.redirects} finalUrl={http.url} finalStatus={http.status_code} />
        </section>
      ) : null}

      <section className="grid gap-1">
        <h4 className={HEADING}>Technologie</h4>
        <ul className="divide-y divide-line">
          {http.technologies.map((t) => (
            <li key={t.name} className="grid gap-1 py-2.5">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <span className="font-semibold">
                  {t.name} {t.version ? <span className="mono font-normal text-ink-2">{t.version}</span> : null}
                </span>
                <span className="text-sm text-ink-2">
                  {TECH_CATEGORY_LABEL[t.category]}, <span className="tabular">{Math.round(t.confidence * 100)}%</span>
                </span>
              </div>
              <ul className="grid gap-0.5 text-xs text-ink-2">
                {t.sources.map((s, i) => (
                  <li key={i} className="mono break-all">
                    {s.detail}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </section>

      <section className="grid gap-1">
        <h4 className={HEADING}>Nagłówki odpowiedzi</h4>
        <dl className="divide-y divide-line text-sm">
          {http.headers.map((h, i) => (
            <div key={i} className={cn("grid gap-x-4 gap-y-0.5 py-1.5 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]", h.note && "-mx-2 rounded-md bg-unstable-soft/60 px-2")}>
              <dt className="mono font-medium break-all">{h.name}</dt>
              <dd className="min-w-0">
                <span className="mono break-all">{h.value}</span>
                {h.note ? <span className="mt-0.5 block text-xs font-semibold text-unstable-ink">{h.note}</span> : null}
              </dd>
            </div>
          ))}
        </dl>
      </section>

      {http.cookies.length ? (
        <section className="grid gap-1">
          <h4 className={cn(HEADING, "flex items-center gap-1.5")}>
            Ciasteczka <Lock className="size-3.5 text-ink-2" aria-label="wartości szyfrowane w bazie" />
          </h4>
          <ul className="divide-y divide-line">
            {http.cookies.map((c) => (
              <li key={c.name} className="grid gap-1.5 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="mono font-medium">{c.name}</span>
                  <span className="flex flex-wrap gap-x-3 gap-y-1">
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
          <h4 className={HEADING}>Certyfikat TLS</h4>
          <DefinitionList
            items={[
              { label: "Podmiot (CN)", value: <span className="mono">{http.tls.subject_cn}</span> },
              { label: "Wystawca", value: http.tls.issuer },
              { label: "Nazwy (SAN)", value: <span className="mono text-sm">{http.tls.san.join(", ")}</span> },
              {
                label: "Ważność",
                value: (
                  <span className={cn("inline-flex flex-wrap items-center gap-1.5", http.tls.expired ? "font-semibold text-danger" : http.tls.days_left < 21 ? "font-semibold text-unstable-ink" : undefined)}>
                    {http.tls.expired || http.tls.days_left < 21 ? <TriangleAlert className="size-3.5" aria-hidden /> : null}
                    {fmtDate(http.tls.not_before)} – {fmtDate(http.tls.not_after)} ({http.tls.expired ? "wygasł" : countLabel(http.tls.days_left, ["dzień", "dni", "dni"])})
                  </span>
                ),
              },
              { label: "Protokół", value: `${http.tls.version}, ${http.tls.cipher}` },
              { label: "SHA-256", value: <span className="mono text-xs break-all">{http.tls.sha256}</span> },
            ]}
          />
        </section>
      ) : null}

      {http.body_excerpt ? (
        <section className="grid gap-2">
          <h4 className={HEADING}>Fragment treści</h4>
          <pre className="mono overflow-x-auto rounded-lg bg-surface-2 p-3 text-xs leading-relaxed whitespace-pre-wrap contrast:border contrast:border-line">{http.body_excerpt}</pre>
        </section>
      ) : null}
    </div>
  );
}
