"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Download, Plus, Radar } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { EmptyState, ErrorState, Guard, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { Container } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Panel, Progress, Skeleton } from "@/components/ui/misc";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { AvailabilityHeatmap } from "@/components/viz/availability-heatmap";
import { SegmentBar, TechBars } from "@/components/viz/bits";
import { ChangesTimeline, KIND_COLOR, KIND_ORDER } from "@/components/viz/changes-timeline";
import { HilbertMap, MAP_RANGES } from "@/components/viz/hilbert-map";
import { Sparkline } from "@/components/viz/sparkline";
import { FindingDrawer } from "@/features/findings/finding-drawer";
import { FindingsTable } from "@/features/findings/findings-table";
import { api } from "@/lib/api/endpoints";
import type { ChangeKind, DashboardSummary, FindingCategory } from "@/lib/api/types";
import { fmtDuration, fmtNumber, fmtPercent, fmtRelative, fmtSigned, fmtSmart } from "@/lib/format";
import { useDownload } from "@/lib/hooks";
import { AUDIT_ACTION_LABEL, CHANGE_LABEL_PLURAL, FINDING_CATEGORY_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

function KpiCard({ title, topBar, children, className }: { title: string; topBar: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <article className={cn("relative flex flex-col gap-3 overflow-hidden rounded-[14px] border border-chrome-line bg-chrome-raised p-5 pt-6", className)}>
      <div className="absolute inset-x-0 top-0">{topBar}</div>
      <h2 className="text-sm font-semibold text-chrome-ink-2">{title}</h2>
      {children}
    </article>
  );
}

function WindowCard({ s }: { s: DashboardSummary }) {
  const running = s.running_scan;
  const [sh, sm] = s.window.start.split(":").map(Number);
  const [eh, em] = s.window.end.split(":").map(Number);
  const windowMin = (eh * 60 + em - (sh * 60 + sm) + 24 * 60) % (24 * 60) || 24 * 60;
  const windowLen = windowMin * 60;
  const lastUse = s.last_scan ? Math.min(1, s.last_scan.duration_s / windowLen) : 0;
  return (
    <KpiCard
      title={`Okno skanowania ${s.window.start}–${s.window.end}`}
      topBar={<div className="h-[3px] bg-chrome-line"><div className="h-full bg-accent transition-[width] duration-700" style={{ width: `${(running ? running.progress : s.window_open ? s.window_progress : lastUse) * 100}%` }} /></div>}
    >
      {running ? (
        <div className="grid gap-3">
          <p className="flex items-baseline gap-2">
            <span className="tabular text-[2.5rem] leading-none font-extrabold">{fmtPercent(running.progress)}</span>
            <span className="text-sm text-chrome-ink-2">skanu #{running.number}</span>
          </p>
          <Progress value={running.progress} className="h-2 bg-chrome-line" label="Postęp skanowania" />
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <dt className="text-chrome-ink-2">Tempo</dt>
              <dd className="tabular font-semibold">{fmtNumber(running.rate_rps)} zapytań/s</dd>
            </div>
            <div>
              <dt className="text-chrome-ink-2">{running.status === "paused_window" ? "Wznowienie" : "Pozostało"}</dt>
              <dd className="font-semibold">
                {running.status === "paused_window" ? fmtSmart(running.resume_at) : running.eta_s !== null ? `ok. ${fmtDuration(running.eta_s)}` : "—"}
              </dd>
            </div>
          </dl>
        </div>
      ) : (
        <div className="grid gap-3">
          <p className="flex items-baseline gap-2">
            <span className="tabular text-[2.5rem] leading-none font-extrabold">{lastUse > 0 && lastUse < 0.01 ? "<1%" : fmtPercent(lastUse)}</span>
            <span className="text-sm text-chrome-ink-2">okna wykorzystał ostatni przebieg</span>
          </p>
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <dt className="text-chrome-ink-2">Czas skanu #{s.last_scan?.number}</dt>
              <dd className="font-semibold">{fmtDuration(s.last_scan?.duration_s)}</dd>
            </div>
            <div>
              <dt className="text-chrome-ink-2">Limit tempa</dt>
              <dd className="tabular font-semibold">{fmtNumber(s.rate_limit_rps)} zapytań/s</dd>
            </div>
          </dl>
          <p className="text-sm text-chrome-ink-2">
            {s.window_open ? "Okno jest teraz otwarte." : `Następne okno: ${fmtSmart(s.next_window_at)} (${fmtRelative(s.next_window_at)}).`}
          </p>
        </div>
      )}
      <div className="mt-auto">
        {running ? (
          <Button asChild variant="chrome" className="w-full">
            <Link href={`/scans/${running.id}`}>
              Podgląd na żywo <ArrowRight />
            </Link>
          </Button>
        ) : (
          <Guard permission="scans:create">
            <Button asChild variant="primary" size="lg" className="w-full">
              <Link href="/scans/new">
                <Plus /> Nowe skanowanie
              </Link>
            </Button>
          </Guard>
        )}
      </div>
    </KpiCard>
  );
}

function Hero({ s, mapCidr, setMapCidr }: { s: DashboardSummary | undefined; mapCidr: string; setMapCidr: (c: string) => void }) {
  const running = s?.running_scan;
  return (
    <section className="chrome-dots on-chrome border-b border-chrome-line bg-chrome text-chrome-ink" aria-labelledby="hero-title">
      <Container className="grid gap-8 pt-9 pb-10 xl:grid-cols-[minmax(0,1fr)_auto] xl:gap-10">
        <div className="grid min-w-0 content-start gap-7">
          <div className="grid gap-3">
            <h1 id="hero-title" className="text-[clamp(2.25rem,1.1rem+3.4vw,4rem)] leading-[1.02] font-extrabold tracking-[-0.03em]">
              Attack Surface Intelligence.
            </h1>
            <p className="max-w-2xl text-[1.0625rem] leading-relaxed text-chrome-ink-2">
              Ciągły monitoring i analiza zmian infrastruktury sieciowej uczelni — {s ? fmtNumber(s.monitored_addresses) : "ponad 10 000"} adresów IP pod stałą obserwacją.
            </p>
            <div className="flex items-center gap-2 text-sm font-semibold" aria-live="polite">
              <span className={cn("size-2 shrink-0 rounded-full", running ? "animate-pulse-dot bg-accent" : "bg-new")} aria-hidden />
              {!s ? (
                <Skeleton className="h-4 w-80" />
              ) : running ? (
                running.status === "paused_window" ? (
                  <>Skanowanie #{running.number} czeka na okno czasowe — wznowi się {fmtSmart(running.resume_at)}.</>
                ) : (
                  <>
                    Trwa skanowanie #{running.number}: podgrupa {running.batches_done} z {running.batches_total}, {fmtNumber(running.rate_rps)} zapytań/s.
                  </>
                )
              ) : s.last_scan ? (
                <>
                  Ostatnie skanowanie #{s.last_scan.number} zakończyło się {fmtSmart(s.last_scan.finished_at)} i trwało {fmtDuration(s.last_scan.duration_s)}.
                </>
              ) : (
                <>Brak zakończonych skanowań.</>
              )}
            </div>
          </div>

          {s ? (
            <div className="grid gap-4 md:grid-cols-3">
              <KpiCard title="Aktywne hosty" topBar={<div className="h-[3px] bg-accent" />}>
                <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className="tabular text-[2.75rem] leading-none font-extrabold tracking-tight">{fmtNumber(s.active_hosts)}</span>
                  <span className={cn("text-sm font-bold", s.active_hosts_delta >= 0 ? "text-[#5fe39a]" : "text-[#ff8a8f]")}>
                    {fmtSigned(s.active_hosts_delta)}
                  </span>
                </p>
                <p className="text-sm text-chrome-ink-2">
                  od skanu #{s.changes_base_scan}; {fmtNumber(s.services_count)} usług, w tym {fmtNumber(s.web_services_count)} WWW
                </p>
                <div className="mt-auto">
                  <Sparkline points={s.active_trend} label="Aktywne hosty" />
                </div>
              </KpiCard>

              <KpiCard
                title="Zmiany od poprzedniego skanu"
                topBar={<SegmentBar parts={KIND_ORDER.map((k) => ({ value: s.changes[k], color: KIND_COLOR[k], label: CHANGE_LABEL_PLURAL[k] }))} />}
              >
                <p className="tabular text-[2.75rem] leading-none font-extrabold tracking-tight">
                  {fmtNumber(KIND_ORDER.reduce((n, k) => n + s.changes[k], 0))}
                </p>
                <ul className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
                  {KIND_ORDER.map((k: ChangeKind) => (
                    <li key={k}>
                      <Link href={`/changes?kind=${k}`} className="flex items-center gap-2 rounded hover:text-white">
                        <span className="size-2.5 rounded-[3px]" style={{ background: KIND_COLOR[k] }} aria-hidden />
                        <span className="text-chrome-ink-2">{CHANGE_LABEL_PLURAL[k]}</span>
                        <span className="tabular ml-auto font-bold">{fmtNumber(s.changes[k])}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
                <Link href="/changes" className="mt-auto inline-flex items-center gap-1 text-sm font-semibold text-accent hover:underline">
                  Porównanie #{s.changes_base_scan} → #{s.changes_head_scan} <ArrowRight className="size-3.5" aria-hidden />
                </Link>
              </KpiCard>

              <WindowCard s={s} />
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-3">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-56 rounded-[14px]" />
              ))}
            </div>
          )}
        </div>

        <div className="grid content-start gap-3 xl:w-[392px]">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-chrome-ink-2">Mapa przestrzeni adresowej</h2>
            <SimpleSelect
              aria-label="Zakres na mapie"
              className="h-8 w-56 border-chrome-line bg-chrome-raised text-sm text-chrome-ink"
              value={mapCidr}
              onChange={(v) => setMapCidr(v || "10.0.0.0/16")}
              options={MAP_RANGES.map((r) => ({ value: r.cidr, label: `${r.cidr} ${r.label}` }))}
            />
          </div>
          <HilbertMap cidr={mapCidr} size={392} />
          <p className="text-xs leading-relaxed text-chrome-ink-2">
            Każdy punkt to jeden adres IP ułożony wzdłuż krzywej Hilberta — kwadrat 16×16 to jedna podsieć /24. Kliknij, aby zobaczyć jej hosty.
          </p>
        </div>
      </Container>
    </section>
  );
}

const CHANGE_FILTERS = [
  { value: "new", label: "Nowe" },
  { value: "changed", label: "Zmienione" },
  { value: "unstable", label: "Niestabilne" },
  { value: "gone", label: "Zniknęły" },
];

export function DashboardView() {
  const router = useRouter();
  const qc = useQueryClient();
  const can = useCan();
  const download = useDownload();
  const [mapCidr, setMapCidr] = React.useState("10.0.0.0/16");
  const [q, setQ] = React.useState("");
  const [change, setChange] = React.useState("");
  const [category, setCategory] = React.useState<FindingCategory | "">("");
  const [openId, setOpenId] = React.useState<string | null>(null);
  const dq = useDebouncedValue(q);

  const summary = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: api.dashboard.summary,
    refetchInterval: (query) => (query.state.data?.running_scan ? 3000 : 30_000),
  });
  const top = useQuery({
    queryKey: ["top-findings", dq, change, category],
    queryFn: () => api.dashboard.topFindings({ limit: 10, q: dq, change, category }),
    enabled: can("findings:read"),
    placeholderData: (prev) => prev,
  });
  const timeline = useQuery({ queryKey: ["changes-timeline"], queryFn: () => api.dashboard.changesTimeline({ limit: 30 }), enabled: can("changes:read") });
  const heat = useQuery({ queryKey: ["availability"], queryFn: api.dashboard.availability, enabled: can("changes:read") });
  const tech = useQuery({ queryKey: ["technologies"], queryFn: () => api.dashboard.technologies({ limit: 10 }), enabled: can("assets:read") });
  const activity = useQuery({ queryKey: ["audit", "recent"], queryFn: () => api.audit.list({ page_size: 7 }), enabled: can("audit:read") });
  const recentScans = useQuery({ queryKey: ["scans", "recent"], queryFn: () => api.scans.list({ page_size: 6 }), enabled: !can("audit:read") && can("scans:read") });

  return (
    <>
      <Hero s={summary.data} mapCidr={mapCidr} setMapCidr={setMapCidr} />
      <Container className="grid gap-6 py-8">
        {summary.isError ? <ErrorState error={summary.error} onRetry={() => summary.refetch()} /> : null}

        {can("findings:read") ? (
          <Panel
            id="top-findings"
            title="Najważniejsze znaleziska"
            description="Dziesięć obserwacji o najwyższym priorytecie analitycznym. Kliknij wiersz, aby zobaczyć dowody i ocenić znalezisko."
            flush
            actions={
              <>
                <Button asChild variant="ghost" size="sm">
                  <Link href="/findings">
                    Wszystkie znaleziska <ArrowRight />
                  </Link>
                </Button>
                {can("findings:export") ? (
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button size="sm">
                        <Download /> Eksport
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuItem onSelect={() => download(() => api.findings.export({ format: "csv", q: dq, change, category }), "Pobrano raport CSV")}>Raport CSV</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => download(() => api.findings.export({ format: "json", q: dq, change, category }), "Pobrano raport JSON")}>Raport JSON</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                ) : null}
              </>
            }
          >
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
              <SearchInput value={q} onChange={setQ} placeholder="Szukaj po IP, domenie, technologii…" className="w-full sm:w-80" />
              <SimpleSelect aria-label="Status zmiany" className="w-44" value={change} onChange={setChange} allLabel="Każdy status zmiany" options={CHANGE_FILTERS} />
              <SimpleSelect
                aria-label="Kategoria"
                className="w-56"
                value={category}
                onChange={(v) => setCategory(v as FindingCategory | "")}
                allLabel="Wszystkie kategorie"
                options={(Object.keys(FINDING_CATEGORY_LABEL) as FindingCategory[]).map((c) => ({ value: c, label: FINDING_CATEGORY_LABEL[c] }))}
              />
            </div>
            {top.isError ? <ErrorState className="m-4" error={top.error} onRetry={() => top.refetch()} /> : null}
            <FindingsTable
              rows={top.data}
              loading={top.isFetching}
              onOpen={setOpenId}
              onChanged={() => qc.invalidateQueries({ queryKey: ["top-findings"] })}
              empty={<EmptyState title="Brak znalezisk dla wybranych filtrów" description="Zmień kryteria albo wyczyść wyszukiwanie." />}
            />
          </Panel>
        ) : null}

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          {can("changes:read") ? (
            <Panel title="Zmiany w kolejnych skanach" description="Liczba wykrytych zmian w ostatnich 30 przebiegach. Kliknij słupek, aby porównać ten skan z poprzednim.">
              {timeline.data ? (
                <ChangesTimeline points={timeline.data} onSelect={(p) => router.push(`/changes?head=${p.scan_id}`)} selected={timeline.data.at(-1)?.scan_number} />
              ) : (
                <Skeleton className="h-60" />
              )}
            </Panel>
          ) : null}
          {can("changes:read") ? (
            <Panel title="Dostępność według pory dnia" description="Jak często hosty niestabilne odpowiadają w poszczególnych godzinach (pomiary kontrolne z ostatnich 4 tygodni).">
              {heat.data ? <AvailabilityHeatmap matrix={heat.data.matrix} /> : <Skeleton className="h-60" />}
            </Panel>
          ) : null}
        </div>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          {can("assets:read") ? (
            <Panel title="Technologie i CMS" description="Najczęściej rozpoznawane technologie w aktywnych usługach; zielona liczba to nowe wystąpienia.">
              {tech.data ? <TechBars items={tech.data} onSelect={(t) => router.push(`/assets?tab=services&q=${encodeURIComponent(t.name)}`)} /> : <Skeleton className="h-64" />}
            </Panel>
          ) : null}
          {can("audit:read") ? (
            <Panel
              title="Ostatnia aktywność"
              description="Edycje, eksporty i działania skanera. Pełna historia w dzienniku zdarzeń."
              actions={
                <Button asChild size="sm" variant="ghost">
                  <Link href="/admin/audit">
                    Dziennik zdarzeń <ArrowRight />
                  </Link>
                </Button>
              }
              flush
            >
              <ul className="divide-y divide-line">
                {(activity.data?.items ?? []).map((e) => (
                  <li key={e.id} className="grid grid-cols-[auto_1fr_auto] items-start gap-3 px-5 py-3 text-sm">
                    <span className="mt-0.5 grid size-7 place-items-center rounded-full bg-surface-3 text-xs font-extrabold text-ink-2">
                      {e.actor.name === "Harmonogram" || e.actor.name === "System" ? <Radar className="size-3.5" aria-hidden /> : e.actor.name.split(" ").map((p) => p[0]).join("").slice(0, 2)}
                    </span>
                    <span className="grid gap-0.5">
                      <span>
                        <span className="font-semibold">{e.actor.name}</span> <span className="text-ink-2">— {AUDIT_ACTION_LABEL[e.action].toLowerCase()}</span>
                      </span>
                      <span className="text-ink">{e.summary}</span>
                      {e.resource_label ? <span className="mono truncate text-xs text-ink-2">{e.resource_label}</span> : null}
                    </span>
                    <time dateTime={e.at} className="text-xs whitespace-nowrap text-ink-2">
                      {fmtRelative(e.at)}
                    </time>
                  </li>
                ))}
                {!activity.data ? (
                  <li className="grid gap-3 p-5">
                    <Skeleton className="h-10" />
                    <Skeleton className="h-10" />
                    <Skeleton className="h-10" />
                  </li>
                ) : null}
              </ul>
            </Panel>
          ) : can("scans:read") ? (
            <Panel title="Ostatnie skanowania" flush>
              <ul className="divide-y divide-line">
                {(recentScans.data?.items ?? []).map((sc) => (
                  <li key={sc.id}>
                    <Link href={`/scans/${sc.id}`} className="flex items-center justify-between gap-3 px-5 py-3 text-sm hover:bg-surface-2">
                      <span className="font-semibold">
                        #{sc.number} {sc.name}
                      </span>
                      <span className="text-ink-2">{fmtSmart(sc.finished_at ?? sc.started_at)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Panel>
          ) : null}
        </div>
      </Container>
      <FindingDrawer id={openId} onOpenChange={(o) => !o && setOpenId(null)} />
    </>
  );
}
