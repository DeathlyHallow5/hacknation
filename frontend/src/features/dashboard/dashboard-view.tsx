"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Plus, Radar } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { EmptyState, ErrorState, Guard, ResourceLabel, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { Container } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Panel, Progress, Skeleton } from "@/components/ui/misc";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/overlays";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, SimpleSelect } from "@/components/ui/select";
import { AvailabilityHeatmap } from "@/components/viz/availability-heatmap";
import { SegmentBar, TechBars } from "@/components/viz/bits";
import { ChangesTimeline, KIND_COLOR, KIND_ORDER } from "@/components/viz/changes-timeline";
import { HilbertMap, MAP_RANGES } from "@/components/viz/hilbert-map";
import { Sparkline } from "@/components/viz/sparkline";
import { GettingStarted } from "@/features/dashboard/getting-started";
import { FindingDrawer } from "@/features/findings/finding-drawer";
import { FindingsTable } from "@/features/findings/findings-table";
import { api } from "@/lib/api/endpoints";
import type { AuditEvent, ChangeKind, DashboardSummary, FindingCategory } from "@/lib/api/types";
import { countLabel, fmtDuration, fmtNumber, fmtPercent, fmtRelative, fmtSigned, fmtSmart } from "@/lib/format";
import { useDownload, useMediaQuery } from "@/lib/hooks";
import { CHANGE_LABEL_PLURAL, FINDING_CATEGORY_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

/** The three KPI numbers share one size and weight (800 is reserved for the hero and these). */
const KPI_NUMBER = "tabular text-[2.5rem] leading-none font-extrabold tracking-tight";

function KpiCard({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <article className={cn("flex flex-col gap-3 rounded-xl border border-chrome-line bg-chrome-raised p-5", className)}>
      <h2 className="text-sm font-semibold text-chrome-ink-2">{title}</h2>
      {children}
    </article>
  );
}

function WindowCard({ s, className }: { s: DashboardSummary; className?: string }) {
  const running = s.running_scan;
  const [sh, sm] = s.window.start.split(":").map(Number);
  const [eh, em] = s.window.end.split(":").map(Number);
  const windowMin = (eh * 60 + em - (sh * 60 + sm) + 24 * 60) % (24 * 60) || 24 * 60;
  const windowLen = windowMin * 60;
  const lastUse = s.last_scan ? Math.min(1, s.last_scan.duration_s / windowLen) : 0;
  const lastUseText = lastUse > 0 && lastUse < 0.01 ? "<1%" : fmtPercent(lastUse);
  return (
    <KpiCard title={`Okno skanowania ${s.window.start}–${s.window.end}`} className={className}>
      {running ? (
        <div className="grid gap-3">
          <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className={KPI_NUMBER}>{fmtPercent(running.progress)}</span>
            <span className="text-sm text-chrome-ink-2">skanu #{running.number}</span>
          </p>
          <Progress value={running.progress} className="h-2 bg-chrome-line contrast:bg-black contrast:ring-1 contrast:ring-white" label="Postęp skanowania" />
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
          <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className={KPI_NUMBER}>{lastUseText}</span>
            <span className="text-sm text-chrome-ink-2">{s.last_scan ? `okna zajął skan #${s.last_scan.number}` : "brak zakończonego skanu"}</span>
          </p>
          <Progress
            value={lastUse}
            className="h-2 bg-chrome-line contrast:bg-black contrast:ring-1 contrast:ring-white"
            label={s.last_scan ? `Skan #${s.last_scan.number} zajął ${lastUseText} okna` : "Wykorzystanie okna"}
          />
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <dt className="text-chrome-ink-2">Czas skanu</dt>
              <dd className="font-semibold">{fmtDuration(s.last_scan?.duration_s)}</dd>
            </div>
            <div>
              <dt className="text-chrome-ink-2">Limit tempa</dt>
              <dd className="tabular font-semibold">{fmtNumber(s.rate_limit_rps)} zapytań/s</dd>
            </div>
          </dl>
          <p className="text-sm text-pretty text-chrome-ink-2">
            {s.window_open ? "Okno jest teraz otwarte." : `Następne okno: ${fmtSmart(s.next_window_at)} (${fmtRelative(s.next_window_at)}).`}
          </p>
        </div>
      )}
      <div className="mt-auto pt-1">
        {running ? (
          <Button asChild variant="chrome" className="w-full">
            <Link href={`/scans/${running.id}`}>Podgląd na żywo</Link>
          </Button>
        ) : (
          <Guard permission="scans:create">
            {/* Full width in a column card; natural width when the card spans the tablet row. */}
            <Button asChild variant="primary" size="lg" className="w-full md:w-auto md:px-8 lg:w-full">
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

/** One plain status line under the title: only the scan number and the time stand out. */
function StatusLine({ s }: { s: DashboardSummary | undefined }) {
  const running = s?.running_scan;
  const em = "font-semibold text-chrome-ink";
  const watched = s ? ` Pod obserwacją: ${countLabel(s.monitored_addresses, ["adres IP", "adresy IP", "adresów IP"])}.` : "";
  return (
    <div className="flex max-w-4xl items-start gap-2.5 text-base leading-relaxed text-pretty text-chrome-ink-2" aria-live="polite">
      <span className={cn("mt-[0.6em] size-2 shrink-0 rounded-full", running ? "animate-pulse-dot bg-signal" : "bg-chrome-ink-2")} aria-hidden />
      {!s ? (
        <Skeleton className="mt-1 h-4 w-80" />
      ) : running ? (
        running.status === "paused_window" ? (
          <span>
            Skanowanie <span className={em}>#{running.number}</span> czeka na okno czasowe i wznowi się <span className={em}>{fmtSmart(running.resume_at)}</span>.{watched}
          </span>
        ) : (
          <span>
            Trwa skanowanie <span className={em}>#{running.number}</span>: podgrupa {running.batches_done} z {running.batches_total}, {fmtNumber(running.rate_rps)} zapytań/s.
            {watched}
          </span>
        )
      ) : s.last_scan ? (
        <span>
          Ostatnie skanowanie <span className={em}>#{s.last_scan.number}</span> zakończyło się <span className={em}>{fmtSmart(s.last_scan.finished_at)}</span> i trwało{" "}
          {fmtDuration(s.last_scan.duration_s)}.{watched}
        </span>
      ) : (
        <span>Brak zakończonych skanowań.{watched}</span>
      )}
    </div>
  );
}

function MapRangeSelect({
  value,
  onChange,
  ranges,
}: {
  value: string;
  onChange: (cidr: string) => void;
  ranges: { cidr: string; label: string }[];
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v || ranges[0].cidr)}>
      <SelectTrigger aria-label="Zakres na mapie" className="h-8 w-44 shrink-0 border-chrome-line bg-chrome-raised text-chrome-ink">
        {/* The trigger shows the range itself; the list adds the human name. */}
        <SelectValue>
          <span className="mono">{value}</span>
        </SelectValue>
      </SelectTrigger>
      <SelectContent align="end">
        {ranges.map((r) => (
          <SelectItem key={r.cidr} value={r.cidr}>
            <span className="mono">{r.cidr}</span> <span className="text-ink-2">{r.label}</span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function Hero({
  s,
  mapCidr,
  setMapCidr,
  ranges,
}: {
  s: DashboardSummary | undefined;
  mapCidr: string;
  setMapCidr: (c: string) => void;
  ranges: { cidr: string; label: string }[];
}) {
  const phone = useMediaQuery("(max-width: 767px)");
  const [mapOpen, setMapOpen] = React.useState(false);
  const total = s ? KIND_ORDER.reduce((n, k) => n + s.changes[k], 0) : 0;
  return (
    <section className="chrome-dots on-chrome border-b border-chrome-line bg-chrome text-chrome-ink" aria-labelledby="hero-title">
      <Container className="grid gap-8 pt-9 pb-10 xl:grid-cols-[minmax(0,1fr)_auto] xl:gap-10">
        <div className="grid min-w-0 content-start gap-7">
          <div className="grid gap-4">
            <h1 id="hero-title" className="text-[clamp(2.25rem,1.1rem+3.4vw,4rem)] leading-[1.02] font-extrabold tracking-[-0.03em] text-balance">
              Attack Surface Intelligence.
            </h1>
            <StatusLine s={s} />
          </div>

          {s ? (
            // Tablet: two cards side by side, the window card below at full width; three columns from lg.
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <KpiCard title="Aktywne hosty">
                <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className={KPI_NUMBER}>{fmtNumber(s.active_hosts)}</span>
                  <span className="text-sm text-chrome-ink-2">
                    <span className={cn("font-semibold", s.active_hosts_delta >= 0 ? "text-chrome-up" : "text-chrome-down")}>{fmtSigned(s.active_hosts_delta)}</span> od skanu #
                    {s.changes_base_scan}
                  </span>
                </p>
                <p className="text-sm text-pretty text-chrome-ink-2">
                  {countLabel(s.services_count, ["usługa", "usługi", "usług"])}, w tym {fmtNumber(s.web_services_count)} WWW
                </p>
                <div className="mt-auto">
                  <Sparkline points={s.active_trend} label="Aktywne hosty" height={phone ? 40 : 56} />
                </div>
              </KpiCard>

              <KpiCard title="Zmiany od poprzedniego skanu">
                <p className={KPI_NUMBER}>{fmtNumber(total)}</p>
                <SegmentBar parts={KIND_ORDER.map((k) => ({ value: s.changes[k], color: KIND_COLOR[k], label: CHANGE_LABEL_PLURAL[k] }))} />
                <ul className="grid gap-y-1 text-sm">
                  {KIND_ORDER.map((k: ChangeKind) => (
                    <li key={k}>
                      <Link href={`/changes?kind=${k}`} className="group flex items-center gap-2 rounded-sm">
                        <span className="size-2.5 shrink-0 rounded-[3px]" style={{ background: KIND_COLOR[k] }} aria-hidden />
                        <span className="text-chrome-ink-2 group-hover:text-chrome-ink">{CHANGE_LABEL_PLURAL[k]}</span>
                        <span className="tabular ml-auto font-semibold">{fmtNumber(s.changes[k])}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
                <Link href="/changes" className="mt-auto w-fit pt-1 text-sm font-semibold text-accent hover:underline">
                  Porównaj skany #{s.changes_base_scan} i #{s.changes_head_scan}
                </Link>
              </KpiCard>

              <WindowCard s={s} className="md:col-span-2 lg:col-span-1" />
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-56 rounded-xl" />
              ))}
            </div>
          )}
        </div>

        {/* The range select sits on the map's own right edge at every width. */}
        <div className="grid w-full max-w-[392px] content-start gap-3 xl:w-[392px]">
          {/* On phones the map waits behind a button, so the findings table is not three screens down. */}
          <Button variant="chrome" className="md:hidden" aria-expanded={mapOpen} aria-controls="hero-map" onClick={() => setMapOpen((o) => !o)}>
            {mapOpen ? "Ukryj mapę adresów" : "Pokaż mapę adresów"}
          </Button>
          <div id="hero-map" className={cn("grid content-start gap-3", !mapOpen && "max-md:hidden")}>
            {/* With A++ the select drops below the title instead of pushing past the map's width. */}
            <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
              <h2 className="text-sm font-semibold whitespace-nowrap text-chrome-ink-2">Mapa przestrzeni adresowej</h2>
              <MapRangeSelect value={mapCidr} onChange={setMapCidr} ranges={ranges} />
            </div>
            <HilbertMap cidr={mapCidr} size={392} />
            <p className="text-xs leading-relaxed text-chrome-ink-2">Punkt to jeden adres IP, kwadrat 16×16 to podsieć /24.</p>
          </div>
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

/** Consecutive identical events (e.g. five logins in a row) collapse into one row: display only, the log is untouched. */
function groupRepeats(items: AuditEvent[]) {
  const out: { e: AuditEvent; count: number }[] = [];
  for (const e of items) {
    const prev = out.at(-1);
    if (prev && prev.e.actor.id === e.actor.id && prev.e.action === e.action && prev.e.summary === e.summary && prev.e.resource_label === e.resource_label) prev.count += 1;
    else out.push({ e, count: 1 });
  }
  return out;
}

function ActivityList({ items }: { items: AuditEvent[] | undefined }) {
  return (
    <ul className="divide-y divide-line">
      {groupRepeats(items ?? []).slice(0, 7).map(({ e, count }) => (
        <li key={e.id} className="grid min-w-0 gap-0.5 px-5 py-3 text-sm">
          <span className="text-pretty text-ink">
            {e.summary}
            {/* The label is skipped when the summary already names it ("Wysłano 4 znaleziska…"). */}
            {e.resource_label && !e.summary.includes(e.resource_label) ? (
              <>
                {" "}
                <ResourceLabel label={e.resource_label} />
              </>
            ) : null}
            {count > 1 ? (
              <>
                <span className="tabular ml-1.5 text-ink-2" aria-hidden>
                  ×{count}
                </span>
                <span className="sr-only">, {countLabel(count, ["raz", "razy", "razy"])}</span>
              </>
            ) : null}
          </span>
          <span className="flex items-center gap-1.5 text-xs text-ink-2">
            {e.actor.id === "system" ? <Radar className="size-3.5 shrink-0" aria-hidden /> : null}
            <span>
              {e.actor.name},{" "}
              <time dateTime={e.at} title={fmtSmart(e.at)}>
                {fmtRelative(e.at)}
              </time>
            </span>
          </span>
        </li>
      ))}
      {!items ? (
        <li className="grid gap-3 p-5">
          <Skeleton className="h-10" />
          <Skeleton className="h-10" />
          <Skeleton className="h-10" />
        </li>
      ) : null}
    </ul>
  );
}

export function DashboardView() {
  const router = useRouter();
  const qc = useQueryClient();
  const can = useCan();
  const download = useDownload();
  // Map ranges: the CIDR targets being monitored (/16 or smaller); the built-in sample
  // ranges only when there are none (e.g. the mock backend before any import).
  const cidrTargets = useQuery({
    queryKey: ["targets", "map-ranges"],
    queryFn: () => api.targets.list({ type: "cidr", page_size: 50, sort: "value" }),
    enabled: can("targets:read"),
  });
  const ranges = React.useMemo(() => {
    const own = (cidrTargets.data?.items ?? [])
      .filter((t) => !t.excluded && Number(t.value.split("/")[1]) >= 16 && !t.value.includes(":"))
      .map((t) => ({ cidr: t.value, label: t.name ?? "" }));
    return own.length ? own : MAP_RANGES;
  }, [cidrTargets.data]);
  const [pickedCidr, setMapCidr] = React.useState<string | null>(null);
  const mapCidr = pickedCidr && ranges.some((r) => r.cidr === pickedCidr) ? pickedCidr : ranges[0].cidr;
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
  // 20 events in, at most 7 rows out: repeated events (e.g. a run of logins) collapse and must not empty the list.
  const activity = useQuery({ queryKey: ["audit", "recent"], queryFn: () => api.audit.list({ page_size: 20 }), enabled: can("audit:read") });
  const recentScans = useQuery({ queryKey: ["scans", "recent"], queryFn: () => api.scans.list({ page_size: 6 }), enabled: !can("audit:read") && can("scans:read") });

  return (
    <>
      <Hero s={summary.data} mapCidr={mapCidr} setMapCidr={setMapCidr} ranges={ranges} />
      <Container className="grid gap-6 py-8">
        {summary.isError ? <ErrorState error={summary.error} onRetry={() => summary.refetch()} /> : null}
        <GettingStarted s={summary.data} />

        {can("findings:read") ? (
          <Panel
            id="top-findings"
            title="Najważniejsze znaleziska"
            flush
            actions={
              <>
                <Button asChild variant="ghost" size="sm">
                  <Link href="/findings">Wszystkie znaleziska</Link>
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
            <div className="grid grid-cols-2 gap-2 border-b border-line px-5 py-3 sm:flex sm:flex-wrap sm:items-center">
              <SearchInput value={q} onChange={setQ} placeholder="Szukaj po IP, domenie, technologii…" className="col-span-2 sm:w-80" />
              <SimpleSelect aria-label="Status zmiany" className="w-full sm:w-48" value={change} onChange={setChange} allLabel="Każdy status zmiany" options={CHANGE_FILTERS} />
              <SimpleSelect
                aria-label="Kategoria"
                className="w-full sm:w-56"
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
              empty={<EmptyState title="Brak znalezisk dla tych filtrów." description="Zmień kryteria albo wyczyść wyszukiwanie." />}
            />
          </Panel>
        ) : null}

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          {can("changes:read") ? (
            <Panel title="Zmiany w kolejnych skanach">
              {timeline.data ? (
                <ChangesTimeline points={timeline.data} height={240} onSelect={(p) => router.push(`/changes?head=${p.scan_id}`)} selected={timeline.data.at(-1)?.scan_number} />
              ) : (
                <Skeleton className="h-72" />
              )}
            </Panel>
          ) : null}
          {can("changes:read") ? (
            <Panel title="Kiedy odpowiadają hosty niestabilne" description="Ostatnie 4 tygodnie">
              {heat.data ? <AvailabilityHeatmap matrix={heat.data.matrix} /> : <Skeleton className="h-72" />}
            </Panel>
          ) : null}
        </div>

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          {can("assets:read") ? (
            <Panel title="Technologie i CMS">
              {tech.data ? <TechBars items={tech.data} onSelect={(t) => router.push(`/assets?tab=services&q=${encodeURIComponent(t.name)}`)} /> : <Skeleton className="h-64" />}
            </Panel>
          ) : null}
          {can("audit:read") ? (
            <Panel
              title="Ostatnia aktywność"
              actions={
                <Button asChild size="sm" variant="ghost">
                  <Link href="/admin/audit">Dziennik zdarzeń</Link>
                </Button>
              }
              flush
            >
              <ActivityList items={activity.data?.items} />
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
