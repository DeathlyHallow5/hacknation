"use client";

import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Ellipsis, FileUp, Gauge, Pencil, Plus, Radar, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { EmptyState, ErrorState, Guard } from "@/components/data/bits";
import { DataTable, Pagination, type Column } from "@/components/data/data-table";
import { ScanStatusChip } from "@/components/data/status";
import { ImportWizard } from "@/components/edit/import-wizard";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Segmented, Slider, Switch } from "@/components/ui/form-controls";
import { Chip, Panel, Progress, Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import {
  ConfirmDialog,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ScanProfile, ScanRun, Schedule } from "@/lib/api/types";
import { fmtDuration, fmtNumber, fmtPercent, fmtSmart } from "@/lib/format";
import { useApiMutation } from "@/lib/hooks";
import { WEEKDAYS } from "@/lib/labels";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

const STATUS_FILTERS = [
  { value: "running,paused,paused_window", label: "W toku i wstrzymane" },
  { value: "completed", label: "Zakończone" },
  { value: "cancelled,failed", label: "Przerwane i błędy" },
];

function RunsTab({ onImport }: { onImport: () => void }) {
  const router = useRouter();
  const qc = useQueryClient();
  const can = useCan();
  const [status, setStatus] = React.useState("");
  const [source, setSource] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [toDelete, setToDelete] = React.useState<ScanRun | null>(null);
  const q = useQuery({
    queryKey: ["scans", status, source, page],
    queryFn: () => api.scans.list({ status, source, page, page_size: 15 }),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => (query.state.data?.items.some((s) => s.status === "running") ? 3000 : false),
  });

  const columns: Column<ScanRun>[] = [
    {
      key: "number",
      header: "Skan",
      cell: (s) => (
        <div className="grid gap-0.5">
          <span className="font-semibold">
            #{s.number} {s.name}
          </span>
          <span className="text-xs text-ink-2">{s.source === "import" ? "Import wyników z pliku" : s.profile_name ? `Profil: ${s.profile_name}` : "—"}</span>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (s) => (
        <div className="grid min-w-32 gap-1.5">
          <ScanStatusChip value={s.status} />
          {s.status === "running" || s.status === "paused" || s.status === "paused_window" ? <Progress value={s.progress} className="h-1.5" label={`Postęp skanu ${s.number}`} /> : null}
        </div>
      ),
    },
    { key: "targets", header: "Zakres", hideBelow: "lg", cell: (s) => <span className="text-[0.8125rem] text-ink-2">{s.targets_label}</span> },
    { key: "started", header: "Start", hideBelow: "md", cell: (s) => <span className="text-[0.8125rem] whitespace-nowrap">{fmtSmart(s.started_at)}</span> },
    {
      key: "duration",
      header: "Czas trwania",
      hideBelow: "md",
      cell: (s) => (
        <span className="text-[0.8125rem] whitespace-nowrap">
          {s.source === "import" ? "—" : fmtDuration(s.duration_s)}
          {s.windows_used > 1 ? <span className="ml-1 text-ink-2">({s.windows_used} okna)</span> : null}
        </span>
      ),
    },
    {
      key: "changes",
      header: "Wyniki",
      cell: (s) =>
        s.status === "completed" && s.source === "scanner" ? (
          <span className="flex flex-wrap gap-1 text-xs">
            <Chip tone="outline" className="tabular">{fmtNumber(s.stats.hosts_alive)} hostów</Chip>
            {s.stats.new ? <Chip className="bg-new-soft text-new-ink">+{s.stats.new}</Chip> : null}
            {s.stats.changed ? <Chip className="bg-changed-soft text-changed-ink">~{s.stats.changed}</Chip> : null}
            {s.stats.gone ? <Chip className="bg-gone-soft text-gone-ink">−{s.stats.gone}</Chip> : null}
          </span>
        ) : s.source === "import" ? (
          <Chip tone="outline">{fmtNumber(s.stats.hosts_alive)} hostów z pliku</Chip>
        ) : (
          <span className="text-[0.8125rem] text-ink-2">{s.status === "running" ? `${fmtPercent(s.progress)}, ${fmtNumber(s.rate_rps)} zapytań/s` : "—"}</span>
        ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Akcje</span>,
      cell: (s) => (
        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="secondary" asChild>
            <Link href={`/scans/${s.id}`}>{s.status === "running" ? "Podgląd na żywo" : "Szczegóły"}</Link>
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="icon-sm" variant="ghost" aria-label={`Więcej działań dla skanu ${s.number}`}>
                <Ellipsis />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem disabled={s.status !== "completed" || s.source !== "scanner"} onSelect={() => router.push(`/changes?head=${s.id}`)}>
                Porównaj z poprzednim
              </DropdownMenuItem>
              <DropdownMenuItem destructive disabled={!can("scans:delete")} onSelect={() => setToDelete(s)}>
                <Trash2 /> Usuń z historii
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  return (
    <Panel bodyClassName="p-0">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
        <SimpleSelect aria-label="Status" className="w-56" value={status} onChange={(v) => { setStatus(v); setPage(1); }} allLabel="Wszystkie statusy" options={STATUS_FILTERS} />
        <Segmented
          aria-label="Źródło"
          value={source || "all"}
          onChange={(v) => {
            setSource(v === "all" ? "" : v);
            setPage(1);
          }}
          options={[
            { value: "all", label: "Wszystkie" },
            { value: "scanner", label: "Skaner" },
            { value: "import", label: "Importy" },
          ]}
        />
        <div className="ml-auto">
          <Guard permission="scans:import">
            <Button size="sm" onClick={onImport}>
              <FileUp /> Importuj wyniki skanu
            </Button>
          </Guard>
        </div>
      </div>
      {q.isError ? <ErrorState className="m-4" error={q.error} onRetry={() => q.refetch()} /> : null}
      <DataTable
        columns={columns}
        rows={q.data?.items}
        getId={(s) => s.id}
        loading={q.isFetching && !q.data}
        onRowClick={(s) => router.push(`/scans/${s.id}`)}
        caption="Przebiegi skanowania"
        empty={<EmptyState title="Brak przebiegów" description="Uruchom pierwsze skanowanie albo zaimportuj wyniki z pliku." />}
      />
      {q.data ? <Pagination page={page} pageSize={15} total={q.data.total} onPage={setPage} /> : null}
      <ConfirmDialog
        open={Boolean(toDelete)}
        onOpenChange={(o) => !o && setToDelete(null)}
        title={`Usunąć skan #${toDelete?.number}?`}
        description="Przebieg zniknie z historii i z wykresu zmian. Hosty i znaleziska pozostaną. Tej operacji nie można cofnąć."
        confirmLabel="Usuń z historii"
        onConfirm={async () => {
          try {
            await api.scans.remove(toDelete!.id);
            qc.invalidateQueries({ queryKey: ["scans"] });
            toast.success(`Usunięto skan #${toDelete!.number}`);
          } catch (e) {
            toast.error("Nie udało się usunąć", { description: errorMessage(e) });
          }
          setToDelete(null);
        }}
      />
    </Panel>
  );
}

function ScheduleSheet({ schedule, onClose }: { schedule: Schedule | null; onClose: () => void }) {
  const [last, setLast] = React.useState(schedule);
  if (schedule && schedule !== last) setLast(schedule);
  return (
    <Sheet open={Boolean(schedule)} onOpenChange={(o) => !o && onClose()}>
      <SheetContent>{last ? <ScheduleForm schedule={last} onClose={onClose} /> : null}</SheetContent>
    </Sheet>
  );
}

function ScheduleForm({ schedule, onClose }: { schedule: Schedule; onClose: () => void }) {
  const [enabled, setEnabled] = React.useState(schedule.enabled);
  const [start, setStart] = React.useState(schedule.window.start);
  const [end, setEnd] = React.useState(schedule.window.end);
  const [days, setDays] = React.useState<number[]>(schedule.days);
  const [behaviour, setBehaviour] = React.useState<Schedule["on_window_exceeded"]>(schedule.on_window_exceeded);
  const save = useApiMutation(
    () => api.schedules.update(schedule.id, { enabled, window: { ...schedule.window, start, end }, days, on_window_exceeded: behaviour }),
    { success: "Zapisano harmonogram", invalidate: [["schedules"], ["dashboard-summary"]], onSuccess: onClose },
  );
  return (
    <>
        <SheetHeader>
          <SheetTitle>{schedule.name}</SheetTitle>
          <SheetDescription>Okno czasowe, dni tygodnia i zachowanie po przekroczeniu okna.</SheetDescription>
        </SheetHeader>
        <SheetBody className="grid content-start gap-5">
          <label className="flex items-center justify-between gap-3 rounded-lg border border-line p-3">
            <span className="text-sm font-semibold">Harmonogram aktywny</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </label>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Początek okna" htmlFor="sch-start">
              <Input id="sch-start" type="time" value={start} onChange={(e) => setStart(e.target.value)} />
            </Field>
            <Field label="Koniec okna" htmlFor="sch-end" hint="Okno może przechodzić przez północ.">
              <Input id="sch-end" type="time" value={end} onChange={(e) => setEnd(e.target.value)} />
            </Field>
          </div>
          <Field label="Dni tygodnia">
            <div className="flex flex-wrap gap-1.5">
              {WEEKDAYS.map((d, i) => {
                const on = days.includes(i + 1);
                return (
                  <button
                    key={d}
                    type="button"
                    aria-pressed={on}
                    onClick={() => setDays((prev) => (on ? prev.filter((x) => x !== i + 1) : [...prev, i + 1].sort()))}
                    className={cn("h-9 w-11 rounded-lg border text-sm font-semibold transition-colors", on ? "border-accent bg-accent/12 text-ink" : "border-line-strong text-ink-2 hover:border-ink-3")}
                  >
                    {d}
                  </button>
                );
              })}
            </div>
          </Field>
          <Field label="Gdy skan nie zmieści się w oknie">
            <Segmented
              aria-label="Zachowanie po przekroczeniu okna"
              value={behaviour}
              onChange={setBehaviour}
              options={[
                { value: "pause_resume", label: "Wstrzymaj i wznów w kolejnym oknie" },
                { value: "stop", label: "Zatrzymaj" },
              ]}
            />
          </Field>
          {schedule.frequency === "cron" ? (
            <p className="rounded-lg bg-surface-2 px-3 py-2 text-[0.8125rem]">
              Wyrażenie cron: <code className="mono font-semibold">{schedule.cron}</code>
            </p>
          ) : null}
        </SheetBody>
        <SheetFooter>
          <Button variant="secondary" onClick={onClose}>
            Anuluj
          </Button>
          <Guard permission="schedules:update">
            <Button variant="primary" onClick={() => save.mutate(undefined)} disabled={save.isPending || !days.length}>
              Zapisz harmonogram
            </Button>
          </Guard>
        </SheetFooter>
    </>
  );
}

function SchedulesTab() {
  const can = useCan();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["schedules"], queryFn: api.schedules.list });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: api.profiles.list });
  const [editing, setEditing] = React.useState<Schedule | null>(null);
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {(q.data ?? []).map((s) => (
        <article key={s.id} className={cn("grid content-start gap-4 rounded-xl border border-line bg-surface p-5", !s.enabled && "opacity-70")}>
          <div className="flex items-start justify-between gap-3">
            <div className="grid gap-1">
              <h3 className="font-bold">{s.name}</h3>
              <p className="text-[0.8125rem] text-ink-2">Profil: {profiles.data?.find((p) => p.id === s.profile_id)?.name ?? "—"}</p>
            </div>
            <Switch
              aria-label={`Włącz harmonogram ${s.name}`}
              checked={s.enabled}
              disabled={!can("schedules:update")}
              onCheckedChange={async (c) => {
                await api.schedules.update(s.id, { enabled: c });
                qc.invalidateQueries({ queryKey: ["schedules"] });
                toast.success(c ? "Włączono harmonogram" : "Wyłączono harmonogram", { description: s.name });
              }}
            />
          </div>
          <div className="flex items-center gap-3 rounded-lg bg-surface-2 p-3">
            <CalendarClock className="size-5 text-link" aria-hidden />
            <div className="grid">
              <span className="tabular text-lg font-extrabold">
                {s.window.start}–{s.window.end}
              </span>
              <span className="text-xs text-ink-2">
                {s.frequency === "cron" ? `cron: ${s.cron}` : s.days.length === 7 ? "codziennie" : s.days.map((d) => WEEKDAYS[d - 1]).join(", ")}
              </span>
            </div>
          </div>
          <dl className="grid gap-1.5 text-[0.8125rem]">
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Następne uruchomienie</dt>
              <dd className="font-semibold">{s.enabled ? fmtSmart(s.next_run_at) : "wyłączony"}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Po przekroczeniu okna</dt>
              <dd className="font-semibold">{s.on_window_exceeded === "pause_resume" ? "wstrzymaj i wznów" : "zatrzymaj"}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Cele</dt>
              <dd className="font-semibold">{s.target_ids.length}</dd>
            </div>
          </dl>
          <Button size="sm" onClick={() => setEditing(s)}>
            <Pencil /> {can("schedules:update") ? "Edytuj" : "Szczegóły"}
          </Button>
        </article>
      ))}
      {!q.data ? [0, 1, 2].map((i) => <Skeleton key={i} className="h-72 rounded-xl" />) : null}
      <ScheduleSheet schedule={editing} onClose={() => setEditing(null)} />
    </div>
  );
}

function ProfileSheet({ profile, onClose }: { profile: ScanProfile | null; onClose: () => void }) {
  const [last, setLast] = React.useState(profile);
  if (profile && profile !== last) setLast(profile);
  return (
    <Sheet open={Boolean(profile)} onOpenChange={(o) => !o && onClose()}>
      <SheetContent>{last ? <ProfileForm profile={last} onClose={onClose} /> : null}</SheetContent>
    </Sheet>
  );
}

function ProfileForm({ profile, onClose }: { profile: ScanProfile; onClose: () => void }) {
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings.get });
  const [rate, setRate] = React.useState(profile.rate_limit_rps);
  const [conc, setConc] = React.useState(profile.max_concurrency);
  const [timing, setTiming] = React.useState<ScanProfile["nmap_timing"]>(profile.nmap_timing);
  const [retries, setRetries] = React.useState(profile.unstable_retries);
  const max = settings.data?.scan_safety.max_rate_rps ?? 500;
  const save = useApiMutation(() => api.profiles.update(profile.id, { rate_limit_rps: rate, max_concurrency: conc, nmap_timing: timing, unstable_retries: retries }), {
    success: "Zapisano profil",
    invalidate: [["profiles"]],
    onSuccess: onClose,
  });
  return (
    <>
        <SheetHeader>
          <SheetTitle>{profile.name}</SheetTitle>
          <SheetDescription>{profile.description}</SheetDescription>
        </SheetHeader>
        <SheetBody className="grid content-start gap-6">
          <Field label={`Limit tempa: ${fmtNumber(rate)} zapytań/s`} hint={`Globalny limit bezpieczeństwa: ${fmtNumber(max)} zapytań/s (Administracja → Ustawienia).`}>
            <Slider aria-label="Limit zapytań na sekundę" min={10} max={max} step={10} value={[Math.min(rate, max)]} onValueChange={([v]) => setRate(v)} />
          </Field>
          <Field label={`Równoległe wątki: ${conc}`}>
            <Slider aria-label="Liczba równoległych wątków" min={1} max={128} step={1} value={[conc]} onValueChange={([v]) => setConc(v)} />
          </Field>
          <Field label="Tempo nmap" hint="T2 jest najłagodniejsze — zalecane dla drukarek, kamer i kontrolerów BMC.">
            <Segmented
              aria-label="Tempo nmap"
              value={timing}
              onChange={setTiming}
              options={[
                { value: "T2", label: "T2 — ostrożnie" },
                { value: "T3", label: "T3 — standard" },
                { value: "T4", label: "T4 — szybko" },
              ]}
            />
          </Field>
          <Field label={`Powtórne pomiary hostów niestabilnych: ${retries}`} hint="Ile razy ponowić pomiar, zanim zmiana zostanie uznana za pewną.">
            <Slider aria-label="Liczba powtórzeń" min={0} max={5} step={1} value={[retries]} onValueChange={([v]) => setRetries(v)} />
          </Field>
        </SheetBody>
        <SheetFooter>
          <Button variant="secondary" onClick={onClose}>
            Anuluj
          </Button>
          <Guard permission="scans:update">
            <Button variant="primary" onClick={() => save.mutate(undefined)} disabled={save.isPending}>
              Zapisz profil
            </Button>
          </Guard>
        </SheetFooter>
    </>
  );
}

function ProfilesTab() {
  const q = useQuery({ queryKey: ["profiles"], queryFn: api.profiles.list });
  const [editing, setEditing] = React.useState<ScanProfile | null>(null);
  const can = useCan();
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {(q.data ?? []).map((p) => (
        <article key={p.id} className="grid content-start gap-3 rounded-xl border border-line bg-surface p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="grid gap-1">
              <h3 className="flex items-center gap-2 font-bold">
                {p.name} {p.builtin ? <Chip tone="outline">wbudowany</Chip> : null}
              </h3>
              <p className="text-[0.8125rem] text-ink-2">{p.description}</p>
            </div>
            <Gauge className="size-5 shrink-0 text-ink-3" aria-hidden />
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Chip>{fmtNumber(p.rate_limit_rps)} zapytań/s</Chip>
            <Chip>{p.max_concurrency} wątków</Chip>
            <Chip>nmap {p.nmap_timing}</Chip>
            <Chip>{p.ports.preset === "top100" ? "100 portów" : p.ports.preset === "top1000" ? "1000 portów" : p.ports.preset === "allowed" ? "porty dozwolone" : "porty własne"}</Chip>
            <Chip>{p.http_probe ? "HTTP/HTTPS" : "bez HTTP"}</Chip>
            <Chip>{p.signatures === "all" ? "wszystkie sygnatury" : p.signatures === "none" ? "bez sygnatur" : `${p.signature_ids.length} sygnatury`}</Chip>
            <Chip>podgrupy {p.batch_strategy === "auto" ? "automatyczne" : `/${p.batch_prefix}`}</Chip>
          </div>
          <div>
            <Button size="sm" onClick={() => setEditing(p)}>
              <Pencil /> {can("scans:update") ? "Edytuj" : "Szczegóły"}
            </Button>
          </div>
        </article>
      ))}
      {!q.data ? [0, 1].map((i) => <Skeleton key={i} className="h-48 rounded-xl" />) : null}
      <ProfileSheet profile={editing} onClose={() => setEditing(null)} />
    </div>
  );
}

export function ScansView() {
  const params = useSearchParams();
  const router = useRouter();
  const qc = useQueryClient();
  const [tab, setTab] = React.useState(params.get("tab") ?? "runs");
  const [importOpen, setImportOpen] = React.useState(params.get("import") === "1");
  return (
    <Container className="pb-12">
      <PageHeader
        title="Skanowania"
        description="Przebiegi skanowania, harmonogramy z oknami czasowymi i profile określające tempo oraz zakres sprawdzeń."
        actions={
          <Guard permission="scans:create">
            <Button variant="primary" asChild>
              <Link href="/scans/new">
                <Plus /> Nowe skanowanie
              </Link>
            </Button>
          </Guard>
        }
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="runs">
            <Radar /> Przebiegi
          </TabsTrigger>
          <TabsTrigger value="schedules">
            <CalendarClock /> Harmonogramy
          </TabsTrigger>
          <TabsTrigger value="profiles">
            <Gauge /> Profile
          </TabsTrigger>
        </TabsList>
        <TabsContent value="runs">
          <RunsTab onImport={() => setImportOpen(true)} />
        </TabsContent>
        <TabsContent value="schedules">
          <SchedulesTab />
        </TabsContent>
        <TabsContent value="profiles">
          <ProfilesTab />
        </TabsContent>
      </Tabs>
      <ImportWizard
        open={importOpen}
        onOpenChange={(o) => {
          setImportOpen(o);
          if (!o && params.get("import")) router.replace("/scans", { scroll: false });
        }}
        title="Importuj wyniki skanu"
        description="Wyniki z zewnętrznego narzędzia (np. nmap przekonwertowany do CSV/JSON). Trafią do tej samej bazy co wyniki skanera i będą porównywane tak samo."
        formatHint="CSV: ip, hostname, port, protocol, service, product, version. JSON: { hosts: [{ ip, hostnames, services: [...] }] }"
        samples={[
          { label: "wyniki.csv", href: "/samples/scan-results.csv" },
          { label: "wyniki.json", href: "/samples/scan-results.json" },
        ]}
        commit={async (fd) => {
          const run = await api.scans.import(fd);
          qc.invalidateQueries({ queryKey: ["scans"] });
          toast.success(`Zaimportowano jako skan #${run.number}`, { description: run.notes ?? undefined });
          return run.id;
        }}
      />
    </Container>
  );
}
