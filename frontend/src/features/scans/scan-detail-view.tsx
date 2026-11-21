"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, CircleStop, Download, GitCompareArrows, Pause, Pencil, Play } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard, TagInput } from "@/components/data/bits";
import { ScanStatusChip } from "@/components/data/status";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/form-controls";
import { Chip, Panel, Progress, Skeleton } from "@/components/ui/misc";
import { ConfirmDialog, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/overlays";
import { BatchGrid } from "@/components/viz/bits";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ScanBatch, ScanEvent, ScanLogLine, ScanRun } from "@/lib/api/types";
import { fmtDateTime, fmtDuration, fmtNumber, fmtPercent, fmtRelative, fmtSmart, fmtTime } from "@/lib/format";
import { useApiMutation, useDownload } from "@/lib/hooks";
import { SCAN_PHASES } from "@/lib/labels";
import { cn } from "@/lib/utils";

const LIVE = ["running", "paused", "paused_window", "queued"];

/** Live updates over Server-Sent Events (GET /scans/{id}/events). */
function useScanStream(id: string, enabled: boolean) {
  const qc = useQueryClient();
  const [scan, setScan] = React.useState<ScanRun | null>(null);
  const [logs, setLogs] = React.useState<ScanLogLine[]>([]);
  const [batches, setBatches] = React.useState<Record<number, ScanBatch>>({});
  React.useEffect(() => {
    if (!enabled) return;
    const es = new EventSource(api.scans.eventsUrl(id));
    const parse = (e: MessageEvent) => JSON.parse(e.data) as ScanEvent;
    es.addEventListener("progress", (e) => {
      const ev = parse(e as MessageEvent);
      if (ev.type === "progress") setScan(ev.scan);
    });
    es.addEventListener("log", (e) => {
      const ev = parse(e as MessageEvent);
      if (ev.type === "log") setLogs((prev) => [...prev, { at: ev.at, level: ev.level, message: ev.message }].slice(-300));
    });
    es.addEventListener("batch", (e) => {
      const ev = parse(e as MessageEvent);
      if (ev.type === "batch") setBatches((prev) => ({ ...prev, [ev.batch.index]: ev.batch }));
    });
    es.addEventListener("window", (e) => {
      const ev = parse(e as MessageEvent);
      if (ev.type !== "window") return;
      if (ev.state === "paused") toast.warning("Koniec okna czasowego — skan wstrzymany", { description: `Punkt kontrolny zapisany. Wznowienie ${fmtSmart(ev.resume_at)}.` });
      else toast.success("Nowe okno — skan wznowiony od punktu kontrolnego");
    });
    es.addEventListener("done", (e) => {
      const ev = parse(e as MessageEvent);
      if (ev.type === "done") {
        setScan(ev.scan);
        if (ev.scan.status === "completed")
          toast.success(`Skan #${ev.scan.number} zakończony`, {
            description: `${ev.scan.stats.new} nowe, ${ev.scan.stats.changed} zmienione, ${ev.scan.stats.gone} zniknęło, ${ev.scan.stats.unstable} niestabilne.`,
            // eslint-disable-next-line @next/next/no-location-assign-relative-destination
            action: { label: "Zobacz zmiany", onClick: () => (window.location.href = `/changes?head=${ev.scan.id}`) },
          });
      }
      es.close();
      for (const k of [["scan", id], ["scan-batches", id], ["scan-logs", id], ["scans"], ["dashboard-summary"], ["address-map"], ["live-scan"], ["top-findings"], ["changes-timeline"]])
        qc.invalidateQueries({ queryKey: k });
    });
    return () => es.close();
  }, [id, enabled, qc]);
  return { scan, logs, batches };
}

function PhaseStepper({ phase, done }: { phase: ScanRun["phase"]; done: boolean }) {
  const idx = done ? SCAN_PHASES.length : SCAN_PHASES.findIndex((p) => p.key === phase);
  return (
    <ol className="grid gap-2 sm:grid-cols-3 xl:grid-cols-6">
      {SCAN_PHASES.map((p, i) => {
        const state = i < idx ? "done" : i === idx ? "current" : "todo";
        return (
          <li
            key={p.key}
            aria-current={state === "current" ? "step" : undefined}
            className={cn(
              "grid gap-0.5 rounded-lg border px-3 py-2",
              state === "current" ? "border-accent bg-accent/[0.07]" : state === "done" ? "border-line bg-surface-2" : "border-dashed border-line-strong",
            )}
          >
            <span className="flex items-center gap-1.5 text-sm font-bold">
              {state === "done" ? <Check className="size-3.5 text-success" strokeWidth={3} aria-hidden /> : state === "current" ? <span className="size-2 animate-pulse-dot rounded-full bg-accent" aria-hidden /> : null}
              {p.label}
            </span>
            <span className="mono text-xs text-ink-2">{p.tool}</span>
          </li>
        );
      })}
    </ol>
  );
}

function LogConsole({ logs }: { logs: ScanLogLine[] }) {
  const ref = React.useRef<HTMLDivElement>(null);
  React.useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight });
  }, [logs.length]);
  return (
    <div ref={ref} className="scroll-quiet max-h-80 overflow-y-auto rounded-lg bg-chrome p-4 text-chrome-ink" role="log" aria-live="polite" aria-label="Dziennik skanowania">
      {logs.length === 0 ? <p className="text-sm text-chrome-ink-2">Brak wpisów.</p> : null}
      <ol className="grid gap-1">
        {logs.map((l, i) => (
          <li key={i} className="mono grid grid-cols-[4.5rem_1fr] gap-3 text-sm leading-relaxed">
            <span className="text-chrome-ink-2">{fmtTime(l.at)}</span>
            <span className={cn(l.level === "warn" && "text-[#f7c35f]", l.level === "error" && "text-[#ff8a8f]")}>{l.message}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function EditScanSheet({ scan, open, onOpenChange }: { scan: ScanRun; open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <EditScanForm scan={scan} onOpenChange={onOpenChange} />
      </SheetContent>
    </Sheet>
  );
}

function EditScanForm({ scan, onOpenChange }: { scan: ScanRun; onOpenChange: (o: boolean) => void }) {
  const [name, setName] = React.useState(scan.name);
  const [notes, setNotes] = React.useState(scan.notes ?? "");
  const [tags, setTags] = React.useState(scan.tags);
  const save = useApiMutation(() => api.scans.update(scan.id, { name, notes: notes || null, tags }), {
    success: "Zapisano zmiany skanu",
    invalidate: [["scan", scan.id], ["scans"]],
    onSuccess: () => onOpenChange(false),
  });
  return (
    <>
        <SheetHeader>
          <SheetTitle>Edytuj skan #{scan.number}</SheetTitle>
          <SheetDescription>Nazwę, notatki i tagi możesz zmieniać w każdej chwili — także w trakcie skanowania.</SheetDescription>
        </SheetHeader>
        <SheetBody className="grid content-start gap-4">
          <Field label="Nazwa" htmlFor="sc-name">
            <Input id="sc-name" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Tagi" htmlFor="sc-tags">
            <TagInput id="sc-tags" value={tags} onChange={setTags} />
          </Field>
          <Field label="Notatki" htmlFor="sc-notes">
            <Textarea id="sc-notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
          </Field>
        </SheetBody>
        <SheetFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Anuluj
          </Button>
          <Button variant="primary" onClick={() => save.mutate(undefined)} disabled={save.isPending || !name.trim()}>
            Zapisz zmiany
          </Button>
        </SheetFooter>
    </>
  );
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: React.ReactNode }) {
  return (
    <div className="grid gap-0.5">
      <span className="text-sm text-ink-2">{label}</span>
      <span className="tabular text-xl font-extrabold">{value}</span>
      {hint ? <span className="text-xs text-ink-2">{hint}</span> : null}
    </div>
  );
}

export function ScanDetailView({ id }: { id: string }) {
  const qc = useQueryClient();
  const download = useDownload();
  const base = useQuery({ queryKey: ["scan", id], queryFn: () => api.scans.get(id) });
  const live = base.data ? LIVE.includes(base.data.status) : false;
  const stream = useScanStream(id, live);
  const scan = stream.scan ?? base.data;
  const isLive = scan ? LIVE.includes(scan.status) : false;
  const batchesQ = useQuery({ queryKey: ["scan-batches", id], queryFn: () => api.scans.batches(id), enabled: Boolean(base.data), refetchInterval: isLive ? 4000 : false });
  const logsQ = useQuery({ queryKey: ["scan-logs", id], queryFn: () => api.scans.logs(id), enabled: Boolean(base.data) });
  const [editOpen, setEditOpen] = React.useState(false);
  const [confirmCancel, setConfirmCancel] = React.useState(false);

  const batches = React.useMemo(() => {
    const list = (batchesQ.data ?? []).slice();
    for (const b of Object.values(stream.batches)) list[b.index] = b;
    return list;
  }, [batchesQ.data, stream.batches]);
  const logs = React.useMemo(() => {
    const seen = new Set<string>();
    return [...(logsQ.data ?? []), ...stream.logs]
      .filter((l) => {
        const k = l.at + l.message;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .sort((a, b) => a.at.localeCompare(b.at));
  }, [logsQ.data, stream.logs]);

  const control = async (action: "pause" | "resume" | "cancel") => {
    try {
      const s = await api.scans[action](id);
      qc.setQueryData(["scan", id], s);
      qc.invalidateQueries({ queryKey: ["live-scan"] });
      toast.success(action === "pause" ? "Skan wstrzymany" : action === "resume" ? "Skan wznowiony" : "Skan przerwany");
    } catch (e) {
      toast.error("Operacja nie powiodła się", { description: errorMessage(e) });
    }
  };

  if (base.isError) return <Container className="py-8"><ErrorState error={base.error} onRetry={() => base.refetch()} /></Container>;
  if (!scan) return <Container className="grid gap-4 py-8"><Skeleton className="h-10 w-80" /><Skeleton className="h-64" /></Container>;

  return (
    <Container className="pb-12">
      <PageHeader
        back={{ href: "/scans", label: "Skanowania" }}
        title={`#${scan.number} ${scan.name}`}
        description={scan.notes ?? undefined}
        meta={
          <>
            <ScanStatusChip value={scan.status} />
            <Chip tone="outline">{scan.targets_label}</Chip>
            {scan.profile_name ? <Chip tone="outline">Profil: {scan.profile_name}</Chip> : null}
            {scan.tags.map((t) => (
              <Chip key={t} tone="outline">#{t}</Chip>
            ))}
          </>
        }
        actions={
          <>
            <Guard permission="scans:update">
              <Button onClick={() => setEditOpen(true)}>
                <Pencil /> Edytuj
              </Button>
            </Guard>
            {isLive ? (
              <>
                {scan.status === "running" ? (
                  <Guard permission="scans:control">
                    <Button onClick={() => control("pause")}>
                      <Pause /> Wstrzymaj
                    </Button>
                  </Guard>
                ) : (
                  <Guard permission="scans:control">
                    <Button variant="primary" onClick={() => control("resume")}>
                      <Play /> {scan.status === "paused_window" ? "Wznów teraz" : "Wznów"}
                    </Button>
                  </Guard>
                )}
                <Guard permission="scans:control">
                  <Button variant="danger" onClick={() => setConfirmCancel(true)}>
                    <CircleStop /> Przerwij
                  </Button>
                </Guard>
              </>
            ) : (
              <>
                {scan.status === "completed" && scan.source === "scanner" ? (
                  <Button asChild>
                    <Link href={`/changes?head=${scan.id}`}>
                      <GitCompareArrows /> Zmiany względem poprzedniego
                    </Link>
                  </Button>
                ) : null}
                <Guard permission="scans:export">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button>
                        <Download /> Eksport wyników
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuItem onSelect={() => download(() => api.scans.export(scan.id, "json"), "Pobrano wyniki (JSON)")}>JSON</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => download(() => api.scans.export(scan.id, "csv"), "Pobrano wyniki (CSV)")}>CSV</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </Guard>
              </>
            )}
          </>
        }
      />

      <div className="grid gap-6">
        <Panel
          title={isLive ? "Postęp na żywo" : "Przebieg"}
          description={
            isLive
              ? scan.status === "paused_window"
                ? `Okno czasowe zamknięte — skan wznowi się ${fmtSmart(scan.resume_at)} od ostatniej ukończonej podgrupy.`
                : scan.window_ends_at
                  ? `Okno zamyka się ${fmtRelative(scan.window_ends_at)}; po jego końcu skan zapisze punkt kontrolny.`
                  : "Aktualizacje przez Server-Sent Events, co sekundę."
              : `Start ${fmtDateTime(scan.started_at)}, koniec ${fmtDateTime(scan.finished_at)}.`
          }
        >
          <div className="grid gap-6">
            <div className="grid gap-2">
              <div className="flex items-baseline justify-between gap-3">
                <span className="tabular text-4xl font-extrabold tracking-tight">{fmtPercent(scan.progress)}</span>
                <span className="text-sm text-ink-2">
                  podgrupa {fmtNumber(scan.batches_done)} z {fmtNumber(scan.batches_total)}
                </span>
              </div>
              <Progress value={scan.progress} className="h-3" barClassName={scan.status === "paused_window" || scan.status === "paused" ? "bg-unstable" : undefined} label="Postęp skanowania" />
            </div>
            <div className="grid grid-cols-2 gap-5 md:grid-cols-5">
              <Stat label="Tempo" value={`${fmtNumber(scan.rate_rps)}/s`} hint={`limit ${fmtNumber(scan.rate_limit_rps)} zapytań/s`} />
              <Stat label="Czas trwania" value={fmtDuration(scan.duration_s)} hint={scan.windows_used > 1 ? `${scan.windows_used} okna czasowe` : scan.window ? `okno ${scan.window.start}–${scan.window.end}` : undefined} />
              <Stat label={isLive ? "Pozostało" : "Adresy"} value={isLive ? (scan.eta_s !== null ? fmtDuration(scan.eta_s) : "—") : fmtNumber(scan.address_count)} />
              <Stat label="Aktywne hosty" value={fmtNumber(scan.stats.hosts_alive)} hint={!isLive ? `${fmtNumber(scan.stats.services)} usług` : "dotychczas"} />
              <Stat
                label="Zmiany"
                value={scan.status === "completed" ? fmtNumber(scan.stats.new + scan.stats.changed + scan.stats.gone + scan.stats.unstable) : "—"}
                hint={scan.status === "completed" ? `${scan.stats.new} nowe, ${scan.stats.changed} zmienione, ${scan.stats.gone} zniknęło` : "po zakończeniu"}
              />
            </div>
            {scan.source === "scanner" ? <PhaseStepper phase={scan.phase} done={scan.status === "completed"} /> : null}
          </div>
        </Panel>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Panel title="Podgrupy adresów" description="Adresy podzielone na podgrupy według przepustowości. Po przekroczeniu okna skan wraca do pierwszej nieukończonej podgrupy.">
            {batches.length ? <BatchGrid batches={batches} /> : <Skeleton className="h-40" />}
          </Panel>
          <Panel title="Dziennik skanowania" description="Fazy, podgrupy, okna czasowe i decyzje silnika.">
            <LogConsole logs={logs} />
          </Panel>
        </div>
      </div>

      <EditScanSheet scan={scan} open={editOpen} onOpenChange={setEditOpen} />
      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title={`Przerwać skan #${scan.number}?`}
        description="Wyniki zebrane do tej pory zostaną zachowane, ale porównanie zmian nie zostanie wykonane."
        confirmLabel="Przerwij skan"
        onConfirm={() => {
          setConfirmCancel(false);
          void control("cancel");
        }}
      />
    </Container>
  );
}
