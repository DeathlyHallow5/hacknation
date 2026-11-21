"use client";

import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeftRight, Info, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { EmptyState, ErrorState, Guard, MonoValue, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { Pagination } from "@/components/data/data-table";
import { ChangeChip, ConfidenceMeter, ResponsePattern } from "@/components/data/status";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/form-controls";
import { Panel, Skeleton, Spinner } from "@/components/ui/misc";
import { SimpleSelect } from "@/components/ui/select";
import { FieldDiff } from "@/components/viz/bits";
import { ChangesTimeline, KIND_COLOR, KIND_ORDER } from "@/components/viz/changes-timeline";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ChangeKind, UnstableHost } from "@/lib/api/types";
import { fmtDayMonth, fmtNumber, fmtPercent, fmtRelative } from "@/lib/format";
import { CHANGE_LABEL_PLURAL } from "@/lib/labels";
import { cn } from "@/lib/utils";

function HourBars({ values }: { values: (number | null)[] }) {
  return (
    <span className="flex h-6 items-end gap-px" role="img" aria-label="Odsetek odpowiedzi według godziny doby">
      {values.map((v, h) => (
        <span
          key={h}
          title={`${String(h).padStart(2, "0")}:00 — ${v === null ? "brak pomiarów" : fmtPercent(v)}`}
          className={cn("w-1.5 rounded-t-[2px]", h >= 22 || h < 6 ? "bg-ink-3" : "bg-data")}
          style={{ height: `${Math.max(8, (v ?? 0) * 100)}%`, opacity: v === null ? 0.25 : 1 }}
        />
      ))}
    </span>
  );
}

function UnstablePanel() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["unstable"], queryFn: api.hosts.unstable, refetchInterval: (query) => (query.state.data?.some((u) => u.recheck_pending) ? 3000 : false) });
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings.get });
  const recheck = async (u: UnstableHost) => {
    try {
      await api.hosts.recheck(u.host_id);
      qc.invalidateQueries({ queryKey: ["unstable"] });
      toast.success(`Zlecono pomiar ${u.ip}`, { description: "Wynik pojawi się za kilka sekund." });
    } catch (e) {
      toast.error("Nie udało się zlecić pomiaru", { description: errorMessage(e) });
    }
  };
  return (
    <Panel
      title="Hosty niestabilne"
      description={`Odpowiadają nieregularnie, więc zmiana może być szumem. Host staje się nieaktywny po ${settings.data?.change_detection.inactive_after_misses ?? 3} skanach bez odpowiedzi; pomiar można powtórzyć w ciągu dnia.`}
      bodyClassName="p-0"
    >
      <ul className="scroll-quiet max-h-[34rem] divide-y divide-line overflow-y-auto">
        {(q.data ?? []).slice(0, 40).map((u) => (
          <li key={u.host_id} className="grid gap-2 px-5 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
            <div className="grid min-w-0 gap-1">
              <Link href={`/assets/${u.host_id}`} className="flex min-w-0 items-baseline gap-2 hover:underline">
                <MonoValue value={u.ip} copy={false} className="font-semibold" />
                {u.hostname ? <span className="truncate text-xs text-ink-2">{u.hostname}</span> : null}
              </Link>
              <span className="flex flex-wrap items-center gap-3">
                <ResponsePattern pattern={u.pattern} />
                <span className="text-xs text-ink-2">{fmtPercent(u.response_rate)} odpowiedzi</span>
                <HourBars values={u.by_hour} />
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-ink-2">{u.last_recheck_at ? `pomiar ${fmtRelative(u.last_recheck_at)}` : "bez pomiarów w dzień"}</span>
              <Guard permission="assets:recheck">
                <Button size="sm" variant="secondary" disabled={u.recheck_pending} onClick={() => recheck(u)}>
                  {u.recheck_pending ? <Spinner /> : <RefreshCw />} {u.recheck_pending ? "Mierzę…" : "Ponów pomiar"}
                </Button>
              </Guard>
            </div>
          </li>
        ))}
        {!q.data ? (
          <li className="grid gap-2 p-5">
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
          </li>
        ) : null}
      </ul>
      <p className="flex items-center gap-2 border-t border-line px-5 py-3 text-xs text-ink-2">
        <Info className="size-3.5" aria-hidden /> Szare słupki to godziny okna nocnego 22:00–06:00.
      </p>
    </Panel>
  );
}

export function ChangesView() {
  const params = useSearchParams();
  const router = useRouter();
  const [head, setHead] = React.useState(params.get("head") ?? "");
  const [base, setBase] = React.useState(params.get("base") ?? "");
  const [kinds, setKinds] = React.useState<Set<ChangeKind>>(new Set(params.get("kind") ? [params.get("kind") as ChangeKind] : []));
  const [q, setQ] = React.useState("");
  const [onlySure, setOnlySure] = React.useState(false);
  const [page, setPage] = React.useState(1);
  const dq = useDebouncedValue(q);

  const runs = useQuery({ queryKey: ["scans", "completed"], queryFn: () => api.scans.list({ status: "completed", source: "scanner", page_size: 60 }) });
  const timeline = useQuery({ queryKey: ["changes-timeline"], queryFn: () => api.dashboard.changesTimeline({ limit: 30 }) });
  const diff = useQuery({
    queryKey: ["diff", head, base, [...kinds].join(","), dq, onlySure, page],
    queryFn: () => api.diffs.get({ head, base, kind: [...kinds].join(","), q: dq, min_confidence: onlySure ? 0.7 : "", page, page_size: 30 }),
    placeholderData: keepPreviousData,
  });
  const d = diff.data;
  const runOptions = (runs.data?.items ?? []).map((r) => ({ value: r.id, label: `#${r.number} — ${fmtDayMonth(r.finished_at)}` }));

  const setPair = (h: string, b = "") => {
    setHead(h);
    setBase(b);
    setPage(1);
    const sp = new URLSearchParams();
    if (h) sp.set("head", h);
    if (b) sp.set("base", b);
    router.replace(`/changes${sp.toString() ? `?${sp}` : ""}`, { scroll: false });
  };
  const toggleKind = (k: ChangeKind) => {
    setKinds((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
    setPage(1);
  };

  return (
    <Container className="pb-12">
      <PageHeader
        title="Zmiany"
        description="Porównanie dwóch przebiegów skanowania: co się pojawiło, zniknęło, zmieniło lub odpowiada nieregularnie. Pewność zmiany uwzględnia powtórne pomiary."
      />
      <div className="grid gap-6">
        <Panel bodyClassName="grid gap-5">
          <div className="flex flex-wrap items-end gap-3">
            <label className="grid gap-1.5">
              <span className="text-[0.8125rem] font-semibold text-ink-2">Skan bazowy</span>
              <SimpleSelect aria-label="Skan bazowy" className="w-56" value={base || d?.base.id || ""} onChange={(v) => setPair(head || d?.head.id || "", v)} options={runOptions} />
            </label>
            <span className="grid h-9 place-items-center px-1 text-ink-3" aria-hidden>
              <ArrowLeftRight className="size-4" />
            </span>
            <label className="grid gap-1.5">
              <span className="text-[0.8125rem] font-semibold text-ink-2">Skan porównywany</span>
              <SimpleSelect aria-label="Skan porównywany" className="w-56" value={head || d?.head.id || ""} onChange={(v) => setPair(v)} options={runOptions} />
            </label>
            <Button variant="ghost" onClick={() => setPair("")}>
              Ostatnie dwa skany
            </Button>
          </div>
          {d ? (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {KIND_ORDER.map((k) => {
                const active = kinds.has(k);
                return (
                  <button
                    key={k}
                    type="button"
                    aria-pressed={active}
                    onClick={() => toggleKind(k)}
                    className={cn(
                      "grid gap-1 rounded-xl border p-4 text-left transition-colors",
                      active ? "border-ink bg-surface-2 ring-1 ring-ink" : "border-line hover:border-line-strong",
                    )}
                  >
                    <span className="flex items-center gap-2 text-sm font-semibold text-ink-2">
                      <span className="size-2.5 rounded-[3px]" style={{ background: KIND_COLOR[k] }} aria-hidden />
                      {CHANGE_LABEL_PLURAL[k]}
                    </span>
                    <span className="tabular text-3xl font-extrabold">{fmtNumber(d.summary[k])}</span>
                    <span className="text-xs text-ink-2">{active ? "Filtr aktywny — kliknij, aby usunąć" : "Kliknij, aby filtrować"}</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <Skeleton className="h-24" />
          )}
          {timeline.data ? <ChangesTimeline points={timeline.data} height={150} selected={d?.head.number} onSelect={(p) => setPair(p.scan_id)} /> : null}
        </Panel>

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
          <Panel
            title={d ? `Skan #${d.base.number} → #${d.head.number}` : "Lista zmian"}
            description={d ? `${fmtNumber(d.total)} zmian po filtrach.` : undefined}
            bodyClassName="p-0"
            actions={
              <label className="flex items-center gap-2 text-[0.8125rem] font-semibold text-ink-2">
                <Switch checked={onlySure} onCheckedChange={(c) => { setOnlySure(c); setPage(1); }} /> Tylko pewne (≥ 70%)
              </label>
            }
          >
            <div className="border-b border-line px-5 py-3">
              <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="IP, domena lub opis zmiany…" className="w-full sm:w-80" />
            </div>
            {diff.isError ? <ErrorState className="m-4" error={diff.error} onRetry={() => diff.refetch()} /> : null}
            <ul className={cn("divide-y divide-line", diff.isFetching && "opacity-60")}>
              {(d?.items ?? []).map((c) => (
                <li key={c.id} className="grid gap-2.5 px-5 py-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="grid min-w-0 gap-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <ChangeChip state={c.kind} measurements={c.measurements} />
                        <span className="font-semibold">{c.summary}</span>
                      </span>
                      <Link href={`/assets/${c.host_id}${c.port ? `#svc-${c.port}` : ""}`} className="flex min-w-0 items-baseline gap-2 text-sm hover:underline">
                        <MonoValue value={`${c.ip}${c.port ? `:${c.port}` : ""}`} copy={false} className="font-semibold text-link" />
                        {c.hostname ? <span className="truncate text-xs text-ink-2">{c.hostname}</span> : null}
                      </Link>
                    </div>
                    <div className="grid justify-items-end gap-0.5">
                      <span className="text-xs text-ink-2">Pewność zmiany</span>
                      <ConfidenceMeter value={c.confidence} compact />
                    </div>
                  </div>
                  <FieldDiff fields={c.fields} />
                </li>
              ))}
            </ul>
            {d && !d.items.length ? <EmptyState title="Brak zmian dla wybranych filtrów" description="Zmień parę skanów albo wyłącz filtry." /> : null}
            {d ? <Pagination page={page} pageSize={30} total={d.total} onPage={setPage} /> : null}
          </Panel>
          <UnstablePanel />
        </div>
      </div>
    </Container>
  );
}
