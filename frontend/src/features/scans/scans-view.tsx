"use client";

import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ellipsis, FileUp, Plus, Trash2 } from "lucide-react";
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
import { Segmented } from "@/components/ui/form-controls";
import { Panel, Progress, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { ConfirmDialog, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { ProfilesTab } from "@/features/scans/profiles-tab";
import { SchedulesTab } from "@/features/scans/schedules-tab";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ScanRun } from "@/lib/api/types";
import { countLabel, fmtDuration, fmtNumber, fmtPercent, fmtSmart } from "@/lib/format";
import { CHANGE_COUNT_FORMS } from "@/lib/labels";
import { useCan } from "@/lib/session";

const STATUS_FILTERS = [
  { value: "running,paused,paused_window", label: "W toku i wstrzymane" },
  { value: "completed", label: "Zakończone" },
  { value: "cancelled,failed", label: "Przerwane i błędy" },
];

/** "12 480 hostów +34 ~19 −7": the signs carry the meaning, colour only repeats it; the full sentence goes to screen readers. */
function RunResults({ s }: { s: ScanRun }) {
  const st = s.stats;
  const hosts = countLabel(st.hosts_alive, ["host", "hosty", "hostów"]);
  const spoken = [hosts, st.new ? countLabel(st.new, CHANGE_COUNT_FORMS.new) : null, st.changed ? countLabel(st.changed, CHANGE_COUNT_FORMS.changed) : null, st.gone ? countLabel(st.gone, CHANGE_COUNT_FORMS.gone) : null]
    .filter(Boolean)
    .join(", ");
  return (
    // Hosts and the change counts wrap as two units, so a narrow column breaks between them, never inside one.
    <span className="tabular text-sm" title={spoken}>
      <span aria-hidden className="inline-flex flex-wrap gap-x-2">
        <span className="whitespace-nowrap text-ink">{hosts}</span>
        <span className="inline-flex gap-2 whitespace-nowrap">
          {st.new ? <span className="text-new-ink">+{st.new}</span> : null}
          {st.changed ? <span className="text-changed-ink">~{st.changed}</span> : null}
          {st.gone ? <span className="text-gone-ink">−{st.gone}</span> : null}
        </span>
      </span>
      <span className="sr-only">{spoken}</span>
    </span>
  );
}

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

  const results = (s: ScanRun) =>
    s.status === "completed" && s.source === "scanner" ? (
      <RunResults s={s} />
    ) : s.source === "import" ? (
      <span className="tabular text-sm">{countLabel(s.stats.hosts_alive, ["host", "hosty", "hostów"])} z pliku</span>
    ) : (
      <span className="tabular text-sm text-ink-2">{s.status === "running" ? `${fmtPercent(s.progress)}, ${fmtNumber(s.rate_rps)} zapytań/s` : "—"}</span>
    );

  // Columns give way by width: range from xl, start and duration from lg, status and results get their own
  // columns from md; on phones they sit under the scan name.
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
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-1 md:hidden">
            <ScanStatusChip value={s.status} />
            {results(s)}
          </span>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      hideBelow: "md",
      cell: (s) => (
        <div className="grid min-w-32 gap-1.5">
          <ScanStatusChip value={s.status} />
          {s.status === "running" || s.status === "paused" || s.status === "paused_window" ? <Progress value={s.progress} className="h-1.5" label={`Postęp skanu ${s.number}`} /> : null}
        </div>
      ),
    },
    { key: "targets", header: "Zakres", hideBelow: "xl", cell: (s) => <span className="text-sm whitespace-nowrap text-ink-2">{s.targets_label}</span> },
    { key: "started", header: "Start", hideBelow: "lg", cell: (s) => <span className="text-sm whitespace-nowrap">{fmtSmart(s.started_at)}</span> },
    {
      key: "duration",
      header: "Czas trwania",
      hideBelow: "xl",
      cell: (s) => (
        <span className="text-sm whitespace-nowrap">
          {s.source === "import" ? "—" : fmtDuration(s.duration_s)}
          {s.windows_used > 1 ? <span className="ml-1 text-ink-2">({countLabel(s.windows_used, ["okno", "okna", "okien"])})</span> : null}
        </span>
      ),
    },
    {
      key: "changes",
      header: "Wyniki",
      hideBelow: "md",
      cell: results,
    },
    {
      key: "actions",
      header: <span className="sr-only">Akcje</span>,
      cell: (s) => (
        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          {/* On phones the whole row opens the scan; only the menu stays. */}
          <Button size="sm" variant="ghost" className="hidden md:inline-flex" asChild>
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
    <Panel flush>
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
          <TabsTrigger value="runs">Przebiegi</TabsTrigger>
          <TabsTrigger value="schedules">Harmonogramy</TabsTrigger>
          <TabsTrigger value="profiles">Profile</TabsTrigger>
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
