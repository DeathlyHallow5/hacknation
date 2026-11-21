"use client";

import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Download, Ellipsis, FileUp, Pencil, Plus, RotateCcw, Tag, Trash2 } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { EmptyState, ErrorState, Guard, MonoValue, SearchInput, TagInput, TagList, useDebouncedValue } from "@/components/data/bits";
import { DataTable, Pagination, type Column } from "@/components/data/data-table";
import { ImportWizard } from "@/components/edit/import-wizard";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Switch, Textarea } from "@/components/ui/form-controls";
import { Chip, Panel } from "@/components/ui/misc";
import {
  ConfirmDialog,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
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
import { AddTargetsDialog } from "@/features/targets/add-targets-dialog";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Criticality, Target, TargetType } from "@/lib/api/types";
import { countLabel, fmtNumber, fmtRelative, fmtSmart } from "@/lib/format";
import { useApiMutation, useDownload } from "@/lib/hooks";
import { CRITICALITY_LABEL, TARGET_TYPE_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

const CRIT_OPTIONS = (Object.keys(CRITICALITY_LABEL) as Criticality[]).map((c) => ({ value: c, label: CRITICALITY_LABEL[c] }));
const CRIT_DOT: Record<Criticality, string> = {
  low: "bg-inactive",
  medium: "bg-data",
  high: "bg-unstable",
  critical: "bg-gone",
};

function CriticalityCell({ t }: { t: Target }) {
  const can = useCan();
  const qc = useQueryClient();
  if (!can("targets:update"))
    return (
      <span className="inline-flex items-center gap-1.5 text-sm">
        <span className={cn("size-2 rounded-full", CRIT_DOT[t.criticality])} aria-hidden />
        {CRITICALITY_LABEL[t.criticality]}
      </span>
    );
  return (
    <div onClick={(e) => e.stopPropagation()}>
      <SimpleSelect
        aria-label={`Krytyczność ${t.value}`}
        className="h-8 w-32 text-[0.8125rem]"
        value={t.criticality}
        options={CRIT_OPTIONS}
        onChange={async (v) => {
          if (!v || v === t.criticality) return;
          try {
            await api.targets.update(t.id, { criticality: v as Criticality });
            qc.invalidateQueries({ queryKey: ["targets"] });
            toast.success(`Krytyczność ${t.value}: ${CRITICALITY_LABEL[v as Criticality].toLowerCase()}`, {
              action: { label: "Cofnij", onClick: () => api.targets.update(t.id, { criticality: t.criticality }).then(() => qc.invalidateQueries({ queryKey: ["targets"] })) },
            });
          } catch (e) {
            toast.error("Nie udało się zapisać", { description: errorMessage(e) });
          }
        }}
      />
    </div>
  );
}

function EditTargetSheet({ target, onClose }: { target: Target | null; onClose: () => void }) {
  // Keep the last target so the panel keeps its content during the closing animation.
  const [last, setLast] = React.useState(target);
  if (target && target !== last) setLast(target);
  return (
    <Sheet open={Boolean(target)} onOpenChange={(o) => !o && onClose()}>
      <SheetContent>{last ? <EditTargetForm target={last} onClose={onClose} /> : null}</SheetContent>
    </Sheet>
  );
}

/** Lives inside SheetContent, so its state starts fresh each time the panel opens. */
function EditTargetForm({ target, onClose }: { target: Target; onClose: () => void }) {
  const [name, setName] = React.useState(target.name ?? "");
  const [owner, setOwner] = React.useState(target.owner ?? "");
  const [criticality, setCriticality] = React.useState<Criticality>(target.criticality);
  const [tags, setTags] = React.useState<string[]>(target.tags);
  const [notes, setNotes] = React.useState(target.notes ?? "");
  const [excluded, setExcluded] = React.useState(target.excluded);
  const save = useApiMutation(
    () => api.targets.update(target.id, { name: name || null, owner: owner || null, criticality, tags, notes: notes || null, excluded }),
    { success: "Zapisano zmiany celu", invalidate: [["targets"]], onSuccess: onClose },
  );
  return (
    <>
        <SheetHeader>
          <SheetTitle className="mono">{target.value}</SheetTitle>
          <SheetDescription>
            {`${TARGET_TYPE_LABEL[target.type]}, ${fmtNumber(target.address_count)} adresów. Ostatnia zmiana: ${target.updated_by ?? "—"}, ${fmtRelative(target.updated_at)}.`}
          </SheetDescription>
        </SheetHeader>
        <SheetBody>
          <form
            id="edit-target"
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate(undefined);
            }}
          >
            <Field label="Nazwa" htmlFor="et-name">
              <Input id="et-name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Właściciel" htmlFor="et-owner">
                <Input id="et-owner" value={owner} onChange={(e) => setOwner(e.target.value)} />
              </Field>
              <Field label="Krytyczność">
                <SimpleSelect aria-label="Krytyczność" value={criticality} onChange={(v) => setCriticality((v || "medium") as Criticality)} options={CRIT_OPTIONS} />
              </Field>
            </div>
            <Field label="Tagi" htmlFor="et-tags">
              <TagInput id="et-tags" value={tags} onChange={setTags} />
            </Field>
            <Field label="Notatki" htmlFor="et-notes">
              <Textarea id="et-notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Np. kontakt do administratora, okno serwisowe, uwagi o skanowaniu." />
            </Field>
            <label className="flex items-start justify-between gap-4 rounded-lg border border-line p-3">
              <span className="grid gap-0.5">
                <span className="text-sm font-semibold">Wyklucz ze skanowania</span>
                <span className="text-[0.8125rem] text-ink-2">Skaner nigdy nie wyśle ruchu do tych adresów — np. systemy wrażliwe na skanowanie.</span>
              </span>
              <Switch checked={excluded} onCheckedChange={setExcluded} />
            </label>
          </form>
        </SheetBody>
        <SheetFooter>
          <Button variant="secondary" onClick={onClose}>
            Anuluj
          </Button>
          <Guard permission="targets:update">
            <Button type="submit" form="edit-target" variant="primary" disabled={save.isPending}>
              Zapisz zmiany
            </Button>
          </Guard>
        </SheetFooter>
    </>
  );
}

function BulkTagDialog({ ids, onDone }: { ids: string[] | null; onDone: () => void }) {
  const [tag, setTag] = React.useState("");
  const qc = useQueryClient();
  return (
    <Dialog open={Boolean(ids)} onOpenChange={(o) => !o && onDone()}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>Dodaj tag</DialogTitle>
          <DialogDescription>Tag zostanie dodany do {ids ? countLabel(ids.length, ["zaznaczonego celu", "zaznaczonych celów", "zaznaczonych celów"]) : ""}.</DialogDescription>
        </DialogHeader>
        <Input autoFocus value={tag} onChange={(e) => setTag(e.target.value)} placeholder="np. kampania-2026" />
        <DialogFooter>
          <Button variant="secondary" onClick={onDone}>
            Anuluj
          </Button>
          <Button
            variant="primary"
            disabled={!tag.trim()}
            onClick={async () => {
              await api.targets.bulk({ ids: ids!, action: "tag", payload: { tag: tag.trim().toLowerCase() } });
              qc.invalidateQueries({ queryKey: ["targets"] });
              toast.success(`Dodano tag #${tag.trim().toLowerCase()}`);
              setTag("");
              onDone();
            }}
          >
            Dodaj tag
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function TargetsView() {
  const params = useSearchParams();
  const router = useRouter();
  const qc = useQueryClient();
  const can = useCan();
  const download = useDownload();
  const [q, setQ] = React.useState(params.get("q") ?? "");
  const [type, setType] = React.useState<TargetType | "">("");
  const [crit, setCrit] = React.useState<Criticality | "">("");
  const [page, setPage] = React.useState(1);
  const [sort, setSort] = React.useState("-criticality_rank");
  const [selection, setSelection] = React.useState<Set<string>>(new Set());
  const [editing, setEditing] = React.useState<Target | null>(null);
  const [addOpen, setAddOpen] = React.useState(params.get("add") === "1");
  const [importOpen, setImportOpen] = React.useState(params.get("import") === "1");
  const [confirmDelete, setConfirmDelete] = React.useState<string[] | null>(null);
  const [tagIds, setTagIds] = React.useState<string[] | null>(null);
  const dq = useDebouncedValue(q);

  const query = useQuery({
    queryKey: ["targets", dq, type, crit, page, sort],
    queryFn: () => api.targets.list({ q: dq, type, criticality: crit, page, page_size: 25, sort }),
    placeholderData: keepPreviousData,
  });
  const all = useQuery({ queryKey: ["targets", "summary"], queryFn: () => api.targets.list({ page_size: 500 }) });
  const summary = React.useMemo(() => {
    const items = all.data?.items ?? [];
    return {
      ranges: items.filter((t) => t.type === "cidr" && !t.excluded).length,
      domains: items.filter((t) => t.type === "domain").length,
      addresses: items.filter((t) => !t.excluded && t.type !== "domain").reduce((n, t) => n + t.address_count, 0),
      excluded: items.filter((t) => t.excluded).reduce((n, t) => n + t.address_count, 0),
    };
  }, [all.data]);

  const clearUrlFlag = () => router.replace("/targets", { scroll: false });
  const bulk = async (action: "exclude" | "include" | "delete", ids: string[]) => {
    try {
      const r = await api.targets.bulk({ ids, action });
      qc.invalidateQueries({ queryKey: ["targets"] });
      setSelection(new Set());
      toast.success(action === "delete" ? `Usunięto ${countLabel(r.affected, ["cel", "cele", "celów"])}` : action === "exclude" ? `Wykluczono ${countLabel(r.affected, ["cel", "cele", "celów"])} ze skanowania` : `Przywrócono ${countLabel(r.affected, ["cel", "cele", "celów"])} do skanowania`);
    } catch (e) {
      toast.error("Operacja nie powiodła się", { description: errorMessage(e) });
    }
  };

  const columns: Column<Target>[] = [
    {
      key: "value",
      header: "Cel",
      sort: "value",
      cell: (t) => (
        <div className="grid min-w-0 gap-0.5">
          <MonoValue value={t.value} className="font-semibold" />
          {t.name ? <span className="truncate text-xs text-ink-2">{t.name}</span> : null}
        </div>
      ),
    },
    { key: "type", header: "Typ", sort: "type", hideBelow: "md", cell: (t) => <Chip tone="outline">{TARGET_TYPE_LABEL[t.type]}</Chip> },
    { key: "addresses", header: "Adresy", sort: "address_count", className: "tabular text-right", headerClassName: "text-right", cell: (t) => fmtNumber(t.address_count) },
    { key: "active", header: "Aktywne hosty", sort: "active_hosts", hideBelow: "lg", className: "tabular text-right", headerClassName: "text-right", cell: (t) => (t.excluded ? "—" : fmtNumber(t.active_hosts)) },
    { key: "owner", header: "Właściciel", sort: "owner", hideBelow: "lg", cell: (t) => <span className="text-sm">{t.owner ?? "—"}</span> },
    { key: "crit", header: "Krytyczność", sort: "criticality_rank", cell: (t) => <CriticalityCell t={t} /> },
    { key: "tags", header: "Tagi", hideBelow: "xl", cell: (t) => <TagList tags={t.tags} /> },
    {
      key: "status",
      header: "Skanowanie",
      hideBelow: "md",
      cell: (t) =>
        t.excluded ? (
          <Chip tone="danger">
            <Ban className="size-3" aria-hidden /> Wykluczony
          </Chip>
        ) : (
          <span className="text-[0.8125rem] text-ink-2">{t.last_scanned_at ? fmtSmart(t.last_scanned_at) : "Jeszcze nie skanowano"}</span>
        ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Akcje</span>,
      cell: (t) => (
        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="secondary" onClick={() => setEditing(t)}>
            <Pencil /> Edytuj
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="icon-sm" variant="ghost" aria-label={`Więcej działań dla ${t.value}`}>
                <Ellipsis />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem disabled={!can("targets:update")} onSelect={() => bulk(t.excluded ? "include" : "exclude", [t.id])}>
                {t.excluded ? <RotateCcw /> : <Ban />} {t.excluded ? "Przywróć do skanowania" : "Wyklucz ze skanowania"}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => router.push(t.type === "domain" ? `/assets?q=${encodeURIComponent(t.value)}` : `/assets?cidr=${encodeURIComponent(t.value)}`)}>
                Pokaż hosty
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem destructive disabled={!can("targets:delete")} onSelect={() => setConfirmDelete([t.id])}>
                <Trash2 /> Usuń cel
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  const selected = [...selection];
  return (
    <Container className="pb-12">
      <PageHeader
        title="Zakresy"
        description="Adresy IP, zakresy CIDR i domeny objęte monitoringiem. Dodaj je ręcznie lub zaimportuj z pliku — każdy wpis jest sprawdzany tak samo."
        meta={
          <>
            <Chip tone="outline">{summary.ranges} zakresów CIDR</Chip>
            <Chip tone="outline">{summary.domains} domen</Chip>
            <Chip tone="accent">{fmtNumber(summary.addresses)} adresów monitorowanych</Chip>
            {summary.excluded ? <Chip tone="danger">{fmtNumber(summary.excluded)} wykluczonych</Chip> : null}
          </>
        }
        actions={
          <>
            {can("targets:export") ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button>
                    <Download /> Eksport
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem onSelect={() => download(() => api.targets.export({ format: "csv" }), "Pobrano cele (CSV)")}>CSV</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => download(() => api.targets.export({ format: "json" }), "Pobrano cele (JSON)")}>JSON</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
            <Guard permission="targets:import">
              <Button onClick={() => setImportOpen(true)}>
                <FileUp /> Importuj
              </Button>
            </Guard>
            <Guard permission="targets:create">
              <Button variant="primary" onClick={() => setAddOpen(true)}>
                <Plus /> Dodaj cele
              </Button>
            </Guard>
          </>
        }
      />
      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
          <SearchInput
            value={q}
            onChange={(v) => {
              setQ(v);
              setPage(1);
            }}
            placeholder="Szukaj po adresie, nazwie, właścicielu…"
            className="w-full sm:w-80"
          />
          <SimpleSelect aria-label="Typ celu" className="w-40" value={type} onChange={(v) => { setType(v as TargetType | ""); setPage(1); }} allLabel="Każdy typ" options={(Object.keys(TARGET_TYPE_LABEL) as TargetType[]).map((t) => ({ value: t, label: TARGET_TYPE_LABEL[t] }))} />
          <SimpleSelect aria-label="Krytyczność" className="w-44" value={crit} onChange={(v) => { setCrit(v as Criticality | ""); setPage(1); }} allLabel="Każda krytyczność" options={CRIT_OPTIONS} />
          {selected.length ? (
            <div className="ml-auto flex flex-wrap items-center gap-2 rounded-lg bg-accent/10 px-3 py-1.5 text-sm">
              <span className="font-semibold">Zaznaczono: {selected.length}</span>
              <Guard permission="targets:update">
                <Button size="sm" variant="ghost" onClick={() => setTagIds(selected)}>
                  <Tag /> Dodaj tag
                </Button>
              </Guard>
              <Guard permission="targets:update">
                <Button size="sm" variant="ghost" onClick={() => bulk("exclude", selected)}>
                  <Ban /> Wyklucz
                </Button>
              </Guard>
              <Guard permission="targets:update">
                <Button size="sm" variant="ghost" onClick={() => bulk("include", selected)}>
                  <RotateCcw /> Przywróć
                </Button>
              </Guard>
              <Guard permission="targets:delete">
                <Button size="sm" variant="danger" onClick={() => setConfirmDelete(selected)}>
                  <Trash2 /> Usuń
                </Button>
              </Guard>
            </div>
          ) : null}
        </div>
        {query.isError ? <ErrorState className="m-4" error={query.error} onRetry={() => query.refetch()} /> : null}
        <DataTable
          columns={columns}
          rows={query.data?.items}
          getId={(t) => t.id}
          loading={query.isFetching}
          sort={sort}
          onSort={setSort}
          selection={can("targets:update") || can("targets:delete") ? selection : undefined}
          onSelectionChange={setSelection}
          onRowClick={(t) => setEditing(t)}
          rowClassName={(t) => (t.excluded ? "opacity-70" : undefined)}
          caption="Cele skanowania"
          empty={
            <EmptyState
              title={dq || type || crit ? "Brak celów spełniających kryteria" : "Nie masz jeszcze żadnych celów"}
              description={dq || type || crit ? "Zmień filtry lub wyczyść wyszukiwanie." : "Dodaj adresy IP, zakresy CIDR lub domeny, aby rozpocząć monitoring."}
              action={
                can("targets:create") ? (
                  <Button variant="primary" onClick={() => setAddOpen(true)}>
                    <Plus /> Dodaj cele
                  </Button>
                ) : null
              }
            />
          }
        />
        {query.data ? <Pagination page={page} pageSize={25} total={query.data.total} onPage={setPage} /> : null}
      </Panel>

      <AddTargetsDialog
        open={addOpen}
        onOpenChange={(o) => {
          setAddOpen(o);
          if (!o && params.get("add")) clearUrlFlag();
        }}
      />
      <ImportWizard
        open={importOpen}
        onOpenChange={(o) => {
          setImportOpen(o);
          if (!o && params.get("import")) clearUrlFlag();
        }}
        title="Importuj cele z pliku"
        description="Plik CSV z nagłówkiem (kolumna value) albo JSON (tablica obiektów lub obiekt z polem targets). Przed importem zobaczysz wynik walidacji każdego wiersza."
        formatHint="CSV: value, name, owner, criticality, tags (oddzielone |), notes, excluded. JSON: [{ &quot;value&quot;: &quot;10.0.0.0/24&quot; }]"
        samples={[
          { label: "cele.csv", href: "/samples/targets.csv" },
          { label: "cele.json", href: "/samples/targets.json" },
        ]}
        conflictOption
        preview={(fd) => api.targets.import(fd)}
        commit={async (fd) => {
          const r = await api.targets.import(fd);
          qc.invalidateQueries({ queryKey: ["targets"] });
          toast.success(`Zaimportowano ${countLabel(r.created, ["nowy cel", "nowe cele", "nowych celów"])}`, {
            description: `${r.updated} zaktualizowanych, ${r.duplicates} pominiętych duplikatów, ${r.invalid} błędnych wierszy.`,
          });
          return "ok";
        }}
      />
      <EditTargetSheet target={editing} onClose={() => setEditing(null)} />
      <BulkTagDialog ids={tagIds} onDone={() => setTagIds(null)} />
      <ConfirmDialog
        open={Boolean(confirmDelete)}
        onOpenChange={(o) => !o && setConfirmDelete(null)}
        title={confirmDelete && confirmDelete.length > 1 ? `Usunąć ${confirmDelete.length} celów?` : "Usunąć cel?"}
        description="Cel zniknie z listy i z kolejnych skanowań. Wyniki wcześniejszych przebiegów pozostaną w historii. Tej operacji nie można cofnąć."
        confirmLabel="Usuń"
        onConfirm={async () => {
          await bulk("delete", confirmDelete!);
          setConfirmDelete(null);
        }}
      />
    </Container>
  );
}
