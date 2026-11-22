"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileUp, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { EmptyState, ErrorState, Guard, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { DataTable, type Column } from "@/components/data/data-table";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Segmented, Switch } from "@/components/ui/form-controls";
import { Panel } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Signature } from "@/lib/api/types";
import { countLabel, fmtNumber, fmtRelative } from "@/lib/format";
import { useDownload } from "@/lib/hooks";
import { CONDITION_TYPE_LABEL, FINDING_CATEGORY_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";

export function categoryLabel(c: Signature["category"]) {
  return c === "technology" ? "Technologia" : FINDING_CATEGORY_LABEL[c];
}

function ImportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const [file, setFile] = React.useState<File | null>(null);
  const [pending, setPending] = React.useState(false);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Importuj sygnatury</DialogTitle>
          <DialogDescription>Plik YAML lub JSON z listą sygnatur. Każda reguła przechodzi kontrolę bezpieczeństwa; niebezpieczne zostaną odrzucone.</DialogDescription>
        </DialogHeader>
        <input type="file" accept=".yaml,.yml,.json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
        <a href="/samples/signatures.yaml" download className="text-sm font-semibold text-link hover:underline">
          Pobierz przykładowy plik sygnatury.yaml
        </a>
        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Anuluj
          </Button>
          <Button
            variant="primary"
            disabled={!file || pending}
            onClick={async () => {
              setPending(true);
              try {
                const fd = new FormData();
                fd.set("file", file!);
                const r = await api.signatures.import(fd);
                qc.invalidateQueries({ queryKey: ["signatures"] });
                toast.success(`Zaimportowano sygnatury: ${countLabel(r.created, ["nowa", "nowe", "nowych"])}, ${countLabel(r.updated, ["zaktualizowana", "zaktualizowane", "zaktualizowanych"])}`, {
                  description: r.errors.length ? `Odrzucono ${r.errors.length}: ${r.errors[0]}` : undefined,
                });
                onOpenChange(false);
              } catch (e) {
                toast.error("Import nie powiódł się", { description: errorMessage(e) });
              } finally {
                setPending(false);
              }
            }}
          >
            <FileUp /> Importuj
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function SignaturesView() {
  const router = useRouter();
  const qc = useQueryClient();
  const can = useCan();
  const download = useDownload();
  const [q, setQ] = React.useState("");
  const [source, setSource] = React.useState<"all" | "custom" | "builtin">("all");
  const [importOpen, setImportOpen] = React.useState(false);
  const dq = useDebouncedValue(q);
  const query = useQuery({ queryKey: ["signatures", dq, source], queryFn: () => api.signatures.list({ q: dq, source: source === "all" ? "" : source }) });
  const all = query.data ?? [];

  const toggle = async (s: Signature, enabled: boolean) => {
    try {
      await api.signatures.update(s.id, { enabled });
      qc.invalidateQueries({ queryKey: ["signatures"] });
      toast.success(enabled ? "Włączono sygnaturę" : "Wyłączono sygnaturę", { description: s.name });
    } catch (e) {
      toast.error("Nie udało się zmienić", { description: errorMessage(e) });
    }
  };

  const columns: Column<Signature>[] = [
    {
      key: "name",
      header: "Sygnatura",
      cell: (s) => (
        <div className="grid max-w-xl gap-0.5">
          <span className="font-semibold">
            {s.name} {!s.enabled ? <span className="font-normal text-ink-2">(wyłączona)</span> : null}
          </span>
          <span className="text-xs text-ink-2">{s.description}</span>
        </div>
      ),
    },
    {
      // Label in sans, the machine value (header, cookie, path) in mono.
      key: "cond",
      header: "Warunki",
      hideBelow: "lg",
      cell: (s) => (
        <span className="grid max-w-72 gap-0.5 text-sm">
          {s.match.conditions.slice(0, 2).map((c, i) => (
            <span key={i} className="truncate">
              <span className="text-ink-2">{CONDITION_TYPE_LABEL[c.type]}</span>
              {c.name || c.path ? (
                <>
                  : <code className="mono text-ink">{c.name ?? c.path}</code>
                </>
              ) : null}
            </span>
          ))}
          {s.match.conditions.length > 2 ? <span className="tabular text-xs text-ink-2">+{s.match.conditions.length - 2}</span> : null}
        </span>
      ),
    },
    { key: "cat", header: "Kategoria", hideBelow: "md", cell: (s) => <span className="text-sm">{categoryLabel(s.category)}</span> },
    {
      key: "source",
      header: "Źródło",
      hideBelow: "md",
      cell: (s) => <span className="text-sm whitespace-nowrap text-ink-2">{s.source === "builtin" ? "wbudowana" : `własna, ${s.author}`}</span>,
    },
    { key: "matches", header: "Dopasowania", className: "tabular text-right", headerClassName: "text-right", cell: (s) => fmtNumber(s.matches_last_scan) },
    { key: "updated", header: "Zmiana", hideBelow: "xl", cell: (s) => <span className="text-xs text-ink-2">{fmtRelative(s.updated_at)}</span> },
    {
      key: "enabled",
      header: "Aktywna",
      cell: (s) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Switch aria-label={`Aktywna: ${s.name}`} checked={s.enabled} disabled={!can("signatures:update")} onCheckedChange={(c) => toggle(s, c)} />
        </div>
      ),
    },
  ];

  return (
    <Container className="pb-12">
      <PageHeader
        title="Sygnatury"
        description="Reguły, po których panel rozpoznaje usługi i panele administracyjne (nagłówki, tytuł strony, baner). Sygnatury tylko rozpoznają: nie logują się, nie wysyłają formularzy ani ładunków ataku."
        actions={
          <>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button>
                  <Download /> Eksport
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onSelect={() => download(() => api.signatures.export("yaml"), "Pobrano sygnatury (YAML)")}>YAML</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => download(() => api.signatures.export("json"), "Pobrano sygnatury (JSON)")}>JSON</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Guard permission="signatures:create">
              <Button onClick={() => setImportOpen(true)}>
                <FileUp /> Importuj
              </Button>
            </Guard>
            <Guard permission="signatures:create">
              <Button variant="primary" asChild>
                <Link href="/signatures/new">
                  <Plus /> Nowa sygnatura
                </Link>
              </Button>
            </Guard>
          </>
        }
      />
      <Panel flush>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
          <SearchInput value={q} onChange={setQ} placeholder="Szukaj sygnatury…" className="w-full sm:w-80" />
          <Segmented
            aria-label="Źródło"
            value={source}
            onChange={setSource}
            options={[
              { value: "all", label: "Wszystkie" },
              { value: "custom", label: "Własne" },
              { value: "builtin", label: "Wbudowane" },
            ]}
          />
          <span className="text-sm text-ink-2 tabular sm:ml-auto">
            {query.data
              ? `${countLabel(all.length, ["sygnatura", "sygnatury", "sygnatur"])}, w tym ${countLabel(
                  all.filter((s) => s.source === "custom").length,
                  ["własna", "własne", "własnych"],
                )}`
              : ""}
          </span>
        </div>
        {query.isError ? <ErrorState className="m-4" error={query.error} onRetry={() => query.refetch()} /> : null}
        <DataTable
          columns={columns}
          rows={query.data}
          getId={(s) => s.id}
          loading={query.isFetching && !query.data}
          onRowClick={(s) => router.push(`/signatures/${s.id}`)}
          caption="Sygnatury"
          empty={<EmptyState title="Brak sygnatur" description="Utwórz pierwszą sygnaturę własną lub zaimportuj plik YAML." />}
        />
      </Panel>
      <ImportDialog open={importOpen} onOpenChange={setImportOpen} />
    </Container>
  );
}
