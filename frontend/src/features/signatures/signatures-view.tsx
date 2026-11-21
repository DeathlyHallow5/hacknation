"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileUp, Fingerprint, Plus, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { EmptyState, ErrorState, Guard, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { DataTable, type Column } from "@/components/data/data-table";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Segmented, Switch } from "@/components/ui/form-controls";
import { Chip, Panel } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Signature } from "@/lib/api/types";
import { fmtNumber, fmtRelative } from "@/lib/format";
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
          <DialogDescription>Plik YAML lub JSON z listą sygnatur. Każda reguła przechodzi kontrolę bezpieczeństwa — niebezpieczne zostaną odrzucone.</DialogDescription>
        </DialogHeader>
        <input type="file" accept=".yaml,.yml,.json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
        <a href="/samples/signatures.yaml" download className="text-[0.8125rem] font-semibold text-link hover:underline">
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
                toast.success(`Zaimportowano sygnatury: ${r.created} nowych, ${r.updated} zaktualizowanych`, {
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
          <span className="font-semibold">{s.name}</span>
          <span className="text-xs text-ink-2">{s.description}</span>
        </div>
      ),
    },
    {
      key: "cond",
      header: "Warunki",
      hideBelow: "lg",
      cell: (s) => (
        <span className="flex max-w-64 flex-wrap gap-1">
          {s.match.conditions.map((c, i) => (
            <Chip key={i} tone="outline">
              {CONDITION_TYPE_LABEL[c.type]}
              {c.name ? `: ${c.name}` : c.path ? `: ${c.path}` : ""}
            </Chip>
          ))}
        </span>
      ),
    },
    { key: "cat", header: "Kategoria", hideBelow: "md", cell: (s) => <span className="text-[0.8125rem]">{categoryLabel(s.category)}</span> },
    { key: "source", header: "Źródło", hideBelow: "md", cell: (s) => (s.source === "builtin" ? <Chip tone="outline">wbudowana</Chip> : <Chip tone="accent">własna — {s.author}</Chip>) },
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
        description="Reguły rozpoznawania technologii i cech usług. Sygnatury tylko wykrywają — nie logują się, nie wysyłają formularzy ani ładunków ataku."
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
      <div className="mb-6 grid gap-4 md:grid-cols-3">
        <div className="flex items-start gap-3 rounded-xl border border-line bg-surface p-4">
          <Fingerprint className="mt-0.5 size-5 text-link" aria-hidden />
          <div className="grid gap-0.5">
            <span className="tabular text-2xl font-extrabold">{all.length}</span>
            <span className="text-[0.8125rem] text-ink-2">sygnatur, w tym {all.filter((s) => s.source === "custom").length} własnych</span>
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-xl border border-line bg-surface p-4">
          <ShieldCheck className="mt-0.5 size-5 text-success" aria-hidden />
          <div className="grid gap-0.5 text-[0.8125rem]">
            <span className="font-bold text-ink">Bezpieczne z założenia</span>
            <span className="text-ink-2">Ścieżki tylko GET/HEAD, bez parametrów, logowania i znaków typowych dla ataków.</span>
          </div>
        </div>
        <div className="grid gap-0.5 rounded-xl border border-line bg-surface p-4 text-[0.8125rem]">
          <span className="font-bold">Typy warunków</span>
          <span className="text-ink-2">Nagłówek, ciasteczko, hash favicony, fragment HTML, ścieżka, tytuł, wersja w treści, kod odpowiedzi.</span>
        </div>
      </div>
      <Panel bodyClassName="p-0">
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
        </div>
        {query.isError ? <ErrorState className="m-4" error={query.error} onRetry={() => query.refetch()} /> : null}
        <DataTable
          columns={columns}
          rows={query.data}
          getId={(s) => s.id}
          loading={query.isFetching && !query.data}
          onRowClick={(s) => router.push(`/signatures/${s.id}`)}
          rowClassName={(s) => (!s.enabled ? "opacity-60" : undefined)}
          caption="Sygnatury"
          empty={<EmptyState title="Brak sygnatur" description="Utwórz pierwszą sygnaturę własną lub zaimportuj plik YAML." />}
        />
      </Panel>
      <ImportDialog open={importOpen} onOpenChange={setImportOpen} />
    </Container>
  );
}
