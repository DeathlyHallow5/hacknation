"use client";

import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Send, Tag, UserRoundCheck } from "lucide-react";
import { useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { EmptyState, ErrorState, Guard, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { Pagination } from "@/components/data/data-table";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Input, RadioCards } from "@/components/ui/form-controls";
import { Panel } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { FindingDrawer } from "@/features/findings/finding-drawer";
import { FindingsTable } from "@/features/findings/findings-table";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ChangeState, FindingCategory, FindingStatus } from "@/lib/api/types";
import { countLabel, fmtNumber } from "@/lib/format";
import { useDownload } from "@/lib/hooks";
import { CHANGE_LABEL, FINDING_CATEGORY_LABEL, FINDING_STATUS_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";

const SCORE_OPTIONS = [
  { value: "70", label: "Wysoki (70+)" },
  { value: "40", label: "Średni i wyższy (40+)" },
];

function DefectDojoDialog({ ids, onDone }: { ids: string[] | null; onDone: (sent: boolean) => void }) {
  const [as, setAs] = React.useState<"finding" | "evidence">("finding");
  const [pending, setPending] = React.useState(false);
  const dd = useQuery({ queryKey: ["defectdojo"], queryFn: api.integrations.defectdojo, enabled: Boolean(ids) });
  return (
    <Dialog open={Boolean(ids)} onOpenChange={(o) => !o && onDone(false)}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Wyślij do DefectDojo</DialogTitle>
          <DialogDescription>
            {ids ? countLabel(ids.length, ["znalezisko", "znaleziska", "znalezisk"]) : ""} trafi do produktu „{dd.data?.product_name ?? "…"}”, engagement „{dd.data?.engagement_name ?? "…"}”.
          </DialogDescription>
        </DialogHeader>
        <RadioCards
          columns={2}
          value={as}
          onValueChange={setAs}
          options={[
            { value: "finding", title: "Finding informacyjny", description: "Nowy finding z severity „Info”, endpointem i dowodami w opisie." },
            { value: "evidence", title: "Evidence do analizy", description: "Załącznik do istniejącego findingu — do dalszej analizy ręcznej." },
          ]}
        />
        <div className="rounded-lg bg-surface-2 p-3 text-sm text-ink-2">
          Mapowanie pól: tytuł → <span className="mono text-ink">title</span>, priorytet → <span className="mono text-ink">severity: Info</span> + tag priorytetu, adres i port →{" "}
          <span className="mono text-ink">endpoints</span>, dowody → <span className="mono text-ink">description</span>.
        </div>
        <DialogFooter>
          <Button variant="secondary" onClick={() => onDone(false)}>
            Anuluj
          </Button>
          <Button
            variant="primary"
            disabled={pending}
            onClick={async () => {
              setPending(true);
              try {
                const r = await api.findings.defectdojo({ ids: ids!, as });
                toast.success(`Wysłano ${countLabel(r.exported, ["znalezisko", "znaleziska", "znalezisk"])} do DefectDojo`);
                onDone(true);
              } catch (e) {
                toast.error("Nie udało się wysłać", { description: errorMessage(e) });
              } finally {
                setPending(false);
              }
            }}
          >
            <Send /> Wyślij
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function FindingsView() {
  const params = useSearchParams();
  const qc = useQueryClient();
  const can = useCan();
  const download = useDownload();
  const [q, setQ] = React.useState(params.get("q") ?? "");
  const [category, setCategory] = React.useState<FindingCategory | "">((params.get("category") as FindingCategory) ?? "");
  const [change, setChange] = React.useState<ChangeState | "">((params.get("change") as ChangeState) ?? "");
  const [status, setStatus] = React.useState<FindingStatus | "">("");
  const [minScore, setMinScore] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(25);
  const [sort, setSort] = React.useState("-score");
  const [selection, setSelection] = React.useState<Set<string>>(new Set());
  const [openId, setOpenId] = React.useState<string | null>(params.get("open"));
  const [ddIds, setDdIds] = React.useState<string[] | null>(null);
  const [tagOpen, setTagOpen] = React.useState(false);
  const [tag, setTag] = React.useState("");
  const dq = useDebouncedValue(q);
  const filters = { q: dq, category, change, status, min_score: minScore };
  const query = useQuery({
    queryKey: ["findings", filters, page, pageSize, sort],
    queryFn: () => api.findings.list({ ...filters, page, page_size: pageSize, sort }),
    placeholderData: keepPreviousData,
  });
  const refresh = () => qc.invalidateQueries({ queryKey: ["findings"] });
  const selected = [...selection];
  const bulk = async (action: "set_status" | "tag" | "assign", payload: Record<string, unknown>, label: string) => {
    try {
      const r = await api.findings.bulk({ ids: selected, action, payload });
      toast.success(`${label}: ${countLabel(r.affected, ["znalezisko", "znaleziska", "znalezisk"])}`);
      setSelection(new Set());
      refresh();
    } catch (e) {
      toast.error("Operacja nie powiodła się", { description: errorMessage(e) });
    }
  };
  const resetPage = () => setPage(1);

  return (
    <Container className="pb-12">
      <PageHeader
        title="Znaleziska"
        description="Obserwacje warte uwagi: panele administracyjne, środowiska testowe, przestarzałe komponenty, ciekawe nagłówki i ciasteczka. Oceniaj je, przypisuj i wysyłaj do DefectDojo."
        actions={
          can("findings:export") ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button>
                  <Download /> Eksport
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuLabel>Z bieżącymi filtrami</DropdownMenuLabel>
                <DropdownMenuItem onSelect={() => download(() => api.findings.export({ ...filters, format: "csv" }), "Pobrano raport CSV")}>Raport CSV</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => download(() => api.findings.export({ ...filters, format: "json" }), "Pobrano raport JSON")}>Raport JSON</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : null
        }
      />
      <Panel flush>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
          <SearchInput value={q} onChange={(v) => { setQ(v); resetPage(); }} placeholder="Tytuł, IP, domena, technologia, tag…" className="w-full sm:w-80" />
          <SimpleSelect aria-label="Kategoria" className="w-56" value={category} onChange={(v) => { setCategory(v as FindingCategory | ""); resetPage(); }} allLabel="Wszystkie kategorie" options={(Object.keys(FINDING_CATEGORY_LABEL) as FindingCategory[]).map((c) => ({ value: c, label: FINDING_CATEGORY_LABEL[c] }))} />
          <SimpleSelect aria-label="Status zmiany" className="w-44" value={change} onChange={(v) => { setChange(v as ChangeState | ""); resetPage(); }} allLabel="Każda zmiana" options={(["new", "changed", "unstable", "gone", "unchanged"] as ChangeState[]).map((c) => ({ value: c, label: CHANGE_LABEL[c] }))} />
          <SimpleSelect aria-label="Status obsługi" className="w-48" value={status} onChange={(v) => { setStatus(v as FindingStatus | ""); resetPage(); }} allLabel="Każdy status obsługi" options={(Object.keys(FINDING_STATUS_LABEL) as FindingStatus[]).map((s) => ({ value: s, label: FINDING_STATUS_LABEL[s] }))} />
          <SimpleSelect aria-label="Minimalny priorytet" className="w-48" value={minScore} onChange={(v) => { setMinScore(v); resetPage(); }} allLabel="Każdy priorytet" options={SCORE_OPTIONS} />
          <span className="ml-auto text-sm text-ink-2">{query.data ? `${fmtNumber(query.data.total)} znalezisk` : ""}</span>
        </div>
        {selected.length ? (
          <div className="flex flex-wrap items-center gap-2 border-b border-line bg-accent/[0.06] px-5 py-2.5 text-sm">
            <span className="font-semibold">Zaznaczono: {selected.length}</span>
            <Guard permission="findings:update">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button size="sm" variant="ghost">
                    Zmień status
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start">
                  {(Object.keys(FINDING_STATUS_LABEL) as FindingStatus[]).map((s) => (
                    <DropdownMenuItem key={s} onSelect={() => bulk("set_status", { status: s }, `Status „${FINDING_STATUS_LABEL[s]}”`)}>
                      {FINDING_STATUS_LABEL[s]}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </Guard>
            <Guard permission="findings:update">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button size="sm" variant="ghost">
                    <UserRoundCheck /> Przypisz
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start">
                  {["Anna Nowak", "Piotr Wiśniewski", "Katarzyna Zielińska", "Jan Kowalski"].map((a) => (
                    <DropdownMenuItem key={a} onSelect={() => bulk("assign", { assignee: a }, `Przypisano do: ${a}`)}>
                      {a}
                    </DropdownMenuItem>
                  ))}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={() => bulk("assign", { assignee: null }, "Usunięto przypisanie")}>Nikt</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </Guard>
            <Guard permission="findings:update">
              <Button size="sm" variant="ghost" onClick={() => setTagOpen(true)}>
                <Tag /> Dodaj tag
              </Button>
            </Guard>
            <Guard permission="findings:defectdojo">
              <Button size="sm" variant="secondary" onClick={() => setDdIds(selected)}>
                <Send /> Wyślij do DefectDojo
              </Button>
            </Guard>
            {can("findings:export") ? (
              <Button size="sm" variant="ghost" onClick={() => download(() => api.findings.export({ ids: selected.join(","), format: "csv" }), "Pobrano zaznaczone (CSV)")}>
                <Download /> Eksport zaznaczonych
              </Button>
            ) : null}
          </div>
        ) : null}
        {query.isError ? <ErrorState className="m-4" error={query.error} onRetry={() => query.refetch()} /> : null}
        <FindingsTable
          rows={query.data?.items}
          loading={query.isFetching}
          sort={sort}
          onSort={setSort}
          selection={can("findings:update") || can("findings:defectdojo") || can("findings:export") ? selection : undefined}
          onSelectionChange={setSelection}
          onOpen={setOpenId}
          onChanged={refresh}
          showStatus
          empty={<EmptyState title="Brak znalezisk dla wybranych filtrów" description="Zmień kryteria albo wyczyść wyszukiwanie." />}
        />
        {query.data ? <Pagination page={page} pageSize={pageSize} total={query.data.total} onPage={setPage} onPageSize={(s) => { setPageSize(s); setPage(1); }} /> : null}
      </Panel>
      <FindingDrawer id={openId} onOpenChange={(o) => !o && setOpenId(null)} />
      <DefectDojoDialog
        ids={ddIds}
        onDone={(sent) => {
          setDdIds(null);
          if (sent) {
            setSelection(new Set());
            refresh();
          }
        }}
      />
      <Dialog open={tagOpen} onOpenChange={setTagOpen}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>Dodaj tag do zaznaczonych</DialogTitle>
            <DialogDescription>{countLabel(selected.length, ["znalezisko", "znaleziska", "znalezisk"])}</DialogDescription>
          </DialogHeader>
          <Input autoFocus value={tag} onChange={(e) => setTag(e.target.value)} placeholder="np. zgłoszone-właścicielowi" />
          <DialogFooter>
            <Button variant="secondary" onClick={() => setTagOpen(false)}>
              Anuluj
            </Button>
            <Button
              variant="primary"
              disabled={!tag.trim()}
              onClick={async () => {
                await bulk("tag", { tag: tag.trim().toLowerCase().replace(/\s+/g, "-") }, `Dodano tag #${tag.trim()}`);
                setTag("");
                setTagOpen(false);
              }}
            >
              Dodaj tag
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Container>
  );
}
