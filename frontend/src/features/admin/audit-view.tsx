"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronDown } from "lucide-react";
import * as React from "react";
import { EmptyState, ErrorState, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { Pagination } from "@/components/data/data-table";
import { Container, PageHeader } from "@/components/layout/page";
import { Chip, Panel, Skeleton } from "@/components/ui/misc";
import { SimpleSelect } from "@/components/ui/select";
import { FieldDiff } from "@/components/viz/bits";
import { api } from "@/lib/api/endpoints";
import type { AuditAction } from "@/lib/api/types";
import { fmtDateTime, fmtRelative } from "@/lib/format";
import { AUDIT_ACTION_LABEL } from "@/lib/labels";
import { cn } from "@/lib/utils";

const RESOURCES = [
  { value: "target", label: "Cele" },
  { value: "scan", label: "Skanowania" },
  { value: "host", label: "Hosty" },
  { value: "service", label: "Usługi" },
  { value: "finding", label: "Znaleziska" },
  { value: "signature", label: "Sygnatury" },
  { value: "user", label: "Użytkownicy" },
  { value: "role", label: "Role" },
  { value: "settings", label: "Ustawienia" },
  { value: "integration", label: "Integracje" },
  { value: "session", label: "Sesje" },
];

export function AuditView() {
  const [q, setQ] = React.useState("");
  const [action, setAction] = React.useState<AuditAction | "">("");
  const [resource, setResource] = React.useState("");
  const [actor, setActor] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [open, setOpen] = React.useState<Set<string>>(new Set());
  const dq = useDebouncedValue(q);
  const users = useQuery({ queryKey: ["users"], queryFn: api.users.list });
  const query = useQuery({
    queryKey: ["audit", dq, action, resource, actor, page],
    queryFn: () => api.audit.list({ q: dq, action, resource, actor, page, page_size: 30 }),
    placeholderData: keepPreviousData,
  });
  return (
    <Container className="pb-12">
      <PageHeader
        title="Dziennik zdarzeń"
        description="Każda zmiana danych, eksport, logowanie i działanie skanera — kto, co i kiedy. Wpisy są tylko do odczytu."
      />
      <Panel flush>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
          <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Szukaj w opisie, zasobie, osobie…" className="w-full sm:w-80" />
          <SimpleSelect aria-label="Osoba" className="w-52" value={actor} onChange={(v) => { setActor(v); setPage(1); }} allLabel="Każda osoba" options={[{ value: "system", label: "System / harmonogram" }, ...(users.data ?? []).map((u) => ({ value: u.id, label: u.name }))]} />
          <SimpleSelect aria-label="Działanie" className="w-52" value={action} onChange={(v) => { setAction(v as AuditAction | ""); setPage(1); }} allLabel="Każde działanie" options={(Object.keys(AUDIT_ACTION_LABEL) as AuditAction[]).map((a) => ({ value: a, label: AUDIT_ACTION_LABEL[a] }))} />
          <SimpleSelect aria-label="Zasób" className="w-44" value={resource} onChange={(v) => { setResource(v); setPage(1); }} allLabel="Każdy zasób" options={RESOURCES} />
        </div>
        {query.isError ? <ErrorState className="m-4" error={query.error} onRetry={() => query.refetch()} /> : null}
        <ol className={cn("divide-y divide-line", query.isFetching && "opacity-70")}>
          {(query.data?.items ?? []).map((e) => {
            const expanded = open.has(e.id);
            return (
              <li key={e.id} className="px-5 py-3">
                <button
                  type="button"
                  className="grid w-full grid-cols-[minmax(0,1fr)_auto] items-start gap-3 text-left"
                  aria-expanded={e.changes.length ? expanded : undefined}
                  onClick={() =>
                    e.changes.length &&
                    setOpen((prev) => {
                      const next = new Set(prev);
                      if (next.has(e.id)) next.delete(e.id);
                      else next.add(e.id);
                      return next;
                    })
                  }
                >
                  <span className="grid gap-1">
                    <span className="flex flex-wrap items-center gap-2 text-sm">
                      <Chip tone="outline">{AUDIT_ACTION_LABEL[e.action]}</Chip>
                      <span className="font-semibold">{e.actor.name}</span>
                      <span className="text-ink-2">({e.actor.role})</span>
                    </span>
                    <span className="text-sm text-ink">{e.summary}</span>
                    {e.resource_label ? <span className="mono text-xs text-ink-2">{e.resource_label}</span> : null}
                  </span>
                  <span className="flex items-center gap-2 text-xs whitespace-nowrap text-ink-2">
                    <time dateTime={e.at} title={fmtDateTime(e.at)}>
                      {fmtRelative(e.at)}
                    </time>
                    {e.changes.length ? <ChevronDown className={cn("size-4 transition-transform", expanded && "rotate-180")} aria-hidden /> : null}
                  </span>
                </button>
                {expanded ? (
                  <div className="mt-3 rounded-lg bg-surface-2 p-3">
                    <FieldDiff fields={e.changes} />
                  </div>
                ) : null}
              </li>
            );
          })}
        </ol>
        {!query.data ? (
          <div className="grid gap-2 p-5">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : null}
        {query.data && !query.data.items.length ? <EmptyState title="Brak wpisów dla wybranych filtrów" /> : null}
        {query.data ? <Pagination page={page} pageSize={30} total={query.data.total} onPage={setPage} /> : null}
      </Panel>
    </Container>
  );
}
