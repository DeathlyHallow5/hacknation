"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronDown } from "lucide-react";
import * as React from "react";
import { EmptyState, ErrorState, ResourceLabel, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { Pagination } from "@/components/data/data-table";
import { Container, PageHeader } from "@/components/layout/page";
import { Panel, Skeleton } from "@/components/ui/misc";
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
      <PageHeader title="Dziennik zdarzeń" description="Wpisów nie można edytować ani usuwać." />
      <Panel flush>
        <div className="grid grid-cols-2 gap-2 border-b border-line px-5 py-3 sm:flex sm:flex-wrap sm:items-center">
          <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Szukaj w opisie, zasobie, osobie…" className="col-span-2 sm:w-80" />
          <SimpleSelect aria-label="Osoba" className="w-full sm:w-52" value={actor} onChange={(v) => { setActor(v); setPage(1); }} allLabel="Każda osoba" options={[{ value: "system", label: "System / harmonogram" }, ...(users.data ?? []).map((u) => ({ value: u.id, label: u.name }))]} />
          <SimpleSelect aria-label="Działanie" className="w-full sm:w-52" value={action} onChange={(v) => { setAction(v as AuditAction | ""); setPage(1); }} allLabel="Każde działanie" options={(Object.keys(AUDIT_ACTION_LABEL) as AuditAction[]).map((a) => ({ value: a, label: AUDIT_ACTION_LABEL[a] }))} />
          <SimpleSelect aria-label="Zasób" className="w-full sm:w-44" value={resource} onChange={(v) => { setResource(v); setPage(1); }} allLabel="Każdy zasób" options={RESOURCES} />
        </div>
        {query.isError ? <ErrorState className="m-4" error={query.error} onRetry={() => query.refetch()} /> : null}
        <ol className={cn("divide-y divide-line", query.isFetching && "opacity-70")}>
          {(query.data?.items ?? []).map((e) => {
            const expanded = open.has(e.id);
            return (
              <li key={e.id} className="px-5 py-3">
                {/* A log reads by time: absolute timestamp first (relative one on hover), then what happened, then who. */}
                <button
                  type="button"
                  className="grid w-full grid-cols-[minmax(0,1fr)_auto] items-start gap-x-4 gap-y-1 text-left sm:grid-cols-[10rem_minmax(0,1fr)_auto]"
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
                  <time dateTime={e.at} title={fmtRelative(e.at)} className="tabular col-span-2 pt-px text-sm text-ink-2 sm:col-span-1">
                    {fmtDateTime(e.at)}
                  </time>
                  <span className="grid min-w-0 gap-0.5">
                    <span className="text-sm text-pretty text-ink">
                      {e.summary}
                      {e.resource_label && !e.summary.includes(e.resource_label) ? (
                        <>
                          {" "}
                          <ResourceLabel label={e.resource_label} />
                        </>
                      ) : null}
                    </span>
                    <span className="text-xs text-ink-2">
                      {e.actor.name} ({e.actor.role}), {AUDIT_ACTION_LABEL[e.action].toLowerCase()}
                    </span>
                  </span>
                  <span className="pt-0.5 text-ink-2">{e.changes.length ? <ChevronDown className={cn("size-4 transition-transform", expanded && "rotate-180")} aria-hidden /> : null}</span>
                </button>
                {expanded ? (
                  <div className="mt-3 rounded-lg bg-surface-2 p-3 sm:ml-[calc(10rem+1rem)]">
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
        {query.data && !query.data.items.length ? <EmptyState title="Brak wpisów dla tych filtrów." /> : null}
        {query.data ? <Pagination page={page} pageSize={30} total={query.data.total} onPage={setPage} /> : null}
      </Panel>
    </Container>
  );
}
