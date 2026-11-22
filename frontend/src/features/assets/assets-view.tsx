"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Pencil, TriangleAlert, X } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { EmptyState, ErrorState, MonoValue, SearchInput, useDebouncedValue } from "@/components/data/bits";
import { DataTable, Pagination, type Column } from "@/components/data/data-table";
import { AvailabilityBadge, ChangeChip, ResponsePattern, ScoreMeter } from "@/components/data/status";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/form-controls";
import { Chip, Panel, Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { Tooltip } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { api } from "@/lib/api/endpoints";
import type { Availability, ChangeState, DeviceType, HostSummary, ServiceSummary } from "@/lib/api/types";
import { countLabel, fmtNumber, fmtSmart } from "@/lib/format";
import { AVAILABILITY_LABEL, CHANGE_LABEL, DEVICE_LABEL } from "@/lib/labels";

/** An active filter that came from elsewhere (a map square, a group): neutral, removable. */
function FilterToken({ children, onRemove, removeLabel }: { children: React.ReactNode; onRemove: () => void; removeLabel: string }) {
  return (
    <span className="inline-flex h-8 w-fit items-center gap-1 rounded-md border border-line-strong bg-surface-2 pr-1 pl-2.5 text-sm text-ink">
      {children}
      <button type="button" aria-label={removeLabel} onClick={onRemove} className="rounded-sm p-1 text-ink-2 hover:bg-surface-3 hover:text-ink">
        <X className="size-3.5" />
      </button>
    </span>
  );
}

function HostsTab() {
  const params = useSearchParams();
  const router = useRouter();
  const [q, setQ] = React.useState(params.get("q") ?? "");
  const [cidr, setCidr] = React.useState(params.get("cidr") ?? "");
  const [availability, setAvailability] = React.useState<Availability | "">("");
  const [change, setChange] = React.useState<ChangeState | "">((params.get("change") as ChangeState) ?? "");
  const [device, setDevice] = React.useState<DeviceType | "">("");
  const [overrides, setOverrides] = React.useState(false);
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(50);
  const [sort, setSort] = React.useState("ip");
  const dq = useDebouncedValue(q);
  const query = useQuery({
    queryKey: ["hosts", dq, cidr, availability, change, device, overrides, page, pageSize, sort],
    queryFn: () => api.hosts.list({ q: dq, cidr, availability, change, device, has_overrides: overrides ? "true" : "", page, page_size: pageSize, sort }),
    placeholderData: keepPreviousData,
  });
  const reset = () => setPage(1);

  const columns: Column<HostSummary>[] = [
    {
      key: "ip",
      header: "Adres IP / nazwa",
      sort: "ip",
      cell: (h) => (
        <div className="grid min-w-0 gap-0.5">
          <span className="flex items-center gap-1.5">
            <MonoValue value={h.ip} className="font-medium" />
            {h.has_manual_overrides ? (
              <Tooltip content="Dane edytowane ręcznie, zachowane przy kolejnych skanach">
                <Pencil className="size-3 text-changed-ink" aria-label="edytowano ręcznie" />
              </Tooltip>
            ) : null}
          </span>
          {h.hostnames[0] ? <span className="max-w-72 truncate text-xs text-ink-2">{h.hostnames[0]}</span> : null}
        </div>
      ),
    },
    {
      key: "availability",
      header: "Dostępność",
      sort: "availability",
      cell: (h) => (
        <div className="grid gap-1">
          <AvailabilityBadge value={h.availability} />
          {/* The measurement dots only earn their place when a scan was missed. */}
          {h.response_pattern.some((p) => !p) ? <ResponsePattern pattern={h.response_pattern} /> : null}
        </div>
      ),
    },
    { key: "change", header: "Zmiana", cell: (h) => (h.change === "unchanged" ? <span className="text-ink-3">—</span> : <ChangeChip state={h.change} />) },
    { key: "device", header: "Typ", hideBelow: "lg", cell: (h) => <span className="text-sm">{DEVICE_LABEL[h.device_type]}</span> },
    {
      key: "ports",
      header: "Porty",
      sort: "services",
      hideBelow: "md",
      cell: (h) =>
        h.open_ports.length ? (
          <span className="text-sm whitespace-nowrap" title={h.open_ports.length > 3 ? h.open_ports.join(", ") : undefined}>
            <span className="mono text-ink">{h.open_ports.slice(0, 3).join(", ")}</span>
            {h.open_ports.length > 3 ? <span className="tabular text-ink-2"> +{h.open_ports.length - 3}</span> : null}
          </span>
        ) : (
          <span className="text-sm text-ink-2">tylko ping</span>
        ),
    },
    {
      key: "tech",
      header: "Technologie",
      hideBelow: "xl",
      cell: (h) =>
        h.technologies.length ? (
          <span className="block max-w-64 truncate text-xs text-ink-2" title={h.technologies.join(", ")}>
            {h.technologies.join(", ")}
          </span>
        ) : (
          <span className="text-ink-3">—</span>
        ),
    },
    { key: "owner", header: "Właściciel", sort: "owner", hideBelow: "xl", cell: (h) => <span className="text-sm">{h.owner ?? "—"}</span> },
    { key: "score", header: "Priorytet", sort: "score", hideBelow: "lg", cell: (h) => (h.score ? <ScoreMeter score={h.score} /> : <span className="text-ink-3">—</span>) },
    { key: "seen", header: "Ostatnio", sort: "last_seen", hideBelow: "md", cell: (h) => <span className="text-sm whitespace-nowrap text-ink-2">{fmtSmart(h.last_seen)}</span> },
  ];

  return (
    <Panel flush>
      <div className="grid grid-cols-2 gap-2 border-b border-line px-5 py-3 sm:flex sm:flex-wrap sm:items-center">
        <SearchInput value={q} onChange={(v) => { setQ(v); reset(); }} placeholder="IP, nazwa hosta, właściciel lub tag…" className="col-span-2 sm:w-80" />
        <SimpleSelect aria-label="Dostępność" className="w-full sm:w-40" value={availability} onChange={(v) => { setAvailability(v as Availability | ""); reset(); }} allLabel="Dostępność" options={(Object.keys(AVAILABILITY_LABEL) as Availability[]).map((a) => ({ value: a, label: AVAILABILITY_LABEL[a] }))} />
        <SimpleSelect aria-label="Zmiana" className="w-full sm:w-40" value={change} onChange={(v) => { setChange(v as ChangeState | ""); reset(); }} allLabel="Każda zmiana" options={(["new", "changed", "gone", "unstable", "unchanged"] as ChangeState[]).map((c) => ({ value: c, label: CHANGE_LABEL[c] }))} />
        <SimpleSelect aria-label="Typ urządzenia" className="w-full sm:w-48" value={device} onChange={(v) => { setDevice(v as DeviceType | ""); reset(); }} allLabel="Każdy typ" options={(Object.keys(DEVICE_LABEL) as DeviceType[]).map((d) => ({ value: d, label: DEVICE_LABEL[d] }))} />
        <label className="col-span-2 flex items-center gap-2 text-sm font-semibold text-ink-2 sm:col-span-1">
          <Switch checked={overrides} onCheckedChange={(c) => { setOverrides(c); reset(); }} /> Edytowane ręcznie
        </label>
        {cidr ? (
          <FilterToken removeLabel="Usuń filtr podsieci" onRemove={() => { setCidr(""); router.replace("/assets", { scroll: false }); }}>
            <span className="mono">{cidr}</span>
          </FilterToken>
        ) : null}
        <span className="col-span-2 text-sm text-ink-2 tabular sm:ml-auto">{query.data ? countLabel(query.data.total, ["host", "hosty", "hostów"]) : ""}</span>
      </div>
      {query.isError ? <ErrorState className="m-4" error={query.error} onRetry={() => query.refetch()} /> : null}
      <DataTable
        columns={columns}
        rows={query.data?.items}
        getId={(h) => h.id}
        loading={query.isFetching}
        sort={sort}
        onSort={setSort}
        onRowClick={(h) => router.push(`/assets/${h.id}`)}
        caption="Hosty"
        dense
        empty={<EmptyState title="Brak hostów dla wybranych filtrów" description="Zmień kryteria wyszukiwania lub usuń filtr podsieci." />}
      />
      {query.data ? <Pagination page={page} pageSize={pageSize} total={query.data.total} onPage={setPage} onPageSize={(s) => { setPageSize(s); setPage(1); }} /> : null}
    </Panel>
  );
}

function ServicesTab({ initialGroup }: { initialGroup: string }) {
  const params = useSearchParams();
  const router = useRouter();
  const [q, setQ] = React.useState(params.get("q") ?? "");
  const [port, setPort] = React.useState("");
  const [web, setWeb] = React.useState(false);
  const [group, setGroup] = React.useState(initialGroup);
  const [page, setPage] = React.useState(1);
  const dq = useDebouncedValue(q);
  const query = useQuery({
    queryKey: ["services", dq, port, web, group, page],
    queryFn: () => api.services.list({ q: dq, port, web: web ? "true" : "", group, page, page_size: 50 }),
    placeholderData: keepPreviousData,
  });
  const columns: Column<ServiceSummary>[] = [
    {
      key: "addr",
      header: "Adres i port",
      cell: (s) => (
        <div className="grid gap-0.5">
          <MonoValue value={`${s.ip}:${s.port}`} className="font-medium" />
          {s.hostname ? <span className="max-w-64 truncate text-xs text-ink-2">{s.hostname}</span> : null}
        </div>
      ),
    },
    {
      key: "svc",
      header: "Usługa",
      cell: (s) => (
        <div className="grid gap-0.5">
          <span className="text-sm font-semibold">
            {s.product ?? s.name} {s.version ? <span className="mono font-normal text-ink-2">{s.version}</span> : null}
            {s.has_manual_overrides ? <Pencil className="ml-1 inline size-3 text-changed-ink" aria-label="poprawione ręcznie" /> : null}
          </span>
          <span className="text-xs text-ink-2">
            <span className="mono">
              {s.port}/{s.protocol}
            </span>{" "}
            {s.name}
            {s.tls ? ", TLS" : ""}
          </span>
        </div>
      ),
    },
    { key: "title", header: "Tytuł strony", hideBelow: "lg", cell: (s) => <span className="line-clamp-2 max-w-72 text-sm">{s.title ?? "—"}</span> },
    {
      key: "tech",
      header: "Technologie",
      hideBelow: "md",
      cell: (s) =>
        s.technologies.length ? (
          <span className="block max-w-64 truncate text-xs text-ink-2" title={s.technologies.join(", ")}>
            {s.technologies.join(", ")}
          </span>
        ) : (
          <span className="text-ink-3">—</span>
        ),
    },
    { key: "conf", header: "Pewność", hideBelow: "lg", cell: (s) => <span className="tabular text-sm text-ink-2">{Math.round(s.confidence * 100)}%</span> },
    { key: "change", header: "Zmiana", cell: (s) => (s.change === "unchanged" ? <span className="text-ink-3">—</span> : <ChangeChip state={s.change} />) },
  ];
  return (
    <Panel flush>
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
        <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Produkt, technologia, IP…" className="w-full sm:w-72" />
        <SearchInput value={port} onChange={(v) => { setPort(v.replace(/\D/g, "")); setPage(1); }} placeholder="Port" className="w-28" aria-label="Filtr portu" />
        <label className="flex items-center gap-2 text-sm font-semibold text-ink-2">
          <Switch checked={web} onCheckedChange={(c) => { setWeb(c); setPage(1); }} /> Tylko WWW
        </label>
        {group ? (
          <FilterToken removeLabel="Usuń filtr grupy" onRemove={() => { setGroup(""); router.replace("/assets?tab=services", { scroll: false }); }}>
            Grupa: {group}
          </FilterToken>
        ) : null}
        <span className="text-sm text-ink-2 tabular sm:ml-auto">{query.data ? countLabel(query.data.total, ["usługa", "usługi", "usług"]) : ""}</span>
      </div>
      <DataTable
        columns={columns}
        rows={query.data?.items}
        getId={(s) => s.id}
        loading={query.isFetching}
        onRowClick={(s) => router.push(`/assets/${s.host_id}#svc-${s.port}`)}
        caption="Usługi"
        dense
        empty={<EmptyState title="Brak usług dla tych filtrów." />}
      />
      {query.data ? <Pagination page={page} pageSize={50} total={query.data.total} onPage={setPage} /> : null}
    </Panel>
  );
}

function GroupsTab({ onOpenGroup }: { onOpenGroup: (key: string) => void }) {
  const [q, setQ] = React.useState("");
  const dq = useDebouncedValue(q);
  const query = useQuery({ queryKey: ["service-groups", dq], queryFn: () => api.services.groups({ q: dq }) });
  const max = Math.max(1, ...(query.data ?? []).map((g) => g.count));
  return (
    <div className="grid gap-4">
      <SearchInput value={q} onChange={setQ} placeholder="Szukaj grupy usług…" className="w-full sm:w-80" />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(query.data ?? []).slice(0, 30).map((g) => {
          const vmax = Math.max(1, ...g.versions.map((v) => v.count));
          return (
            <article key={g.key} className="grid content-start gap-3 rounded-xl border border-line bg-surface p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="grid gap-0.5">
                  <h3 className="font-semibold">{g.label}</h3>
                  <span className="text-xs text-ink-2">
                    porty: <span className="mono">{g.port_set.slice(0, 6).join(", ")}</span>
                  </span>
                </div>
                <div className="grid justify-items-end gap-1">
                  <span className="tabular text-lg font-semibold">{fmtNumber(g.count)}</span>
                  {g.outdated ? (
                    <Chip tone="warning">
                      <TriangleAlert className="size-3" aria-hidden /> nieaktualne wersje
                    </Chip>
                  ) : null}
                </div>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-surface-3">
                <div className="h-full rounded-full bg-data" style={{ width: `${(g.count / max) * 100}%` }} />
              </div>
              <ul className="grid gap-1">
                {g.versions.slice(0, 4).map((v) => (
                  <li key={v.version ?? "?"} className="grid grid-cols-[minmax(0,8rem)_1fr_auto] items-center gap-2 text-sm">
                    <span className="mono truncate">{v.version ?? "nieznana"}</span>
                    <span className="h-1.5 rounded-r bg-surface-3">
                      <span className="block h-full rounded-r bg-ink-3" style={{ width: `${(v.count / vmax) * 100}%` }} />
                    </span>
                    <span className="tabular text-ink-2">{fmtNumber(v.count)}</span>
                  </li>
                ))}
              </ul>
              <Button size="sm" variant="ghost" className="justify-self-start" onClick={() => onOpenGroup(g.key)}>
                Pokaż usługi
              </Button>
            </article>
          );
        })}
        {!query.data ? [0, 1, 2, 3, 4, 5].map((i) => <Skeleton key={i} className="h-48 rounded-xl" />) : null}
      </div>
    </div>
  );
}

export function AssetsView() {
  const params = useSearchParams();
  const [tab, setTab] = React.useState(params.get("tab") ?? "hosts");
  const [group, setGroup] = React.useState(params.get("group") ?? "");
  return (
    <Container className="pb-12">
      <PageHeader
        title="Zasoby"
        description="Wszystko, co skaner znalazł w zakresach: hosty, otwarte porty, usługi z wersjami i technologie stron WWW. Kliknij host, aby zobaczyć szczegóły i historię."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="hosts">Hosty</TabsTrigger>
          <TabsTrigger value="services">Usługi</TabsTrigger>
          <TabsTrigger value="groups">Grupy podobnych usług</TabsTrigger>
        </TabsList>
        <TabsContent value="hosts">
          <HostsTab />
        </TabsContent>
        <TabsContent value="services">
          <ServicesTab key={group} initialGroup={group} />
        </TabsContent>
        <TabsContent value="groups">
          <GroupsTab
            onOpenGroup={(k) => {
              setGroup(k);
              setTab("services");
            }}
          />
        </TabsContent>
      </Tabs>
    </Container>
  );
}
