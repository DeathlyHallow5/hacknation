"use client";

import { Copy, Ellipsis, Eye, Send, Server, ShieldOff } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";
import { MonoValue } from "@/components/data/bits";
import { DataTable, type Column } from "@/components/data/data-table";
import { ChangeChip, ConfidenceMeter, FindingStatusChip, ScoreMeter } from "@/components/data/status";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Finding } from "@/lib/api/types";
import { FINDING_CATEGORY_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";
import { copyToClipboard } from "@/lib/utils";

function RowActions({ f, onOpen, onChanged }: { f: Finding; onOpen: () => void; onChanged: () => void }) {
  const can = useCan();
  return (
    <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
      <Button size="sm" variant="ghost" onClick={onOpen}>
        Szczegóły
      </Button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon-sm" variant="ghost" aria-label={`Więcej działań dla ${f.ip}`}>
            <Ellipsis />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem onSelect={onOpen}>
            <Eye /> Pokaż dowody
          </DropdownMenuItem>
          <DropdownMenuItem asChild>
            <Link href={`/assets/${f.host_id}`}>
              <Server /> Otwórz host
            </Link>
          </DropdownMenuItem>
          <DropdownMenuItem
            onSelect={async () => {
              await copyToClipboard(f.ip);
              toast.success("Skopiowano adres IP", { description: f.ip });
            }}
          >
            <Copy /> Kopiuj adres IP
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            disabled={!can("findings:defectdojo")}
            onSelect={async () => {
              try {
                await api.findings.defectdojo({ ids: [f.id], as: "finding" });
                toast.success("Wysłano do DefectDojo");
                onChanged();
              } catch (e) {
                toast.error("Nie udało się wysłać", { description: errorMessage(e) });
              }
            }}
          >
            <Send /> Wyślij do DefectDojo
          </DropdownMenuItem>
          <DropdownMenuItem
            disabled={!can("findings:update")}
            onSelect={async () => {
              try {
                await api.findings.update(f.id, { status: "false_positive" });
                toast.success("Oznaczono jako fałszywy alarm", {
                  action: { label: "Cofnij", onClick: () => api.findings.update(f.id, { status: f.status }).then(onChanged) },
                });
                onChanged();
              } catch (e) {
                toast.error("Nie udało się zapisać", { description: errorMessage(e) });
              }
            }}
          >
            <ShieldOff /> Oznacz jako fałszywy alarm
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

export function FindingsTable({
  rows,
  loading,
  sort,
  onSort,
  selection,
  onSelectionChange,
  onOpen,
  onChanged,
  showStatus,
  empty,
}: {
  rows: Finding[] | undefined;
  loading?: boolean;
  sort?: string;
  onSort?: (s: string) => void;
  selection?: Set<string>;
  onSelectionChange?: (s: Set<string>) => void;
  onOpen: (id: string) => void;
  onChanged: () => void;
  showStatus?: boolean;
  empty?: React.ReactNode;
}) {
  const columns: Column<Finding>[] = [
    {
      // Below xl one stacked column replaces address, port and description, so nothing is cut off.
      // Phones also get status and priority here; tablets and laptops keep those as their own columns.
      key: "summary",
      header: "Znalezisko",
      showBelow: "xl",
      cell: (f) => (
        <div className="grid min-w-0 gap-1">
          <span className="line-clamp-2 font-semibold text-ink">{f.title}</span>
          <span className="mono truncate text-sm text-ink-2">
            {f.ip}
            {f.port ? `:${f.port}` : ""}
          </span>
          {f.technologies.length ? <span className="hidden truncate text-xs text-ink-2 md:block">{f.technologies.join(", ")}</span> : null}
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 md:hidden">
            <ChangeChip state={f.change} measurements={f.measurements} />
            <ScoreMeter score={f.score_override ?? f.score} overridden={f.score_override !== null} />
          </span>
        </div>
      ),
    },
    {
      key: "address",
      header: "Adres IP / domena",
      sort: "ip",
      hideBelow: "xl",
      cell: (f) => (
        <div className="grid min-w-0 gap-0.5">
          <MonoValue value={f.ip} className="font-medium text-ink" />
          {f.hostname ? <span className="max-w-48 truncate text-xs text-ink-2" title={f.hostname}>{f.hostname}</span> : null}
        </div>
      ),
    },
    {
      key: "service",
      header: "Port / usługa",
      hideBelow: "xl",
      cell: (f) => <span className="mono text-sm whitespace-nowrap text-ink">{f.service_label ?? "—"}</span>,
    },
    {
      key: "what",
      header: "Znalezisko i technologie",
      sort: "title",
      hideBelow: "xl",
      cell: (f) => (
        <div className="grid max-w-sm min-w-56 gap-0.5" title={FINDING_CATEGORY_LABEL[f.category]}>
          <span className="font-semibold text-ink">{f.title}</span>
          {f.technologies.length ? <span className="truncate text-xs text-ink-2">{f.technologies.join(", ")}</span> : null}
        </div>
      ),
    },
    {
      key: "change",
      header: "Status zmiany",
      sort: "change",
      hideBelow: "md",
      cell: (f) => <ChangeChip state={f.change} measurements={f.measurements} />,
    },
    ...(showStatus
      ? [
          {
            key: "status",
            header: "Obsługa",
            sort: "status",
            hideBelow: "lg" as const,
            cell: (f: Finding) => (
              <div className="grid gap-0.5">
                <FindingStatusChip value={f.status} />
                {f.assignee ? <span className="text-xs text-ink-2">{f.assignee}</span> : null}
              </div>
            ),
          },
        ]
      : []),
    {
      key: "score",
      header: "Priorytet",
      sort: "score",
      hideBelow: "md",
      cell: (f) => <ScoreMeter score={f.score_override ?? f.score} overridden={f.score_override !== null} />,
    },
    {
      // One meter per row is enough: confidence is a plain percentage.
      key: "confidence",
      header: "Pewność",
      sort: "confidence",
      hideBelow: "xl",
      cell: (f) => <ConfidenceMeter value={f.confidence} compact valueClassName="text-ink-2" />,
    },
    {
      key: "actions",
      header: "Akcje",
      headerClassName: "text-right",
      hideBelow: "md",
      cell: (f) => <RowActions f={f} onOpen={() => onOpen(f.id)} onChanged={onChanged} />,
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={rows}
      getId={(f) => f.id}
      loading={loading}
      sort={sort}
      onSort={onSort}
      selection={selection}
      onSelectionChange={onSelectionChange}
      onRowClick={(f) => onOpen(f.id)}
      caption="Znaleziska"
      empty={empty}
    />
  );
}
