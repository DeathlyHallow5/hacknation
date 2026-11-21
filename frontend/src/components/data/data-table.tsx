"use client";

import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/form-controls";
import { Skeleton } from "@/components/ui/misc";
import { SimpleSelect } from "@/components/ui/select";
import { fmtNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  cell: (row: T) => React.ReactNode;
  /** Server sort field; enables the sort toggle. */
  sort?: string;
  className?: string;
  headerClassName?: string;
  /** Hide below this breakpoint. */
  hideBelow?: "sm" | "md" | "lg" | "xl";
}

const HIDE = { sm: "hidden sm:table-cell", md: "hidden md:table-cell", lg: "hidden lg:table-cell", xl: "hidden xl:table-cell" };

export function DataTable<T>({
  columns,
  rows,
  getId,
  loading,
  sort,
  onSort,
  selection,
  onSelectionChange,
  onRowClick,
  rowClassName,
  empty,
  skeletonRows = 8,
  caption,
  dense,
}: {
  columns: Column<T>[];
  rows: T[] | undefined;
  getId: (row: T) => string;
  loading?: boolean;
  sort?: string;
  onSort?: (sort: string) => void;
  selection?: Set<string>;
  onSelectionChange?: (s: Set<string>) => void;
  onRowClick?: (row: T) => void;
  rowClassName?: (row: T) => string | undefined;
  empty?: React.ReactNode;
  skeletonRows?: number;
  caption?: string;
  dense?: boolean;
}) {
  const selectable = Boolean(selection && onSelectionChange);
  const ids = (rows ?? []).map(getId);
  const allSelected = selectable && ids.length > 0 && ids.every((id) => selection!.has(id));
  const someSelected = selectable && ids.some((id) => selection!.has(id));

  const toggleAll = () => {
    const next = new Set(selection);
    if (allSelected) ids.forEach((id) => next.delete(id));
    else ids.forEach((id) => next.add(id));
    onSelectionChange!(next);
  };
  const toggle = (id: string) => {
    const next = new Set(selection);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onSelectionChange!(next);
  };

  const sortField = sort?.replace(/^-/, "");
  const desc = sort?.startsWith("-");
  const cellPad = dense ? "px-3 py-2" : "px-4 py-3";

  return (
    <div className="scroll-quiet w-full overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead>
          <tr className="border-b border-line bg-surface-2 text-left">
            {selectable ? (
              <th scope="col" className="w-10 px-4 py-2.5">
                <Checkbox
                  aria-label="Zaznacz wszystkie na stronie"
                  checked={allSelected ? true : someSelected ? "indeterminate" : false}
                  onCheckedChange={toggleAll}
                />
              </th>
            ) : null}
            {columns.map((c) => {
              const active = c.sort && sortField === c.sort;
              return (
                <th
                  key={c.key}
                  scope="col"
                  aria-sort={active ? (desc ? "descending" : "ascending") : undefined}
                  className={cn("px-4 py-2.5 text-[0.8125rem] font-semibold whitespace-nowrap text-ink-2", dense && "px-3", c.hideBelow && HIDE[c.hideBelow], c.headerClassName)}
                >
                  {c.sort && onSort ? (
                    <button
                      type="button"
                      onClick={() => onSort(active && !desc ? `-${c.sort}` : c.sort!)}
                      className="-mx-1 inline-flex items-center gap-1 rounded px-1 hover:text-ink"
                    >
                      {c.header}
                      {active ? (desc ? <ArrowDown className="size-3.5" /> : <ArrowUp className="size-3.5" />) : <ArrowUpDown className="size-3.5 opacity-40" />}
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {loading && !rows
            ? Array.from({ length: skeletonRows }).map((_, i) => (
                <tr key={i} className="border-b border-line last:border-0">
                  {selectable ? <td className={cellPad} /> : null}
                  {columns.map((c) => (
                    <td key={c.key} className={cn(cellPad, c.hideBelow && HIDE[c.hideBelow])}>
                      <Skeleton className="h-4" style={{ width: `${45 + ((i * 7 + c.key.length * 13) % 45)}%` }} />
                    </td>
                  ))}
                </tr>
              ))
            : (rows ?? []).map((row) => {
                const id = getId(row);
                const selected = selection?.has(id);
                return (
                  <tr
                    key={id}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    className={cn(
                      "border-b border-line transition-colors last:border-0",
                      onRowClick && "cursor-pointer hover:bg-surface-2",
                      selected && "bg-accent/[0.05]",
                      loading && "opacity-60",
                      rowClassName?.(row),
                    )}
                  >
                    {selectable ? (
                      <td className={cellPad} onClick={(e) => e.stopPropagation()}>
                        <Checkbox aria-label="Zaznacz wiersz" checked={selected} onCheckedChange={() => toggle(id)} />
                      </td>
                    ) : null}
                    {columns.map((c) => (
                      <td key={c.key} className={cn(cellPad, "align-middle", c.hideBelow && HIDE[c.hideBelow], c.className)}>
                        {c.cell(row)}
                      </td>
                    ))}
                  </tr>
                );
              })}
        </tbody>
      </table>
      {!loading && rows && rows.length === 0 ? <div className="border-t border-line">{empty}</div> : null}
    </div>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
  onPageSize,
  sizes = [25, 50, 100],
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
  onPageSize?: (s: number) => void;
  sizes?: number[];
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3 text-[0.8125rem] text-ink-2">
      <span className="tabular">
        {fmtNumber(from)}–{fmtNumber(to)} z {fmtNumber(total)}
      </span>
      <div className="flex items-center gap-3">
        {onPageSize ? (
          <label className="flex items-center gap-2">
            <span>Na stronie</span>
            <SimpleSelect
              aria-label="Liczba wierszy na stronie"
              className="h-8 w-20"
              value={String(pageSize)}
              onChange={(v) => onPageSize(Number(v))}
              options={sizes.map((s) => ({ value: String(s), label: String(s) }))}
            />
          </label>
        ) : null}
        <div className="flex items-center gap-1">
          <Button size="icon-sm" variant="ghost" aria-label="Poprzednia strona" disabled={page <= 1} onClick={() => onPage(page - 1)}>
            <ChevronLeft />
          </Button>
          <span className="tabular min-w-20 text-center">
            Strona {fmtNumber(page)} z {fmtNumber(pages)}
          </span>
          <Button size="icon-sm" variant="ghost" aria-label="Następna strona" disabled={page >= pages} onClick={() => onPage(page + 1)}>
            <ChevronRight />
          </Button>
        </div>
      </div>
    </div>
  );
}
