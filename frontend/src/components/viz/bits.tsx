"use client";

import { ArrowRight } from "lucide-react";
import * as React from "react";
import { ChartTooltip, LegendItem, TipRow, useWidth, type TipState } from "@/components/viz/core";
import type { FieldChange, RedirectHop, ScanBatch, TechStat } from "@/lib/api/types";
import { fmtDuration, fmtNumber } from "@/lib/format";
import { TECH_CATEGORY_LABEL } from "@/lib/labels";
import { cn } from "@/lib/utils";

/** Horizontal bars, one hue; values are direct-labelled. */
export function TechBars({ items, onSelect }: { items: TechStat[]; onSelect?: (t: TechStat) => void }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <ul className="grid gap-2.5" aria-label="Najczęściej wykrywane technologie">
      {items.map((t) => (
        <li key={t.name}>
          <button
            type="button"
            onClick={() => onSelect?.(t)}
            className="group grid w-full grid-cols-[minmax(7rem,11rem)_1fr_auto] items-center gap-3 rounded-md text-left text-sm"
            title={`${t.name}: ${fmtNumber(t.count)} usług (${TECH_CATEGORY_LABEL[t.category]})`}
          >
            <span className="truncate font-semibold text-ink group-hover:text-link">{t.name}</span>
            <span className="relative h-2.5 rounded-r bg-surface-3">
              <span className="absolute inset-y-0 left-0 rounded-r-[4px] bg-data transition-[width] duration-500" style={{ width: `${(t.count / max) * 100}%` }} />
            </span>
            <span className="tabular w-20 text-right text-ink">
              {fmtNumber(t.count)}
              {t.delta > 0 ? <span className="ml-1 text-xs font-semibold text-new-ink">+{t.delta}</span> : null}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

const BATCH_STYLE: Record<ScanBatch["status"], { fill: string; label: string }> = {
  done: { fill: "var(--data)", label: "Zakończona" },
  running: { fill: "var(--accent)", label: "W toku" },
  paused: { fill: "var(--unstable)", label: "Wstrzymana (punkt kontrolny)" },
  failed: { fill: "var(--gone)", label: "Przerwana" },
  pending: { fill: "transparent", label: "Oczekuje" },
};

/** Sub-groups (address batches) of a scan as a grid of cells. */
export function BatchGrid({ batches }: { batches: ScanBatch[] }) {
  const [ref, width] = useWidth<HTMLDivElement>(600);
  const [hover, setHover] = React.useState<number | null>(null);
  const cols = batches.length > 128 ? 32 : 16;
  const gap = 3;
  const cell = Math.max(10, Math.min(30, Math.floor((width - gap * (cols - 1)) / cols)));
  const rows = Math.ceil(batches.length / cols);
  const counts = batches.reduce<Record<string, number>>((m, b) => ((m[b.status] = (m[b.status] ?? 0) + 1), m), {});
  const tip: TipState | null =
    hover === null
      ? null
      : {
          x: (hover % cols) * (cell + gap) + cell / 2,
          y: Math.floor(hover / cols) * (cell + gap) + cell / 2,
          content: (
            <>
              <div className="mono mb-1 font-bold text-white">{batches[hover].cidr}</div>
              <TipRow value={BATCH_STYLE[batches[hover].status].label} label={`podgrupa ${batches[hover].index + 1}`} />
              {batches[hover].hosts_alive ? <TipRow value={fmtNumber(batches[hover].hosts_alive)} label="aktywnych hostów" /> : null}
              {batches[hover].duration_s ? <TipRow value={fmtDuration(batches[hover].duration_s)} label="czas trwania" /> : null}
              {batches[hover].retries ? <TipRow value={batches[hover].retries} label="ponowień" /> : null}
            </>
          ),
        };
  return (
    <div className="grid gap-3">
      <div ref={ref} className="relative">
        <div
          className="grid"
          style={{ gridTemplateColumns: `repeat(${cols}, ${cell}px)`, gap, height: rows * (cell + gap) }}
          role="list"
          aria-label="Podgrupy adresów"
        >
          {batches.map((b, i) => (
            <span
              key={b.id}
              role="listitem"
              aria-label={`${b.cidr}: ${BATCH_STYLE[b.status].label}`}
              onPointerEnter={() => setHover(i)}
              onPointerLeave={() => setHover(null)}
              className={cn(
                "rounded-[4px] transition-transform hover:scale-110",
                b.status === "pending" && "border border-dashed border-line-strong",
                b.status === "running" && "animate-pulse-dot",
              )}
              style={{ width: cell, height: cell, background: BATCH_STYLE[b.status].fill }}
            />
          ))}
        </div>
        <ChartTooltip tip={tip} containerWidth={width} />
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {(["done", "running", "paused", "pending", "failed"] as const)
          .filter((s) => counts[s])
          .map((s) => (
            <LegendItem key={s} color={BATCH_STYLE[s].fill === "transparent" ? "var(--line-strong)" : BATCH_STYLE[s].fill} label={BATCH_STYLE[s].label} value={counts[s]} />
          ))}
      </div>
    </div>
  );
}

/** Before/after rows for a change. */
export function FieldDiff({ fields }: { fields: FieldChange[] }) {
  if (!fields.length) return null;
  return (
    <div className="grid gap-1.5">
      {fields.map((f) => (
        <div key={f.field} className="grid gap-1 text-[0.8125rem] sm:grid-cols-[9rem_1fr]">
          <span className="text-ink-2">{f.label}</span>
          <span className="flex min-w-0 flex-wrap items-center gap-1.5">
            {f.before !== null ? (
              <span className="mono rounded bg-gone-soft px-1.5 py-0.5 text-gone-ink line-through decoration-1 contrast:border contrast:border-current">{f.before}</span>
            ) : (
              <span className="text-ink-3">brak</span>
            )}
            <ArrowRight className="size-3.5 shrink-0 text-ink-3" aria-label="zmieniono na" />
            {f.after !== null ? (
              <span className="mono rounded bg-new-soft px-1.5 py-0.5 text-new-ink contrast:border contrast:border-current">{f.after}</span>
            ) : (
              <span className="text-ink-3">brak</span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

export function RedirectChain({ hops, finalUrl, finalStatus }: { hops: RedirectHop[]; finalUrl: string; finalStatus: number }) {
  const all = [...hops, { url: finalUrl, status_code: finalStatus }];
  return (
    <ol className="grid gap-1.5">
      {all.map((h, i) => (
        <li key={i} className="flex min-w-0 items-center gap-2 text-[0.8125rem]">
          <span
            className={cn(
              "tabular shrink-0 rounded px-1.5 py-0.5 text-xs font-bold",
              h.status_code >= 300 && h.status_code < 400 ? "bg-unstable-soft text-unstable-ink" : h.status_code >= 400 ? "bg-gone-soft text-gone-ink" : "bg-new-soft text-new-ink",
            )}
          >
            {h.status_code}
          </span>
          <span className="mono truncate">{h.url}</span>
          {i < all.length - 1 ? <ArrowRight className="size-3.5 shrink-0 text-ink-3" aria-hidden /> : null}
        </li>
      ))}
    </ol>
  );
}

/** Data-bearing top border: proportional segments with 2px gaps. */
export function SegmentBar({ parts, className }: { parts: { value: number; color: string; label: string }[]; className?: string }) {
  const total = parts.reduce((s, p) => s + p.value, 0) || 1;
  return (
    <div className={cn("flex h-[3px] w-full gap-[2px]", className)} role="img" aria-label={parts.map((p) => `${p.label}: ${p.value}`).join(", ")}>
      {parts
        .filter((p) => p.value > 0)
        .map((p) => (
          <span key={p.label} className="h-full first:rounded-l-full last:rounded-r-full" style={{ flexGrow: p.value / total, background: p.color }} />
        ))}
    </div>
  );
}
