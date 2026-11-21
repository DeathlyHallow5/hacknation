"use client";

import { Table2 } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { ChartTooltip, LegendItem, TipRow, useWidth, type TipState } from "@/components/viz/core";
import type { ChangeKind, ChangesTimelinePoint } from "@/lib/api/types";
import { fmtDayMonth, fmtNumber } from "@/lib/format";
import { CHANGE_LABEL_PLURAL } from "@/lib/labels";
import { cn } from "@/lib/utils";

/** Stack order chosen with the palette validator (adjacent pairs stay CVD-separable). */
export const KIND_ORDER: ChangeKind[] = ["new", "changed", "gone", "unstable"];
export const KIND_COLOR: Record<ChangeKind, string> = {
  new: "var(--new)",
  changed: "var(--changed)",
  gone: "var(--gone)",
  unstable: "var(--unstable)",
};

function topRounded(x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.min(r, w / 2, h);
  return `M${x},${y + h} V${y + rr} Q${x},${y} ${x + rr},${y} H${x + w - rr} Q${x + w},${y} ${x + w},${y + rr} V${y + h} Z`;
}

/**
 * Stacked columns: changes detected by each scan. 2px surface gaps separate
 * segments; only the top of a column is rounded (the data end).
 */
export function ChangesTimeline({
  points,
  height = 200,
  selected,
  onSelect,
}: {
  points: ChangesTimelinePoint[];
  height?: number;
  selected?: number | null;
  onSelect?: (p: ChangesTimelinePoint) => void;
}) {
  const [ref, width] = useWidth<HTMLDivElement>(640);
  const [hover, setHover] = React.useState<number | null>(null);
  const [table, setTable] = React.useState(false);
  const left = 34;
  const bottom = 22;
  const top = 8;
  const plotW = Math.max(100, width - left);
  const plotH = height - bottom - top;
  const totals = points.map((p) => KIND_ORDER.reduce((s, k) => s + p[k], 0));
  const maxTotal = Math.max(10, ...totals);
  const step = maxTotal > 80 ? 40 : maxTotal > 40 ? 20 : 10;
  const yMax = Math.ceil(maxTotal / step) * step;
  const ticks = Array.from({ length: yMax / step + 1 }, (_, i) => i * step);
  const n = Math.max(1, points.length);
  const slot = plotW / n;
  const barW = Math.max(4, Math.min(22, slot - 4));
  const sy = (v: number) => (v / yMax) * plotH;
  const last = points.at(-1);

  const tip: TipState | null =
    hover === null
      ? null
      : {
          x: left + hover * slot + slot / 2,
          y: top + plotH - sy(totals[hover]) / 2 - 10,
          content: (
            <>
              <div className="mb-1 text-chrome-ink-2">
                Skan #{points[hover].scan_number}, {fmtDayMonth(points[hover].at)}
              </div>
              {KIND_ORDER.slice()
                .reverse()
                .map((k) => (
                  <TipRow key={k} color={KIND_COLOR[k]} value={fmtNumber(points[hover][k])} label={CHANGE_LABEL_PLURAL[k as Exclude<ChangeKind, never>]} />
                ))}
              {onSelect ? <div className="mt-1.5 text-chrome-ink-2">Kliknij, aby porównać z poprzednim</div> : null}
            </>
          ),
        };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-x-4 gap-y-1.5" aria-label="Legenda">
          {KIND_ORDER.map((k) => (
            <LegendItem key={k} color={KIND_COLOR[k]} label={CHANGE_LABEL_PLURAL[k]} value={last ? fmtNumber(last[k]) : undefined} />
          ))}
        </div>
        <Button size="sm" variant="ghost" onClick={() => setTable((t) => !t)} aria-pressed={table}>
          <Table2 /> {table ? "Wykres" : "Tabela"}
        </Button>
      </div>
      {table ? (
        <div className="scroll-quiet max-h-64 overflow-auto rounded-lg border border-line">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface-2 text-left text-[0.8125rem] text-ink-2">
              <tr>
                <th className="px-3 py-2 font-semibold">Skan</th>
                <th className="px-3 py-2 font-semibold">Data</th>
                {KIND_ORDER.map((k) => (
                  <th key={k} className="px-3 py-2 text-right font-semibold">
                    {CHANGE_LABEL_PLURAL[k]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {points
                .slice()
                .reverse()
                .map((p) => (
                  <tr key={p.scan_id} className="border-t border-line">
                    <td className="px-3 py-1.5 font-semibold">#{p.scan_number}</td>
                    <td className="px-3 py-1.5 text-ink-2">{fmtDayMonth(p.at)}</td>
                    {KIND_ORDER.map((k) => (
                      <td key={k} className="tabular px-3 py-1.5 text-right">
                        {fmtNumber(p[k])}
                      </td>
                    ))}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div ref={ref} className="relative">
          <svg width={width} height={height} className="block" role="img" aria-label={`Zmiany wykryte w ostatnich ${points.length} skanach. Szczegóły dostępne w widoku tabeli.`}>
            {ticks.map((t) => (
              <g key={t}>
                <line x1={left} x2={width} y1={top + plotH - sy(t)} y2={top + plotH - sy(t)} stroke="var(--line)" strokeWidth="1" />
                <text x={left - 8} y={top + plotH - sy(t)} dy="0.32em" textAnchor="end" className="fill-ink-2 text-[11px] tabular">
                  {t}
                </text>
              </g>
            ))}
            {points.map((p, i) => {
              let acc = 0;
              const x = left + i * slot + (slot - barW) / 2;
              const dim = hover !== null && hover !== i;
              const isSel = selected === p.scan_number;
              const segs = KIND_ORDER.filter((k) => p[k] > 0);
              return (
                <g key={p.scan_id} opacity={dim ? 0.45 : 1}>
                  {segs.map((k, si) => {
                    const h = sy(p[k]);
                    const gap = si < segs.length - 1 ? 2 : 0;
                    const y0 = top + plotH - acc - h;
                    acc += h;
                    const isTop = si === segs.length - 1;
                    return isTop ? (
                      <path key={k} d={topRounded(x, y0, barW, Math.max(1, h), 4)} fill={KIND_COLOR[k]} />
                    ) : (
                      <rect key={k} x={x} y={y0 + gap} width={barW} height={Math.max(0.5, h - gap)} fill={KIND_COLOR[k]} />
                    );
                  })}
                  {isSel ? <rect x={x - 3} y={top - 2} width={barW + 6} height={plotH + 4} rx="5" fill="none" stroke="var(--ink)" strokeWidth="1.5" strokeDasharray="3 3" /> : null}
                  <rect
                    x={left + i * slot}
                    y={top}
                    width={slot}
                    height={plotH + bottom}
                    fill="transparent"
                    className={cn(onSelect && "cursor-pointer")}
                    onPointerEnter={() => setHover(i)}
                    onPointerLeave={() => setHover(null)}
                    onClick={() => onSelect?.(p)}
                    tabIndex={onSelect ? 0 : -1}
                    onFocus={() => setHover(i)}
                    onBlur={() => setHover(null)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") onSelect?.(p);
                    }}
                    aria-label={`Skan ${p.scan_number}: ${p.new} nowe, ${p.changed} zmienione, ${p.gone} zniknęły, ${p.unstable} niestabilne`}
                  />
                  {i % Math.ceil(n / 8) === 0 || i === n - 1 ? (
                    <text x={left + i * slot + slot / 2} y={height - 6} textAnchor="middle" className={cn("text-[11px] tabular", i === n - 1 ? "fill-ink font-bold" : "fill-ink-2")}>
                      #{p.scan_number}
                    </text>
                  ) : null}
                </g>
              );
            })}
          </svg>
          <ChartTooltip tip={tip} containerWidth={width} />
        </div>
      )}
    </div>
  );
}
