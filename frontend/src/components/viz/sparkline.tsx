"use client";

import * as React from "react";
import { ChartTooltip, TipRow, useWidth, type TipState } from "@/components/viz/core";
import { fmtDayMonth, fmtNumber } from "@/lib/format";

/**
 * Stat-tile sparkline: history in the de-emphasis hue, the current value as an
 * accent dot. Crosshair + tooltip snap to the nearest scan.
 */
export function Sparkline({
  points,
  height = 56,
  unit = "hostów",
  label,
}: {
  points: { scan_number: number; at: string; value: number }[];
  height?: number;
  unit?: string;
  label: string;
}) {
  const [ref, width] = useWidth<HTMLDivElement>(260);
  const [hover, setHover] = React.useState<number | null>(null);
  if (points.length < 2) return <div ref={ref} style={{ height }} />;
  const values = points.map((p) => p.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const pad = 6;
  const x = (i: number) => pad + (i / (points.length - 1)) * (width - pad * 2);
  const y = (v: number) => pad + (1 - (v - min) / Math.max(1, max - min)) * (height - pad * 2);
  const d = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
  const area = `${d} L${x(points.length - 1).toFixed(1)},${height} L${x(0).toFixed(1)},${height} Z`;
  const last = points.length - 1;
  const hi = hover ?? null;
  const tip: TipState | null =
    hi === null
      ? null
      : {
          x: x(hi),
          y: y(points[hi].value),
          content: (
            <>
              <div className="mb-1 text-chrome-ink-2">
                Skan #{points[hi].scan_number}, {fmtDayMonth(points[hi].at)}
              </div>
              <TipRow color="var(--accent)" value={fmtNumber(points[hi].value)} label={unit} />
            </>
          ),
        };

  const onMove = (e: React.PointerEvent) => {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const rel = (e.clientX - rect.left - pad) / Math.max(1, width - pad * 2);
    setHover(Math.max(0, Math.min(last, Math.round(rel * last))));
  };

  return (
    <div ref={ref} className="relative" style={{ height }}>
      <svg
        width={width}
        height={height}
        role="img"
        aria-label={`${label}: od ${fmtNumber(values[0])} do ${fmtNumber(values[last])} w ostatnich ${points.length} skanach`}
        onPointerMove={onMove}
        onPointerLeave={() => setHover(null)}
        className="block touch-none"
      >
        <path d={area} fill="var(--chrome-ink-2)" fillOpacity="0.08" />
        <path d={d} fill="none" stroke="var(--chrome-ink-2)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        {hi !== null ? <line x1={x(hi)} x2={x(hi)} y1={0} y2={height} stroke="var(--chrome-ink-2)" strokeOpacity="0.5" strokeWidth="1" /> : null}
        <circle cx={x(last)} cy={y(values[last])} r="4.5" fill="var(--accent)" stroke="var(--chrome-raised)" strokeWidth="2" />
        {hi !== null && hi !== last ? <circle cx={x(hi)} cy={y(values[hi])} r="4" fill="var(--chrome-ink)" stroke="var(--chrome-raised)" strokeWidth="2" /> : null}
      </svg>
      <ChartTooltip tip={tip} containerWidth={width} />
    </div>
  );
}
