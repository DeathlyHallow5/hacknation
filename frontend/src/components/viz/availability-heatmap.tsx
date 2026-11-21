"use client";

import * as React from "react";
import { ChartTooltip, TipRow, useWidth, type TipState } from "@/components/viz/core";
import { fmtPercent } from "@/lib/format";
import { WEEKDAYS, WEEKDAYS_LONG } from "@/lib/labels";
import { cn } from "@/lib/utils";

const STEPS = 6;
const seq = (v: number) => `var(--seq-${Math.min(STEPS - 1, Math.floor(v * STEPS))})`;

function inWindow(hour: number, start: number, end: number) {
  return start > end ? hour >= start || hour < end : hour >= start && hour < end;
}

/**
 * Response rate of unstable hosts by weekday x hour (sequential, one hue).
 * The scan window is outlined so the time-of-day blind spot is visible.
 */
export function AvailabilityHeatmap({
  matrix,
  windowStart = 22,
  windowEnd = 6,
}: {
  matrix: (number | null)[][];
  windowStart?: number;
  windowEnd?: number;
}) {
  const [ref, width] = useWidth<HTMLDivElement>(560);
  const [hover, setHover] = React.useState<{ d: number; h: number } | null>(null);
  const left = 30;
  const top = 20;
  const gap = 2;
  const cell = Math.max(8, Math.floor((width - left) / 24) - gap);
  const rowH = Math.max(16, Math.min(26, cell));
  const height = top + 7 * (rowH + gap) + 22;
  const x = (h: number) => left + h * (cell + gap);
  const y = (d: number) => top + d * (rowH + gap);

  // Insight: average response inside the window vs. working hours.
  let winSum = 0;
  let winN = 0;
  let daySum = 0;
  let dayN = 0;
  matrix.forEach((row, d) =>
    row.forEach((v, h) => {
      if (v === null) return;
      if (inWindow(h, windowStart, windowEnd)) {
        winSum += v;
        winN++;
      } else if (d < 5 && h >= 8 && h < 19) {
        daySum += v;
        dayN++;
      }
    }),
  );
  const winAvg = winN ? winSum / winN : 0;
  const dayAvg = dayN ? daySum / dayN : 0;

  const windowRanges = windowStart > windowEnd ? [[windowStart, 24], [0, windowEnd]] : [[windowStart, windowEnd]];

  const tip: TipState | null = hover
    ? {
        x: x(hover.h) + cell / 2,
        y: y(hover.d) + rowH / 2,
        content: (
          <>
            <div className="mb-1 text-chrome-ink-2">
              {WEEKDAYS_LONG[hover.d]}, {String(hover.h).padStart(2, "0")}:00–{String((hover.h + 1) % 24).padStart(2, "0")}:00
            </div>
            <TipRow value={matrix[hover.d][hover.h] === null ? "brak pomiarów" : fmtPercent(matrix[hover.d][hover.h])} label="odpowiedzi" />
            {inWindow(hover.h, windowStart, windowEnd) ? <div className="mt-1 text-chrome-ink-2">W oknie skanowania</div> : null}
          </>
        ),
      }
    : null;

  return (
    <div className="grid min-w-0 grid-cols-1 gap-3">
      <div ref={ref} className="relative min-w-0">
        <svg width={width} height={height} className="block" role="img" aria-label={`Odsetek odpowiedzi hostów niestabilnych według dnia tygodnia i godziny. W oknie skanowania średnio ${fmtPercent(winAvg)}, w godzinach pracy ${fmtPercent(dayAvg)}.`}>
          <defs>
            <pattern id="win-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <line x1="0" y1="0" x2="0" y2="6" stroke="var(--ink-3)" strokeWidth="1" strokeOpacity="0.35" />
            </pattern>
          </defs>
          {windowRanges.map(([a, b]) => (
            <g key={a}>
              <rect x={x(a) - 2} y={top - 4} width={x(b) - x(a)} height={7 * (rowH + gap) + 4} rx="4" fill="url(#win-hatch)" stroke="var(--ink-2)" strokeDasharray="4 3" strokeWidth="1" />
              <text x={x(a) - 1} y={top - 8} className="fill-ink-2 text-[11px] font-semibold">
                okno
              </text>
            </g>
          ))}
          {matrix.map((row, d) => (
            <g key={d}>
              <text x={left - 8} y={y(d) + rowH / 2} dy="0.32em" textAnchor="end" className={cn("text-[11px]", d >= 5 ? "fill-ink-3" : "fill-ink-2")}>
                {WEEKDAYS[d]}
              </text>
              {row.map((v, h) => (
                <rect
                  key={h}
                  x={x(h)}
                  y={y(d)}
                  width={cell}
                  height={rowH}
                  rx="3"
                  fill={v === null ? "transparent" : seq(v)}
                  stroke={hover && hover.d === d && hover.h === h ? "var(--ink)" : v === null ? "var(--line-strong)" : "none"}
                  strokeWidth={hover && hover.d === d && hover.h === h ? 2 : 1}
                  strokeDasharray={v === null ? "2 2" : undefined}
                  onPointerEnter={() => setHover({ d, h })}
                  onPointerLeave={() => setHover(null)}
                />
              ))}
            </g>
          ))}
          {[0, 3, 6, 9, 12, 15, 18, 21].map((h) => (
            <text key={h} x={x(h) + cell / 2} y={height - 6} textAnchor="middle" className="fill-ink-2 text-[11px] tabular">
              {String(h).padStart(2, "0")}
            </text>
          ))}
        </svg>
        <ChartTooltip tip={tip} containerWidth={width} />
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-ink-2">
        <span className="inline-flex items-center gap-2">
          0%
          <span className="flex gap-0.5" aria-hidden>
            {Array.from({ length: STEPS }).map((_, i) => (
              <span key={i} className="h-2.5 w-5 rounded-sm" style={{ background: `var(--seq-${i})` }} />
            ))}
          </span>
          100% odpowiedzi
        </span>
      </div>
      <p className="rounded-lg bg-surface-2 px-3 py-2.5 text-sm leading-relaxed text-ink">
        W oknie 22:00–06:00 hosty niestabilne odpowiadają średnio w <strong>{fmtPercent(winAvg)}</strong> przypadków, a w dni robocze
        8:00–19:00 — w <strong>{fmtPercent(dayAvg)}</strong>. Nocny skan ich nie widzi: dla tej grupy warto utrzymać pomiary kontrolne w dzień.
      </p>
    </div>
  );
}
