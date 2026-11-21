"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

/** Width of an element, tracked with ResizeObserver. */
export function useWidth<T extends HTMLElement>(fallback = 600) {
  const ref = React.useRef<T>(null);
  const [width, setWidth] = React.useState(fallback);
  React.useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.clientWidth || fallback);
    const ro = new ResizeObserver(([entry]) => setWidth(Math.max(120, Math.round(entry.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, [fallback]);
  return [ref, width] as const;
}

export interface TipState {
  x: number;
  y: number;
  content: React.ReactNode;
}

/** Tooltip positioned inside a relatively positioned chart container. */
export function ChartTooltip({ tip, containerWidth }: { tip: TipState | null; containerWidth: number }) {
  if (!tip) return null;
  const flip = tip.x > containerWidth - 190;
  return (
    <div
      role="status"
      className="pointer-events-none absolute z-20 min-w-36 rounded-lg bg-chrome px-3 py-2 text-xs text-chrome-ink shadow-pop contrast:border contrast:border-white"
      style={{
        left: tip.x,
        top: tip.y,
        transform: `translate(${flip ? "calc(-100% - 12px)" : "12px"}, -50%)`,
      }}
    >
      {tip.content}
    </div>
  );
}

/** Tooltip row: value first (strong), label second, keyed by a short stroke. */
export function TipRow({ color, value, label }: { color?: string; value: React.ReactNode; label: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 py-0.5">
      {color ? <span className="h-0.5 w-3 shrink-0 rounded-full" style={{ background: color }} aria-hidden /> : null}
      <span className="tabular font-semibold text-white contrast:text-white">{value}</span>
      <span className="text-chrome-ink-2">{label}</span>
    </div>
  );
}

export function LegendItem({
  color,
  label,
  value,
  shape = "rect",
  className,
}: {
  color: string;
  label: React.ReactNode;
  value?: React.ReactNode;
  shape?: "rect" | "line" | "plus" | "cross" | "diamond" | "ring" | "hatch";
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-sm text-ink-2", className)}>
      <LegendGlyph shape={shape} color={color} />
      <span>{label}</span>
      {value !== undefined ? <span className="tabular font-semibold text-ink">{value}</span> : null}
    </span>
  );
}

export function LegendGlyph({ shape, color, size = 12 }: { shape: "rect" | "line" | "plus" | "cross" | "diamond" | "ring" | "hatch"; color: string; size?: number }) {
  const s = size;
  return (
    <svg width={s} height={s} viewBox="0 0 12 12" aria-hidden className="shrink-0">
      {shape === "rect" ? <rect x="1" y="1" width="10" height="10" rx="2.5" fill={color} /> : null}
      {shape === "line" ? <rect x="0" y="5" width="12" height="2" rx="1" fill={color} /> : null}
      {shape === "plus" ? <path d="M6 1.5v9M1.5 6h9" stroke={color} strokeWidth="2.4" strokeLinecap="round" /> : null}
      {shape === "cross" ? <path d="M2.5 2.5l7 7M9.5 2.5l-7 7" stroke={color} strokeWidth="2.4" strokeLinecap="round" /> : null}
      {shape === "diamond" ? <path d="M6 1 11 6 6 11 1 6Z" fill={color} /> : null}
      {shape === "ring" ? <circle cx="6" cy="6" r="4" fill="none" stroke={color} strokeWidth="2.2" /> : null}
      {shape === "hatch" ? (
        <>
          <rect x="1" y="1" width="10" height="10" rx="2.5" fill={color} opacity="0.35" />
          <path d="M1 9 9 1M3 11l8-8" stroke={color} strokeWidth="1.4" />
        </>
      ) : null}
    </svg>
  );
}

/** Read a CSS custom property (for canvas drawing). */
export function cssVar(name: string, fallback = "#000") {
  if (typeof window === "undefined") return fallback;
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

/** Re-render when the theme attribute on <html> changes (canvas charts). */
export function useThemeVersion() {
  const [v, setV] = React.useState(0);
  React.useEffect(() => {
    const mo = new MutationObserver(() => setV((x) => x + 1));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => mo.disconnect();
  }, []);
  return v;
}
