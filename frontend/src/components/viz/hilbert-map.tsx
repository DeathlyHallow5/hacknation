"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import * as React from "react";
import { cssVar, LegendItem, useThemeVersion } from "@/components/viz/core";
import { api } from "@/lib/api/endpoints";
import { AddressStatus } from "@/lib/api/types";
import { fmtNumber } from "@/lib/format";
import { hilbertD2XY, hilbertXY2D, intToIp, parseCidr } from "@/lib/net";
import { usePrefersReducedMotion } from "@/lib/prefs";
import { cn } from "@/lib/utils";

const STATUS_LABEL: Record<AddressStatus, string> = {
  [AddressStatus.None]: "Brak odpowiedzi",
  [AddressStatus.Active]: "Aktywny",
  [AddressStatus.New]: "Nowy",
  [AddressStatus.Changed]: "Zmieniony",
  [AddressStatus.Gone]: "Zniknął",
  [AddressStatus.Unstable]: "Niestabilny",
  [AddressStatus.Inactive]: "Nieaktywny",
  [AddressStatus.Excluded]: "Wykluczony ze skanowania",
};

export const MAP_RANGES = [
  { cidr: "10.0.0.0/16", label: "Cała sieć" },
  { cidr: "10.0.0.0/18", label: "Serwerownie i DMZ" },
  { cidr: "10.0.64.0/18", label: "Sieć wydziałowa" },
  { cidr: "10.0.128.0/18", label: "Akademiki i Wi-Fi" },
  { cidr: "10.0.192.0/18", label: "Urządzenia, zarządzanie, laboratoria" },
];

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? h.split("").map((c) => c + c).join("") : h;
  return [parseInt(full.slice(0, 2), 16), parseInt(full.slice(2, 4), 16), parseInt(full.slice(4, 6), 16)];
}

function decode(b64: string, size: number): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    const byte = bin.charCodeAt(i >> 1);
    out[i] = i % 2 === 0 ? byte >> 4 : byte & 15;
  }
  return out;
}

/**
 * The address space on a Hilbert curve: neighbouring addresses stay neighbours,
 * so every /24 is a compact square. Base layer = availability, change markers
 * are drawn as shapes (+ new, ◆ changed, × gone) so they never rely on colour.
 */
export function HilbertMap({ cidr, size = 360, className }: { cidr: string; size?: number; className?: string }) {
  const router = useRouter();
  const reduced = usePrefersReducedMotion();
  const themeV = useThemeVersion();
  const parsed = parseCidr(cidr);
  const { data } = useQuery({
    queryKey: ["address-map", cidr],
    queryFn: () => api.dashboard.addressMap(cidr),
    refetchInterval: (q) => (q.state.data?.scan_head !== null && q.state.data?.scan_head !== undefined ? 5000 : 60_000),
  });
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const animated = React.useRef(false);
  const [hover, setHover] = React.useState<{ x: number; y: number; w: number; idx: number } | null>(null);

  const statuses = React.useMemo(() => (data ? decode(data.data, data.size) : null), [data]);
  const n = data ? Math.round(Math.sqrt(data.size)) : 256;
  const blockSide = Math.max(1, Math.round(Math.sqrt(256))); // a /24 is 16x16 cells

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !statuses || !data) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(size * dpr);
    canvas.height = Math.round(size * dpr);
    const ctx = canvas.getContext("2d")!;
    ctx.imageSmoothingEnabled = false;

    const colors: Record<number, [number, number, number]> = {
      [AddressStatus.None]: hexToRgb(cssVar("--map-none", "#142846")),
      [AddressStatus.Active]: hexToRgb(cssVar("--map-active", "#3b7cc9")),
      [AddressStatus.New]: hexToRgb(cssVar("--map-active", "#3b7cc9")),
      [AddressStatus.Changed]: hexToRgb(cssVar("--map-active", "#3b7cc9")),
      [AddressStatus.Gone]: hexToRgb(cssVar("--map-inactive", "#34425b")),
      [AddressStatus.Unstable]: hexToRgb(cssVar("--map-unstable", "#c4860f")),
      [AddressStatus.Inactive]: hexToRgb(cssVar("--map-inactive", "#34425b")),
      [AddressStatus.Excluded]: hexToRgb(cssVar("--map-excluded", "#2a3550")),
    };
    const img = new ImageData(n, n);
    const px = img.data;
    const coords = new Uint16Array(data.size * 2);
    for (let d = 0; d < data.size; d++) {
      const [x, y] = hilbertD2XY(n, d);
      coords[d * 2] = x;
      coords[d * 2 + 1] = y;
    }
    const off = document.createElement("canvas");
    off.width = n;
    off.height = n;
    const octx = off.getContext("2d")!;
    const paintRange = (from: number, to: number) => {
      for (let d = from; d < to; d++) {
        const s = statuses[d];
        let [r, g, b] = colors[s];
        if (s === AddressStatus.Excluded && (coords[d * 2] + coords[d * 2 + 1]) % 3 === 0) [r, g, b] = [r + 30, g + 34, b + 44];
        const o = (coords[d * 2 + 1] * n + coords[d * 2]) * 4;
        px[o] = r;
        px[o + 1] = g;
        px[o + 2] = b;
        px[o + 3] = 255;
      }
    };
    const draw = () => {
      octx.putImageData(img, 0, 0);
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(off, 0, 0, canvas.width, canvas.height);
      // /24 grid for orientation
      const step = (canvas.width / n) * blockSide;
      ctx.strokeStyle = "rgba(11,24,48,0.55)";
      ctx.lineWidth = Math.max(1, dpr * 0.75);
      if (n >= 64) {
        ctx.beginPath();
        for (let v = step; v < canvas.width - 1; v += step) {
          ctx.moveTo(Math.round(v) + 0.5, 0);
          ctx.lineTo(Math.round(v) + 0.5, canvas.height);
          ctx.moveTo(0, Math.round(v) + 0.5);
          ctx.lineTo(canvas.width, Math.round(v) + 0.5);
        }
        ctx.stroke();
      }
    };
    const drawMarkers = () => {
      const marker = (d: number, kind: AddressStatus) => {
        const cx = (coords[d * 2] + 0.5) * (canvas.width / n);
        const cy = (coords[d * 2 + 1] + 0.5) * (canvas.height / n);
        const r = 3.4 * dpr;
        ctx.lineCap = "round";
        const ring = cssVar("--chrome", "#0b1830");
        if (kind === AddressStatus.New || kind === AddressStatus.Gone) {
          const color = cssVar(kind === AddressStatus.New ? "--map-new" : "--map-gone");
          const pathFn = () => {
            ctx.beginPath();
            if (kind === AddressStatus.New) {
              ctx.moveTo(cx - r, cy);
              ctx.lineTo(cx + r, cy);
              ctx.moveTo(cx, cy - r);
              ctx.lineTo(cx, cy + r);
            } else {
              ctx.moveTo(cx - r * 0.8, cy - r * 0.8);
              ctx.lineTo(cx + r * 0.8, cy + r * 0.8);
              ctx.moveTo(cx + r * 0.8, cy - r * 0.8);
              ctx.lineTo(cx - r * 0.8, cy + r * 0.8);
            }
          };
          pathFn();
          ctx.strokeStyle = ring;
          ctx.lineWidth = 4.6 * dpr;
          ctx.stroke();
          pathFn();
          ctx.strokeStyle = color;
          ctx.lineWidth = 2.2 * dpr;
          ctx.stroke();
        } else if (kind === AddressStatus.Changed) {
          ctx.beginPath();
          ctx.moveTo(cx, cy - r);
          ctx.lineTo(cx + r, cy);
          ctx.lineTo(cx, cy + r);
          ctx.lineTo(cx - r, cy);
          ctx.closePath();
          ctx.fillStyle = cssVar("--map-changed");
          ctx.strokeStyle = ring;
          ctx.lineWidth = 1.6 * dpr;
          ctx.fill();
          ctx.stroke();
        }
      };
      for (let d = 0; d < data.size; d++) {
        const s = statuses[d];
        if (s === AddressStatus.New || s === AddressStatus.Changed || s === AddressStatus.Gone) marker(d, s);
      }
    };

    // Fill with "no response" first.
    for (let i = 0; i < n * n; i++) {
      const [r, g, b] = colors[AddressStatus.None];
      px[i * 4] = r;
      px[i * 4 + 1] = g;
      px[i * 4 + 2] = b;
      px[i * 4 + 3] = 255;
    }

    if (reduced || animated.current) {
      paintRange(0, data.size);
      draw();
      drawMarkers();
      return;
    }
    // The one orchestrated moment: sweep along the Hilbert curve on first load.
    animated.current = true;
    let raf = 0;
    const start = performance.now();
    const duration = 950;
    let painted = 0;
    const frame = (t: number) => {
      // The first rAF timestamp can precede `start`: clamp so the range never goes negative.
      const p = Math.min(1, Math.max(0, (t - start) / duration));
      const eased = 1 - Math.pow(1 - p, 2);
      const target = Math.max(painted, Math.min(data.size, Math.floor(eased * data.size)));
      paintRange(painted, target);
      painted = target;
      draw();
      if (p < 1) raf = requestAnimationFrame(frame);
      else drawMarkers();
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [statuses, data, n, size, reduced, themeV, blockSide]);

  const onMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!statuses || !data) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const cx = Math.floor(((e.clientX - rect.left) / rect.width) * n);
    const cy = Math.floor(((e.clientY - rect.top) / rect.height) * n);
    if (cx < 0 || cy < 0 || cx >= n || cy >= n) return setHover(null);
    setHover({ x: e.clientX - rect.left, y: e.clientY - rect.top, w: rect.width, idx: hilbertXY2D(n, cx, cy) });
  };

  const hoverInfo = React.useMemo(() => {
    if (!hover || !statuses || !parsed) return null;
    const ip = intToIp(parsed.network + hover.idx);
    const block = hover.idx - (hover.idx % 256);
    let active = 0;
    for (let i = block; i < Math.min(block + 256, statuses.length); i++) if (statuses[i] !== AddressStatus.None && statuses[i] !== AddressStatus.Excluded) active++;
    return { ip, status: statuses[hover.idx] as AddressStatus, subnet: `${intToIp(parsed.network + block)}/24`, active };
  }, [hover, statuses, parsed]);

  const head =
    data && data.scan_head !== null && data.scan_head !== undefined ? hilbertD2XY(n, Math.min(data.size - 1, data.scan_head)) : null;

  const c = data?.counts;
  return (
    <div className={cn("grid gap-3", className)}>
      <div className="relative aspect-square w-full" style={{ maxWidth: size }}>
        {!data ? <div className="on-chrome skeleton absolute inset-0 rounded-lg" /> : null}
        <canvas
          ref={canvasRef}
          style={{ width: "100%", height: "100%" }}
          className={cn("block cursor-crosshair rounded-lg", !data && "invisible")}
          role="img"
          aria-label={
            c
              ? `Mapa ${data?.cidr}: ${fmtNumber(c.active + c.new + c.changed)} aktywnych, ${c.unstable} niestabilnych, ${c.new} nowych, ${c.changed} zmienionych, ${c.gone} zniknęło, ${fmtNumber(c.excluded)} wykluczonych.`
              : "Mapa przestrzeni adresowej — wczytywanie"
          }
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
          onClick={() => hoverInfo && router.push(`/assets?cidr=${encodeURIComponent(hoverInfo.subnet)}`)}
        />
        {head ? (
          <span
            className="pointer-events-none absolute size-4 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-accent shadow-[0_0_0_4px_rgba(30,178,234,0.25)]"
            style={{ left: `${((head[0] + 0.5) / n) * 100}%`, top: `${((head[1] + 0.5) / n) * 100}%` }}
            aria-hidden
          >
            <span className="absolute inset-0 animate-ping rounded-full bg-accent/40" />
          </span>
        ) : null}
        {hover && hoverInfo ? (
          <div
            className="pointer-events-none absolute z-20 min-w-44 rounded-lg border border-chrome-line bg-chrome px-3 py-2 text-xs text-chrome-ink shadow-pop"
            style={{ left: hover.x, top: hover.y, transform: `translate(${hover.x > hover.w - 200 ? "calc(-100% - 14px)" : "14px"}, -50%)` }}
          >
            <div className="mono text-sm font-bold text-white">{hoverInfo.ip}</div>
            <div className="text-chrome-ink-2">{STATUS_LABEL[hoverInfo.status]}</div>
            <div className="mt-1.5 border-t border-chrome-line pt-1.5 text-chrome-ink-2">
              <span className="mono text-chrome-ink">{hoverInfo.subnet}</span>: {hoverInfo.active} hostów. Kliknij, aby otworzyć listę.
            </div>
          </div>
        ) : null}
      </div>
      {c ? (
        <div className="grid gap-1.5 text-chrome-ink-2 [&_span]:!text-chrome-ink-2 [&_.tabular]:!text-chrome-ink">
          <div className="flex flex-wrap gap-x-3.5 gap-y-1">
            <LegendItem color="var(--map-active)" label="Aktywny" value={fmtNumber(c.active)} />
            <LegendItem color="var(--map-unstable)" label="Niestabilny" value={fmtNumber(c.unstable)} />
            <LegendItem color="var(--map-inactive)" label="Nieaktywny" value={fmtNumber(c.inactive)} />
            <LegendItem color="var(--map-excluded)" shape="hatch" label="Wykluczony" value={fmtNumber(c.excluded)} />
          </div>
          <div className="flex flex-wrap gap-x-3.5 gap-y-1">
            <LegendItem color="var(--map-new)" shape="plus" label="Nowy" value={fmtNumber(c.new)} />
            <LegendItem color="var(--map-changed)" shape="diamond" label="Zmieniony" value={fmtNumber(c.changed)} />
            <LegendItem color="var(--map-gone)" shape="cross" label="Zniknął" value={fmtNumber(c.gone)} />
            {head ? <LegendItem color="var(--accent)" shape="ring" label="Pozycja skanu" /> : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
