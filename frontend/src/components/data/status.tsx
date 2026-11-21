import {
  ArrowUpRight,
  CircleCheck,
  CircleDot,
  CircleMinus,
  CirclePause,
  CircleX,
  Clock,
  Loader,
  Pencil,
  Plus,
  TriangleAlert,
  Waves,
} from "lucide-react";
import type { Availability, ChangeState, FindingStatus, ScanStatus } from "@/lib/api/types";
import { AVAILABILITY_LABEL, CHANGE_LABEL, FINDING_STATUS_LABEL, SCAN_STATUS_LABEL } from "@/lib/labels";
import { cn } from "@/lib/utils";

const chip =
  "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-bold whitespace-nowrap [&_svg]:size-3.5 [&_svg]:shrink-0 contrast:border contrast:border-current";

const CHANGE_STYLE: Record<ChangeState, string> = {
  new: "bg-new-soft text-new-ink",
  changed: "bg-changed-soft text-changed-ink",
  gone: "bg-gone-soft text-gone-ink",
  unstable: "bg-unstable-soft text-unstable-ink",
  unchanged: "bg-surface-3 text-ink-2",
};

const CHANGE_ICON = {
  new: Plus,
  changed: Pencil,
  gone: CircleMinus,
  unstable: Waves,
  unchanged: CircleDot,
} as const;

/** Change-state chip: always icon + label, never color alone. */
export function ChangeChip({
  state,
  measurements,
  className,
}: {
  state: ChangeState;
  measurements?: { responded: number; total: number };
  className?: string;
}) {
  const Icon = CHANGE_ICON[state];
  return (
    <span className={cn(chip, CHANGE_STYLE[state], className)}>
      <Icon aria-hidden strokeWidth={2.6} />
      {CHANGE_LABEL[state]}
      {state === "unstable" && measurements ? (
        <span className="font-semibold opacity-80">
          ({measurements.responded}/{measurements.total})
        </span>
      ) : null}
    </span>
  );
}

const AVAIL_STYLE: Record<Availability, string> = {
  active: "text-new-ink",
  unstable: "text-unstable-ink",
  inactive: "text-inactive-ink",
};

export function AvailabilityBadge({ value, missCount, className }: { value: Availability; missCount?: number; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[0.8125rem] font-semibold whitespace-nowrap", AVAIL_STYLE[value], className)}>
      <span
        aria-hidden
        className={cn(
          "size-2 rounded-full",
          value === "active" ? "bg-new" : value === "unstable" ? "bg-unstable" : "border-[1.5px] border-inactive bg-transparent",
        )}
      />
      {AVAILABILITY_LABEL[value]}
      {value === "inactive" && missCount ? <span className="font-normal text-ink-2">({missCount} skanów bez odpowiedzi)</span> : null}
    </span>
  );
}

const FS_STYLE: Record<FindingStatus, string> = {
  open: "border border-line-strong text-ink",
  in_review: "bg-accent/12 text-link",
  confirmed: "bg-gone-soft text-gone-ink",
  false_positive: "bg-surface-3 text-ink-2 line-through decoration-1",
  accepted: "bg-surface-3 text-ink-2",
};

export function FindingStatusChip({ value, className }: { value: FindingStatus; className?: string }) {
  return <span className={cn(chip, "font-semibold", FS_STYLE[value], className)}>{FINDING_STATUS_LABEL[value]}</span>;
}

const SCAN_ICON = {
  queued: Clock,
  running: Loader,
  paused: CirclePause,
  paused_window: Clock,
  completed: CircleCheck,
  cancelled: CircleX,
  failed: TriangleAlert,
} as const;

const SCAN_STYLE: Record<ScanStatus, string> = {
  queued: "bg-surface-3 text-ink-2",
  running: "bg-accent/14 text-link",
  paused: "bg-unstable-soft text-unstable-ink",
  paused_window: "bg-unstable-soft text-unstable-ink",
  completed: "bg-new-soft text-new-ink",
  cancelled: "bg-surface-3 text-ink-2",
  failed: "bg-gone-soft text-gone-ink",
};

export function ScanStatusChip({ value, className }: { value: ScanStatus; className?: string }) {
  const Icon = SCAN_ICON[value];
  return (
    <span className={cn(chip, SCAN_STYLE[value], className)}>
      <Icon aria-hidden className={value === "running" ? "animate-spin [animation-duration:2.4s]" : undefined} />
      {SCAN_STATUS_LABEL[value]}
    </span>
  );
}

/** Analytical priority 0..100 — monochrome meter + number. */
export function ScoreMeter({ score, overridden, className }: { score: number; overridden?: boolean; className?: string }) {
  const level = score >= 70 ? "Wysoki" : score >= 40 ? "Średni" : "Niski";
  return (
    <span className={cn("inline-flex items-center gap-2", className)} title={`Priorytet ${score}/100 (${level.toLowerCase()})${overridden ? ", ustawiony ręcznie" : ""}`}>
      <span className="tabular w-7 text-right text-sm font-bold text-ink">{score}</span>
      <span className="flex gap-[2px]" aria-hidden>
        {[0, 1, 2, 3, 4].map((i) => (
          <span
            key={i}
            className={cn("h-3 w-[5px] rounded-[1.5px]", score >= (i + 1) * 20 - 10 ? "bg-ink" : "bg-line-strong")}
          />
        ))}
      </span>
      <span className="sr-only">{`Priorytet ${score} na 100, ${level.toLowerCase()}`}</span>
      {overridden ? <Pencil className="size-3 text-ink-2" aria-label="ustawiony ręcznie" /> : null}
    </span>
  );
}

/** Identification / change confidence (0..1) with measurement count. */
export function ConfidenceMeter({
  value,
  measurements,
  className,
  compact,
}: {
  value: number;
  measurements?: { responded: number; total: number };
  className?: string;
  compact?: boolean;
}) {
  const pct = Math.round(value * 100);
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span className="tabular w-9 text-right text-sm font-semibold text-ink">{pct}%</span>
      {!compact ? (
        <span className="relative h-1.5 w-14 overflow-hidden rounded-full bg-surface-3" aria-hidden>
          <span className="absolute inset-y-0 left-0 rounded-full bg-ink-2" style={{ width: `${pct}%` }} />
        </span>
      ) : null}
      {measurements ? (
        <span className="text-xs whitespace-nowrap text-ink-2" title="Liczba pomiarów, w których host odpowiedział">
          {measurements.responded}/{measurements.total} pomiarów
        </span>
      ) : null}
    </span>
  );
}

/** Sparkline of the last N measurements: filled = responded. */
export function ResponsePattern({ pattern, className }: { pattern: boolean[]; className?: string }) {
  const responded = pattern.filter(Boolean).length;
  return (
    <span
      className={cn("inline-flex items-center gap-[3px]", className)}
      role="img"
      aria-label={`Odpowiedział w ${responded} z ${pattern.length} ostatnich pomiarów`}
      title={`Odpowiedział w ${responded} z ${pattern.length} ostatnich pomiarów (od najstarszego)`}
    >
      {pattern.map((p, i) => (
        <span key={i} className={cn("size-2 rounded-full", p ? "bg-ink-2" : "border border-ink-3 bg-transparent")} />
      ))}
    </span>
  );
}

export function TrendArrow({ delta, className }: { delta: number; className?: string }) {
  if (delta === 0) return null;
  return (
    <ArrowUpRight
      aria-hidden
      className={cn("size-3.5", delta < 0 && "rotate-90", className)}
    />
  );
}
