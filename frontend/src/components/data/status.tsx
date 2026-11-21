import {
  ArrowUpRight,
  Circle,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CircleMinus,
  CirclePause,
  CircleSlash,
  CircleX,
  Clock,
  Loader,
  Pencil,
  Plus,
  ShieldCheck,
  TriangleAlert,
  Waves,
  type LucideIcon,
} from "lucide-react";
import type { Availability, ChangeState, FindingStatus, ScanStatus } from "@/lib/api/types";
import { countLabel } from "@/lib/format";
import { AVAILABILITY_LABEL, CHANGE_LABEL, FINDING_STATUS_LABEL, SCAN_STATUS_LABEL } from "@/lib/labels";
import { cn } from "@/lib/utils";

/*
 * Status vocabulary. A status is always icon + text, never colour alone.
 * Only states that need attention get a filled chip; the normal state ("Zakończony",
 * "Do analizy", "Bez zmian") is quiet text with the same icon slot.
 */
const chip =
  "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-semibold whitespace-nowrap [&_svg]:size-3.5 [&_svg]:shrink-0 contrast:border contrast:border-current";
const quiet = "inline-flex items-center gap-1 text-sm whitespace-nowrap text-ink-2 [&_svg]:size-3.5 [&_svg]:shrink-0";

const CHANGE_STYLE: Record<ChangeState, string> = {
  new: cn(chip, "bg-new-soft text-new-ink"),
  changed: cn(chip, "bg-changed-soft text-changed-ink"),
  gone: cn(chip, "bg-gone-soft text-gone-ink"),
  unstable: cn(chip, "bg-unstable-soft text-unstable-ink"),
  unchanged: quiet,
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
    <span className={cn(CHANGE_STYLE[state], className)}>
      <Icon aria-hidden strokeWidth={2.6} />
      {CHANGE_LABEL[state]}
      {state === "unstable" && measurements ? (
        <span className="font-normal">
          ({measurements.responded}/{measurements.total})
        </span>
      ) : null}
    </span>
  );
}

/** Host availability: a dot as the icon. "Aktywny" uses the map's blue, not the green of "Nowy". */
export function AvailabilityBadge({ value, missCount, className }: { value: Availability; missCount?: number; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 text-sm whitespace-nowrap",
        value === "active" ? "text-ink" : value === "unstable" ? "text-unstable-ink" : "text-ink-2",
        className,
      )}
    >
      <span
        aria-hidden
        className={cn(
          "size-2 shrink-0 rounded-full",
          value === "active" ? "bg-active" : value === "unstable" ? "bg-unstable" : "border-[1.5px] border-inactive bg-transparent",
        )}
      />
      {AVAILABILITY_LABEL[value]}
      {value === "inactive" && missCount ? <span className="text-ink-2">({countLabel(missCount, ["skan", "skany", "skanów"])} bez odpowiedzi)</span> : null}
    </span>
  );
}

const FS: Record<FindingStatus, { icon: LucideIcon; cls: string }> = {
  open: { icon: Circle, cls: quiet },
  in_review: { icon: CircleDashed, cls: cn(chip, "bg-surface-3 text-ink") },
  confirmed: { icon: CircleAlert, cls: cn(chip, "bg-danger-soft text-danger") },
  false_positive: { icon: CircleSlash, cls: cn(quiet, "[&>span]:line-through [&>span]:decoration-1") },
  accepted: { icon: ShieldCheck, cls: quiet },
};

export function FindingStatusChip({ value, className }: { value: FindingStatus; className?: string }) {
  const { icon: Icon, cls } = FS[value];
  return (
    <span className={cn(cls, className)}>
      <Icon aria-hidden />
      <span>{FINDING_STATUS_LABEL[value]}</span>
    </span>
  );
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
  queued: quiet,
  running: cn(chip, "bg-accent/14 text-link"),
  paused: cn(chip, "bg-unstable-soft text-unstable-ink"),
  paused_window: cn(chip, "bg-unstable-soft text-unstable-ink"),
  completed: quiet,
  cancelled: quiet,
  failed: cn(chip, "bg-danger-soft text-danger"),
};

export function ScanStatusChip({ value, className }: { value: ScanStatus; className?: string }) {
  const Icon = SCAN_ICON[value];
  return (
    <span className={cn(SCAN_STYLE[value], className)}>
      <Icon aria-hidden className={value === "running" ? "animate-spin [animation-duration:2.4s]" : undefined} />
      {SCAN_STATUS_LABEL[value]}
    </span>
  );
}

/** Analytical priority 0..100: monochrome meter + number. */
export function ScoreMeter({ score, overridden, className }: { score: number; overridden?: boolean; className?: string }) {
  const level = score >= 70 ? "Wysoki" : score >= 40 ? "Średni" : "Niski";
  return (
    <span className={cn("inline-flex items-center gap-2", className)} title={`Priorytet ${score}/100 (${level.toLowerCase()})${overridden ? ", ustawiony ręcznie" : ""}`}>
      <span className="tabular w-7 text-right text-sm font-semibold text-ink">{score}</span>
      <span className="flex gap-[2px]" aria-hidden>
        {[0, 1, 2, 3, 4].map((i) => (
          <span
            key={i}
            className={cn(
              "h-3 w-[5px] rounded-[1.5px]",
              score >= (i + 1) * 20 - 10 ? "bg-ink" : "bg-line-strong contrast:bg-transparent contrast:ring-1 contrast:ring-white contrast:ring-inset",
            )}
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
  valueClassName,
  compact,
}: {
  value: number;
  measurements?: { responded: number; total: number };
  className?: string;
  valueClassName?: string;
  compact?: boolean;
}) {
  const pct = Math.round(value * 100);
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span className={cn("tabular text-right text-sm text-ink", !compact && "w-9", valueClassName)}>{pct}%</span>
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

/** Last N measurements: filled = responded. Show it only when there is a miss to see. */
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
  return <ArrowUpRight aria-hidden className={cn("size-3.5", delta < 0 && "rotate-90", className)} />;
}
