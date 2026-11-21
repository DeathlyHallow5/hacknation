/**
 * Wall-clock time in Europe/Warsaw and schedule timing. Shared by the schedule
 * form (live "next run" preview, cron validation) and the mock API, which
 * fills `next_run_at` with the same rules the Rust backend should follow
 * (README → Harmonogramy).
 */
import { TZ } from "@/lib/format";

const partsFmt = new Intl.DateTimeFormat("en-US", {
  timeZone: TZ,
  hourCycle: "h23",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  weekday: "short",
});

export interface ZonedParts {
  y: number;
  mo: number; // 0-based
  d: number;
  h: number;
  mi: number;
  s: number;
  /** ISO weekday 1 = Monday … 7 = Sunday */
  dow: number;
}

const DOW: Record<string, number> = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };

export function zoned(date: Date): ZonedParts {
  const p = Object.fromEntries(partsFmt.formatToParts(date).map((x) => [x.type, x.value]));
  return {
    y: Number(p.year),
    mo: Number(p.month) - 1,
    d: Number(p.day),
    h: Number(p.hour),
    mi: Number(p.minute),
    s: Number(p.second),
    dow: DOW[p.weekday as string] ?? 1,
  };
}

function offsetMinutes(date: Date): number {
  const z = zoned(date);
  const asUtc = Date.UTC(z.y, z.mo, z.d, z.h, z.mi, z.s);
  return Math.round((asUtc - date.getTime()) / 60000);
}

/** Wall-clock time in Warsaw -> Date (UTC instant). Day may overflow (Date.UTC normalises). */
export function warsaw(y: number, mo: number, d: number, h: number, mi: number): Date {
  const guess = Date.UTC(y, mo, d, h, mi);
  const off = offsetMinutes(new Date(guess));
  const first = new Date(guess - off * 60000);
  const off2 = offsetMinutes(first);
  return off2 === off ? first : new Date(guess - off2 * 60000);
}

export function parseHM(hm: string): [number, number] {
  const [h, m] = hm.split(":").map(Number);
  return [h || 0, m || 0];
}

/** Expands one cron field ("*", "1-5", "0,30", "*\/15", "8-18/2") into its values; null when malformed. */
function cronField(spec: string, min: number, max: number): Set<number> | null {
  const out = new Set<number>();
  for (const part of spec.split(",")) {
    const m = /^(\*|(\d+)(?:-(\d+))?)(?:\/(\d+))?$/.exec(part);
    if (!m) return null;
    const step = m[4] ? Number(m[4]) : 1;
    const lo = m[1] === "*" ? min : Number(m[2]);
    const hi = m[1] === "*" ? max : m[3] ? Number(m[3]) : m[4] ? max : lo;
    if (step < 1 || lo < min || hi > max || lo > hi) return null;
    for (let v = lo; v <= hi; v += step) out.add(v);
  }
  return out;
}

/** Whether the Warsaw wall-clock time of `at` falls inside the daily window [start, end), which may cross midnight. */
export function isWithinWindow(at: Date, start: string, end: string): boolean {
  const z = zoned(at);
  const t = z.h * 60 + z.mi;
  const [sh, sm] = parseHM(start);
  const [eh, em] = parseHM(end);
  const s = sh * 60 + sm;
  const e = eh * 60 + em;
  return s < e ? t >= s && t < e : t >= s || t < e;
}

export interface ScheduleTiming {
  frequency: "daily" | "weekly" | "cron";
  /** ISO weekdays 1 = Monday … 7 = Sunday */
  days: number[];
  cron: string | null;
  window: { start: string };
}

/**
 * Next start of a schedule strictly after `now`, in Warsaw wall-clock time.
 * daily/weekly: the window start on one of `days`; cron: the next matching
 * minute of a 5-field expression (Vixie semantics: when both day-of-month and
 * day-of-week are restricted, either may match; 0 and 7 are Sunday).
 * Null when the cron expression is malformed or matches nothing within a year.
 */
export function nextScheduleRun(s: ScheduleTiming, now: Date = new Date()): Date | null {
  const z = zoned(now);
  const dayAt = (i: number) => new Date(Date.UTC(z.y, z.mo, z.d + i));
  if (s.frequency === "cron") {
    const f = (s.cron ?? "").trim().split(/\s+/);
    if (f.length !== 5) return null;
    const mins = cronField(f[0], 0, 59);
    const hours = cronField(f[1], 0, 23);
    const doms = cronField(f[2], 1, 31);
    const months = cronField(f[3], 1, 12);
    const dows = cronField(f[4], 0, 7);
    if (!mins || !hours || !doms || !months || !dows) return null;
    if (dows.has(7)) dows.add(0);
    const either = !f[2].startsWith("*") && !f[4].startsWith("*");
    const hs = [...hours].sort((a, b) => a - b);
    const ms = [...mins].sort((a, b) => a - b);
    for (let i = 0; i <= 366; i++) {
      const day = dayAt(i);
      if (!months.has(day.getUTCMonth() + 1)) continue;
      const domOk = doms.has(day.getUTCDate());
      const dowOk = dows.has(day.getUTCDay());
      if (either ? !(domOk || dowOk) : !(domOk && dowOk)) continue;
      for (const h of hs) {
        if (i === 0 && h < z.h) continue;
        for (const mi of ms) {
          if (i === 0 && h === z.h && mi <= z.mi) continue;
          const at = warsaw(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), h, mi);
          if (at.getTime() > now.getTime()) return at;
        }
      }
    }
    return null;
  }
  const days = s.days?.length ? s.days : [1, 2, 3, 4, 5, 6, 7];
  const [sh, sm] = parseHM(s.window.start);
  for (let i = 0; i <= 7; i++) {
    const day = dayAt(i);
    if (!days.includes(day.getUTCDay() || 7)) continue;
    const at = warsaw(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), sh, sm);
    if (at.getTime() > now.getTime()) return at;
  }
  return null;
}
