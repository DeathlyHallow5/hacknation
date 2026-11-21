/** Time helpers for the mock (Europe/Warsaw scan windows). */

export const TZ = "Europe/Warsaw";

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

/** Window [start, end) that contains `now`, or the most recent one before it. */
export function windowAround(now: Date, start: string, end: string): { open: boolean; startAt: Date; endAt: Date } {
  const z = zoned(now);
  const [sh, sm] = parseHM(start);
  const [eh, em] = parseHM(end);
  const crossesMidnight = eh * 60 + em <= sh * 60 + sm;
  const todayStart = warsaw(z.y, z.mo, z.d, sh, sm);
  let startAt: Date;
  if (now.getTime() >= todayStart.getTime()) startAt = todayStart;
  else startAt = warsaw(z.y, z.mo, z.d - 1, sh, sm);
  const sz = zoned(startAt);
  const endAt = warsaw(sz.y, sz.mo, sz.d + (crossesMidnight ? 1 : 0), eh, em);
  const open = now.getTime() >= startAt.getTime() && now.getTime() < endAt.getTime();
  return { open, startAt, endAt };
}

export function nextWindowStart(now: Date, start: string, end: string): Date {
  const w = windowAround(now, start, end);
  if (w.open) return w.startAt;
  const z = zoned(now);
  const [sh, sm] = parseHM(start);
  const today = warsaw(z.y, z.mo, z.d, sh, sm);
  return today.getTime() > now.getTime() ? today : warsaw(z.y, z.mo, z.d + 1, sh, sm);
}

export const iso = (d: Date | number) => new Date(d).toISOString();

export const MIN = 60_000;
export const HOUR = 3_600_000;
export const DAY = 86_400_000;
