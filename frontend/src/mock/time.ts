/** Time helpers for the mock (Europe/Warsaw scan windows). Wall-clock math lives in @/lib/schedule. */
import { parseHM, warsaw, zoned } from "@/lib/schedule";

export { nextScheduleRun, parseHM, warsaw, zoned, type ZonedParts } from "@/lib/schedule";

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
