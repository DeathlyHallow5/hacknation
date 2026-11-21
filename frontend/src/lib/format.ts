/** Polish formatting helpers. Display time zone is always Europe/Warsaw. */

export const TZ = "Europe/Warsaw";

const nf = new Intl.NumberFormat("pl-PL");
const nf1 = new Intl.NumberFormat("pl-PL", { maximumFractionDigits: 1 });
const pr = new Intl.PluralRules("pl-PL");
const rtf = new Intl.RelativeTimeFormat("pl-PL", { numeric: "auto" });

const dtf = new Intl.DateTimeFormat("pl-PL", {
  timeZone: TZ,
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const df = new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, day: "2-digit", month: "2-digit", year: "numeric" });
const dmf = new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, day: "2-digit", month: "2-digit" });
const tf = new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });
const wdf = new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, weekday: "short" });
const keyf = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" });

export function fmtNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return nf.format(n);
}

export function fmtSigned(n: number): string {
  if (n === 0) return "0";
  return `${n > 0 ? "+" : "−"}${nf.format(Math.abs(n))}`;
}

export function fmtDecimal(n: number): string {
  return nf1.format(n);
}

export function fmtPercent(x: number | null | undefined, digits = 0): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return `${(x * 100).toFixed(digits).replace(".", ",")}%`;
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return dtf.format(new Date(iso));
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return df.format(new Date(iso));
}

export function fmtDayMonth(iso: string | null | undefined): string {
  if (!iso) return "—";
  return dmf.format(new Date(iso));
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return tf.format(new Date(iso));
}

export function fmtWeekday(iso: string): string {
  return wdf.format(new Date(iso));
}

function dayKey(d: Date) {
  return keyf.format(d);
}

/** "dziś, 05:42" · "wczoraj, 22:10" · "18.11, 22:00" · "18.11.2025" */
export function fmtSmart(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const today = dayKey(now);
  const yesterday = dayKey(new Date(now.getTime() - 86_400_000));
  const tomorrow = dayKey(new Date(now.getTime() + 86_400_000));
  const k = dayKey(d);
  if (k === today) return `dziś, ${tf.format(d)}`;
  if (k === yesterday) return `wczoraj, ${tf.format(d)}`;
  if (k === tomorrow) return `jutro, ${tf.format(d)}`;
  if (d.getFullYear() === now.getFullYear()) return `${dmf.format(d)}, ${tf.format(d)}`;
  return df.format(d);
}

export function fmtRelative(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const diff = (new Date(iso).getTime() - now.getTime()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return diff < 0 ? "przed chwilą" : "za chwilę";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86_400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 86_400 * 30) return rtf.format(Math.round(diff / 86_400), "day");
  return fmtDate(iso);
}

/** 26 000 s -> "7 h 13 min"; 95 s -> "1 min 35 s". */
export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return m ? `${h} h ${m} min` : `${h} h`;
  if (m > 0) return sec ? `${m} min ${sec} s` : `${m} min`;
  return `${sec} s`;
}

/** Polish plural: plural(5, ["host", "hosty", "hostów"]) -> "hostów". */
export function plural(n: number, forms: [one: string, few: string, many: string]): string {
  const rule = pr.select(n);
  if (rule === "one") return forms[0];
  if (rule === "few") return forms[1];
  return forms[2];
}

export function countLabel(n: number, forms: [string, string, string]): string {
  return `${fmtNumber(n)} ${plural(n, forms)}`;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${nf1.format(n / 1024)} KB`;
  return `${nf1.format(n / 1024 / 1024)} MB`;
}
