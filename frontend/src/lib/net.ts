/** IPv4 / CIDR / domain helpers shared by the UI and the mock backend. */

import type { TargetType } from "@/lib/api/types";

export function isValidIPv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && !(p.length > 1 && p.startsWith("0")) && Number(p) <= 255);
}

export function ipToInt(ip: string): number {
  return ip.split(".").reduce((acc, p) => (acc * 256 + Number(p)) >>> 0, 0) >>> 0;
}

export function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export interface ParsedCidr {
  network: number;
  prefix: number;
  size: number;
  /** Normalised notation, e.g. "10.0.0.0/18". */
  cidr: string;
  /** True when the input had host bits set (e.g. 10.0.0.5/24). */
  normalized: boolean;
}

export function parseCidr(s: string): ParsedCidr | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(s.trim());
  if (!m || !isValidIPv4(m[1])) return null;
  const prefix = Number(m[2]);
  if (prefix < 0 || prefix > 32) return null;
  const ip = ipToInt(m[1]);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ip & mask) >>> 0;
  return {
    network,
    prefix,
    size: 2 ** (32 - prefix),
    cidr: `${intToIp(network)}/${prefix}`,
    normalized: network !== ip,
  };
}

export function cidrContains(cidr: string, ip: string): boolean {
  const c = parseCidr(cidr);
  if (!c || !isValidIPv4(ip)) return false;
  const n = ipToInt(ip);
  return n >= c.network && n < c.network + c.size;
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/;

export function isValidDomain(s: string): boolean {
  return DOMAIN_RE.test(s.toLowerCase());
}

/** Largest range accepted in one entry (a /12 ≈ 1M addresses). */
export const MAX_PREFIX = 12;

export interface TargetCheck {
  input: string;
  ok: boolean;
  type?: TargetType;
  value?: string;
  address_count?: number;
  error?: string;
  note?: string;
}

/** Validate one manual/import entry the same way the backend does. */
export function checkTarget(raw: string): TargetCheck {
  const input = raw.trim();
  if (!input) return { input, ok: false, error: "Pusta wartość" };
  const v = input.toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");

  if (v.includes("/")) {
    const c = parseCidr(v);
    if (!c) return { input, ok: false, error: "Nieprawidłowy zakres CIDR (oczekiwano np. 10.0.0.0/24)" };
    if (c.prefix < MAX_PREFIX)
      return { input, ok: false, error: `Zakres zbyt duży (maksymalnie /${MAX_PREFIX}, czyli 1 048 576 adresów)` };
    if (c.prefix === 32) return { input, ok: true, type: "ip", value: intToIp(c.network), address_count: 1 };
    return {
      input,
      ok: true,
      type: "cidr",
      value: c.cidr,
      address_count: c.size,
      note: c.normalized ? `Znormalizowano do ${c.cidr}` : undefined,
    };
  }
  if (/^[\d.]+$/.test(v)) {
    if (!isValidIPv4(v)) return { input, ok: false, error: "Nieprawidłowy adres IPv4" };
    return { input, ok: true, type: "ip", value: v, address_count: 1 };
  }
  if (isValidDomain(v)) return { input, ok: true, type: "domain", value: v, address_count: 1 };
  return { input, ok: false, error: "To nie jest adres IP, zakres CIDR ani domena" };
}

/** Split pasted text into entries (newlines, commas, semicolons, spaces). */
export function splitEntries(text: string): string[] {
  return text
    .split(/[\n,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Hilbert curve: distance d (0 .. n*n-1) -> (x, y) on an n x n grid,
 * n a power of two. Keeps CIDR blocks contiguous as squares/rectangles.
 */
export function hilbertD2XY(n: number, d: number): [number, number] {
  let rx: number;
  let ry: number;
  let t = d;
  let x = 0;
  let y = 0;
  for (let s = 1; s < n; s *= 2) {
    rx = 1 & (t / 2);
    ry = 1 & (t ^ rx);
    if (ry === 0) {
      if (rx === 1) {
        x = s - 1 - x;
        y = s - 1 - y;
      }
      const tmp = x;
      x = y;
      y = tmp;
    }
    x += s * rx;
    y += s * ry;
    t = Math.floor(t / 4);
  }
  return [x, y];
}

export function hilbertXY2D(n: number, x0: number, y0: number): number {
  let d = 0;
  let x = x0;
  let y = y0;
  for (let s = n / 2; s > 0; s = Math.floor(s / 2)) {
    const rx = (x & s) > 0 ? 1 : 0;
    const ry = (y & s) > 0 ? 1 : 0;
    d += s * s * ((3 * rx) ^ ry);
    if (ry === 0) {
      if (rx === 1) {
        x = n - 1 - x;
        y = n - 1 - y;
      }
      const tmp = x;
      x = y;
      y = tmp;
    }
  }
  return d;
}
