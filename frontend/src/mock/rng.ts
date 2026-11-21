/** Deterministic PRNG utilities so the mock data is identical after restarts. */

export type Rng = () => number;

export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function hashString(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function rngFor(...parts: (string | number)[]): Rng {
  return mulberry32(hashString(parts.join("|")));
}

export function pick<T>(rng: Rng, arr: readonly T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

export function pickWeighted<T>(rng: Rng, items: readonly (readonly [T, number])[]): T {
  const total = items.reduce((s, [, w]) => s + w, 0);
  let r = rng() * total;
  for (const [item, w] of items) {
    r -= w;
    if (r <= 0) return item;
  }
  return items[items.length - 1][0];
}

export function int(rng: Rng, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

export function chance(rng: Rng, p: number): boolean {
  return rng() < p;
}

export function shuffle<T>(rng: Rng, arr: T[]): T[] {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export function sample<T>(rng: Rng, arr: readonly T[], n: number): T[] {
  return shuffle(rng, arr.slice()).slice(0, Math.min(n, arr.length));
}

export function hex(rng: Rng, len: number): string {
  let s = "";
  for (let i = 0; i < len; i++) s += Math.floor(rng() * 16).toString(16);
  return s;
}
