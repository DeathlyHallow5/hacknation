"use client";

import * as React from "react";

/** Accessibility & appearance preferences (A / A+ / A++, theme, motion). */
export type ThemePref = "light" | "dark" | "contrast";
export type TextPref = "md" | "lg" | "xl";
export type MotionPref = "full" | "reduce";

export interface Prefs {
  theme: ThemePref;
  text: TextPref;
  motion: MotionPref;
}

export const PREFS_KEY = "asi:prefs";
const DEFAULTS: Prefs = { theme: "light", text: "md", motion: "full" };

/** Runs in <head> before first paint, so there is no flash of the wrong theme/size. */
export const PREFS_SCRIPT = `(function(){try{var p=JSON.parse(localStorage.getItem("${PREFS_KEY}")||"{}");var d=document.documentElement;if(p.theme)d.setAttribute("data-theme",p.theme);if(p.text&&p.text!=="md")d.setAttribute("data-text",p.text);if(p.motion==="reduce")d.setAttribute("data-motion","reduce")}catch(e){}})()`;

/* A tiny external store over localStorage (read through useSyncExternalStore). */
let cache: Prefs | null = null;
const listeners = new Set<() => void>();

function readStorage(): Prefs {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}") };
  } catch {
    return DEFAULTS;
  }
}

const store = {
  get(): Prefs {
    if (!cache) cache = readStorage();
    return cache;
  },
  set(patch: Partial<Prefs>) {
    cache = { ...store.get(), ...patch };
    try {
      localStorage.setItem(PREFS_KEY, JSON.stringify(cache));
    } catch {
      /* storage may be unavailable */
    }
    listeners.forEach((l) => l());
  },
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
};

function apply(p: Prefs) {
  const d = document.documentElement;
  d.setAttribute("data-theme", p.theme);
  if (p.text === "md") d.removeAttribute("data-text");
  else d.setAttribute("data-text", p.text);
  if (p.motion === "reduce") d.setAttribute("data-motion", "reduce");
  else d.removeAttribute("data-motion");
}

const Ctx = React.createContext<{ prefs: Prefs; set: (patch: Partial<Prefs>) => void } | null>(null);

export function PrefsProvider({ children }: { children: React.ReactNode }) {
  // Server and the hydration pass see DEFAULTS; the stored value comes right after.
  const prefs = React.useSyncExternalStore(store.subscribe, store.get, () => DEFAULTS);

  // Keep <html> in sync (also re-applies after React's dev remount resets attributes).
  React.useLayoutEffect(() => {
    apply(prefs);
  }, [prefs]);

  const value = React.useMemo(() => ({ prefs, set: store.set }), [prefs]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePrefs() {
  const ctx = React.useContext(Ctx);
  if (!ctx) throw new Error("usePrefs must be used inside PrefsProvider");
  return ctx;
}

function subscribeMotion(cb: () => void) {
  const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
  mq.addEventListener("change", cb);
  return () => mq.removeEventListener("change", cb);
}

export function usePrefersReducedMotion() {
  const { prefs } = usePrefs();
  const system = React.useSyncExternalStore(
    subscribeMotion,
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    () => false,
  );
  return prefs.motion === "reduce" || system;
}
