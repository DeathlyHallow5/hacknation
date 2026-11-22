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

/* v2: the default theme became "contrast"; earlier entries saved every field (theme "light" too,
   even when only the text size was changed), so they are not read. Only fields a user picked are
   stored, so a later change of a default reaches everyone who never picked that field. */
export const PREFS_KEY = "asi:prefs:v2";
/** Keep in sync with data-theme on <html> in app/layout.tsx. */
export const DEFAULT_THEME: ThemePref = "contrast";
const DEFAULTS: Prefs = { theme: DEFAULT_THEME, text: "md", motion: "full" };

/** Runs in <head> before first paint, so there is no flash of the wrong theme/size. */
export const PREFS_SCRIPT = `(function(){try{var p=JSON.parse(localStorage.getItem("${PREFS_KEY}")||"{}");var d=document.documentElement;if(p.theme)d.setAttribute("data-theme",p.theme);if(p.text&&p.text!=="md")d.setAttribute("data-text",p.text);if(p.motion==="reduce")d.setAttribute("data-motion","reduce")}catch(e){}})()`;

/* A tiny external store over localStorage (read through useSyncExternalStore). */
let cache: Prefs | null = null;
const listeners = new Set<() => void>();

/** Only the fields the user picked. */
function readPicked(): Partial<Prefs> {
  try {
    const v = JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}");
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}

const store = {
  get(): Prefs {
    if (!cache) cache = { ...DEFAULTS, ...readPicked() };
    return cache;
  },
  set(patch: Partial<Prefs>) {
    cache = { ...store.get(), ...patch };
    try {
      localStorage.setItem(PREFS_KEY, JSON.stringify({ ...readPicked(), ...patch }));
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
