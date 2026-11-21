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

function read(): Prefs {
  if (typeof window === "undefined") return DEFAULTS;
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}") };
  } catch {
    return DEFAULTS;
  }
}

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
  // Start from defaults so server and client render the same markup; the inline
  // script has already applied the stored values to <html> before paint.
  const [prefs, setPrefs] = React.useState<Prefs>(DEFAULTS);

  React.useLayoutEffect(() => {
    if (prefs === DEFAULTS) {
      const stored = read();
      apply(stored);
      setPrefs(stored);
      return;
    }
    // Also re-applies after React's dev remount resets <html> attributes.
    apply(prefs);
  }, [prefs]);

  const set = React.useCallback((patch: Partial<Prefs>) => {
    setPrefs((prev) => {
      const next = { ...prev, ...patch };
      try {
        localStorage.setItem(PREFS_KEY, JSON.stringify(next));
      } catch {
        /* storage may be unavailable */
      }
      return next;
    });
  }, []);

  return <Ctx.Provider value={{ prefs, set }}>{children}</Ctx.Provider>;
}

export function usePrefs() {
  const ctx = React.useContext(Ctx);
  if (!ctx) throw new Error("usePrefs must be used inside PrefsProvider");
  return ctx;
}

export function usePrefersReducedMotion() {
  const { prefs } = usePrefs();
  const [system, setSystem] = React.useState(false);
  React.useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setSystem(mq.matches);
    const on = () => setSystem(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return prefs.motion === "reduce" || system;
}
