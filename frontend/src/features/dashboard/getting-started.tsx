"use client";

import { Check, CircleHelp } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/misc";
import type { DashboardSummary, Permission } from "@/lib/api/types";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

const HIDE_KEY = "asi:getting-started-hidden";

/* "Ukryj" lives in this browser; a module flag covers browsers without storage for this visit. */
let hiddenThisVisit = false;
const listeners = new Set<() => void>();
const hiddenStore = {
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  get(): boolean {
    try {
      return hiddenThisVisit || localStorage.getItem(HIDE_KEY) === "1";
    } catch {
      return hiddenThisVisit;
    }
  },
  hide() {
    hiddenThisVisit = true;
    try {
      localStorage.setItem(HIDE_KEY, "1");
    } catch {
      /* storage may be unavailable */
    }
    listeners.forEach((l) => l());
  },
};

/**
 * "Jak zacząć": shown on the dashboard until the installation has a target, a finished scan and a
 * second scan to compare (the state in which the dashboard is still empty), to users who can act
 * on it. Each step is checked off from the dashboard summary; "Ukryj" hides it in this browser.
 */
export function GettingStarted({ s }: { s: DashboardSummary | undefined }) {
  const can = useCan();
  // Hidden on the server and during hydration; the stored choice comes right after.
  const hidden = React.useSyncExternalStore(hiddenStore.subscribe, hiddenStore.get, () => true);

  if (!s || hidden || !(can("targets:create") || can("scans:create"))) return null;
  const scanned = Boolean(s.last_scan || s.running_scan);
  const steps: { title: string; text: string; done: boolean; href: string; action: string; perm: Permission }[] = [
    {
      title: "Dodaj zakres",
      text: "Adresy IP, sieci CIDR lub domeny, które chcesz monitorować.",
      done: s.targets_count > 0,
      href: "/targets?add=1",
      action: "Dodaj zakres",
      perm: "targets:create",
    },
    {
      title: "Uruchom pierwsze skanowanie",
      text: "Wybierz zakres i profil — postęp i dziennik zobaczysz na żywo. Wyniki trafią do Zasobów i Znalezisk.",
      done: scanned,
      href: "/scans/new",
      action: "Nowe skanowanie",
      perm: "scans:create",
    },
    {
      title: "Uruchom kolejne skanowanie",
      text: "Dopiero porównanie dwóch skanów pokaże w Zmianach, co się pojawiło, zniknęło lub zmieniło.",
      done: s.changes_base_scan !== null,
      href: "/scans/new",
      action: "Skanuj ponownie",
      perm: "scans:create",
    },
  ];
  const current = steps.findIndex((st) => !st.done);
  if (current === -1) return null;

  return (
    <Panel
      id="jak-zaczac"
      title="Jak zacząć"
      description={`Krok ${current + 1} z ${steps.length}`}
      actions={
        <>
          <Button asChild variant="ghost" size="sm">
            <Link href="/pomoc">
              <CircleHelp /> Pełna instrukcja
            </Link>
          </Button>
          <Button variant="ghost" size="sm" onClick={hiddenStore.hide}>
            Ukryj
          </Button>
        </>
      }
    >
      <ol className="grid gap-3 md:grid-cols-3">
        {steps.map((st, n) => {
          const isCurrent = n === current;
          return (
            <li
              key={st.title}
              aria-current={isCurrent ? "step" : undefined}
              className={cn("flex gap-3 rounded-lg border p-4", isCurrent ? "border-accent bg-surface-2" : "border-line")}
            >
              <span
                className={cn(
                  "grid size-7 shrink-0 place-items-center rounded-full text-sm font-semibold tabular",
                  st.done ? "bg-success-soft text-success" : isCurrent ? "bg-accent text-accent-ink" : "border border-line-strong text-ink-2",
                )}
                aria-hidden
              >
                {st.done ? <Check className="size-4" strokeWidth={3} /> : n + 1}
              </span>
              <div className="grid content-start gap-1.5">
                <h3 className={cn("text-sm font-semibold", st.done ? "text-ink-2" : "text-ink")}>
                  {st.title}
                  {st.done ? <span className="font-normal"> — gotowe</span> : null}
                </h3>
                <p className="text-sm text-pretty text-ink-2">{st.text}</p>
                {isCurrent && can(st.perm) ? (
                  <Button asChild variant="primary" size="sm" className="mt-1 w-fit">
                    <Link href={st.href}>{st.action}</Link>
                  </Button>
                ) : null}
                {isCurrent && !can(st.perm) ? <p className="text-sm text-ink-2">Ten krok wykonuje osoba z uprawnieniem do skanowania.</p> : null}
              </div>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}
