"use client";

import Link from "next/link";
import * as React from "react";
import { CommandPalette } from "@/components/layout/command-palette";
import { TopBar } from "@/components/layout/top-bar";
import { Skeleton } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { ApiError, errorMessage } from "@/lib/api/client";
import { SessionProvider, useMeta, useSessionQuery } from "@/lib/session";

function Footer() {
  const { data: meta } = useMeta();
  return (
    <footer className="mt-auto border-t border-line bg-surface">
      <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-4 text-sm text-ink-2 sm:px-6 lg:px-8">
        <span>© 2026 Centrum Bezpieczeństwa Informacji AGH</span>
        <Link href="/dostepnosc" className="font-semibold text-link hover:underline">
          Deklaracja dostępności
        </Link>
        <span>Wersja {meta?.version ?? "0.1.0"}</span>
        <span className="ml-auto inline-flex items-center gap-2">
          <span
            className={`size-2 rounded-full ${meta?.mode === "mock" ? "bg-unstable" : "bg-new"}`}
            aria-hidden
          />
          {meta?.mode === "mock"
            ? "Źródło danych: dane demonstracyjne (wbudowany mock API)"
            : meta?.mode === "hybrid"
              ? `Źródło danych: backend ${meta.upstream} + mock dla brakujących endpointów`
              : meta
                ? `Źródło danych: backend ${meta.upstream}`
                : "Łączenie z API…"}
        </span>
      </div>
    </footer>
  );
}

function ShellSkeleton() {
  return (
    <div className="min-h-dvh bg-canvas">
      <div className="h-14 bg-chrome lg:h-[6.25rem]" />
      <div className="mx-auto grid max-w-[1440px] gap-4 px-4 py-8 sm:px-6 lg:px-8">
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-4 w-96" />
        <Skeleton className="mt-4 h-64 w-full" />
      </div>
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const session = useSessionQuery();
  const [searchOpen, setSearchOpen] = React.useState(false);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearchOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (session.isPending) return <ShellSkeleton />;
  if (session.isError) {
    const unauthorized = session.error instanceof ApiError && session.error.status === 401;
    return (
      <div className="grid min-h-dvh place-items-center bg-canvas p-6">
        <div className="grid max-w-md gap-3 rounded-2xl border border-line bg-surface p-6">
          <h1 className="text-lg font-bold">{unauthorized ? "Sesja wygasła" : "Nie udało się połączyć z API"}</h1>
          <p className="text-sm text-ink-2">
            {unauthorized
              ? "Zaloguj się ponownie, aby kontynuować pracę."
              : `${errorMessage(session.error)}. Sprawdź, czy backend działa, i odśwież stronę.`}
          </p>
          <div className="flex gap-2">
            {/* eslint-disable-next-line @next/next/no-location-assign-relative-destination */}
            <Button variant="primary" onClick={() => (window.location.href = "/login")}>
              Przejdź do logowania
            </Button>
            {!unauthorized ? <Button onClick={() => session.refetch()}>Spróbuj ponownie</Button> : null}
          </div>
        </div>
      </div>
    );
  }

  return (
    <SessionProvider session={session.data}>
      <div className="flex min-h-dvh flex-col bg-canvas">
        <a
          href="#main"
          className="sr-only z-[100] rounded-lg bg-accent px-4 py-2 font-semibold text-accent-ink focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
        >
          Przejdź do treści
        </a>
        <TopBar onOpenSearch={() => setSearchOpen(true)} />
        <main id="main" tabIndex={-1} className="flex-1 outline-none">
          {children}
        </main>
        <Footer />
        <CommandPalette open={searchOpen} onOpenChange={setSearchOpen} />
      </div>
    </SessionProvider>
  );
}
