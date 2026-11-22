"use client";

import { useQuery } from "@tanstack/react-query";
import { ChevronDown, LogOut, Menu, Search, ShieldCheck, UserRoundCog } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import * as React from "react";
import { Wordmark } from "@/components/brand/logo";
import { ADMIN_NAV, NAV, isActive } from "@/components/layout/nav";
import { Button } from "@/components/ui/button";
import { Segmented, Switch } from "@/components/ui/form-controls";
import { Kbd } from "@/components/ui/misc";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Sheet,
  SheetBody,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/overlays";
import { api } from "@/lib/api/endpoints";
import { fmtPercent } from "@/lib/format";
import { usePrefs } from "@/lib/prefs";
import { DEMO_USERS, useCan, useMeta, useSession, useSwitchUser } from "@/lib/session";
import { cn } from "@/lib/utils";

function initials(name: string) {
  return name
    .split(/\s+/)
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

export function useLiveScan() {
  return useQuery({
    queryKey: ["live-scan"],
    queryFn: () => api.scans.list({ status: "running,paused,paused_window", page_size: 3 }),
    refetchInterval: 4000,
    select: (d) => d.items.find((s) => s.status === "running") ?? d.items[0] ?? null,
  });
}

function LiveScanPill() {
  const { data: scan } = useLiveScan();
  if (!scan) return null;
  const running = scan.status === "running";
  return (
    <Link
      href={`/scans/${scan.id}`}
      className="hidden h-9 items-center gap-2 rounded-lg border border-chrome-line bg-chrome-raised px-3 text-sm font-semibold text-chrome-ink transition-colors hover:border-accent md:inline-flex"
      title="Przejdź do skanowania w toku"
    >
      <span className={cn("size-2 rounded-full", running ? "animate-pulse-dot bg-signal" : "bg-unstable")} aria-hidden />
      <span>
        Skan #{scan.number}
        <span className="text-chrome-ink-2">{running ? `: ${fmtPercent(scan.progress)}` : scan.status === "paused_window" ? ": czeka na okno" : ": wstrzymany"}</span>
      </span>
    </Link>
  );
}

function A11yMenu() {
  const { prefs, set } = usePrefs();
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="chrome" size="sm" className="h-9 px-2.5" aria-label="Ustawienia dostępności: rozmiar tekstu, kontrast, motyw">
          <span aria-hidden className="text-base leading-none font-semibold">A+</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-4">
        <div className="grid gap-4">
          <h2 className="text-sm font-semibold">Dostępność</h2>
          <div className="grid gap-1.5">
            <span className="text-sm font-semibold text-ink-2">Rozmiar tekstu</span>
            <Segmented
              aria-label="Rozmiar tekstu"
              value={prefs.text}
              onChange={(text) => set({ text })}
              options={[
                { value: "md", label: <span className="text-sm">A</span> },
                { value: "lg", label: <span className="text-base">A+</span> },
                { value: "xl", label: <span className="text-lg">A++</span> },
              ]}
            />
          </div>
          <div className="grid gap-1.5">
            <span className="text-sm font-semibold text-ink-2">Wygląd</span>
            <Segmented
              aria-label="Motyw"
              value={prefs.theme}
              onChange={(theme) => set({ theme })}
              options={[
                { value: "light", label: "Jasny" },
                { value: "dark", label: "Ciemny" },
                { value: "contrast", label: "Wysoki kontrast" },
              ]}
            />
          </div>
          <label className="flex items-center justify-between gap-3 text-sm">
            <span>Ogranicz animacje</span>
            <Switch checked={prefs.motion === "reduce"} onCheckedChange={(c) => set({ motion: c ? "reduce" : "full" })} />
          </label>
          <Link href="/dostepnosc" className="text-sm font-semibold text-link hover:underline">
            Deklaracja dostępności
          </Link>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function UserMenu() {
  const session = useSession();
  const { data: meta } = useMeta();
  const switchUser = useSwitchUser();
  const can = useCan();
  const logout = async () => {
    await api.auth.logout().catch(() => undefined);
    // Full reload on purpose: clears all client state of the previous user.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    window.location.href = "/login";
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="inline-flex h-9 items-center gap-2 rounded-lg border border-chrome-line bg-chrome-raised py-1 pr-2.5 pl-1 text-left text-chrome-ink transition-colors hover:border-accent"
        >
          {/* The avatar is identity, not an action: chrome line colour, not the action colour. */}
          <span className="grid size-7 place-items-center rounded-full bg-chrome-line text-xs font-semibold text-chrome-ink contrast:bg-transparent contrast:ring-1 contrast:ring-white">
            {initials(session.user.name)}
          </span>
          <span className="hidden leading-tight lg:grid">
            <span className="text-sm font-semibold">{session.user.name}</span>
            <span className="text-xs text-chrome-ink-2">{session.role.name}</span>
          </span>
          <ChevronDown className="hidden size-3.5 text-chrome-ink-2 sm:block" aria-hidden />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-72">
        <div className="grid gap-0.5 px-2.5 py-2">
          <span className="text-sm font-semibold">{session.user.name}</span>
          <span className="text-sm text-ink-2">{session.user.email}</span>
          <span className="text-sm text-ink-2">Rola: {session.role.name}</span>
        </div>
        {can("roles:read") ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href="/admin/roles">
                <ShieldCheck /> Role i uprawnienia
              </Link>
            </DropdownMenuItem>
          </>
        ) : null}
        {meta?.mode !== "proxy" ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Tryb demonstracyjny: zaloguj jako</DropdownMenuLabel>
            {DEMO_USERS.filter((u) => u.login !== session.user.login).map((u) => (
              <DropdownMenuItem key={u.login} onSelect={() => switchUser(u.login)}>
                <UserRoundCog />
                <span className="grid leading-tight">
                  <span>
                    {u.name} <span className="text-ink-2">({u.role})</span>
                  </span>
                  <span className="text-xs text-ink-2">{u.hint}</span>
                </span>
              </DropdownMenuItem>
            ))}
          </>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={logout}>
          <LogOut /> Wyloguj się
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function AdminMenu({ pathname }: { pathname: string }) {
  const can = useCan();
  const items = ADMIN_NAV.filter((i) => can(i.perm));
  if (!items.length) return null;
  const active = items.some((i) => isActive(pathname, i.href));
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className={cn(
            "relative inline-flex h-11 items-center gap-1 px-3 text-sm font-semibold transition-colors hover:text-chrome-ink",
            active ? "text-chrome-ink" : "text-chrome-ink-2",
          )}
        >
          Administracja <ChevronDown className="size-3.5" aria-hidden />
          {active ? <span className="absolute inset-x-3 bottom-0 h-[3px] rounded-t-full bg-accent" aria-hidden /> : null}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-72">
        {items.map((i) => (
          <DropdownMenuItem key={i.href} asChild>
            <Link href={i.href}>
              <i.icon />
              <span className="grid leading-tight">
                <span>{i.label}</span>
                <span className="text-xs text-ink-2">{i.description}</span>
              </span>
            </Link>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function MobileNav({ pathname }: { pathname: string }) {
  const can = useCan();
  const [open, setOpen] = React.useState(false);
  const items = [...NAV, ...ADMIN_NAV].filter((i) => can(i.perm));
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <Button variant="chrome-ghost" size="icon" className="lg:hidden" aria-label="Otwórz menu" onClick={() => setOpen(true)}>
        <Menu />
      </Button>
      <SheetContent width="md" className="max-w-sm">
        <SheetHeader>
          <SheetTitle>Menu</SheetTitle>
        </SheetHeader>
        <SheetBody className="grid content-start gap-1 px-3">
          {items.map((i) => (
            <Link
              key={i.href}
              href={i.href}
              onClick={() => setOpen(false)}
              aria-current={isActive(pathname, i.href) ? "page" : undefined}
              className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-semibold text-ink-2 hover:bg-surface-3 hover:text-ink aria-[current=page]:bg-accent/10 aria-[current=page]:text-ink"
            >
              <i.icon className="size-4" aria-hidden />
              {i.label}
            </Link>
          ))}
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}

export function TopBar({ onOpenSearch }: { onOpenSearch: () => void }) {
  const pathname = usePathname();
  const can = useCan();
  return (
    <header className="sticky top-0 z-40 bg-chrome text-chrome-ink">
      <div className="mx-auto flex h-14 max-w-[1440px] items-center gap-3 px-4 sm:px-6 lg:px-8">
        <MobileNav pathname={pathname} />
        <Link href="/" className="shrink-0 rounded-md" aria-label="Strona główna: CBI AGH, Attack Surface Intelligence">
          <Wordmark />
        </Link>
        {/* Search takes whatever room is left (up to 20rem) instead of a fixed width, so the bar never overflows. */}
        <div className="ml-auto flex min-w-0 flex-1 items-center justify-end gap-1.5 sm:gap-2">
          <button
            type="button"
            onClick={onOpenSearch}
            className="hidden h-9 min-w-0 flex-1 items-center gap-2 rounded-lg border border-chrome-line bg-chrome-raised px-3 text-left text-sm text-chrome-ink-2 transition-colors hover:border-accent md:flex md:max-w-72 xl:max-w-80"
          >
            <Search className="size-4 shrink-0" aria-hidden />
            <span className="min-w-0 flex-1 truncate">Szukaj adresu IP, domeny lub hosta…</span>
            <Kbd className="hidden shrink-0 lg:inline-flex">Ctrl K</Kbd>
          </button>
          <Button variant="chrome-ghost" size="icon" className="md:hidden" aria-label="Szukaj" onClick={onOpenSearch}>
            <Search />
          </Button>
          <LiveScanPill />
          <A11yMenu />
          <UserMenu />
        </div>
      </div>
      <nav aria-label="Główne sekcje" className="hidden border-t border-chrome-line/70 lg:block">
        <div className="scroll-quiet relative mx-auto flex max-w-[1440px] items-center gap-0.5 overflow-x-auto px-5 lg:px-6">
          {NAV.filter((i) => can(i.perm)).map((i) => {
            const active = isActive(pathname, i.href);
            return (
              <Link
                key={i.href}
                href={i.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "relative inline-flex h-11 items-center px-3 text-sm font-semibold transition-colors hover:text-chrome-ink",
                  active ? "text-chrome-ink" : "text-chrome-ink-2",
                )}
              >
                {i.label}
                {active ? <span className="absolute inset-x-3 bottom-0 h-[3px] rounded-t-full bg-accent" aria-hidden /> : null}
              </Link>
            );
          })}
          <AdminMenu pathname={pathname} />
        </div>
      </nav>
    </header>
  );
}
