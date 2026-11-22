"use client";

import { useQuery } from "@tanstack/react-query";
import { ChevronDown, LogOut, Menu, Search, Settings2, ShieldCheck, UserRoundCog } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import * as React from "react";
import { Wordmark } from "@/components/brand/logo";
import { ADMIN_NAV, HELP_NAV, NAV, NAV_GROUP_LABEL, isActive, type NavItem } from "@/components/layout/nav";
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
  Tooltip,
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
    <>
    <span className="mx-1.5 h-5 w-px shrink-0 bg-chrome-line" aria-hidden />
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className={cn(
            "relative inline-flex h-11 shrink-0 items-center gap-2 px-3 text-sm font-semibold transition-colors hover:text-chrome-ink",
            active ? "text-chrome-ink" : "text-chrome-ink-2",
          )}
        >
          <Settings2 className="size-4 shrink-0" aria-hidden />
          Administracja <ChevronDown className="-ml-1 size-3.5" aria-hidden />
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
    </>
  );
}

function MobileNav({ pathname }: { pathname: string }) {
  const can = useCan();
  const [open, setOpen] = React.useState(false);
  const sections: { heading: string; items: Omit<NavItem, "perm">[] }[] = [
    ...(["start", "analysis", "scanning"] as const).map((g) => ({
      heading: NAV_GROUP_LABEL[g],
      items: NAV.filter((i) => i.group === g && can(i.perm)),
    })),
    { heading: "Administracja", items: ADMIN_NAV.filter((i) => can(i.perm)) },
    { heading: "Pomoc", items: [HELP_NAV] },
  ].filter((s) => s.items.length);
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <Button variant="chrome-ghost" size="icon" className="lg:hidden" aria-label="Otwórz menu" onClick={() => setOpen(true)}>
        <Menu />
      </Button>
      <SheetContent width="md" className="max-w-sm">
        <SheetHeader>
          <SheetTitle>Menu</SheetTitle>
        </SheetHeader>
        <SheetBody className="grid content-start gap-4 px-3">
          {sections.map((s) => (
            <section key={s.heading} aria-label={s.heading} className="grid gap-0.5">
              <h3 className="px-3 pb-1 text-xs font-semibold tracking-wide text-ink-2 uppercase">{s.heading}</h3>
              {s.items.map((i) => (
                <Link
                  key={i.href}
                  href={i.href}
                  onClick={() => setOpen(false)}
                  aria-current={isActive(pathname, i.href) ? "page" : undefined}
                  className="group flex items-start gap-3 rounded-lg px-3 py-2 text-ink-2 hover:bg-surface-3 hover:text-ink aria-[current=page]:bg-accent/10 aria-[current=page]:text-ink"
                >
                  <i.icon className="mt-0.5 size-4 shrink-0" aria-hidden />
                  <span className="grid gap-0.5 leading-tight">
                    <span className="text-sm font-semibold text-ink">{i.label}</span>
                    <span className="text-xs text-pretty">{i.description}</span>
                  </span>
                </Link>
              ))}
            </section>
          ))}
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}

function HelpButton() {
  const pathname = usePathname();
  return (
    <Tooltip content={HELP_NAV.description} side="bottom">
      <Button
        asChild
        variant="chrome"
        size="sm"
        className={cn("h-9 px-2.5", isActive(pathname, HELP_NAV.href) && "border-accent")}
      >
        <Link href={HELP_NAV.href} aria-label="Pomoc: jak korzystać z panelu">
          <HELP_NAV.icon className="!size-[1.1rem]" aria-hidden />
          <span className="hidden xl:inline">Pomoc</span>
        </Link>
      </Button>
    </Tooltip>
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
          <HelpButton />
          <A11yMenu />
          <UserMenu />
        </div>
      </div>
      <nav aria-label="Główne sekcje" className="hidden border-t border-chrome-line/70 lg:block">
        <div className="scroll-quiet relative mx-auto flex max-w-[1440px] items-center gap-0.5 overflow-x-auto px-5 lg:px-6">
          {NAV.filter((i) => can(i.perm)).map((i, n, list) => {
            const active = isActive(pathname, i.href);
            // A thin divider where the group changes: Start | Analiza wyników | Konfiguracja skanowania.
            const newGroup = n > 0 && list[n - 1].group !== i.group;
            return (
              <React.Fragment key={i.href}>
                {newGroup ? <span className="mx-1.5 h-5 w-px shrink-0 bg-chrome-line" aria-hidden /> : null}
                <Tooltip content={i.description} side="bottom">
                  <Link
                    href={i.href}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "relative inline-flex h-11 shrink-0 items-center gap-2 px-3 text-sm font-semibold transition-colors hover:text-chrome-ink",
                      active ? "text-chrome-ink" : "text-chrome-ink-2",
                    )}
                  >
                    <i.icon className="size-4 shrink-0" aria-hidden />
                    {i.label}
                    {active ? <span className="absolute inset-x-3 bottom-0 h-[3px] rounded-t-full bg-accent" aria-hidden /> : null}
                  </Link>
                </Tooltip>
              </React.Fragment>
            );
          })}
          <AdminMenu pathname={pathname} />
        </div>
      </nav>
    </header>
  );
}
