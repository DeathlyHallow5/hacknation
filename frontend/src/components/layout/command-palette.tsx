"use client";

import { useQuery } from "@tanstack/react-query";
import { Crosshair, FileUp, Network, Plus, Radar, Server } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { ADMIN_NAV, HELP_NAV, NAV } from "@/components/layout/nav";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/overlays";
import { api } from "@/lib/api/endpoints";
import { useCan } from "@/lib/session";

function useDebounced<T>(value: T, ms = 220) {
  const [v, setV] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg" hideClose className="gap-0 overflow-hidden p-0" aria-describedby={undefined}>
        <DialogTitle className="sr-only">Wyszukiwanie i polecenia</DialogTitle>
        <PaletteBody onOpenChange={onOpenChange} />
      </DialogContent>
    </Dialog>
  );
}

/** Rendered inside the dialog content, so the query resets each time it opens. */
function PaletteBody({ onOpenChange }: { onOpenChange: (o: boolean) => void }) {
  const router = useRouter();
  const can = useCan();
  const [q, setQ] = React.useState("");
  const dq = useDebounced(q.trim());
  const { data } = useQuery({
    queryKey: ["search", dq],
    queryFn: () => api.search(dq),
    enabled: dq.length >= 2,
  });

  const go = (href: string) => {
    onOpenChange(false);
    router.push(href);
  };
  const lower = q.toLowerCase();
  const pages = [...NAV, ...ADMIN_NAV].filter((i) => can(i.perm)).concat([{ ...HELP_NAV, perm: "dashboard:read" }]).filter((i) => !lower || i.label.toLowerCase().includes(lower) || i.description.toLowerCase().includes(lower) || (i.href === HELP_NAV.href && "help jak instrukcja słowniczek".includes(lower)));
  const actions = [
    { label: "Nowe skanowanie", href: "/scans/new", icon: Radar, perm: "scans:create" as const },
    { label: "Dodaj cele (IP, CIDR, domeny)", href: "/targets?add=1", icon: Plus, perm: "targets:create" as const },
    { label: "Importuj cele z pliku CSV/JSON", href: "/targets?import=1", icon: FileUp, perm: "targets:import" as const },
    { label: "Importuj wyniki skanu", href: "/scans?import=1", icon: FileUp, perm: "scans:import" as const },
  ].filter((a) => can(a.perm) && (!lower || a.label.toLowerCase().includes(lower)));

  return (
        <Command shouldFilter={false} label="Wyszukiwanie i polecenia">
          <CommandInput value={q} onValueChange={setQ} placeholder="Wpisz adres IP, domenę, nazwę znaleziska lub sekcji…" />
          <CommandList>
            <CommandEmpty>Brak wyników dla „{q}”. Sprawdź pisownię albo wpisz początek adresu IP.</CommandEmpty>
            {data?.hosts.length ? (
              <CommandGroup heading="Hosty">
                {data.hosts.map((h) => (
                  <CommandItem key={h.id} value={`host-${h.id}`} onSelect={() => go(`/assets/${h.id}`)}>
                    <Server />
                    <span className="mono">{h.ip}</span>
                    {h.hostname ? <span className="truncate text-ink-2">{h.hostname}</span> : null}
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null}
            {data?.findings.length ? (
              <CommandGroup heading="Znaleziska">
                {data.findings.map((f) => (
                  <CommandItem key={f.id} value={`finding-${f.id}`} onSelect={() => go(`/findings?open=${f.id}`)}>
                    <Crosshair />
                    <span className="truncate">{f.title}</span>
                    <span className="mono ml-auto text-ink-2">{f.ip}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null}
            {data?.targets.length ? (
              <CommandGroup heading="Zakresy">
                {data.targets.map((t) => (
                  <CommandItem key={t.id} value={`target-${t.id}`} onSelect={() => go(`/targets?q=${encodeURIComponent(t.value)}`)}>
                    <Network />
                    <span className="mono">{t.value}</span>
                    {t.name ? <span className="truncate text-ink-2">{t.name}</span> : null}
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null}
            {actions.length ? (
              <CommandGroup heading="Działania">
                {actions.map((a) => (
                  <CommandItem key={a.href} value={`action-${a.href}`} onSelect={() => go(a.href)}>
                    <a.icon />
                    {a.label}
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null}
            {pages.length ? (
              <CommandGroup heading="Sekcje">
                {pages.map((p) => (
                  <CommandItem key={p.href} value={`page-${p.href}`} onSelect={() => go(p.href)}>
                    <p.icon />
                    <span>{p.label}</span>
                    <span className="truncate text-ink-2">{p.description}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null}
          </CommandList>
        </Command>
  );
}
