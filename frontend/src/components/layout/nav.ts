import {
  CircleHelp,
  Crosshair,
  Fingerprint,
  GitCompareArrows,
  LayoutDashboard,
  Network,
  Plug,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";
import type { Permission } from "@/lib/api/types";

/** Groups of the main menu: a divider on desktop, a heading in the phone menu. */
export type NavGroup = "start" | "analysis" | "scanning";

export const NAV_GROUP_LABEL: Record<NavGroup, string> = {
  start: "Start",
  analysis: "Analiza wyników",
  scanning: "Konfiguracja skanowania",
};

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  perm: Permission;
  /** One plain sentence: shown as the menu hint, in the phone menu, on the help page and in Ctrl K. */
  description: string;
  group?: NavGroup;
}

export const NAV: NavItem[] = [
  { href: "/", label: "Pulpit", icon: LayoutDashboard, perm: "dashboard:read", group: "start", description: "Podsumowanie: aktywne hosty, ostatnie zmiany i najważniejsze znaleziska" },
  { href: "/findings", label: "Znaleziska", icon: Crosshair, perm: "findings:read", group: "analysis", description: "Co wymaga uwagi: panele administracyjne, staging, stare wersje — ze statusem i priorytetem" },
  { href: "/changes", label: "Zmiany", icon: GitCompareArrows, perm: "changes:read", group: "analysis", description: "Co się pojawiło, zniknęło lub zmieniło między dwoma skanowaniami" },
  { href: "/assets", label: "Zasoby", icon: Server, perm: "assets:read", group: "analysis", description: "Wszystkie wykryte hosty, usługi i technologie" },
  { href: "/scans", label: "Skanowania", icon: Radar, perm: "scans:read", group: "scanning", description: "Uruchamianie skanów i ich postęp, harmonogramy i profile" },
  { href: "/targets", label: "Zakresy", icon: Network, perm: "targets:read", group: "scanning", description: "Co monitorujemy: adresy IP, sieci CIDR i domeny" },
  { href: "/signatures", label: "Sygnatury", icon: Fingerprint, perm: "signatures:read", group: "scanning", description: "Reguły rozpoznawania usług — tylko wykrywanie, bez ataku" },
];

export const ADMIN_NAV: NavItem[] = [
  { href: "/admin/users", label: "Użytkownicy", icon: Users, perm: "users:read", description: "Konta i przypisane role" },
  { href: "/admin/roles", label: "Role i uprawnienia", icon: ShieldCheck, perm: "roles:read", description: "Kto może co zrobić w panelu (RBAC)" },
  { href: "/admin/integrations", label: "Integracje", icon: Plug, perm: "integrations:read", description: "DefectDojo i silniki skanujące" },
  { href: "/admin/audit", label: "Dziennik zdarzeń", icon: ScrollText, perm: "audit:read", description: "Kto, co i kiedy zmienił" },
  { href: "/admin/settings", label: "Ustawienia", icon: Settings, perm: "settings:read", description: "Bezpieczeństwo skanowania i szyfrowanie" },
];

/** Open to every signed-in user, whatever the role: never filter it by `perm`. */
export const HELP_NAV: Omit<NavItem, "perm"> = {
  href: "/pomoc",
  label: "Pomoc",
  icon: CircleHelp,
  description: "Jak korzystać z panelu: kolejność pracy, opis sekcji i słowniczek pojęć",
};

export function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}
