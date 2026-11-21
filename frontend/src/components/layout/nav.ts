import {
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

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  perm: Permission;
  description: string;
}

export const NAV: NavItem[] = [
  { href: "/", label: "Pulpit", icon: LayoutDashboard, perm: "dashboard:read", description: "Najważniejsze znaleziska i zmiany" },
  { href: "/findings", label: "Znaleziska", icon: Crosshair, perm: "findings:read", description: "Obserwacje do analizy i ich status" },
  { href: "/changes", label: "Zmiany", icon: GitCompareArrows, perm: "changes:read", description: "Porównanie przebiegów skanowania" },
  { href: "/assets", label: "Zasoby", icon: Server, perm: "assets:read", description: "Hosty, usługi i technologie" },
  { href: "/scans", label: "Skanowania", icon: Radar, perm: "scans:read", description: "Przebiegi, harmonogramy i profile" },
  { href: "/targets", label: "Zakresy", icon: Network, perm: "targets:read", description: "Adresy IP, zakresy CIDR i domeny" },
  { href: "/signatures", label: "Sygnatury", icon: Fingerprint, perm: "signatures:read", description: "Reguły bezpiecznej detekcji" },
];

export const ADMIN_NAV: NavItem[] = [
  { href: "/admin/users", label: "Użytkownicy", icon: Users, perm: "users:read", description: "Konta i przypisane role" },
  { href: "/admin/roles", label: "Role i uprawnienia", icon: ShieldCheck, perm: "roles:read", description: "Macierz uprawnień RBAC" },
  { href: "/admin/integrations", label: "Integracje", icon: Plug, perm: "integrations:read", description: "DefectDojo i silniki skanujące" },
  { href: "/admin/audit", label: "Dziennik zdarzeń", icon: ScrollText, perm: "audit:read", description: "Kto, co i kiedy zmienił" },
  { href: "/admin/settings", label: "Ustawienia", icon: Settings, perm: "settings:read", description: "Bezpieczeństwo skanowania i szyfrowanie" },
];

export function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}
