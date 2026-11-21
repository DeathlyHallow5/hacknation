import { PERMISSIONS, type Permission } from "@/lib/api/types";

/** Grouping of permissions for the role matrix (resource -> actions). */
export const PERMISSION_GROUPS: { resource: string; label: string; items: { key: Permission; label: string }[] }[] = [
  {
    resource: "dashboard",
    label: "Pulpit",
    items: [{ key: "dashboard:read", label: "Podgląd" }],
  },
  {
    resource: "targets",
    label: "Zakresy",
    items: [
      { key: "targets:read", label: "Podgląd" },
      { key: "targets:create", label: "Dodawanie" },
      { key: "targets:update", label: "Edycja" },
      { key: "targets:delete", label: "Usuwanie" },
      { key: "targets:import", label: "Import" },
      { key: "targets:export", label: "Eksport" },
    ],
  },
  {
    resource: "scans",
    label: "Skanowania",
    items: [
      { key: "scans:read", label: "Podgląd" },
      { key: "scans:create", label: "Uruchamianie" },
      { key: "scans:update", label: "Edycja" },
      { key: "scans:delete", label: "Usuwanie" },
      { key: "scans:control", label: "Wstrzymywanie i wznawianie" },
      { key: "scans:import", label: "Import wyników" },
      { key: "scans:export", label: "Eksport" },
    ],
  },
  {
    resource: "schedules",
    label: "Harmonogramy",
    items: [
      { key: "schedules:read", label: "Podgląd" },
      { key: "schedules:create", label: "Dodawanie" },
      { key: "schedules:update", label: "Edycja" },
      { key: "schedules:delete", label: "Usuwanie" },
    ],
  },
  {
    resource: "assets",
    label: "Zasoby",
    items: [
      { key: "assets:read", label: "Podgląd" },
      { key: "assets:update", label: "Edycja" },
      { key: "assets:recheck", label: "Ponowny pomiar" },
    ],
  },
  {
    resource: "findings",
    label: "Znaleziska",
    items: [
      { key: "findings:read", label: "Podgląd" },
      { key: "findings:update", label: "Edycja" },
      { key: "findings:export", label: "Eksport" },
      { key: "findings:defectdojo", label: "Wysyłka do DefectDojo" },
    ],
  },
  {
    resource: "changes",
    label: "Zmiany",
    items: [{ key: "changes:read", label: "Podgląd" }],
  },
  {
    resource: "signatures",
    label: "Sygnatury",
    items: [
      { key: "signatures:read", label: "Podgląd" },
      { key: "signatures:create", label: "Dodawanie" },
      { key: "signatures:update", label: "Edycja" },
      { key: "signatures:delete", label: "Usuwanie" },
      { key: "signatures:test", label: "Testowanie" },
    ],
  },
  {
    resource: "sensitive",
    label: "Dane wrażliwe",
    items: [{ key: "sensitive:reveal", label: "Odsłanianie wartości" }],
  },
  {
    resource: "admin",
    label: "Administracja",
    items: [
      { key: "users:read", label: "Użytkownicy: podgląd" },
      { key: "users:manage", label: "Użytkownicy: zarządzanie" },
      { key: "roles:read", label: "Role: podgląd" },
      { key: "roles:manage", label: "Role: zarządzanie" },
      { key: "integrations:read", label: "Integracje: podgląd" },
      { key: "integrations:manage", label: "Integracje: zarządzanie" },
      { key: "audit:read", label: "Dziennik zdarzeń" },
      { key: "settings:read", label: "Ustawienia: podgląd" },
      { key: "settings:manage", label: "Ustawienia: zarządzanie" },
    ],
  },
];

const READ: Permission[] = PERMISSIONS.filter((p) => p.endsWith(":read") && !isAdminArea(p));
const EXPORT: Permission[] = ["targets:export", "scans:export", "findings:export"];

function isAdminArea(p: Permission) {
  return /^(users|roles|integrations|audit|settings):/.test(p);
}

/** Four built-in roles required by the brief (point 13). */
export const BUILTIN_ROLES: {
  key: "admin" | "operator" | "analyst" | "viewer";
  name: string;
  description: string;
  permissions: Permission[];
}[] = [
  {
    key: "admin",
    name: "Administrator",
    description: "Administracja: pełny dostęp, w tym użytkownicy, role, integracje i ustawienia.",
    permissions: [...PERMISSIONS],
  },
  {
    key: "operator",
    name: "Operator",
    description: "Dodawanie, usuwanie, modyfikacja: zakresy, skanowania, harmonogramy, sygnatury i znaleziska.",
    permissions: PERMISSIONS.filter((p) => !isAdminArea(p)),
  },
  {
    key: "analyst",
    name: "Analityk",
    description: "Modyfikacja i odczyt: może poprawiać dane i oceniać znaleziska, ale niczego nie dodaje ani nie usuwa.",
    permissions: [
      ...READ,
      ...EXPORT,
      "targets:update",
      "scans:update",
      "schedules:update",
      "assets:update",
      "findings:update",
      "findings:defectdojo",
      "signatures:update",
      "signatures:test",
    ],
  },
  {
    key: "viewer",
    name: "Obserwator",
    description: "Odczyt: przegląda pulpit, wyniki i zmiany oraz eksportuje raporty.",
    permissions: [...READ, ...EXPORT],
  },
];

export function permissionLabel(p: Permission): string {
  for (const g of PERMISSION_GROUPS) {
    const item = g.items.find((i) => i.key === p);
    if (item) return g.resource === "admin" ? item.label : `${g.label}: ${item.label.toLowerCase()}`;
  }
  return p;
}
