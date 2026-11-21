"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { api } from "@/lib/api/endpoints";
import type { Permission, Session } from "@/lib/api/types";

const Ctx = React.createContext<Session | null>(null);

export function useSessionQuery() {
  return useQuery({ queryKey: ["session"], queryFn: api.auth.me, staleTime: 60_000 });
}

export function SessionProvider({ session, children }: { session: Session; children: React.ReactNode }) {
  return <Ctx.Provider value={session}>{children}</Ctx.Provider>;
}

export function useSession(): Session {
  const s = React.useContext(Ctx);
  if (!s) throw new Error("useSession must be used inside SessionProvider");
  return s;
}

/** RBAC check for the current user. The API enforces the same rules. */
export function useCan() {
  const s = React.useContext(Ctx);
  const perms = React.useMemo(() => new Set(s?.permissions ?? []), [s]);
  return React.useCallback((p: Permission) => perms.has(p), [perms]);
}

export function useMeta() {
  return useQuery({ queryKey: ["meta"], queryFn: api.meta, staleTime: Infinity });
}

export function useSwitchUser() {
  const qc = useQueryClient();
  return React.useCallback(
    async (login: string) => {
      await api.auth.login({ login, password: "demo" });
      qc.clear();
      window.location.reload();
    },
    [qc],
  );
}

export const DEMO_USERS = [
  { login: "jan.kowalski", name: "Jan Kowalski", role: "Administrator", hint: "Administracja — pełny dostęp" },
  { login: "anna.nowak", name: "Anna Nowak", role: "Operator", hint: "Dodawanie, usuwanie, modyfikacja" },
  { login: "piotr.wisniewski", name: "Piotr Wiśniewski", role: "Analityk", hint: "Modyfikacja i odczyt" },
  { login: "maria.wojcik", name: "Maria Wójcik", role: "Obserwator", hint: "Tylko odczyt" },
] as const;
