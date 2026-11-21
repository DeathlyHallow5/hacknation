"use client";

import { LockKeyhole } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { Container } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import type { Permission } from "@/lib/api/types";
import { permissionLabel } from "@/lib/permissions";
import { useCan, useSession } from "@/lib/session";

/** Page-level guard: explains the missing permission instead of showing API errors. */
export function Require({ permission, children }: { permission: Permission; children: React.ReactNode }) {
  const can = useCan();
  const session = useSession();
  if (can(permission)) return <>{children}</>;
  return (
    <Container className="grid place-items-center py-20">
      <div className="grid max-w-md justify-items-center gap-3 text-center">
        <LockKeyhole className="size-6 text-ink-2" aria-hidden />
        <h1 className="text-xl font-semibold">Brak dostępu do tej sekcji</h1>
        <p className="text-sm text-ink-2">
          Twoja rola ({session.role.name}) nie ma uprawnienia „{permissionLabel(permission)}”. Jeśli potrzebujesz dostępu, poproś administratora o zmianę roli.
        </p>
        <Button asChild variant="primary" className="mt-2">
          <Link href="/">Wróć na pulpit</Link>
        </Button>
      </div>
    </Container>
  );
}
