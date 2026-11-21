import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { AuditView } from "@/features/admin/audit-view";

export const metadata: Metadata = { title: "Dziennik zdarzeń" };

export default function Page() {
  return <Require permission="audit:read">
      <AuditView />
    </Require>;
}
