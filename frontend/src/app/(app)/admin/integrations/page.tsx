import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { IntegrationsView } from "@/features/admin/integrations-view";

export const metadata: Metadata = { title: "Integracje" };

export default function Page() {
  return <Require permission="integrations:read">
      <IntegrationsView />
    </Require>;
}
