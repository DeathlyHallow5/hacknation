import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { RolesView } from "@/features/admin/roles-view";

export const metadata: Metadata = { title: "Role i uprawnienia" };

export default function Page() {
  return <Require permission="roles:read">
      <RolesView />
    </Require>;
}
