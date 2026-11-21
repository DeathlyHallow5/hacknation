import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { UsersView } from "@/features/admin/users-view";

export const metadata: Metadata = { title: "Użytkownicy" };

export default function Page() {
  return <Require permission="users:read">
      <UsersView />
    </Require>;
}
