import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { SettingsView } from "@/features/admin/settings-view";

export const metadata: Metadata = { title: "Ustawienia" };

export default function Page() {
  return <Require permission="settings:read">
      <SettingsView />
    </Require>;
}
