import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { Suspense } from "react";
import { FindingsView } from "@/features/findings/findings-view";

export const metadata: Metadata = { title: "Znaleziska" };

export default function FindingsPage() {
  return (
    <Suspense>
      <Require permission="findings:read">
      <FindingsView />
    </Require>
    </Suspense>
  );
}
