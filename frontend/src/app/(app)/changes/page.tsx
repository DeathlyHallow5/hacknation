import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { Suspense } from "react";
import { ChangesView } from "@/features/changes/changes-view";

export const metadata: Metadata = { title: "Zmiany" };

export default function ChangesPage() {
  return (
    <Suspense>
      <Require permission="changes:read">
      <ChangesView />
    </Require>
    </Suspense>
  );
}
