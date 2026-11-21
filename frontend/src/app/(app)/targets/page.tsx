import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { Suspense } from "react";
import { TargetsView } from "@/features/targets/targets-view";

export const metadata: Metadata = { title: "Zakresy" };

export default function TargetsPage() {
  return (
    <Suspense>
      <Require permission="targets:read">
      <TargetsView />
    </Require>
    </Suspense>
  );
}
