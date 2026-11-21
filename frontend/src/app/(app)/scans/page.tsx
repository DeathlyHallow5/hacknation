import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { Suspense } from "react";
import { ScansView } from "@/features/scans/scans-view";

export const metadata: Metadata = { title: "Skanowania" };

export default function ScansPage() {
  return (
    <Suspense>
      <Require permission="scans:read">
      <ScansView />
    </Require>
    </Suspense>
  );
}
