import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { Suspense } from "react";
import { AssetsView } from "@/features/assets/assets-view";

export const metadata: Metadata = { title: "Zasoby" };

export default function AssetsPage() {
  return (
    <Suspense>
      <Require permission="assets:read">
      <AssetsView />
    </Require>
    </Suspense>
  );
}
