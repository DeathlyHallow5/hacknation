import type { Metadata } from "next";
import { Suspense } from "react";
import { TargetsView } from "@/features/targets/targets-view";

export const metadata: Metadata = { title: "Zakresy" };

export default function TargetsPage() {
  return (
    <Suspense>
      <TargetsView />
    </Suspense>
  );
}
