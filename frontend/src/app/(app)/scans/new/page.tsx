import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { NewScanView } from "@/features/scans/new-scan-view";

export const metadata: Metadata = { title: "Nowe skanowanie" };

export default function NewScanPage() {
  return <Require permission="scans:create">
      <NewScanView />
    </Require>;
}
