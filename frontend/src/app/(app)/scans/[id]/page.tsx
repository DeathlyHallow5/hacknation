import type { Metadata } from "next";
import { ScanDetailView } from "@/features/scans/scan-detail-view";

export const metadata: Metadata = { title: "Skanowanie" };

export default async function ScanPage({ params }: PageProps<"/scans/[id]">) {
  const { id } = await params;
  return <ScanDetailView id={id} />;
}
