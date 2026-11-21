import type { Metadata } from "next";
import { HostView } from "@/features/assets/host-view";

export const metadata: Metadata = { title: "Host" };

export default async function HostPage({ params }: PageProps<"/assets/[id]">) {
  const { id } = await params;
  return <HostView id={decodeURIComponent(id)} />;
}
