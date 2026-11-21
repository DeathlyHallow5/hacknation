import type { Metadata } from "next";
import { Suspense } from "react";
import { SignatureEditor } from "@/features/signatures/signature-editor";

export const metadata: Metadata = { title: "Sygnatura" };

export default async function SignaturePage({ params }: PageProps<"/signatures/[id]">) {
  const { id } = await params;
  return (
    <Suspense>
      <SignatureEditor id={id} />
    </Suspense>
  );
}
