import type { Metadata } from "next";
import { Require } from "@/components/rbac/require";
import { SignaturesView } from "@/features/signatures/signatures-view";

export const metadata: Metadata = { title: "Sygnatury" };

export default function SignaturesPage() {
  return <Require permission="signatures:read">
      <SignaturesView />
    </Require>;
}
