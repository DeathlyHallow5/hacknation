import type { Metadata } from "next";
import { HelpView } from "@/features/help/help-view";

export const metadata: Metadata = { title: "Pomoc" };

/** No permission check: every signed-in user can read the help. */
export default function HelpPage() {
  return <HelpView />;
}
