import type { Metadata } from "next";
import { Suspense } from "react";
import { LoginView } from "@/features/auth/login-view";

export const metadata: Metadata = { title: "Logowanie" };

export default function LoginPage() {
  return (
    <Suspense>
      <LoginView />
    </Suspense>
  );
}
