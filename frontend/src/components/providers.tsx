"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";
import { Toaster } from "sonner";
import { TooltipProvider } from "@/components/ui/overlays";
import { ApiError } from "@/lib/api/client";
import { PrefsProvider, usePrefs } from "@/lib/prefs";

let browserClient: QueryClient | undefined;

function makeClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: false,
        retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
      },
    },
  });
}

function getClient() {
  if (typeof window === "undefined") return makeClient();
  browserClient ??= makeClient();
  return browserClient;
}

function ThemedToaster() {
  const { prefs } = usePrefs();
  return (
    <Toaster
      position="bottom-right"
      theme={prefs.theme === "light" ? "light" : "dark"}
      closeButton
      toastOptions={{
        classNames: {
          toast:
            "!rounded-xl !border !border-line !bg-surface !text-ink !shadow-pop !font-sans contrast:!border-white",
          description: "!text-ink-2",
          actionButton: "!bg-accent !text-accent-ink !font-semibold",
          success: "[&_[data-icon]]:!text-success",
          error: "[&_[data-icon]]:!text-danger",
        },
      }}
    />
  );
}

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <PrefsProvider>
      <QueryClientProvider client={getClient()}>
        <TooltipProvider delayDuration={250}>
          {children}
          <ThemedToaster />
        </TooltipProvider>
      </QueryClientProvider>
    </PrefsProvider>
  );
}
