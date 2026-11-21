"use client";

import { useMutation, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useRouter, useSearchParams, usePathname } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/lib/api/client";
import { downloadBlob } from "@/lib/utils";

/** Download an export endpoint result with a toast. */
export function useDownload() {
  return React.useCallback(async (fn: () => Promise<{ blob: Blob; filename: string }>, label = "Pobrano plik") => {
    try {
      const { blob, filename } = await fn();
      downloadBlob(blob, filename);
      toast.success(label, { description: filename });
    } catch (e) {
      toast.error("Nie udało się pobrać pliku", { description: errorMessage(e) });
    }
  }, []);
}

/** Mutation that shows a toast and invalidates the given query keys. */
export function useApiMutation<TVars, TData>(
  fn: (v: TVars) => Promise<TData>,
  opts: { success?: string | ((d: TData, v: TVars) => string); invalidate?: QueryKey[]; onSuccess?: (d: TData, v: TVars) => void } = {},
) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: (d, v) => {
      for (const k of opts.invalidate ?? []) qc.invalidateQueries({ queryKey: k });
      if (opts.success) toast.success(typeof opts.success === "function" ? opts.success(d, v) : opts.success);
      opts.onSuccess?.(d, v);
    },
    onError: (e) => toast.error("Nie udało się zapisać zmian", { description: errorMessage(e) }),
  });
}

/** State persisted in the URL query string (shareable filters). */
export function useQueryState(key: string, fallback = "") {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const value = params.get(key) ?? fallback;
  const set = React.useCallback(
    (v: string) => {
      const sp = new URLSearchParams(window.location.search);
      if (v && v !== fallback) sp.set(key, v);
      else sp.delete(key);
      if (key !== "page") sp.delete("page");
      const qs = sp.toString();
      router.replace(`${pathname}${qs ? `?${qs}` : ""}`, { scroll: false });
    },
    [key, fallback, router, pathname],
  );
  return [value, set] as const;
}
