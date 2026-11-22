"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ScanRun } from "@/lib/api/types";

const LIVE: ScanRun["status"][] = ["running", "paused", "paused_window", "queued"];

/** A finished scanner run that still knows its profile and targets can be repeated as is. */
export function canRescan(s: ScanRun) {
  return s.source === "scanner" && !LIVE.includes(s.status) && s.profile_id !== null && s.target_ids.length > 0;
}

/**
 * "Skanuj ponownie": a new scan with the same name, targets, profile, window and tags, started now
 * (POST /scans, start "now"); opens the new run. `pending` is the id of the run being repeated.
 */
export function useRescan() {
  const router = useRouter();
  const qc = useQueryClient();
  const [pending, setPending] = React.useState<string | null>(null);
  const rescan = async (s: ScanRun) => {
    if (!s.profile_id || pending) return;
    setPending(s.id);
    try {
      const run = await api.scans.create({
        name: s.name,
        target_ids: s.target_ids,
        profile_id: s.profile_id,
        start: "now",
        window: s.window,
        tags: s.tags,
      });
      for (const k of [["scans"], ["live-scan"], ["dashboard-summary"]]) qc.invalidateQueries({ queryKey: k });
      toast.success(`Uruchomiono skan #${run.number}`, { description: `Te same cele i profil co w skanie #${s.number}. Postęp możesz śledzić na żywo.` });
      router.push(`/scans/${run.id}`);
    } catch (e) {
      toast.error("Nie udało się uruchomić skanowania", { description: errorMessage(e) });
    } finally {
      setPending(null);
    }
  };
  return { rescan, pending };
}
