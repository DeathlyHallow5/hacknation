import type { RouteFn } from "@/mock/router";
import { adminRoutes } from "@/mock/handlers/admin";
import { assetRoutes } from "@/mock/handlers/assets";
import { coreRoutes } from "@/mock/handlers/core";
import { diffRoutes } from "@/mock/handlers/diffs";
import { findingRoutes } from "@/mock/handlers/findings";
import { scanRoutes } from "@/mock/handlers/scans";
import { signatureRoutes } from "@/mock/handlers/signatures";
import { targetRoutes } from "@/mock/handlers/targets";

export function registerAll(route: RouteFn) {
  coreRoutes(route);
  targetRoutes(route);
  scanRoutes(route);
  assetRoutes(route);
  findingRoutes(route);
  diffRoutes(route);
  signatureRoutes(route);
  adminRoutes(route);
}
