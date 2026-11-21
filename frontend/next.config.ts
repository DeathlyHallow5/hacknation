import type { NextConfig } from "next";

/**
 * Cache Components / Partial Prefetching are intentionally left disabled:
 * the app is a client-rendered dashboard behind authentication that talks to
 * `/api/v1/*` (built-in mock or the Rust backend), so a static shell brings
 * nothing, while route-level <Activity> would keep dialogs/portals alive
 * between navigations.
 */
const nextConfig: NextConfig = {
  // Self-contained server for the Docker image (frontend/Dockerfile).
  output: "standalone",
  poweredByHeader: false,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
