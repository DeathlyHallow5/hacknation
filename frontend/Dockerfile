# Base images come from Docker Hub; when its anonymous pull limit is hit (HTTP 429), build with
# ASI_BASE_REGISTRY=mirror.gcr.io/library (Google's public Docker Hub cache).
ARG BASE_REGISTRY=docker.io/library
FROM ${BASE_REGISTRY}/node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS builder
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM ${BASE_REGISTRY}/node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public
# Real client address for the API proxy (see the file); preloaded before Next.js starts.
COPY --from=builder --chown=node:node /app/client-ip.mjs ./client-ip.mjs
USER node
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3000').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--import", "./client-ip.mjs", "server.js"]
