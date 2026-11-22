/**
 * Real client address for the API proxy (src/app/api/v1/[...path]/route.ts).
 *
 * Route handlers never see the TCP connection, and Next.js only fills X-Forwarded-For with the
 * socket address when the client did not send one itself — so a client could pick the address
 * the core's login limiter and audit log see. This file is preloaded by the image
 * (`node --import ./client-ip.mjs server.js`): before Next.js handles a request it computes the
 * client from the socket, replaces X-Forwarded-For with that single address and drops other
 * client-supplied forwarding headers.
 *
 * ASI_TRUSTED_PROXIES (comma-separated IPs/CIDRs): proxies in front of the dashboard (the TLS
 * proxy of compose.production.yaml). Only when the socket peer is one of them is its
 * X-Forwarded-For read: the client is the right-most entry that is not a trusted proxy.
 * Empty (the default): the socket peer is the client.
 */
import http from "node:http";
import net from "node:net";

const MAX_HOPS = 16;
const trusted = new net.BlockList();

for (const entry of (process.env.ASI_TRUSTED_PROXIES ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
  const [addr, prefix, extra] = entry.split("/");
  const family = net.isIPv4(addr) ? "ipv4" : net.isIPv6(addr) ? "ipv6" : null;
  const max = family === "ipv4" ? 32 : 128;
  const bits = prefix === undefined ? max : /^\d{1,3}$/.test(prefix) ? Number(prefix) : NaN;
  if (!family || extra !== undefined || !(bits >= 0 && bits <= max)) {
    console.error(`ASI_TRUSTED_PROXIES: not an IP address or CIDR: ${entry}`);
    process.exit(1);
  }
  trusted.addSubnet(addr, bits, family);
}

/** "::ffff:10.0.0.1" → "10.0.0.1"; anything that is not an IP address → null. */
function canonical(ip) {
  const v = String(ip ?? "").trim();
  const mapped = v.toLowerCase().startsWith("::ffff:") ? v.slice(7) : null;
  if (mapped && net.isIPv4(mapped)) return mapped;
  return net.isIP(v) ? v : null;
}

function isTrusted(ip) {
  return trusted.check(ip, net.isIPv4(ip) ? "ipv4" : "ipv6");
}

function clientIp(req) {
  let ip = canonical(req.socket?.remoteAddress);
  if (!ip || !isTrusted(ip)) return ip;
  const raw = req.headers["x-forwarded-for"];
  const hops = (Array.isArray(raw) ? raw.join(",") : (raw ?? "")).split(",").map((s) => s.trim());
  for (const hop of hops.reverse().slice(0, MAX_HOPS)) {
    const next = canonical(hop);
    if (!next) break;
    ip = next;
    if (!isTrusted(ip)) break;
  }
  return ip;
}

// `http` is the CommonJS module object itself, so Next.js's require("http") sees this wrapper.
const createServer = http.createServer;
http.createServer = function (...args) {
  const server = createServer.apply(this, args);
  // Runs before Next.js's own request listener.
  server.prependListener("request", (req) => {
    const ip = clientIp(req);
    for (const h of ["x-forwarded-for", "x-real-ip", "forwarded", "x-asi-client-ip"]) delete req.headers[h];
    if (ip) {
      req.headers["x-forwarded-for"] = ip;
      req.headers["x-asi-client-ip"] = ip;
    }
  });
  return server;
};

// Tells the API route that x-asi-client-ip was written here, not by a client (`next dev` runs
// without this file: the route then forwards no client address and the core uses the peer).
process.env.ASI_CLIENT_IP_PRELOAD = "1";
