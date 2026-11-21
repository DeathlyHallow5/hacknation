/**
 * In-memory database of the mock backend. Lives on globalThis so it survives
 * hot reloads; POST /api/v1/_mock/reset rebuilds it from the deterministic seed.
 */
import type {
  AuditEvent,
  Availability,
  Change,
  ChangeState,
  ChangesTimelinePoint,
  Criticality,
  DefectDojoConfig,
  DefectDojoExport,
  DeviceType,
  EncryptionStatus,
  Engine,
  Finding,
  ManualOverrides,
  Role,
  ScanBatch,
  ScanLogLine,
  ScanProfile,
  ScanRun,
  Schedule,
  Settings,
  Signature,
  Target,
  User,
} from "@/lib/api/types";
import type { BlockType } from "@/mock/catalog";
import { createDB } from "@/mock/seed";

export interface ServiceRec {
  id: string;
  port: number;
  protocol: "tcp" | "udp";
  name: string;
  product: string | null;
  version: string | null;
  confidence: number;
  tls: boolean;
  banner: string | null;
  /** Key in WEB_APPS when this is a web service. */
  web: string | null;
  appVersion: string | null;
  serverVersion: string | null;
  /** Key in PLAIN for non-web services. */
  plain: string | null;
  /** Outdated component. */
  old: boolean;
  /** Port this HTTP service redirects to (http -> https). */
  redirectTo: number | null;
  /** Days until TLS certificate expiry at seed time (negative = expired). */
  certDays: number | null;
  certRenewedAt: number | null;
  change: ChangeState;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  notes: string | null;
  overrides: ManualOverrides;
}

export interface HostRec {
  id: string;
  ipInt: number;
  ip: string;
  /** Offset inside 10.0.0.0/16 (0..65535). */
  off: number;
  block: number;
  blockType: BlockType;
  hostnames: string[];
  device: DeviceType;
  osGuess: string | null;
  services: ServiceRec[];
  responded: boolean;
  availability: Availability;
  change: ChangeState;
  pattern: boolean[];
  missCount: number;
  firstSeen: string;
  lastSeen: string;
  owner: string | null;
  criticality: Criticality;
  tags: string[];
  notes: string | null;
  overrides: ManualOverrides;
  recheckRequestedAt: number | null;
  lastRecheckAt: string | null;
  /** Response rate by hour (0..23) observed by daytime re-checks. */
  byHour: (number | null)[] | null;
}

export interface SimState {
  scanId: string;
  totalMs: number;
  activeMs: number;
  lastResumeMs: number | null;
  pausedReason: "user" | "window" | null;
  testWindowMs: number | null;
  windowStartMs: number;
  resumeAtMs: number | null;
  windowsUsed: number;
  cancelled: boolean;
  finalized: boolean;
  logs: ScanLogLine[];
  lastLoggedBatch: number;
  lastPhase: string | null;
  /** Offsets of 10.0.0.0/16 covered (first, size) or null for domains only. */
  span: { first: number; size: number } | null;
  waitingForWindow: boolean;
}

export interface MockDB {
  seededAt: number;
  users: (User & { password: string })[];
  roles: Role[];
  targets: Target[];
  profiles: ScanProfile[];
  schedules: Schedule[];
  scans: ScanRun[];
  batches: Map<string, ScanBatch[]>;
  sims: Map<string, SimState>;
  hosts: HostRec[];
  hostById: Map<string, HostRec>;
  hostByOff: Map<number, HostRec>;
  findings: Finding[];
  latestDiff: { baseId: string; headId: string; changes: Change[] };
  timeline: ChangesTimelinePoint[];
  trend: { scan_number: number; at: string; value: number }[];
  signatures: Signature[];
  audit: AuditEvent[];
  settings: Settings;
  encryption: EncryptionStatus;
  defectdojo: DefectDojoConfig & { token: string | null };
  ddExports: DefectDojoExport[];
  engines: Engine[];
  seq: number;
}

const KEY = "__asiMockDb__" as const;
type G = typeof globalThis & { [KEY]?: MockDB };

export function getDB(): MockDB {
  const g = globalThis as G;
  if (!g[KEY]) g[KEY] = createDB();
  return g[KEY]!;
}

export function resetDB(): MockDB {
  const g = globalThis as G;
  g[KEY] = undefined;
  return getDB();
}

export function nextId(db: MockDB, prefix: string): string {
  db.seq += 1;
  return `${prefix}-${db.seq.toString(36)}`;
}
