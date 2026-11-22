/**
 * API contract of Attack Surface Intelligence (`/api/v1`).
 *
 * This file is the single source of truth for the JSON exchanged between the
 * Next.js frontend and the backend (built-in mock today, Rust/axum later).
 * Conventions: snake_case keys, ISO-8601 UTC timestamps, ids are strings.
 * README.md mirrors these shapes endpoint by endpoint.
 */

export type ID = string;
/** ISO-8601 timestamp in UTC, e.g. "2026-11-21T04:42:00Z". */
export type ISODate = string;

/* ------------------------------------------------------------------ */
/* Common                                                              */
/* ------------------------------------------------------------------ */

export interface Paginated<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}

export interface ApiErrorBody {
  error: {
    /** Machine code: unauthorized | forbidden | not_found | conflict | validation | bad_request | internal */
    code: string;
    /** Human readable message (Polish). */
    message: string;
    /** Present on 403: permission the caller is missing. */
    required_permission?: Permission;
    /** Present on 422: field -> message. */
    fields?: Record<string, string>;
    details?: unknown;
  };
}

export type SortDir = "asc" | "desc";

export interface ListQuery {
  page?: number;
  page_size?: number;
  /** Field name; prefix with "-" for descending, e.g. "-score". */
  sort?: string;
  q?: string;
}

/** Value set by a person; scanners never overwrite it (requirement 14). */
export interface ManualOverride {
  value: unknown;
  /** Value the scanner reported when the override was made. */
  scanner_value?: unknown;
  by: string;
  at: ISODate;
}
export type ManualOverrides = Record<string, ManualOverride>;

export type Criticality = "low" | "medium" | "high" | "critical";

/* ------------------------------------------------------------------ */
/* Auth & RBAC                                                         */
/* ------------------------------------------------------------------ */

export const PERMISSIONS = [
  "dashboard:read",
  "targets:read",
  "targets:create",
  "targets:update",
  "targets:delete",
  "targets:import",
  "targets:export",
  "scans:read",
  "scans:create",
  "scans:update",
  "scans:delete",
  "scans:control",
  "scans:import",
  "scans:export",
  "schedules:read",
  "schedules:create",
  "schedules:update",
  "schedules:delete",
  "assets:read",
  "assets:update",
  "assets:recheck",
  "findings:read",
  "findings:update",
  "findings:export",
  "findings:defectdojo",
  "changes:read",
  "signatures:read",
  "signatures:create",
  "signatures:update",
  "signatures:delete",
  "signatures:test",
  "sensitive:reveal",
  "users:read",
  "users:manage",
  "roles:read",
  "roles:manage",
  "integrations:read",
  "integrations:manage",
  "audit:read",
  "settings:read",
  "settings:manage",
] as const;

export type Permission = (typeof PERMISSIONS)[number];

export interface Role {
  id: ID;
  /** Stable key: admin | operator | analyst | viewer | custom-… */
  key: string;
  name: string;
  description: string;
  builtin: boolean;
  permissions: Permission[];
  users_count: number;
}

export interface User {
  id: ID;
  login: string;
  name: string;
  email: string;
  role_id: ID;
  role_name: string;
  active: boolean;
  last_login_at: ISODate | null;
  created_at: ISODate;
}

export interface Session {
  user: User;
  role: Role;
  permissions: Permission[];
}

export interface LoginRequest {
  login: string;
  password: string;
}

/* ------------------------------------------------------------------ */
/* Targets (Zakresy)                                                   */
/* ------------------------------------------------------------------ */

export type TargetType = "ip" | "cidr" | "domain";

export interface Target {
  id: ID;
  /** Normalised value: "10.0.0.0/18", "10.0.4.7", "usos.uczelnia.example". */
  value: string;
  type: TargetType;
  /** Number of IPv4 addresses covered (1 for ip/domain). */
  address_count: number;
  name: string | null;
  owner: string | null;
  criticality: Criticality;
  tags: string[];
  notes: string | null;
  /** Excluded targets are never scanned ("no-scan list"). */
  excluded: boolean;
  source: "manual" | "import";
  active_hosts: number;
  last_scanned_at: ISODate | null;
  created_at: ISODate;
  updated_at: ISODate;
  updated_by: string | null;
}

export interface TargetInput {
  value: string;
  name?: string | null;
  owner?: string | null;
  criticality?: Criticality;
  tags?: string[];
  notes?: string | null;
  excluded?: boolean;
}

export type TargetPatch = Partial<Omit<TargetInput, "value">>;

export interface TargetCreateRequest {
  items: TargetInput[];
  on_conflict?: "skip" | "update";
}

export interface TargetCreateResult {
  created: Target[];
  updated: Target[];
  skipped: { value: string; reason: string }[];
  errors: { value: string; error: string }[];
}

export type ImportFormat = "csv" | "json";

export interface ImportRowReport {
  row: number;
  value: string;
  status: "ok" | "invalid" | "duplicate";
  type?: TargetType;
  address_count?: number;
  error?: string;
}

export interface ImportReport {
  format: ImportFormat;
  dry_run: boolean;
  total_rows: number;
  valid: number;
  invalid: number;
  duplicates: number;
  created: number;
  updated: number;
  /** First 500 rows, for preview. */
  rows: ImportRowReport[];
}

export interface BulkRequest<A extends string = string> {
  ids: ID[];
  action: A;
  /** e.g. { tag: "dmz" } or { status: "in_review" } */
  payload?: Record<string, unknown>;
}

export interface BulkResult {
  affected: number;
}

/* ------------------------------------------------------------------ */
/* Scans (Skanowania)                                                  */
/* ------------------------------------------------------------------ */

export type ScanStatus =
  | "queued"
  | "running"
  | "paused"
  | "paused_window"
  | "completed"
  | "cancelled"
  | "failed";

export type ScanPhase = "preflight" | "discovery" | "services" | "http" | "signatures" | "diff";

export interface ScanWindow {
  /** Local time HH:MM in `timezone`. */
  start: string;
  end: string;
  timezone: string;
}

export interface ScanStats {
  hosts_alive: number;
  services: number;
  http_services: number;
  findings: number;
  new: number;
  changed: number;
  gone: number;
  unstable: number;
}

export interface ScanRun {
  id: ID;
  /** Human number shown as "#128". */
  number: number;
  name: string;
  status: ScanStatus;
  phase: ScanPhase | null;
  source: "scanner" | "import";
  profile_id: ID | null;
  profile_name: string | null;
  schedule_id: ID | null;
  target_ids: ID[];
  targets_label: string;
  address_count: number;
  /** 0..1 */
  progress: number;
  batches_total: number;
  batches_done: number;
  rate_rps: number;
  rate_limit_rps: number;
  window: ScanWindow | null;
  /** When the current window closes (running scans). */
  window_ends_at: ISODate | null;
  /** When a paused_window scan continues. */
  resume_at: ISODate | null;
  /** How many windows the run needed/has used. */
  windows_used: number;
  started_at: ISODate | null;
  finished_at: ISODate | null;
  duration_s: number;
  eta_s: number | null;
  stats: ScanStats;
  error: string | null;
  tags: string[];
  notes: string | null;
  created_by: string;
}

export type ScanRef = Pick<ScanRun, "id" | "number" | "name" | "started_at" | "finished_at" | "status">;

export interface ScanBatch {
  id: ID;
  index: number;
  /** Sub-group of addresses, e.g. "10.0.8.0/22". */
  cidr: string;
  addresses: number;
  status: "pending" | "running" | "done" | "paused" | "failed";
  started_at: ISODate | null;
  finished_at: ISODate | null;
  duration_s: number | null;
  hosts_alive: number;
  rate_rps: number;
  retries: number;
}

export interface ScanCreateRequest {
  name: string;
  target_ids: ID[];
  profile_id: ID;
  /** "now" starts immediately (inside current window if any), "window" waits for the next window. */
  start: "now" | "window";
  window?: ScanWindow | null;
  on_window_exceeded?: "pause_resume" | "stop";
  /** Demo/testing: close the window after N seconds to show pause & resume. */
  test_window_seconds?: number | null;
  tags?: string[];
  notes?: string | null;
}

export type ScanPatch = Partial<Pick<ScanRun, "name" | "tags" | "notes">>;

export interface ScanEstimateRequest {
  target_ids: ID[];
  profile_id: ID;
  window?: ScanWindow | null;
}

export interface ScanEstimate {
  addresses: number;
  excluded: number;
  est_alive: number;
  /** Prefix length chosen for sub-groups, e.g. 22 -> /22 (1024 addresses). */
  batch_prefix: number;
  batch_size: number;
  batches: number;
  rate_rps: number;
  est_duration_s: number;
  window_seconds: number | null;
  fits_window: boolean;
  windows_needed: number;
  notes: string[];
}

/** Server-Sent Events from GET /scans/{id}/events. */
export type ScanEvent =
  | { type: "progress"; scan: ScanRun }
  | { type: "batch"; batch: ScanBatch }
  | { type: "log"; level: "info" | "warn" | "error"; message: string; at: ISODate }
  | { type: "window"; state: "paused" | "resumed"; resume_at: ISODate | null }
  | { type: "done"; scan: ScanRun };

export interface ScanLogLine {
  at: ISODate;
  level: "info" | "warn" | "error";
  message: string;
}

/* Profiles & schedules */

export interface ScanProfile {
  id: ID;
  name: string;
  description: string;
  builtin: boolean;
  ports: { preset: "top100" | "top1000" | "allowed" | "custom"; custom: string };
  rate_limit_rps: number;
  max_concurrency: number;
  nmap_timing: "T2" | "T3" | "T4";
  host_timeout_s: number;
  http_probe: boolean;
  tls_probe: boolean;
  follow_redirects: boolean;
  max_redirects: number;
  signatures: "all" | "none" | "selected";
  signature_ids: ID[];
  unstable_retries: number;
  batch_strategy: "auto" | "fixed";
  batch_prefix: number;
}

export type ScanProfileInput = Omit<ScanProfile, "id" | "builtin">;

export interface Schedule {
  id: ID;
  name: string;
  enabled: boolean;
  target_ids: ID[];
  profile_id: ID;
  window: ScanWindow;
  /** ISO weekday numbers, 1 = Monday … 7 = Sunday. */
  days: number[];
  frequency: "daily" | "weekly" | "cron";
  cron: string | null;
  on_window_exceeded: "pause_resume" | "stop";
  next_run_at: ISODate | null;
  last_run_id: ID | null;
  created_at: ISODate;
}

export type ScheduleInput = Omit<Schedule, "id" | "next_run_at" | "last_run_id" | "created_at">;

/* ------------------------------------------------------------------ */
/* Hosts, services, HTTP fingerprint (Zasoby)                          */
/* ------------------------------------------------------------------ */

export type Availability = "active" | "unstable" | "inactive";
export type ChangeKind = "new" | "changed" | "gone" | "unstable";
export type ChangeState = ChangeKind | "unchanged";

export type DeviceType =
  | "server"
  | "workstation"
  | "printer"
  | "camera"
  | "network"
  | "bmc"
  | "storage"
  | "iot"
  | "unknown";

export interface HostSummary {
  id: ID;
  ip: string;
  hostnames: string[];
  availability: Availability;
  change: ChangeState;
  /** Last measurements, oldest first: true = responded. */
  response_pattern: boolean[];
  miss_count: number;
  open_ports: number[];
  services_count: number;
  technologies: string[];
  device_type: DeviceType;
  subnet: string;
  owner: string | null;
  criticality: Criticality;
  tags: string[];
  score: number;
  findings_count: number;
  has_manual_overrides: boolean;
  first_seen: ISODate;
  last_seen: ISODate;
}

export interface Host extends HostSummary {
  os_guess: string | null;
  notes: string | null;
  services: Service[];
  manual_overrides: ManualOverrides;
}

export type HostPatch = Partial<{
  owner: string | null;
  criticality: Criticality;
  tags: string[];
  notes: string | null;
  device_type: DeviceType;
  hostnames: string[];
}>;

export type TechCategory =
  | "cms"
  | "framework"
  | "app_server"
  | "web_server"
  | "language"
  | "admin_panel"
  | "devops"
  | "database"
  | "iot"
  | "network"
  | "mail"
  | "other";

export interface Technology {
  name: string;
  version: string | null;
  category: TechCategory;
  /** 0..1, combined from independent evidence sources. */
  confidence: number;
  sources: { type: "header" | "cookie" | "html" | "favicon" | "path" | "title" | "banner" | "signature"; detail: string }[];
}

export interface HttpHeader {
  name: string;
  value: string;
  /** Why the header is interesting, if it is. */
  note: string | null;
}

export interface HttpCookie {
  name: string;
  /** Always masked; full value only via /reveal with sensitive:reveal. */
  value_masked: string;
  domain: string | null;
  path: string;
  secure: boolean;
  http_only: boolean;
  same_site: "Strict" | "Lax" | "None" | null;
  expires: ISODate | null;
  note: string | null;
}

export interface TlsInfo {
  version: string;
  cipher: string;
  subject_cn: string;
  issuer: string;
  san: string[];
  not_before: ISODate;
  not_after: ISODate;
  days_left: number;
  self_signed: boolean;
  expired: boolean;
  sha256: string;
}

export interface RedirectHop {
  url: string;
  status_code: number;
}

export interface HttpFingerprint {
  url: string;
  status_code: number;
  title: string | null;
  content_type: string | null;
  content_length: number | null;
  response_time_ms: number;
  headers: HttpHeader[];
  cookies: HttpCookie[];
  tls: TlsInfo | null;
  /** Chain of hops before the final response (empty if none). */
  redirects: RedirectHop[];
  /** MurmurHash3 of the favicon, Shodan-compatible. */
  favicon_hash: number | null;
  technologies: Technology[];
  environment: "production" | "staging" | "test" | "dev" | null;
  admin_panel: { path: string; title: string } | null;
  body_excerpt: string | null;
}

export interface Service {
  id: ID;
  host_id: ID;
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
  /** nmap service name, e.g. "http", "ssh". */
  name: string;
  product: string | null;
  version: string | null;
  /** 0..1 identification confidence. */
  confidence: number;
  tls: boolean;
  banner: string | null;
  change: ChangeState;
  http: HttpFingerprint | null;
  tags: string[];
  notes: string | null;
  manual_overrides: ManualOverrides;
  first_seen: ISODate;
  last_seen: ISODate;
}

export type ServiceSummary = Omit<Service, "http" | "manual_overrides"> & {
  hostname: string | null;
  title: string | null;
  technologies: string[];
  has_manual_overrides: boolean;
};

export type ServicePatch = Partial<{
  product: string | null;
  version: string | null;
  tags: string[];
  notes: string | null;
}>;

export interface ServiceGroup {
  key: string;
  label: string;
  product: string;
  versions: { version: string | null; count: number }[];
  port_set: number[];
  count: number;
  hosts_sample: { id: ID; ip: string }[];
  outdated: boolean;
}

export interface HostHistoryEntry {
  scan_id: ID;
  scan_number: number;
  at: ISODate;
  responded: boolean;
  open_ports: number[];
  changes: { field: string; label: string; before: string | null; after: string | null }[];
}

export interface UnstableHost {
  host_id: ID;
  ip: string;
  hostname: string | null;
  pattern: boolean[];
  response_rate: number;
  /** Response rate per hour of day (0..23), null when never measured. */
  by_hour: (number | null)[];
  last_recheck_at: ISODate | null;
  recheck_pending: boolean;
  /** Presence depends on the hour of day (Europe/Warsaw), e.g. visible only 08–18; null when no such pattern. */
  time_pattern: TimePattern | null;
}

/** Hours [start_hour, end_hour) when the host answers; end_hour <= start_hour crosses midnight. */
export interface TimePattern {
  start_hour: number;
  end_hour: number;
  inside_responded: number;
  inside_total: number;
  outside_responded: number;
  outside_total: number;
  /** e.g. "Widoczny tylko 08–18" */
  label: string;
  /** Why it is flagged, with the counts behind it (Polish). */
  reason: string;
}

/* ------------------------------------------------------------------ */
/* Findings (Znaleziska)                                               */
/* ------------------------------------------------------------------ */

export type FindingCategory =
  | "admin_panel"
  | "staging"
  | "outdated"
  | "header"
  | "cookie"
  | "tls"
  | "exposure"
  | "iot"
  | "signature";

export type FindingStatus = "open" | "in_review" | "confirmed" | "false_positive" | "accepted";

export interface Evidence {
  type: "header" | "cookie" | "html" | "path" | "tls" | "favicon" | "banner" | "title";
  label: string;
  snippet: string;
  /** Substring of snippet to highlight. */
  highlight: string | null;
}

export interface Finding {
  id: ID;
  title: string;
  category: FindingCategory;
  host_id: ID;
  ip: string;
  hostname: string | null;
  port: number | null;
  service_id: ID | null;
  /** e.g. "8443/HTTPS" */
  service_label: string | null;
  technologies: string[];
  change: ChangeState;
  status: FindingStatus;
  /** Analytical priority 0..100 (computed). */
  score: number;
  score_override: number | null;
  score_breakdown: { factor: string; points: number }[];
  /** 0..1 */
  confidence: number;
  measurements: { responded: number; total: number };
  evidence: Evidence[];
  signature_id: ID | null;
  signature_name: string | null;
  assignee: string | null;
  tags: string[];
  notes: string | null;
  manual_overrides: ManualOverrides;
  defectdojo: { exported_at: ISODate; finding_id: number; url: string } | null;
  /** One finding per problem (category + host/service/URL), across every scan that saw it. */
  first_seen: ISODate;
  last_seen: ISODate;
  /** Finished scans that observed it. */
  occurrences: number;
}

export type FindingPatch = Partial<{
  status: FindingStatus;
  score_override: number | null;
  assignee: string | null;
  tags: string[];
  notes: string | null;
}>;

export interface DefectDojoExportRequest {
  ids: ID[];
  as: "finding" | "evidence";
}

export interface DefectDojoExportResult {
  exported: number;
  failed: number;
  export_id: ID;
  links: { finding_id: ID; url: string }[];
}

/* ------------------------------------------------------------------ */
/* Diffs (Zmiany)                                                      */
/* ------------------------------------------------------------------ */

export interface FieldChange {
  field: string;
  label: string;
  before: string | null;
  after: string | null;
}

export interface Change {
  id: ID;
  kind: ChangeKind;
  entity: "host" | "service" | "http" | "tls" | "technology";
  host_id: ID;
  ip: string;
  hostname: string | null;
  port: number | null;
  summary: string;
  fields: FieldChange[];
  /** Confidence that this is a real change, not noise (0..1). */
  confidence: number;
  measurements: { responded: number; total: number };
  detected_at: ISODate;
}

export interface DiffResponse extends Paginated<Change> {
  base: ScanRef;
  head: ScanRef;
  summary: Record<ChangeKind, number>;
}

/* ------------------------------------------------------------------ */
/* Dashboard (Pulpit)                                                  */
/* ------------------------------------------------------------------ */

export interface DashboardSummary {
  active_hosts: number;
  active_hosts_delta: number;
  active_trend: { scan_number: number; at: ISODate; value: number }[];
  monitored_addresses: number;
  targets_count: number;
  services_count: number;
  web_services_count: number;
  findings_open: number;
  findings_high: number;
  changes: Record<ChangeKind, number>;
  changes_base_scan: number | null;
  changes_head_scan: number | null;
  /** Most recent completed scanner run. */
  last_scan: ScanRun | null;
  running_scan: ScanRun | null;
  window: ScanWindow;
  /** Is "now" inside the scan window? */
  window_open: boolean;
  /** 0..1 elapsed part of the current/most recent window. */
  window_progress: number;
  next_window_at: ISODate | null;
  rate_limit_rps: number;
}

export interface ChangesTimelinePoint {
  scan_id: ID;
  scan_number: number;
  at: ISODate;
  new: number;
  changed: number;
  gone: number;
  unstable: number;
}

export interface AvailabilityHeatmap {
  /** 7 rows (Mon..Sun) x 24 columns (hours), response rate 0..1 or null. */
  matrix: (number | null)[][];
  hosts_considered: number;
  samples: number;
}

export interface TechStat {
  name: string;
  category: TechCategory;
  count: number;
  delta: number;
}

/** Status codes packed 4 bits per address in AddressMap.data. */
export enum AddressStatus {
  None = 0,
  Active = 1,
  New = 2,
  Changed = 3,
  Gone = 4,
  Unstable = 5,
  Inactive = 6,
  Excluded = 7,
}

export interface AddressMap {
  cidr: string;
  prefix: number;
  size: number;
  /** base64 of ceil(size/2) bytes; address i is the high nibble of byte i>>1 when i is even, low nibble when odd. Address order (not Hilbert). */
  data: string;
  counts: Record<"none" | "active" | "new" | "changed" | "gone" | "unstable" | "inactive" | "excluded", number>;
  /** Offset of the address the running scan is at, or null. */
  scan_head: number | null;
  generated_at: ISODate;
}

/* ------------------------------------------------------------------ */
/* Signatures (Sygnatury)                                              */
/* ------------------------------------------------------------------ */

export type SignatureConditionType =
  | "header"
  | "cookie"
  | "favicon_hash"
  | "html"
  | "path"
  | "title"
  | "version"
  | "status";

export interface SignatureCondition {
  type: SignatureConditionType;
  /** Header/cookie name. */
  name?: string | null;
  /** For "path": GET-only probe path, e.g. "/phpmyadmin/". */
  path?: string | null;
  op: "exists" | "equals" | "contains" | "regex";
  value?: string | null;
  /** For "path": expected status code. */
  expect_status?: number | null;
  /** For "version": regex with one capture group. */
  extract?: string | null;
}

export interface Signature {
  id: ID;
  name: string;
  description: string;
  category: FindingCategory | "technology";
  /** Technology reported when matched, e.g. "phpMyAdmin". */
  technology: string | null;
  severity: "info";
  /** Points added to the analytical priority. */
  score_weight: number;
  enabled: boolean;
  source: "builtin" | "custom";
  match: { operator: "and" | "or"; conditions: SignatureCondition[] };
  tags: string[];
  author: string;
  created_at: ISODate;
  updated_at: ISODate;
  matches_last_scan: number;
  version: number;
}

export type SignatureInput = Omit<
  Signature,
  "id" | "source" | "author" | "created_at" | "updated_at" | "matches_last_scan" | "version" | "severity"
>;

export interface SignatureTestRequest {
  signature: SignatureInput;
  target:
    | { service_id: ID }
    | { raw: { status_code: number; headers: string; body: string; favicon_hash?: number | null } };
}

export interface SignatureTestResult {
  matched: boolean;
  conditions: { index: number; matched: boolean; evidence: string | null }[];
  extracted_version: string | null;
  safety: { ok: boolean; issues: string[] };
  target_label: string;
}

/* ------------------------------------------------------------------ */
/* Integrations, audit, settings                                       */
/* ------------------------------------------------------------------ */

export interface DefectDojoConfig {
  enabled: boolean;
  url: string;
  api_token_set: boolean;
  api_token_masked: string | null;
  product_id: number | null;
  product_name: string | null;
  engagement_id: number | null;
  engagement_name: string | null;
  auto_export: boolean;
  min_score: number;
  export_as: "finding" | "evidence";
  verify_tls: boolean;
  last_test: { ok: boolean; at: ISODate; version: string | null; latency_ms: number | null; message: string } | null;
}

export type DefectDojoConfigInput = Partial<
  Omit<DefectDojoConfig, "api_token_set" | "api_token_masked" | "last_test">
> & { api_token?: string };

export interface DefectDojoExport {
  id: ID;
  at: ISODate;
  by: string;
  count: number;
  as: "finding" | "evidence";
  status: "success" | "partial" | "failed";
  message: string;
}

export interface Engine {
  name: "nmap" | "httpx" | "naabu";
  version: string | null;
  status: "ok" | "missing" | "error";
  path: string | null;
  purpose: string;
  last_used_at: ISODate | null;
}

export type AuditAction =
  | "create"
  | "update"
  | "delete"
  | "login"
  | "logout"
  | "import"
  | "export"
  | "scan_start"
  | "scan_pause"
  | "scan_resume"
  | "scan_cancel"
  | "reveal"
  | "rotate_key"
  | "defectdojo_export"
  | "recheck";

export interface AuditEvent {
  id: ID;
  at: ISODate;
  actor: { id: ID; name: string; role: string };
  action: AuditAction;
  resource: string;
  resource_id: ID | null;
  resource_label: string | null;
  summary: string;
  changes: FieldChange[];
}

export interface Settings {
  scan_safety: {
    max_rate_rps: number;
    max_concurrency: number;
    allowed_ports: string;
    excluded_cidrs: string[];
    user_agent: string;
    max_http_requests_per_host: number;
  };
  change_detection: {
    inactive_after_misses: number;
    unstable_retries: number;
    change_confidence_threshold: number;
    recheck_interval_minutes: number;
  };
  retention: { scans_days: number; audit_days: number };
  default_window: ScanWindow;
}

export interface EncryptionStatus {
  enabled: boolean;
  algorithm: string;
  provider: string;
  key_id: string;
  key_created_at: ISODate;
  rotated_at: ISODate;
  encrypted_fields: { table: string; column: string; description: string }[];
  last_check_at: ISODate;
  /** Key being rotated out (ASI_DATA_KEY_PREVIOUS); null when none is configured. */
  previous_key_id?: string | null;
  /** Rows still encrypted with the previous key; null until counted. */
  rows_under_previous_key?: number | null;
  rotation?: EncryptionRotation;
}

export interface EncryptionRotation {
  state: "idle" | "counting" | "rotating" | "done" | "failed";
  started_at: ISODate | null;
  finished_at: ISODate | null;
  remaining_previous: number | null;
  rotated: number;
  /** Rows neither key decrypts. */
  unreadable: number;
  /** `unreadable` comes from a sample (no previous key configured). */
  sampled: boolean;
  error: string | null;
}

export interface TagStat {
  name: string;
  count: number;
}

export interface SearchResult {
  hosts: { id: ID; ip: string; hostname: string | null }[];
  targets: { id: ID; value: string; name: string | null }[];
  findings: { id: ID; title: string; ip: string }[];
}

/** GET /api/v1/_meta — answered by the Next.js dispatcher itself. */
export interface ApiMeta {
  mode: "mock" | "proxy" | "hybrid";
  upstream: string | null;
  version: string;
}
