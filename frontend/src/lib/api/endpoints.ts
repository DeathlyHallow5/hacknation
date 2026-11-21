/**
 * Typed functions for every endpoint of the contract (see README.md).
 * Paths are relative to /api/v1.
 */
import { request, requestFile } from "@/lib/api/client";
import type * as T from "@/lib/api/types";

type Q = Record<string, unknown>;

export const api = {
  meta: () => request<T.ApiMeta>("/_meta"),

  auth: {
    login: (body: T.LoginRequest) => request<T.Session>("/auth/login", { method: "POST", body }),
    logout: () => request<void>("/auth/logout", { method: "POST" }),
    me: () => request<T.Session>("/auth/me"),
  },

  dashboard: {
    summary: () => request<T.DashboardSummary>("/dashboard/summary"),
    topFindings: (query?: Q) => request<T.Finding[]>("/dashboard/top-findings", { query }),
    changesTimeline: (query?: Q) => request<T.ChangesTimelinePoint[]>("/dashboard/changes-timeline", { query }),
    availability: () => request<T.AvailabilityHeatmap>("/dashboard/availability"),
    technologies: (query?: Q) => request<T.TechStat[]>("/dashboard/technologies", { query }),
    addressMap: (cidr: string) => request<T.AddressMap>("/dashboard/address-map", { query: { cidr } }),
  },

  search: (q: string) => request<T.SearchResult>("/search", { query: { q } }),
  tags: () => request<T.TagStat[]>("/tags"),

  targets: {
    list: (query?: Q) => request<T.Paginated<T.Target>>("/targets", { query }),
    get: (id: string) => request<T.Target>(`/targets/${id}`),
    create: (body: T.TargetCreateRequest) => request<T.TargetCreateResult>("/targets", { method: "POST", body }),
    update: (id: string, body: T.TargetPatch) => request<T.Target>(`/targets/${id}`, { method: "PATCH", body }),
    remove: (id: string) => request<void>(`/targets/${id}`, { method: "DELETE" }),
    bulk: (body: T.BulkRequest<"tag" | "untag" | "exclude" | "include" | "delete" | "set_owner" | "set_criticality">) =>
      request<T.BulkResult>("/targets/bulk", { method: "POST", body }),
    import: (form: FormData) => request<T.ImportReport>("/targets/import", { method: "POST", body: form }),
    export: (query?: Q) => requestFile("/targets/export", query),
  },

  scans: {
    list: (query?: Q) => request<T.Paginated<T.ScanRun>>("/scans", { query }),
    get: (id: string) => request<T.ScanRun>(`/scans/${id}`),
    create: (body: T.ScanCreateRequest) => request<T.ScanRun>("/scans", { method: "POST", body }),
    update: (id: string, body: T.ScanPatch) => request<T.ScanRun>(`/scans/${id}`, { method: "PATCH", body }),
    remove: (id: string) => request<void>(`/scans/${id}`, { method: "DELETE" }),
    pause: (id: string) => request<T.ScanRun>(`/scans/${id}/pause`, { method: "POST" }),
    resume: (id: string) => request<T.ScanRun>(`/scans/${id}/resume`, { method: "POST" }),
    cancel: (id: string) => request<T.ScanRun>(`/scans/${id}/cancel`, { method: "POST" }),
    batches: (id: string) => request<T.ScanBatch[]>(`/scans/${id}/batches`),
    logs: (id: string) => request<T.ScanLogLine[]>(`/scans/${id}/logs`),
    estimate: (body: T.ScanEstimateRequest) => request<T.ScanEstimate>("/scans/estimate", { method: "POST", body }),
    import: (form: FormData) => request<T.ScanRun>("/scans/import", { method: "POST", body: form }),
    export: (id: string, format: "json" | "csv") => requestFile(`/scans/${id}/export`, { format }),
    eventsUrl: (id: string) => `/api/v1/scans/${id}/events`,
  },

  profiles: {
    list: () => request<T.ScanProfile[]>("/profiles"),
    create: (body: T.ScanProfileInput) => request<T.ScanProfile>("/profiles", { method: "POST", body }),
    update: (id: string, body: Partial<T.ScanProfileInput>) =>
      request<T.ScanProfile>(`/profiles/${id}`, { method: "PATCH", body }),
    remove: (id: string) => request<void>(`/profiles/${id}`, { method: "DELETE" }),
  },

  schedules: {
    list: () => request<T.Schedule[]>("/schedules"),
    create: (body: T.ScheduleInput) => request<T.Schedule>("/schedules", { method: "POST", body }),
    update: (id: string, body: Partial<T.ScheduleInput>) =>
      request<T.Schedule>(`/schedules/${id}`, { method: "PATCH", body }),
    remove: (id: string) => request<void>(`/schedules/${id}`, { method: "DELETE" }),
  },

  hosts: {
    list: (query?: Q) => request<T.Paginated<T.HostSummary>>("/hosts", { query }),
    get: (id: string) => request<T.Host>(`/hosts/${id}`),
    update: (id: string, body: T.HostPatch) => request<T.Host>(`/hosts/${id}`, { method: "PATCH", body }),
    revert: (id: string, field: string) =>
      request<T.Host>(`/hosts/${id}/overrides/${field}`, { method: "DELETE" }),
    history: (id: string) => request<T.HostHistoryEntry[]>(`/hosts/${id}/history`),
    recheck: (id: string) => request<{ queued: boolean }>(`/hosts/${id}/recheck`, { method: "POST" }),
    unstable: () => request<T.UnstableHost[]>("/hosts/unstable"),
    revealCookie: (serviceId: string, name: string) =>
      request<{ value: string }>(`/services/${serviceId}/cookies/${encodeURIComponent(name)}/reveal`, {
        method: "POST",
      }),
  },

  services: {
    list: (query?: Q) => request<T.Paginated<T.ServiceSummary>>("/services", { query }),
    get: (id: string) => request<T.Service>(`/services/${id}`),
    update: (id: string, body: T.ServicePatch) => request<T.Service>(`/services/${id}`, { method: "PATCH", body }),
    groups: (query?: Q) => request<T.ServiceGroup[]>("/service-groups", { query }),
  },

  findings: {
    list: (query?: Q) => request<T.Paginated<T.Finding>>("/findings", { query }),
    get: (id: string) => request<T.Finding>(`/findings/${id}`),
    update: (id: string, body: T.FindingPatch) => request<T.Finding>(`/findings/${id}`, { method: "PATCH", body }),
    bulk: (body: T.BulkRequest<"set_status" | "tag" | "untag" | "assign">) =>
      request<T.BulkResult>("/findings/bulk", { method: "POST", body }),
    export: (query?: Q) => requestFile("/findings/export", query),
    defectdojo: (body: T.DefectDojoExportRequest) =>
      request<T.DefectDojoExportResult>("/findings/defectdojo", { method: "POST", body }),
  },

  diffs: {
    get: (query: Q) => request<T.DiffResponse>("/diffs", { query }),
  },

  signatures: {
    list: (query?: Q) => request<T.Signature[]>("/signatures", { query }),
    get: (id: string) => request<T.Signature>(`/signatures/${id}`),
    create: (body: T.SignatureInput) => request<T.Signature>("/signatures", { method: "POST", body }),
    update: (id: string, body: Partial<T.SignatureInput>) =>
      request<T.Signature>(`/signatures/${id}`, { method: "PATCH", body }),
    remove: (id: string) => request<void>(`/signatures/${id}`, { method: "DELETE" }),
    test: (body: T.SignatureTestRequest) =>
      request<T.SignatureTestResult>("/signatures/test", { method: "POST", body }),
    import: (form: FormData) =>
      request<{ created: number; updated: number; errors: string[] }>("/signatures/import", {
        method: "POST",
        body: form,
      }),
    export: (format: "yaml" | "json") => requestFile("/signatures/export", { format }),
  },

  users: {
    list: () => request<T.User[]>("/users"),
    create: (body: { login: string; name: string; email: string; role_id: string; password: string }) =>
      request<T.User>("/users", { method: "POST", body }),
    update: (id: string, body: Partial<Pick<T.User, "name" | "email" | "role_id" | "active">>) =>
      request<T.User>(`/users/${id}`, { method: "PATCH", body }),
    remove: (id: string) => request<void>(`/users/${id}`, { method: "DELETE" }),
  },

  roles: {
    list: () => request<T.Role[]>("/roles"),
    create: (body: Pick<T.Role, "name" | "description" | "permissions">) =>
      request<T.Role>("/roles", { method: "POST", body }),
    update: (id: string, body: Partial<Pick<T.Role, "name" | "description" | "permissions">>) =>
      request<T.Role>(`/roles/${id}`, { method: "PATCH", body }),
    remove: (id: string) => request<void>(`/roles/${id}`, { method: "DELETE" }),
    permissions: () => request<T.Permission[]>("/permissions"),
  },

  integrations: {
    defectdojo: () => request<T.DefectDojoConfig>("/integrations/defectdojo"),
    saveDefectdojo: (body: T.DefectDojoConfigInput) =>
      request<T.DefectDojoConfig>("/integrations/defectdojo", { method: "PUT", body }),
    testDefectdojo: () => request<T.DefectDojoConfig>("/integrations/defectdojo/test", { method: "POST" }),
    exports: () => request<T.DefectDojoExport[]>("/integrations/defectdojo/exports"),
    engines: () => request<T.Engine[]>("/engines"),
  },

  audit: {
    list: (query?: Q) => request<T.Paginated<T.AuditEvent>>("/audit", { query }),
  },

  settings: {
    get: () => request<T.Settings>("/settings"),
    update: (body: Partial<T.Settings>) => request<T.Settings>("/settings", { method: "PATCH", body }),
    encryption: () => request<T.EncryptionStatus>("/security/encryption"),
    rotateKey: () => request<T.EncryptionStatus>("/security/encryption/rotate", { method: "POST" }),
  },
};
