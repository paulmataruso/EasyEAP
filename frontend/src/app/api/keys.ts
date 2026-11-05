// Canonical react-query keys. A key always caches the *raw* API response for that URL, so screens and the shell can
// share it. Invalidate with the prefix (e.g. qk.tenantScope(tid)) after mutations that touch several areas.
export const qk = {
  me: () => ['me'] as const,
  tenants: () => ['tenants'] as const,
  overview: () => ['overview'] as const,
  tenantScope: (tid: string) => ['t', tid] as const,
  tenant: (tid: string) => ['t', tid, 'tenant'] as const,
  dashboard: (tid: string) => ['t', tid, 'dashboard'] as const,
  identities: (tid: string, params: object = {}) => ['t', tid, 'identities', params] as const,
  identity: (tid: string, id: string) => ['t', tid, 'identity', id] as const,
  certificates: (tid: string, params: object = {}) => ['t', tid, 'certificates', params] as const,
  certificate: (tid: string, id: string) => ['t', tid, 'certificate', id] as const,
  enrollments: (tid: string, params: object = {}) => ['t', tid, 'enrollments', params] as const,
  /** GET /api/tenants/:tid/policy (raw) */
  policy: (tid: string) => ['t', tid, 'policy'] as const,
  /** GET /api/tenants/:tid/radius (raw) */
  radius: (tid: string) => ['t', tid, 'radius'] as const,
  directory: (tid: string) => ['t', tid, 'directory'] as const,
  directoryGroups: (tid: string) => ['t', tid, 'directory', 'groups'] as const,
  pki: (tid: string) => ['t', tid, 'pki'] as const,
  events: (tid: string, params: object = {}) => ['t', tid, 'events', params] as const,
  sessions: (tid: string) => ['t', tid, 'sessions'] as const,
  tenantAudit: (tid: string, params: object = {}) => ['t', tid, 'audit', params] as const,
  audit: (params: object = {}) => ['audit', params] as const,
  admins: () => ['admins'] as const,
  systemHealth: () => ['system-health'] as const,
}
