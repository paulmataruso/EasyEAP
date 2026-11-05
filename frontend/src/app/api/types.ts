// Core API shapes shared by the shell and every screen. Field names match the backend JSON exactly (snake_case).
// Screen-specific shapes live next to their hooks in src/app/api/<area>.ts.

export type Severity = 'critical' | 'warning' | 'info'

export interface Grant { tenant_id: string; tenant_name: string; role: string; role_label: string }

export interface Me {
  id: string
  email: string
  display_name: string
  platform_role: 'platform_owner' | 'platform_operator' | 'platform_auditor' | null
  platform_role_label: string | null
  mfa_enabled: boolean
  grants: Grant[]
  csrf_token: string
  session_expires_at: string
}

export interface HealthIssue { severity: Severity; code: string; message: string }

export interface TenantHealth {
  auth_24h: { accept: number; reject: number; success_rate: number | null }
  certificates: { active: number; expiring: number }
  users: number
  controllers: number
  directory: { configured: boolean; last_sync_at: string | null; status: 'ok' | 'failed' | null }
  snapshot_built_at: string | null
  pki_ready: boolean
  issues: HealthIssue[]
}

export type TenantStatus = 'setup' | 'active' | 'suspended'

export interface Tenant {
  id: string
  slug: string
  name: string
  domain: string
  status: TenantStatus
  created_at: string | null
}

export interface TenantListItem extends Tenant { health: TenantHealth; roles: string[] }
export interface TenantDetail extends Tenant { health: TenantHealth; permissions: string[] }

export interface EnforcementGap { code: string; message: string; target: ActionTarget }

/** Whether RADIUS can enforce the tenant now and when its local snapshot would fail closed. */
export interface Enforcement {
  enforceable: boolean
  missing: EnforcementGap[]
  snapshot_built_at: string | null
  snapshot_version: number | null
  deadline_at: string | null
  max_snapshot_age_seconds: number
  /** True while the directory is healthy and the worker is running: the snapshot is rebuilt hourly, so the deadline keeps moving. */
  auto_refresh: boolean
  /** What stopped the hourly rebuild, when auto_refresh is false. */
  refresh_blocked_by: 'worker' | 'directory' | null
  /** The snapshot is older than 75 minutes although it should be rebuilt hourly. */
  refresh_overdue: boolean
  directory_fresh: boolean
  worker_alive: boolean
  worker_seen_at: string | null
  agent_online: boolean
  agent_applied_version: number | null
  agent_in_sync: boolean
}

/**
 * Where a needs-action item (or setup gap) sends the user. Screen names, optionally with a filter after a colon:
 * "directory", "radius", "pki", "setup", "system", "tenant", "certificates:expiring", "events:<reason_code>".
 */
export type ActionTarget = string

export interface QueueItem {
  code: string
  severity: Severity
  title: string
  detail: string
  action: { label: string; target: ActionTarget }
  /** People (or devices, for reject groups) affected. */
  affected: number
  /** When users are affected, if known (e.g. fail-closed deadline, certificate expiry). */
  impact_at: string | null
  /** Age of the data behind this item. */
  source_at: string | null
}

export type RadiusState = 'running' | 'idle' | 'starting' | 'stopped'

export const radiusState = (a: Pick<AgentStatus, 'state' | 'radius_running'>): RadiusState => a.state ?? (a.radius_running ? 'running' : 'stopped')

/** Poll quickly while RADIUS is starting for a new tenant, so the console shows "Running" within seconds. */
export const agentPoll = (a: Pick<AgentStatus, 'state' | 'radius_running'> | null | undefined) => (a && radiusState(a) === 'starting' ? 5_000 : 30_000)

export interface AgentStatus {
  agent_id: string
  last_seen_at: string
  config_ok: boolean
  config_error: string | null
  radius_running: boolean
  /**
   * idle: FreeRADIUS is kept stopped because no tenant is active (nothing to serve). starting: a tenant was just
   * activated and the agent hasn't picked it up yet (it polls every 15 seconds). Absent from older API versions.
   */
  state?: RadiusState
  /** Tenants in the configuration the agent last applied. */
  serving?: number | null
  snapshot_versions: Record<string, number>
  config_version: string | number | null
  online: boolean
  detail: Record<string, unknown> | null
}

export interface Page<T> { total: number; page: number; page_size: number; items: T[] }

export type AccessStatus = 'can_connect' | 'allowed_no_certificate' | 'denied'

export interface DecisionStep {
  kind: 'account' | 'certificate' | 'rule' | 'default'
  ok?: boolean
  detail: string
  ruleId?: string
  matched?: boolean
  action?: 'allow' | 'deny'
}

export interface RadiusAttribute { name: string; value: string }

export interface Outcome {
  outcome: 'allow' | 'deny'
  reason_code: string | null
  deciding_rule_id: string | null
  vlan_id: number | null
  attributes: RadiusAttribute[]
  steps: DecisionStep[]
}
