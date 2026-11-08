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

export interface TenantListItem extends Tenant {
  health: TenantHealth
  roles: string[]
  /** The dashboard's enforcement status and its top needs-action item (absent from older API versions). */
  posture?: { status: EnforcementStatus; top: { code: string; severity: Severity; title: string } | null; count: number }
}
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
  /** FreeRADIUS process state as the agent last reported it (null: never reported). */
  radius_state: RadiusState | null
  config_ok: boolean | null
  /** Whether the configuration RADIUS is running includes this tenant; null when the agent doesn't say. */
  served: boolean | null
  /** The snapshot is past its maximum age: RADIUS denies everyone. */
  snapshot_expired: boolean
  agent_applied_version: number | null
  agent_in_sync: boolean
  /** The latest snapshot is under two minutes old: "not applied yet" is expected, not a fault. */
  applying: boolean
  /** The one answer every chip, panel and list shows. */
  status: EnforcementStatus
}

export type EnforcementState = 'suspended' | 'setup' | 'radius_offline' | 'radius_config' | 'radius_stopped' | 'starting' | 'no_snapshot'
  | 'expired' | 'not_served' | 'at_risk' | 'applying' | 'pending' | 'overdue' | 'enforcing'
export interface EnforcementStatus { state: EnforcementState; tone: 'valid' | 'warn' | 'crit' | 'neutral'; label: string; detail: string }

/**
 * Where a needs-action item (or setup gap) sends the user. Screen names, optionally with a filter after a colon:
 * "directory", "radius", "pki", "setup", "system", "tenant", "certificates:<status>", "certificate:<id>", "audit",
 * "events:<reason_code>".
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
/** The parts of an overview tenant that status helpers read. */
export interface OverviewTenantLite { status: Tenant['status']; enforcement: Enforcement }

/** One summary of the RADIUS service for chips and status lines (System health, Tenants). */
export function radiusSummary(a: AgentStatus | null | undefined): { tone: 'valid' | 'neutral' | 'crit'; label: string; short: string } {
  if (!a) return { tone: 'crit', label: 'RADIUS agent has never reported', short: 'Never reported' }
  if (!a.online) return { tone: 'crit', label: 'RADIUS agent not reporting', short: 'Not reporting' }
  if (a.config_ok === false) return { tone: 'crit', label: 'RADIUS rejected its configuration', short: 'Configuration rejected' }
  const state = radiusState(a)
  if (state === 'stopped') return { tone: 'crit', label: 'FreeRADIUS stopped', short: 'Stopped' }
  if (state === 'idle') return { tone: 'neutral', label: 'RADIUS idle: no active tenants yet', short: 'Idle' }
  if (state === 'starting') return { tone: 'neutral', label: 'RADIUS starting', short: 'Starting' }
  return { tone: 'valid', label: 'RADIUS running', short: 'Running' }
}

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
  /** Their IDs (absent from agents that don't report them). */
  serving_ids?: string[] | null
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

/** Whether RADIUS has this tenant's latest snapshot and can use it: not only the version number, but also whether the
 * agent is reporting, FreeRADIUS is running, the snapshot is unexpired and the running configuration includes the tenant. */
export function snapshotState(t: OverviewTenantLite): { tone: 'valid' | 'warn' | 'crit' | 'neutral'; label: string } {
  const e = t.enforcement
  if (t.status !== 'active') return { tone: 'neutral', label: t.status === 'suspended' ? 'Not served: suspended' : 'Not served: setup' }
  if (!e.snapshot_version) return { tone: 'crit', label: 'No snapshot yet' }
  if (e.snapshot_expired) return { tone: 'crit', label: 'Expired: denying everyone' }
  if (e.served === false && !e.applying) return { tone: 'crit', label: 'Not in RADIUS configuration' }
  if (!e.agent_in_sync || e.served === false) {
    if (e.applying) return { tone: 'neutral', label: 'Applying' }
    return { tone: 'warn', label: e.agent_applied_version ? 'Older version' : 'Not loaded' }
  }
  if (!e.agent_online || e.radius_state !== 'running') return { tone: 'neutral', label: 'Applied (RADIUS not running)' }
  return { tone: 'valid', label: 'Applied' }
}
