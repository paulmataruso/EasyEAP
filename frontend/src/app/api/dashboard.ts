// Tenant dashboard (GET /api/tenants/:tid/dashboard) and the MSP overview (GET /api/overview).
// Shapes mirror backend/app/routers/dashboard.py and backend/app/posture.py exactly.
import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { qk } from './keys'
import type { AgentStatus, Enforcement, QueueItem, Severity, Tenant, TenantHealth } from './types'
import type { AuthEvent } from './events'

export interface HourBucket { /** Start of the hour (UTC ISO). The last bucket is the current, partial hour. */ hour: string; accept: number; reject: number }
export interface FailureReason { reason_code: string | null; count: number; title: string }
export interface VlanUsage { vlan_id: number; name: string | null; count: number }
export interface ExpiringCert { id: string; common_name: string; serial: string; not_after: string; identity: { id: string; display_name: string } | null }

export interface DashboardServices {
  radius_agent: AgentStatus | null
  snapshot: { built_at: string | null; age_seconds: number | null; max_age_seconds: number; applied: boolean }
  issuing_ca: { common_name: string; not_after: string } | null
}

export interface DashboardResponse {
  enforcement: Enforcement
  queue: QueueItem[]
  tenant: Tenant
  generated_at: string
  health: TenantHealth
  hourly: HourBucket[]
  failure_reasons: FailureReason[]
  vlan_usage: VlanUsage[]
  expiring: ExpiringCert[]
  recent_events: AuthEvent[]
  services: DashboardServices
}

export interface OverviewTenant extends Tenant {
  health: TenantHealth
  enforcement: Enforcement
  queue_top: QueueItem[]
  queue_count: number
}

export interface OverviewResponse {
  tenants: OverviewTenant[]
  totals: { tenants: number; accept_24h: number; reject_24h: number; active_certificates: number; expiring_certificates: number; critical_issues: number }
  radius_agent: AgentStatus | null
  generated_at: string
}

export function useDashboard(tid: string) {
  return useQuery({
    queryKey: qk.dashboard(tid),
    queryFn: ({ signal }) => api.get<DashboardResponse>(`/api/tenants/${tid}/dashboard`, signal),
    refetchInterval: 30_000,
    staleTime: 10_000,
  })
}

export function useOverview(opts: { refetch?: boolean } = {}) {
  return useQuery({
    queryKey: qk.overview(),
    queryFn: ({ signal }) => api.get<OverviewResponse>('/api/overview', signal),
    refetchInterval: opts.refetch === false ? false : 30_000,
    staleTime: 10_000,
  })
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 }

/** Comparable rank of a queue item, matching backend ordering: severity, then soonest impact, then most affected. */
export function queueRank(item: QueueItem | undefined): [number, number, number] {
  if (!item) return [9, Number.MAX_SAFE_INTEGER, 0]
  return [SEVERITY_RANK[item.severity], item.impact_at ? new Date(item.impact_at).getTime() : Number.MAX_SAFE_INTEGER, -item.affected]
}

export function compareRank(a: [number, number, number], b: [number, number, number]): number {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2]
}

/** Backend titles read "1 rejected attempts: …"; fix the singular locally until the API does. */
export function queueTitle(item: QueueItem): string {
  return item.title.replace(/^1 rejected attempts:/, '1 rejected attempt:')
}
