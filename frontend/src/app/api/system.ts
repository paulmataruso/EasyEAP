// Platform system health (GET /api/system/health, platform:read). Shape mirrors backend/app/routers/system.py.
import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { qk } from './keys'

export type ServiceName = 'database' | 'pki' | 'radius' | 'worker' | 'syslog'

export interface HealthCheck {
  service: ServiceName | string
  ok: boolean
  /** What the status dot shows, per service (e.g. Reachable, Ready, Idle, Delivering). Absent from older API versions. */
  tone?: 'valid' | 'warn' | 'crit' | 'neutral'
  label?: string
  detail: string
  /** Heartbeat time for services that report in (radius, worker). Probed services (database, pki) are checked live. */
  last_seen_at?: string | null
}

export interface SystemHealth {
  version: string
  checks: HealthCheck[]
  jobs: { queued: number; failed_24h: number; recent_failed: Array<{ kind: string; error: string; at: string | null }> }
  /** The most recent backup that was downloaded (from the console or `easyeap backup create`). */
  backup: { at: string; file: string; size: number; encrypted: boolean; downloaded_at?: string } | null
}

export function useSystemHealth(enabled = true) {
  return useQuery({
    queryKey: qk.systemHealth(),
    queryFn: ({ signal }) => api.get<SystemHealth>('/api/system/health', signal),
    refetchInterval: 30_000,
    enabled,
  })
}
