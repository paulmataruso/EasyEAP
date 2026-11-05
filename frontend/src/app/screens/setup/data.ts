// Read-only views of other areas that the setup wizard needs. They use the canonical keys, which cache the raw API
// response, so they share data with the Directory, Access policy and Dashboard screens.
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { qk } from '../../api/keys'
import type { Enforcement } from '../../api/types'

export interface DirectoryLite {
  config: null | {
    enabled: boolean
    domain: string
    hosts: string[]
    last_sync_at: string | null
    last_sync_status: 'ok' | 'failed' | string | null
    last_sync_error: string | null
    last_sync_stats: { users?: number; groups?: number } | null
  }
  group_count: number
}

export interface PolicyLite {
  vlans: Array<{ id: string; vlan_id: number; name: string }>
  rules: Array<{ id: string; name: string; action: 'allow' | 'deny'; enabled: boolean }>
  settings: { default_action: 'allow' | 'deny'; default_vlan_ref: string | null }
}

export function useDirectoryLite(tid: string, enabled: boolean) {
  return useQuery({ queryKey: qk.directory(tid), queryFn: ({ signal }) => api.get<DirectoryLite>(`/api/tenants/${tid}/directory`, signal), enabled })
}

export function usePolicyLite(tid: string, enabled: boolean) {
  return useQuery({ queryKey: qk.policy(tid), queryFn: ({ signal }) => api.get<PolicyLite>(`/api/tenants/${tid}/policy`, signal), enabled })
}

export function useEnforcement(tid: string) {
  return useQuery({ queryKey: qk.dashboard(tid), queryFn: ({ signal }) => api.get<{ enforcement: Enforcement }>(`/api/tenants/${tid}/dashboard`, signal) })
}
