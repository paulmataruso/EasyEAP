// Tenant scope. Every tenant route is /t/:tid/…; the tenant record carries the caller's effective permissions there.
import { createContext, useContext, useMemo, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { qk } from './keys'
import type { TenantDetail, TenantListItem } from './types'

export function useTenantList() {
  return useQuery({ queryKey: qk.tenants(), queryFn: () => api.get<{ tenants: TenantListItem[] }>('/api/tenants').then((r) => r.tenants), staleTime: 30_000 })
}

interface TenantValue {
  tid: string
  tenant: TenantDetail
  /** Permission check, e.g. can('certificates:revoke'). Hide or disable controls the caller can't use. */
  can: (perm: string) => boolean
}

const TenantContext = createContext<TenantValue | null>(null)

export function useTenantQuery(tid: string | undefined) {
  return useQuery({ queryKey: qk.tenant(tid ?? ''), queryFn: () => api.get<TenantDetail>(`/api/tenants/${tid}`), enabled: !!tid, staleTime: 30_000 })
}

export function TenantProvider({ tenant, children }: { tenant: TenantDetail; children: ReactNode }) {
  const value = useMemo(() => {
    const perms = new Set(tenant.permissions)
    return { tid: tenant.id, tenant, can: (p: string) => perms.has(p) }
  }, [tenant])
  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>
}

/** Current tenant. Only valid inside /t/:tid routes. */
export function useTenant() {
  const ctx = useContext(TenantContext)
  if (!ctx) throw new Error('useTenant() outside a tenant route')
  return ctx
}

export const useOptionalTenant = () => useContext(TenantContext)
