// Governance: the hash-chained audit log (tenant and platform) and administrator accounts.
// Shapes match backend/app/routers/events.py (audit) and backend/app/routers/admins.py.
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { api, qs } from './client'
import { qk } from './keys'

export interface AuditEvent {
  id: number
  tenant_id: string | null
  at: string
  actor_type: 'admin' | 'system' | 'enrollee' | 'agent' | string
  actor: string
  action: string
  target_type: string
  target_id: string | null
  target: string
  detail: Record<string, unknown>
  ip: string | null
}

export interface AuditPage { items: AuditEvent[]; next_before_id: number | null }
export interface VerifyResult {
  ok: boolean
  /** Set only when the break is visible to the caller (always on the platform view; in the tenant view only if it's in this tenant). */
  first_bad_id: number | null
  checked: number
  /** Tenant view only. */
  tenant_entries?: number
  break_in_this_tenant?: boolean
}

export const AUDIT_PAGE_SIZE = 50

export function useAudit(scope: 'tenant' | 'platform', tid: string | null, q: string, enabled = true) {
  const key = scope === 'tenant' ? qk.tenantAudit(tid ?? '', { q }) : qk.audit({ q })
  const path = scope === 'tenant' ? `/api/tenants/${tid}/audit` : '/api/audit'
  return useInfiniteQuery({
    // Pages, not the raw response: keep it apart from any plain query on the canonical key.
    queryKey: [...key, 'pages'],
    queryFn: ({ pageParam, signal }) => api.get<AuditPage>(`${path}${qs({ q, before_id: pageParam ?? undefined, page_size: AUDIT_PAGE_SIZE })}`, signal),
    initialPageParam: null as number | null,
    getNextPageParam: (last) => last.next_before_id,
    enabled: enabled && (scope === 'platform' || !!tid),
  })
}

export const verifyAudit = (tid: string | null) => api.post<VerifyResult>(tid ? `/api/tenants/${tid}/audit/verify` : '/api/audit/verify')

// ── Administrators ──────────────────────────────────────────────────────

export type PlatformRole = 'platform_owner' | 'platform_operator' | 'platform_auditor'
export interface AdminGrant { tenant_id: string; role: string }

export interface Admin {
  id: string
  email: string
  display_name: string
  platform_role: PlatformRole | null
  is_active: boolean
  mfa_enabled: boolean
  last_login_at: string | null
  grants: AdminGrant[]
}

export interface RoleOption { id: string; label: string }
export interface AdminsResponse { admins: Admin[]; roles: { platform: RoleOption[]; tenant: RoleOption[] } }

export interface AdminCreate { email: string; display_name: string; password: string; platform_role: string | null; grants: AdminGrant[] }
export interface AdminPatch { display_name?: string; platform_role?: string; clear_platform_role?: boolean; is_active?: boolean; grants?: AdminGrant[] }

export function useAdmins(enabled: boolean) {
  return useQuery({ queryKey: qk.admins(), queryFn: ({ signal }) => api.get<AdminsResponse>('/api/admins', signal), enabled })
}

export const adminsApi = {
  create: (body: AdminCreate) => api.post<Admin>('/api/admins', body),
  update: (id: string, body: AdminPatch) => api.patch<Admin>(`/api/admins/${id}`, body),
  remove: (id: string) => api.del<{ ok: true }>(`/api/admins/${id}`),
  /** Turn off another administrator's two-factor (lost authenticator); ends their sessions. */
  resetMfa: (id: string) => api.post<Admin>(`/api/admins/${id}/reset-mfa`),
}
