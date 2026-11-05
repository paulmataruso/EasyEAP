// RADIUS settings, server certificate, wireless controllers (NAS clients), vendor guides and the CoA queue.
// Shapes mirror backend/app/routers/radius.py exactly. Shared secrets are returned once by create/rotate and are never
// written to the query cache: callers keep them in component state and drop them when the dialog closes.
import { useCallback } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './client'
import { useOneTimeCall } from './oneTime'
import { qk } from './keys'
import type { AgentStatus } from './types'

export const VENDORS = ['cisco-9800', 'cisco-aireos', 'unifi', 'other'] as const
export type Vendor = (typeof VENDORS)[number]
export const vendorLabels: Record<string, string> = {
  'cisco-9800': 'Cisco Catalyst 9800',
  'cisco-aireos': 'Cisco AireOS WLC',
  unifi: 'UniFi Network',
  other: 'Other controller',
}
/** CoA port the backend assigns when none is given (radius.py create_client). */
export const defaultCoaPort = (v: string) => (v === 'cisco-9800' ? 1700 : 3799)

export interface ServerCertificate { id: string; serial: string; common_name: string; not_after: string; fingerprint_sha256: string }

export interface RadiusSettings {
  server_hostname: string
  ssid: string
  wpa3: boolean
  auth_port: number
  acct_port: number
  dedicated_ports: boolean
  tls_min_version: '1.2' | '1.3' | string
  tls_session_cache: boolean
  session_timeout_seconds: number
  server_certificate: ServerCertificate | null
  snapshot_version: number | null
  snapshot_built_at: string | null
  /** Address controllers use to reach RADIUS (EASYEAP_RADIUS_ADDRESS in the deploy .env); empty when unset or unusable. */
  radius_address: string
  /** Why a configured address was withheld (loopback, unspecified); null when there's nothing wrong. */
  radius_address_problem: string | null
}

export interface RadiusClient {
  id: string
  name: string
  vendor: string
  address: string
  site: string
  coa_enabled: boolean
  coa_port: number | null
  secret_set_at: string | null
  last_request_at: string | null
}

export interface RadiusAgent extends AgentStatus {
  /** Present only once this tenant has RADIUS settings. */
  tenant_snapshot_applied?: number | null
  tenant_in_sync?: boolean
}

/** Recent requests that couldn't be tied to a registered controller (their source and NAS address are in no range). */
export interface Unattributed { count: number; last_at: string; nas_addresses: string[]; days: number }
export interface RadiusResponse { settings: RadiusSettings | null; clients: RadiusClient[]; agent: RadiusAgent | null; unattributed: Unattributed | null }

export interface SettingsIn {
  server_hostname: string
  ssid: string
  wpa3: boolean
  dedicated_ports: boolean
  auth_port: number
  acct_port: number
  tls_min_version: string
  tls_session_cache: boolean
  session_timeout_seconds: number
}

export interface ClientIn { name: string; vendor: string; address: string; site: string; coa_enabled: boolean; coa_port: number | null }

export interface Guide { vendor: string; title: string; cli: string | null; steps: string[]; checks: string[]; coa_port: number }

export interface CoaRequest {
  id: string
  kind: string
  attributes: Record<string, string>
  reason: string | null
  status: string
  result_detail: string | null
  created_at: string | null
  completed_at: string | null
  nas_client_id: string
}

const base = (tid: string) => `/api/tenants/${tid}/radius`
export const guideKey = (tid: string, vendor: string) => [...qk.radius(tid), 'guide', vendor] as const
export const coaKey = (tid: string) => [...qk.radius(tid), 'coa'] as const

export function useRadius(tid: string) {
  return useQuery({ queryKey: qk.radius(tid), queryFn: ({ signal }) => api.get<RadiusResponse>(base(tid), signal), refetchInterval: 30_000 })
}

export function useGuide(tid: string, vendor: string | null, enabled = true) {
  return useQuery({
    queryKey: guideKey(tid, vendor ?? ''),
    queryFn: ({ signal }) => api.get<Guide>(`${base(tid)}/guide/${vendor}`, signal),
    enabled: enabled && !!vendor,
    staleTime: 60_000,
  })
}

export function useCoa(tid: string, enabled = true) {
  return useQuery({ queryKey: coaKey(tid), queryFn: ({ signal }) => api.get<{ items: CoaRequest[] }>(`${base(tid)}/coa`, signal), enabled, refetchInterval: 30_000 })
}

/** Invalidate everything a RADIUS change can affect: the RADIUS view, guides, dashboard posture and the tenant health. */
function useInvalidateRadius(tid: string) {
  const qc = useQueryClient()
  return () => Promise.all([
    qc.invalidateQueries({ queryKey: qk.radius(tid) }),
    qc.invalidateQueries({ queryKey: qk.dashboard(tid) }),
    qc.invalidateQueries({ queryKey: qk.tenant(tid) }),
    qc.invalidateQueries({ queryKey: qk.tenants() }),
  ])
}

export function useSaveSettings(tid: string) {
  const inv = useInvalidateRadius(tid)
  return useMutation({ mutationFn: (body: SettingsIn) => api.put<{ settings: RadiusSettings }>(base(tid), body), onSuccess: inv })
}

export function useRotateServerCert(tid: string) {
  const inv = useInvalidateRadius(tid)
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post<{ settings: RadiusSettings }>(`${base(tid)}/server-certificate/rotate`),
    onSuccess: () => Promise.all([inv(), qc.invalidateQueries({ queryKey: ['t', tid, 'certificates'] })]),
  })
}

/** Returns the shared secret once: kept out of the mutation cache (see oneTime.ts). */
export function useCreateClient(tid: string) {
  const inv = useInvalidateRadius(tid)
  const fn = useCallback((body: ClientIn) => api.post<{ client: RadiusClient; shared_secret: string }>(`${base(tid)}/clients`, body), [tid])
  return useOneTimeCall(fn, inv)
}

export function useUpdateClient(tid: string) {
  const inv = useInvalidateRadius(tid)
  return useMutation({ mutationFn: ({ id, body }: { id: string; body: ClientIn }) => api.put<{ client: RadiusClient }>(`${base(tid)}/clients/${id}`, body), onSuccess: inv })
}

/** Returns the new shared secret once: kept out of the mutation cache (see oneTime.ts). */
export function useRotateSecret(tid: string) {
  const inv = useInvalidateRadius(tid)
  const fn = useCallback((id: string) => api.post<{ client: RadiusClient; shared_secret: string }>(`${base(tid)}/clients/${id}/rotate-secret`), [tid])
  return useOneTimeCall(fn, inv)
}

export function useDeleteClient(tid: string) {
  const inv = useInvalidateRadius(tid)
  return useMutation({ mutationFn: (id: string) => api.del<{ ok: boolean }>(`${base(tid)}/clients/${id}`), onSuccess: inv })
}

// ── Guide filling ───────────────────────────────────────────────────────
// The guide API fills the tenant's real values but keeps placeholders for the shared secret (never re-displayed) and,
// when the server has no public RADIUS address configured, for the address. Values here are filled in memory only.
export const SECRET_PLACEHOLDER = '<shared-secret-you-saved>'
export const ADDRESS_PLACEHOLDER = '<easyeap-radius-ip>'
/** Controller-local values the administrator chooses on the controller itself. */
export const LOCAL_PLACEHOLDERS = { wlanId: '<wlan-id>', policyProfile: '<policy-profile>', defaultVlan: '<default-vlan>' } as const

export interface FillValues { secret?: string | null; address?: string | null; wlanId?: string; policyProfile?: string; defaultVlan?: string }

export function fillText(text: string, v: FillValues): string {
  let out = text
  if (v.secret) out = out.split(SECRET_PLACEHOLDER).join(v.secret)
  if (v.address) out = out.split(ADDRESS_PLACEHOLDER).join(v.address)
  if (v.wlanId) out = out.split(LOCAL_PLACEHOLDERS.wlanId).join(v.wlanId)
  if (v.policyProfile) out = out.split(LOCAL_PLACEHOLDERS.policyProfile).join(v.policyProfile)
  if (v.defaultVlan) out = out.split(LOCAL_PLACEHOLDERS.defaultVlan).join(v.defaultVlan)
  // Prose steps refer to the secret in words ("the secret you saved"); with the secret in hand, say it.
  if (v.secret) {
    out = out.replace('shared secret = the secret you saved', `shared secret ${v.secret}`)
    out = out.replace('with the shared secret.', `with the shared secret ${v.secret}.`)
  }
  return out
}

/** Placeholders still present in a text after filling. */
export const remainingPlaceholders = (text: string) => [...new Set(text.match(/<[a-z][a-z0-9-]*>/g) ?? [])]
