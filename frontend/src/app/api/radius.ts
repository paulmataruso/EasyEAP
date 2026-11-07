// RADIUS settings, server certificate, wireless controllers and switches (NAS clients), vendor guides, wired 802.1X
// (port plans, Enforce, readiness) and the CoA queue.
// Shapes mirror backend/app/routers/radius.py exactly. Shared secrets are returned once by create/rotate and are never
// written to the query cache: callers keep them in component state and drop them when the dialog closes.
import { useCallback } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './client'
import { useOneTimeCall } from './oneTime'
import { qk } from './keys'
import { agentPoll, type AgentStatus } from './types'

/** Wireless controller types (Add controller). Switches are added with Add switch (SWITCH_VENDORS). */
export const VENDORS = ['cisco-9800', 'cisco-aireos', 'unifi', 'other'] as const
export type Vendor = (typeof VENDORS)[number] | 'cisco-switch'
export const SWITCH_VENDORS = ['cisco-switch', 'unifi', 'other'] as const
export const vendorLabels: Record<string, string> = {
  'cisco-9800': 'Cisco Catalyst 9800',
  'cisco-aireos': 'Cisco AireOS WLC',
  'cisco-switch': 'Cisco Catalyst switch',
  unifi: 'UniFi Network',
  other: 'Other',
}
export const switchVendorLabels: Record<string, string> = {
  'cisco-switch': 'Cisco Catalyst (IOS / IOS-XE)',
  unifi: 'UniFi switches',
  other: 'Other switch',
}
/** CoA port the backend assigns when none is given (radius.py create_client). */
export const defaultCoaPort = (v: string) => (v === 'cisco-9800' || v === 'cisco-switch' ? 1700 : 3799)

export type Network = 'wireless' | 'wired'
export const networkLabels: Record<Network, string> = { wireless: 'Wi-Fi', wired: 'Wired' }

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
  /** Include wired 802.1X settings in enrollment packages. */
  wired_enabled: boolean
}

/** A switch's port plan (backend app/radius/wired.py WiredProfile). No secrets. */
export interface WiredProfile {
  platform: 'ibns2' | 'classic'
  mode: 'monitor' | 'enforce'
  interfaces: string
  exclude: string
  has_aaa: boolean
  host_mode: 'multi-auth' | 'single-host' | 'multi-host'
  no_supplicant: 'block' | 'vlan'
  no_supplicant_vlan: number | null
  server_down: 'wait' | 'open' | 'vlan'
  server_down_vlan: number | null
  access_vlan: number | null
  source_interface: string
  vrf: string
  fallback_vlan: number | null
  /** MAC authentication for devices without 802.1X (Cisco Catalyst and UniFi). Set when the switch is added, then
   * changed only with its own change (POST …/mab) in monitor mode. */
  mab?: boolean
  mode_set_at?: string | null
  mode_set_by?: string | null
  /** IBNS 2.0: the control policy EasyEAP's latest change attached, and the one it replaced. */
  policy?: string | null
  policy_prev?: string | null
  last_change?: 'created' | 'mab' | 'enforce' | 'monitor' | null
}

export const defaultWiredProfile: WiredProfile = {
  platform: 'ibns2', mode: 'monitor', interfaces: '', exclude: '', has_aaa: false, host_mode: 'multi-auth', no_supplicant: 'block',
  no_supplicant_vlan: null, server_down: 'wait', server_down_vlan: null, access_vlan: null, source_interface: '', vrf: '', fallback_vlan: null, mab: false,
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
  /** What it may authenticate. */
  networks: Network[]
  wired_profile: WiredProfile | null
  /** Rollout mode EasyEAP was told (it can't read the switch); null when not registered for wired. Clients from
   * before wired 802.1X have no port plan and are "enforce": EasyEAP sends VLANs on wired requests as it always did. */
  wired_mode: 'monitor' | 'enforce' | null
}

/** A switch or controller registered for wired 802.1X. */
export const isSwitch = (c: RadiusClient) => c.vendor === 'cisco-switch' || (c.networks.includes('wired') && !!c.wired_profile)

export interface RadiusAgent extends AgentStatus {
  /** Present only once this tenant has RADIUS settings. */
  tenant_snapshot_applied?: number | null
  tenant_in_sync?: boolean
  /** FreeRADIUS runs this tenant's latest configuration change. null: the agent is older and doesn't say. */
  tenant_config_in_sync?: boolean | null
  /** RADIUS runs the latest MAC allow list. null: the agent is older and doesn't say. */
  tenant_mac_in_sync?: boolean | null
  /** What the RADIUS agents in the last 10 minutes support, e.g. "mab". Older agents report none. */
  features?: string[]
}

/** RADIUS answers MAC authentication (an agent from before it refuses every MAC request). */
export const supportsMab = (a: RadiusAgent | null | undefined) => !!a?.features?.includes('mab')
/** Switches that can admit devices by MAC address. */
export const MAB_VENDORS = ['cisco-switch', 'unifi']

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
  wired_enabled?: boolean
}

export interface ClientIn {
  name: string; vendor: string; address: string; site: string; coa_enabled: boolean; coa_port: number | null
  networks?: Network[]
  wired_profile?: Partial<WiredProfile> | null
}

export interface Guide { vendor: string; title: string; cli: string | null; steps: string[]; checks: string[]; coa_port: number }

export interface PreflightCheck { command: string; look_for: string }
/** GET /clients/{id}/wired-guide (and the guide returned by a mode change). */
export interface WiredGuide extends Guide {
  kind: 'wired'
  mode: 'monitor' | 'enforce'
  preflight: PreflightCheck[]
  safe_paste: string[]
  enforce_cli?: string
  monitor_cli?: string
  enforce_steps?: string[]
  monitor_steps?: string[]
  session_command: string | null
  radius_address: string | null
  mab?: boolean
  /** Cisco: the change that turns MAC authentication on or off, shown after that change (monitor mode). */
  mab_cli?: string | null
  /** UniFi: the steps for the same. */
  mab_steps?: string[] | null
}

export interface ReadinessDevice { mac: string | null; username: string | null; result: 'accept' | 'reject'; reason_code: string | null; vlan_id: number | null; monitor: boolean; at: string
  /** How it authenticated: a certificate (802.1X) or its MAC address. */
  method?: 'mac' | 'certificate' }
/** MAC authentication on this switch in the readiness window. Unknown devices are logged once an hour each. */
export interface MabHealth { enabled: boolean; answered: number; accepted: number; unknown: number; last_at: string | null; unknown_action: 'block' | 'vlan'; unknown_vlan: number | null }
export interface ReadinessPort { port: string; devices: ReadinessDevice[]; accepted: number; rejected: number }
export interface Readiness { hours: number; ports: ReadinessPort[]; events: number; would_assign_vlans: number[]; rejected_devices: number; session_command: string; mab?: MabHealth | null }
export interface SwitchSession { interface: string; mac: string; method: string; domain: string; status: string; authorized: boolean }
export interface SessionsCheck { sessions: number; authorized: number; would_lose_access: SwitchSession[]; parsed: boolean }

export interface ActivityEvent { id: string; at: string; result: 'accept' | 'reject'; reason_code: string | null; username: string | null; calling_station_id: string | null;
  network: Network | null; nas_port_id: string | null; vlan_id: number | null; monitor: boolean; explanation: { title: string; explanation: string; fix: string } | null }
export interface Diagnostic { kind: 'unknown_client' | 'bad_secret'; address: string; at: string; message: string }
export interface Activity { events: ActivityEvent[]; last_request_at: string | null; diagnostics: Diagnostic[] }

export interface WiredKit { server_name: string; files: Array<{ name: string; type: string; content: string }>; gpo_steps: string[]; notes: string[] }

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
  return useQuery({ queryKey: qk.radius(tid), queryFn: ({ signal }) => api.get<RadiusResponse>(base(tid), signal), refetchInterval: (q) => agentPoll(q.state.data?.agent) })
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

/** Partial update: omitted fields keep their values (networks and the port plan included). */
export function useUpdateClient(tid: string) {
  const inv = useInvalidateRadius(tid)
  return useMutation({ mutationFn: ({ id, body }: { id: string; body: Partial<ClientIn> }) => api.put<{ client: RadiusClient }>(`${base(tid)}/clients/${id}`, body), onSuccess: inv })
}

export const wiredGuideKey = (tid: string, id: string) => [...qk.radius(tid), 'wired-guide', id] as const

export function useWiredGuide(tid: string, clientId: string | null, enabled = true) {
  return useQuery({
    queryKey: wiredGuideKey(tid, clientId ?? ''),
    queryFn: ({ signal }) => api.get<WiredGuide>(`${base(tid)}/clients/${clientId}/wired-guide`, signal),
    enabled: enabled && !!clientId,
    staleTime: 30_000,
  })
}

export function useSetWiredMode(tid: string) {
  const inv = useInvalidateRadius(tid)
  return useMutation({
    mutationFn: ({ id, mode, confirmed }: { id: string; mode: 'monitor' | 'enforce'; confirmed?: boolean }) =>
      api.post<{ client: RadiusClient; guide: WiredGuide }>(`${base(tid)}/clients/${id}/wired-mode`, { mode, confirmed: !!confirmed }),
    onSuccess: inv,
  })
}

/** Turn MAC authentication on or off (monitor mode only). Returns the guide with the change to paste. */
export function useSetMab(tid: string) {
  const inv = useInvalidateRadius(tid)
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.post<{ client: RadiusClient; guide: WiredGuide }>(`${base(tid)}/clients/${id}/mab`, { enabled }),
    onSuccess: () => Promise.all([inv(), qc.invalidateQueries({ queryKey: qk.mac(tid) })]),
  })
}

/** After a configuration-only change (a switch's Enforce): whether FreeRADIUS runs it yet. Polls every 2 s from
 * `since` (ms) until it does. An older agent doesn't report it, so 20 s after the change counts as live. */
export type ConfigApplied = 'waiting' | 'live' | 'rejected' | 'slow'
export function useConfigApplied(tid: string, since: number | null): { state: ConfigApplied; error: string | null } {
  const q = useQuery({
    queryKey: [...qk.radius(tid), 'config-applied'] as const,
    queryFn: ({ signal }) => api.get<RadiusResponse>(base(tid), signal),
    enabled: since !== null,
    refetchInterval: (query) => (query.state.data?.agent?.tenant_config_in_sync ? false : 2000),
  })
  return since === null ? { state: 'waiting', error: null } : configAppliedState(q.data?.agent ?? null, Date.now() - since)
}

export function configAppliedState(a: RadiusAgent | null, elapsedMs: number): { state: ConfigApplied; error: string | null } {
  if (a?.config_ok === false && a.config_error) return { state: 'rejected', error: a.config_error }
  if (a?.tenant_config_in_sync) return { state: 'live', error: null }
  if (a && a.tenant_config_in_sync == null && elapsedMs > 20_000) return { state: 'live', error: null }
  return { state: elapsedMs > 90_000 ? 'slow' : 'waiting', error: null }
}

export function useReadiness(tid: string, clientId: string | null, enabled = true) {
  return useQuery({
    queryKey: [...qk.radius(tid), 'readiness', clientId ?? ''] as const,
    queryFn: ({ signal }) => api.get<Readiness>(`${base(tid)}/clients/${clientId}/readiness?hours=24`, signal),
    enabled: enabled && !!clientId,
  })
}

export function useCheckSessions(tid: string) {
  return useMutation({ mutationFn: ({ id, text }: { id: string; text: string }) => api.post<SessionsCheck>(`${base(tid)}/clients/${id}/readiness/sessions`, { text }) })
}

/** "Waiting for the first request": polls while `enabled`. */
export function useActivity(tid: string, clientId: string | null, enabled = true) {
  return useQuery({
    queryKey: [...qk.radius(tid), 'activity', clientId ?? ''] as const,
    queryFn: ({ signal }) => api.get<Activity>(`${base(tid)}/clients/${clientId}/activity?minutes=60`, signal),
    enabled: enabled && !!clientId,
    refetchInterval: 5000,
  })
}

export function useWiredKit(tid: string, enabled = true) {
  return useQuery({ queryKey: [...qk.radius(tid), 'wired-kit'] as const, queryFn: ({ signal }) => api.get<WiredKit>(`${base(tid)}/wired-kit`, signal), enabled, staleTime: 60_000 })
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
