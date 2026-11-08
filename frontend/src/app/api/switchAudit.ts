// Switch audit (docs/plans/switch-audit.md): SNMP monitoring of a Cisco switch, its polled ports and sessions, and
// the audit findings. Shapes mirror backend/app/routers/switch_audit.py and app/switchaudit/service.py.
// The community or SNMPv3 keys come back once from setup and are never written to the query cache: the dialog keeps
// them in state and drops them when it closes.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './client'
import { qk } from './keys'

export type SnmpVersion = 'v2c' | 'v3'
export interface Monitoring {
  enabled: boolean
  host: string | null
  port: number
  version: SnmpVersion
  user: string
  auth: 'sha256' | 'sha'
  priv: 'aes128' | 'aes256'
  interval_minutes: number
  credentials_set: boolean
  credentials_set_at: string | null
  pinned: { serial: string; engine_id: string } | null
  set_up: boolean
}
export interface PolledPort {
  if_index: number
  name: string
  short: string
  alias: string
  admin: 'up' | 'down'
  oper: 'up' | 'down'
  auth: { control: 'auto' | 'force-authorized' | 'force-unauthorized' | null; host_mode: string | null; open: boolean | null } | null
  err_disabled: string | null
}
export interface PolledSession {
  port: string
  mac: string
  status: string
  authorized: boolean
  domain: 'data' | 'voice' | 'other'
  user: string
  authorized_by: string
  critical: boolean
  vlan: number | null
  method: 'dot1x' | 'mab' | 'webauth' | 'other' | null
  id: string
}
export interface SwitchState {
  polled_at: string
  ok: boolean
  error_kind: string | null
  error: string | null
  duration_ms: number | null
  failures: number
  last_ok_at: string | null
  facts: { name?: string; descr?: string; model?: string; serial?: string; version?: string; engine_id?: string; uptime_s?: number | null }
  capabilities: { caf?: boolean; errdisable?: boolean }
  ports: PolledPort[]
  sessions: PolledSession[]
  truncated: boolean
  slow: boolean
  next_poll_at: string | null
  poll_requested_at: string | null
}
export type FindingKind = 'port_not_covered' | 'open_access_in_enforce' | 'authorized_without_easyeap' | 'authorized_despite_reject' | 'authorized_after_deny'
  | 'vlan_mismatch' | 'mab_not_expected' | 'critical_auth' | 'err_disabled' | 'caf_missing' | 'switch_changed' | 'snmp_unreachable' | 'snmp_auth'
export interface Finding {
  id: string
  kind: FindingKind | string
  severity: 'critical' | 'warning'
  port: string | null
  mac: string | null
  detail: Record<string, unknown>
  meaning: string
  fix: string
  first_seen_at: string
  last_seen_at: string
  opened_at: string | null
  resolved_at: string | null
  acknowledged_at: string | null
  acknowledged_by: string | null
  ack_note: string | null
  /** What the switch said over syslog about this device or port (last 24 hours). Not evidence on its own. */
  switch_says?: SyslogLine[]
}
/** One syslog message (coalesced per minute): "the switch says". Unauthenticated, so never a finding by itself. */
export interface SyslogLine {
  id: string
  first_at: string
  last_at: string
  count: number
  tag: string
  severity: number
  port: string | null
  mac: string | null
  session_id: string | null
  /** The RADIUS server, the err-disable cause or who configured the switch, when the message names one. */
  subject: string | null
  text: string
}
/** A RADIUS server the switch last said isn't responding. */
export interface RadiusDown extends SyslogLine {
  /** null: "no RADIUS server is responding". */
  server: string | null
  /** It's EasyEAP's RADIUS address (or every server). */
  ours: boolean
}
export interface SyslogStats { day?: string; received?: number; kept?: number; filtered?: number; quota?: number; last_at?: string; last_tag?: string }
export interface MonitoringResponse {
  monitoring: Monitoring
  default_host: string
  state: SwitchState | null
  findings: Finding[]
  /** Seen once, waiting for a second poll before they're shown. */
  pending: number
  resolved: Finding[]
  /** The block to paste, with <community> / <authentication key> / <privacy key> placeholders. */
  config: string | null
  removal: string | null
  source_address: string | null
  collector: { alive: boolean; last_seen_at: string | null }
  poll_requested_at: string | null
  syslog?: {
    /** This server publishes its syslog port (EASYEAP_SYSLOG_BIND); the configuration then includes a logging host. */
    receiving: boolean
    /** The easyeap-syslog service's heartbeat is recent. */
    listening: boolean
    /** Where the switch sends syslog. */
    address: string | null
    port: number | null
    stats: SyslogStats
    recent: SyslogLine[]
    /** The RADIUS servers the switch last said aren't responding. */
    radius_down: RadiusDown[]
  }
}
export interface MonitoringInput { host: string; port?: number; version: SnmpVersion; user?: string; auth?: 'sha256' | 'sha'; priv?: 'aes128' | 'aes256'; interval_minutes: number }
export interface SetupResult {
  monitoring: Monitoring
  credentials: { community?: string; auth_key?: string; priv_key?: string; user: string | null }
  config: string
  /** Lines that remove the previous credentials from the switch, when they changed. */
  retire: string | null
}
export interface TestResult { ok: boolean; error_kind: string | null; error: string | null; duration_ms: number | null; facts: SwitchState['facts'] | null; capabilities: SwitchState['capabilities'] | null; monitoring: Monitoring }

export const COMMUNITY_PLACEHOLDER = '<community>'
export const AUTH_PLACEHOLDER = '<authentication key>'
export const PRIV_PLACEHOLDER = '<privacy key>'

/** The block with the one-time credentials filled in (only while the setup dialog holds them). */
export function fillCredentials(config: string, c: SetupResult['credentials'] | null): string {
  if (!c) return config
  let out = config
  if (c.community) out = out.split(COMMUNITY_PLACEHOLDER).join(c.community)
  if (c.auth_key) out = out.split(AUTH_PLACEHOLDER).join(c.auth_key)
  if (c.priv_key) out = out.split(PRIV_PLACEHOLDER).join(c.priv_key)
  return out
}

export const findingTitles: Record<string, string> = {
  port_not_covered: 'Port not protected',
  open_access_in_enforce: 'Port open before authentication',
  authorized_without_easyeap: 'Authorized without EasyEAP',
  authorized_despite_reject: 'Authorized although EasyEAP refused it',
  authorized_after_deny: 'Still connected after being denied',
  vlan_mismatch: 'Not in the VLAN EasyEAP sent',
  mab_not_expected: 'Admitted by MAC authentication',
  critical_auth: 'Admitted while EasyEAP was unreachable',
  err_disabled: 'Port err-disabled',
  caf_missing: 'Sessions not readable over SNMP',
  switch_changed: 'A different switch answers',
  snmp_unreachable: 'No SNMP answer',
  snmp_auth: 'SNMP credentials refused',
}

const base = (tid: string, id: string) => `/api/tenants/${tid}/radius/clients/${id}/monitoring`

export function useMonitoring(tid: string, clientId: string, enabled = true) {
  return useQuery({
    queryKey: qk.switchAudit(tid, clientId),
    queryFn: ({ signal }) => api.get<MonitoringResponse>(base(tid, clientId), signal),
    enabled,
    // While a "Poll now" waits for the collector, check every few seconds; otherwise once a minute.
    refetchInterval: (q) => (q.state.data?.poll_requested_at ? 4000 : 60_000),
  })
}

function useInvalidate(tid: string, clientId: string) {
  const qc = useQueryClient()
  return () => Promise.all([
    qc.invalidateQueries({ queryKey: qk.switchAudit(tid, clientId) }),
    qc.invalidateQueries({ queryKey: qk.radius(tid) }),
    qc.invalidateQueries({ queryKey: qk.dashboard(tid) }),
  ])
}

export function useSetupMonitoring(tid: string, clientId: string) {
  const inv = useInvalidate(tid, clientId)
  return useMutation({ mutationFn: (body: MonitoringInput) => api.post<SetupResult>(`${base(tid, clientId)}/setup`, body), onSuccess: inv })
}

export function useUpdateMonitoring(tid: string, clientId: string) {
  const inv = useInvalidate(tid, clientId)
  return useMutation({
    mutationFn: (body: { host?: string; port?: number; interval_minutes?: number; enabled?: boolean }) => api.put<{ monitoring: Monitoring }>(base(tid, clientId), body),
    onSuccess: inv,
  })
}

export function useTestMonitoring(tid: string, clientId: string) {
  const inv = useInvalidate(tid, clientId)
  return useMutation({ mutationFn: () => api.post<TestResult>(`${base(tid, clientId)}/test`, {}), onSuccess: inv })
}

export function usePollNow(tid: string, clientId: string) {
  const inv = useInvalidate(tid, clientId)
  return useMutation({ mutationFn: () => api.post<{ requested_at: string }>(`${base(tid, clientId)}/poll`, {}), onSuccess: inv })
}

export function useAckFinding(tid: string, clientId: string) {
  const inv = useInvalidate(tid, clientId)
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) => api.post<{ finding: Finding }>(`${base(tid, clientId)}/findings/${id}/ack`, { note }),
    onSuccess: inv,
  })
}

export function useRemoveMonitoring(tid: string, clientId: string) {
  const inv = useInvalidate(tid, clientId)
  return useMutation({ mutationFn: () => api.del<{ removal: string | null }>(base(tid, clientId)), onSuccess: inv })
}
