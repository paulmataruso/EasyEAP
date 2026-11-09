// Authentication log (GET /api/tenants/:tid/events, /events/:id) and accounting sessions (GET /sessions).
// Shapes mirror backend/app/routers/events.py (event_out, get_event, sessions).
import { useQuery } from '@tanstack/react-query'
import { api, qs } from './client'
import { qk } from './keys'
import type { DecisionStep } from './types'

export interface Explanation { title: string; explanation: string; fix: string }

export interface AuthEvent {
  id: string
  at: string
  result: 'accept' | 'reject'
  reason_code: string | null
  explanation: Explanation | null
  username: string | null
  identity_id: string | null
  device_id: string | null
  cert_serial: string | null
  cert_issuer: string | null
  calling_station_id: string | null
  called_station_id: string | null
  ssid: string | null
  nas_ip: string | null
  nas_client_id: string | null
  /** In monitor mode (`monitor`), the VLAN EasyEAP would have assigned; it sent none. */
  vlan_id: number | null
  /** Which network the request came from; null for events from before wired 802.1X. */
  network: Network | null
  /** The switch port (NAS-Port-Id), e.g. GigabitEthernet1/0/5. */
  nas_port_id: string | null
  /** The switch is in monitor mode: EasyEAP decided but sent no VLAN or attributes. */
  monitor: boolean
  rule_id: string | null
  raw_message: string | null
  /** The device MAC, normalised (AABBCCDDEEFF); null for events from before MAC authentication. */
  mac?: string | null
  /** How it authenticated: eap-tls, mab (Cisco MAC authentication) or mab-eap (UniFi MAC-Based). */
  method?: string | null
  /** The MAC allow-list entry that decided a MAC authentication. */
  mac_device_id?: string | null
}

/** A MAC authentication, not a certificate. */
export const isMab = (e: Pick<AuthEvent, 'method'>) => e.method === 'mab' || e.method === 'mab-eap'

export type Network = 'wireless' | 'wired'
export const networkLabels: Record<Network, string> = { wireless: 'Wi-Fi', wired: 'Wired' }

export interface EventDetail extends AuthEvent {
  /** Present only when the event carried a certificate serial. */
  certificate_id?: string | null
  /** The certificate's *current* policy decision (recomputed on every change), not the decision at the time of the attempt. */
  decision_steps?: DecisionStep[] | null
  /** The MAC allow-list entry (MAC authentication), when it still exists. */
  mac_device?: { id: string; name: string; group_id: string; group_name: string } | null
}

export interface EventsResponse {
  items: AuthEvent[]
  next_before_id: number | null
  /** Reject counts per reason over the same time window (ignores the other filters). */
  reasons: Array<{ reason_code: string | null; count: number; title: string }>
}

export interface EventFilters { result: '' | 'accept' | 'reject'; reason: string; q: string; hours: number; network?: '' | Network }

export const eventsUrl = (tid: string, f: EventFilters, beforeId?: number) =>
  `/api/tenants/${tid}/events${qs({ result: f.result, reason: f.reason, q: f.q.trim(), hours: f.hours, network: f.network ?? '', before_id: beforeId })}`

export const eventsKey = (tid: string, f: EventFilters, beforeId?: number) =>
  qk.events(tid, { result: f.result, reason: f.reason, q: f.q.trim(), hours: f.hours, network: f.network ?? '', before_id: beforeId ?? null })

export function useEvent(tid: string, id: string | null) {
  return useQuery({
    queryKey: [...qk.events(tid), 'detail', id] as const,
    queryFn: ({ signal }) => api.get<EventDetail>(`/api/tenants/${tid}/events/${id}`, signal),
    enabled: !!id,
    staleTime: 60_000,
  })
}

export interface AcctSession {
  id: string
  username: string | null
  calling_station_id: string | null
  called_station_id: string | null
  nas_ip: string
  framed_ip: string | null
  vlan_id: number | null
  network: Network | null
  /** The switch port, for wired sessions. */
  nas_port_id: string | null
  started_at: string | null
  updated_at: string
  stopped_at: string | null
  input_octets: number | null
  output_octets: number | null
}

export function useSessions(tid: string, active: boolean, enabled = true) {
  return useQuery({
    queryKey: qk.sessions(tid, active ? {} : { active: false }),
    queryFn: ({ signal }) => api.get<{ items: AcctSession[] }>(`/api/tenants/${tid}/sessions${active ? '' : '?active=false'}`, signal),
    enabled,
    refetchInterval: 30_000,
  })
}

// ── Name lookups (shared raw caches owned by the RADIUS and Policy screens) ─────────────────────────────
export interface ClientLite { id: string; name: string; address: string; site: string | null; vendor: string }
export interface RuleLite { id: string; name: string; action: 'allow' | 'deny'; enabled: boolean; priority: number }
export interface VlanLite { id: string; vlan_id: number; name: string; color: string }

export function useControllers(tid: string, enabled: boolean) {
  return useQuery({
    queryKey: qk.radius(tid),
    queryFn: () => api.get<{ clients: ClientLite[] }>(`/api/tenants/${tid}/radius`),
    enabled,
    staleTime: 60_000,
  })
}

export function usePolicyLite(tid: string, enabled: boolean) {
  return useQuery({
    queryKey: qk.policy(tid),
    queryFn: () => api.get<{ rules: RuleLite[]; vlans: VlanLite[]; settings: { expiry_warning_days: number; max_snapshot_age_seconds: number } }>(`/api/tenants/${tid}/policy`),
    enabled,
    staleTime: 60_000,
  })
}

const ipv4 = (ip: string): number | null => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim())
  if (!m) return null
  const o = m.slice(1).map(Number)
  return o.some((x) => x > 255) ? null : ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]
}

/** Prefix length if `ip` falls inside `address` (a single IP or an IPv4 CIDR), else -1. */
function matchLength(address: string, ip: string): number {
  if (address === ip) return 32
  const [net, bits] = address.split('/')
  const n = ipv4(net), x = ipv4(ip), b = Number(bits)
  if (n === null || x === null || bits === undefined || !Number.isInteger(b) || b < 0 || b > 32) return -1
  const mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0
  return ((n & mask) >>> 0) === ((x & mask) >>> 0) ? b : -1
}

/** Controller for an event or session: by registered client id, else the most specific address/CIDR match. */
export function controllerFor(clients: ClientLite[] | undefined, e: { nas_client_id?: string | null; nas_ip: string | null }): ClientLite | undefined {
  if (!clients) return undefined
  const byId = e.nas_client_id ? clients.find((c) => c.id === e.nas_client_id) : undefined
  if (byId || !e.nas_ip) return byId
  let best: ClientLite | undefined
  let bestLen = -1
  for (const c of clients) {
    const len = matchLength(c.address, e.nas_ip)
    if (len > bestLen) { best = c; bestLen = len }
  }
  return best
}
