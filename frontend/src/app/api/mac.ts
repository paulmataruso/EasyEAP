// The MAC allow list (docs/plans/mac-auth.md §7): device groups, devices, import/export and "Seen, not allowed".
// Shapes mirror backend/app/routers/mac.py exactly. Changes that affect a live session return what CoA was queued.
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { api, qs } from './client'
import { qk } from './keys'

export interface DeviceGroup {
  id: string
  name: string
  description: string
  vlan_ref: string | null
  vlan_id: number | null
  vlan_name: string | null
  /** Devices keep the switch port's own VLAN (no VLAN sent). */
  port_vlan: boolean
  enabled: boolean
  /** What a switch port gets for this group (the VLAN's "On switch ports" mapping applied); null: the port's own. */
  switch_vlan: number | null
  devices: number
  /** Certificate users are placed on the same VLAN: a copied MAC lands next to them. */
  shared_with_certificates: boolean
}

export type MacStatus = 'allowed' | 'blocked' | 'expired' | 'group_off'

export interface MacDevice {
  id: string
  /** AA:BB:CC:DD:EE:FF */
  mac: string
  name: string
  notes: string
  group_id: string
  group_name: string | null
  enabled: boolean
  expires_at: string | null
  source: 'manual' | 'import' | 'learned' | string
  created_at: string | null
  created_by: string | null
  last_seen_at: string | null
  last_seen_client: string | null
  last_seen_port: string | null
  status: MacStatus
  /** Locally administered address: phones and laptops randomise these, so the entry stops matching. */
  randomized: boolean
}

export interface CoaResult { sessions: number; queued: number; without_coa: number; skipped?: number }

export interface MacOverview {
  groups: DeviceGroup[]
  devices: MacDevice[]
  limits: { devices: number; groups: number; import_lines: number }
  switches_with_mab: Array<{ id: string; name: string; mode: 'monitor' | 'enforce' | null }>
}

export interface DeviceEvent {
  id: number; at: string; result: 'accept' | 'reject'; reason_code: string | null; method: string | null
  switch: string | null; port: string | null; vlan_id: number | null; monitor: boolean
}
export interface MacDeviceDetail extends MacDevice {
  events: DeviceEvent[]
  /** It answers 802.1X and fails, so the switch never tries MAC authentication for it. */
  answers_8021x: boolean
  certificate_device: boolean
}

export interface Sighting {
  id: number
  mac: string
  switch: string | null
  client_id: string
  port: string | null
  first_seen: string
  last_seen: string
  attempts: number
  reason_code: string | null
  certificate_device: boolean
  randomized: boolean
}

export interface GroupIn { name: string; description: string; vlan_ref: string | null; port_vlan: boolean; enabled: boolean }
export interface DeviceIn { mac: string; name: string; group_id: string; notes: string; expires_at: string | null; enabled: boolean; confirm_certificate?: boolean }
export interface DeviceUpdate { name?: string; group_id?: string; notes?: string; expires_at?: string | null; clear_expiry?: boolean; enabled?: boolean }
export interface ImportError { line: number | null; text: string; message: string; code?: string }
export interface ImportResult { added: number; errors: ImportError[]; valid: number }

const base = (tid: string) => `/api/tenants/${tid}/mac`

export const statusLabels: Record<MacStatus, string> = { allowed: 'Allowed', blocked: 'Blocked', expired: 'Expired', group_off: 'Group off' }

export function useMacOverview(tid: string, enabled = true) {
  return useQuery({ queryKey: qk.mac(tid), queryFn: ({ signal }) => api.get<MacOverview>(base(tid), signal), enabled })
}

export function useMacDevice(tid: string, id: string | null) {
  return useQuery({
    queryKey: [...qk.mac(tid), 'device', id ?? ''] as const,
    queryFn: ({ signal }) => api.get<MacDeviceDetail>(`${base(tid)}/devices/${id}`, signal),
    enabled: !!id,
  })
}

export function useSightings(tid: string, days = 30, enabled = true) {
  return useQuery({
    queryKey: [...qk.mac(tid), 'sightings', days] as const,
    queryFn: ({ signal }) => api.get<{ days: number; sightings: Sighting[] }>(`${base(tid)}/sightings${qs({ days })}`, signal),
    enabled,
    refetchInterval: 30_000,
  })
}

function useInvalidateMac(tid: string) {
  const qc = useQueryClient()
  // RADIUS readiness and the tenant's events reflect allow-list changes too.
  return () => Promise.all([qc.invalidateQueries({ queryKey: qk.mac(tid) }), qc.invalidateQueries({ queryKey: qk.radius(tid) })])
}

export function useSaveGroup(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: GroupIn }) =>
      id ? api.put<DeviceGroup & { coa: CoaResult | null }>(`${base(tid)}/groups/${id}`, body) : api.post<DeviceGroup & { coa?: CoaResult | null }>(`${base(tid)}/groups`, body),
    onSuccess: inv,
  })
}

export function useDeleteGroup(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({ mutationFn: (id: string) => api.del<{ ok: boolean }>(`${base(tid)}/groups/${id}`), onSuccess: inv })
}

export function useCreateDevice(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({ mutationFn: (body: DeviceIn) => api.post<MacDevice & { coa: CoaResult | null }>(`${base(tid)}/devices`, body), onSuccess: inv })
}

export function useUpdateDevice(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: DeviceUpdate }) => api.put<MacDevice & { coa: CoaResult | null }>(`${base(tid)}/devices/${id}`, body),
    onSuccess: inv,
  })
}

export function useDeleteDevice(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({ mutationFn: (id: string) => api.del<{ ok: boolean; coa: CoaResult | null }>(`${base(tid)}/devices/${id}`), onSuccess: inv })
}

export function useImportDevices(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({
    mutationFn: (body: { text: string; group_id: string; confirm_certificate?: boolean }) => api.post<ImportResult>(`${base(tid)}/devices/import`, body),
    onSuccess: (r) => (r.added ? inv() : undefined),
  })
}

export function useBulkAllow(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({
    mutationFn: (body: { macs: string[]; group_id: string; confirm_certificate?: boolean }) =>
      api.post<{ added: number; already_listed: number }>(`${base(tid)}/devices/bulk`, body),
    onSuccess: inv,
  })
}

export function useDismissSighting(tid: string) {
  const inv = useInvalidateMac(tid)
  return useMutation({ mutationFn: (id: number) => api.del<{ ok: boolean }>(`${base(tid)}/sightings/${id}`), onSuccess: inv })
}

export const exportUrl = (tid: string) => `${base(tid)}/devices.csv`

/** One sentence about the CoA a change queued, for its toast; null when there was no live session. */
export function coaSummary(c: CoaResult | null | undefined): string | null {
  if (!c || c.sessions === 0) return null
  const parts = []
  if (c.queued) parts.push(`${c.queued} switch${c.queued === 1 ? ' was' : 'es were'} told to apply it now`)
  if (c.without_coa) parts.push(`${c.without_coa} session${c.without_coa === 1 ? '' : 's'} on switches without CoA change at their next re-authentication`)
  if (c.skipped) parts.push(`${c.skipped} more update at their next re-authentication`)
  return parts.length ? `${parts.join('; ')}.` : null
}

/** The canonical MAC (12 uppercase hex digits), or an error to show. Mirrors backend app/mac.py normalize_mac. */
export function checkMac(v: string): { mac: string } | { error: string } {
  const s = v.trim()
  const ok = /^[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$/.test(s) || /^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$/.test(s) || /^[0-9A-Fa-f]{12}$/.test(s)
  if (!ok) return { error: 'Enter a MAC address such as AA:BB:CC:DD:EE:FF.' }
  const mac = s.replace(/[^0-9A-Fa-f]/g, '').toUpperCase()
  if (mac === '000000000000') return { error: '00:00:00:00:00:00 isn’t a device’s address.' }
  if (parseInt(mac[1], 16) & 1) return { error: 'That’s a multicast or broadcast address, not a device’s.' }
  return { mac }
}

/** Locally administered (randomised by phones and laptops). */
export const isRandomized = (mac: string) => (parseInt(mac[1], 16) & 2) !== 0

export const formatMac = (hex: string) => hex.match(/.{2}/g)!.join(':')
