// Tenant-scoped entity search shared by the sidebar search and the command palette.
// Users, certificates, MAC allow-list entries and device-admin accounts are searched server-side; controllers, rules and VLANs come from the
// cached tenant config.
import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, qs } from '../api/client'
import { qk } from '../api/keys'
import { fmtSerial } from '../lib/format'

export type HitKind = 'user' | 'certificate' | 'controller' | 'rule' | 'vlan' | 'mac' | 'admin'
export interface Hit { key: string; kind: HitKind; group: string; id: string; label: string; sub: string; status?: string }

interface IdentityLite { id: string; display_name: string; username: string; upn: string | null; email: string | null; department: string | null; account_state: string }
interface CertLite { id: string; serial: string; common_name: string; status: string; identity: { display_name: string } | null; device: { name: string } | null }
interface ClientLite { id: string; name: string; address: string; site: string | null; vendor: string }
interface RuleLite { id: string; name: string; action: string }
interface VlanLite { id: string; vlan_id: number; name: string; description: string }
interface MacLite { id: string; mac: string; name: string }
interface AdminLite { id: string; username: string; display_name: string }
/** Kinds searched server-side that need a permission besides reading the tenant. */
export interface SearchAllowed { mac: boolean; admin: boolean }

function useDebounced<T>(value: T, ms = 160): T {
  const [v, setV] = useState(value)
  useEffect(() => { const id = setTimeout(() => setV(value), ms); return () => clearTimeout(id) }, [value, ms])
  return v
}

export function useEntitySearch(tid: string | null, query: string, kinds: HitKind[] = ['user', 'certificate', 'controller', 'rule', 'vlan', 'mac', 'admin'], allowed: SearchAllowed = { mac: true, admin: true }) {
  const q = useDebounced(query.trim())
  const on = !!tid && q.length > 0
  const users = useQuery({
    queryKey: ['t', tid, 'search', 'identities', q],
    queryFn: ({ signal }) => api.get<{ items: IdentityLite[] }>(`/api/tenants/${tid}/identities${qs({ q, page_size: 6 })}`, signal).then((r) => r.items),
    enabled: on && kinds.includes('user'),
    staleTime: 15_000,
  })
  const certs = useQuery({
    queryKey: ['t', tid, 'search', 'certificates', q],
    queryFn: ({ signal }) => api.get<{ items: CertLite[] }>(`/api/tenants/${tid}/certificates${qs({ q, page_size: 6 })}`, signal).then((r) => r.items),
    enabled: on && kinds.includes('certificate') && q.length >= 2,
    staleTime: 15_000,
  })
  const macs = useQuery({
    queryKey: ['t', tid, 'search', 'mac', q],
    queryFn: ({ signal }) => api.get<{ items: MacLite[] }>(`/api/tenants/${tid}/mac/search${qs({ q })}`, signal).then((r) => r.items),
    enabled: on && allowed.mac && kinds.includes('mac') && q.length >= 2,
    staleTime: 15_000,
  })
  const admins = useQuery({
    queryKey: ['t', tid, 'search', 'device-admin', q],
    queryFn: ({ signal }) => api.get<{ items: AdminLite[] }>(`/api/tenants/${tid}/device-admin/search${qs({ q })}`, signal).then((r) => r.items),
    enabled: on && allowed.admin && kinds.includes('admin') && q.length >= 2,
    staleTime: 15_000,
  })
  const radius = useQuery({
    queryKey: qk.radius(tid ?? ''),
    queryFn: () => api.get<{ clients: ClientLite[] }>(`/api/tenants/${tid}/radius`),
    enabled: on && kinds.includes('controller'),
    staleTime: 60_000,
  })
  const policy = useQuery({
    queryKey: qk.policy(tid ?? ''),
    queryFn: () => api.get<{ rules: RuleLite[]; vlans: VlanLite[] }>(`/api/tenants/${tid}/policy`),
    enabled: on && (kinds.includes('rule') || kinds.includes('vlan')),
    staleTime: 60_000,
  })

  const hits = useMemo<Hit[]>(() => {
    if (!on) return []
    const ql = q.toLowerCase()
    const has = (...f: Array<string | null | undefined>) => f.some((x) => x?.toLowerCase().includes(ql))
    const out: Hit[] = []
    if (kinds.includes('user')) for (const i of users.data ?? []) out.push({ key: `u:${i.id}`, kind: 'user', group: 'Users', id: i.id, label: i.display_name, sub: [i.upn ?? i.username, i.department].filter(Boolean).join(' · '), status: i.account_state })
    if (kinds.includes('certificate')) for (const c of certs.data ?? []) out.push({ key: `c:${c.id}`, kind: 'certificate', group: 'Certificates', id: c.id, label: `${fmtSerial(c.serial).slice(0, 19)}…`, sub: [c.identity?.display_name, c.device?.name ?? c.common_name].filter(Boolean).join(' · '), status: c.status })
    if (kinds.includes('controller')) for (const c of radius.data?.clients ?? []) if (has(c.name, c.address, c.site)) out.push({ key: `n:${c.id}`, kind: 'controller', group: 'Controllers and switches', id: c.id, label: c.name, sub: [c.address, c.site].filter(Boolean).join(' · ') })
    if (kinds.includes('mac')) for (const d of macs.data ?? []) out.push({ key: `m:${d.id}`, kind: 'mac', group: 'MAC allow list', id: d.id, label: d.name, sub: d.mac })
    if (kinds.includes('admin')) for (const a of admins.data ?? []) out.push({ key: `a:${a.id}`, kind: 'admin', group: 'Device admin accounts', id: a.id, label: a.username, sub: a.display_name })
    if (kinds.includes('rule')) for (const r of policy.data?.rules ?? []) if (has(r.name)) out.push({ key: `r:${r.id}`, kind: 'rule', group: 'Access rules', id: r.id, label: r.name, sub: r.action === 'deny' ? 'Deny rule' : 'Allow rule' })
    if (kinds.includes('vlan')) for (const v of policy.data?.vlans ?? []) if (has(String(v.vlan_id), v.name)) out.push({ key: `v:${v.id}`, kind: 'vlan', group: 'VLANs', id: v.id, label: `VLAN ${v.vlan_id} · ${v.name}`, sub: v.description })
    return out
  }, [on, q, kinds, users.data, certs.data, macs.data, admins.data, radius.data, policy.data])

  const loading = on && (users.isFetching || certs.isFetching || macs.isFetching || admins.isFetching)
  return { hits, loading, query: q }
}
