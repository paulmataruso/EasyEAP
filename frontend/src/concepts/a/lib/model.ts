// Derived, concept-local views over the shared prototype store. Nothing here invents data:
// every value is computed from useTenantData()/useTenants() and the shared policy engine.
import { useMemo } from 'react'
import { evaluatePolicy } from '@/domain/policy'
import type { AuthEvent, Certificate, CertStatus, Decision, Device, HealthState, Identity, RadiusClient, Tenant, Vlan } from '@/domain/types'
import { now, useTenantData } from '@/prototype/store'

export type TenantData = ReturnType<typeof useTenantData>

export interface CertSummary {
  /** Headline status: the one an admin should look at first */
  headline: CertStatus | 'none'
  count: number
  /** Nearest expiry among certificates that still authenticate (active/expiring) */
  nextExpiry: string | null
  statuses: Set<CertStatus>
}

export interface UserRow {
  /** Stable React key (identity ids are not guaranteed unique in the synthetic data) */
  key: string
  index: number
  identity: Identity
  decision: Decision
  certs: Certificate[]
  devices: Device[]
  cert: CertSummary
  vlan: Vlan | null
}

const HEADLINE_ORDER: CertStatus[] = ['expiring', 'active', 'pending', 'expired', 'revoked']

export function summarizeCerts(certs: Certificate[]): CertSummary {
  const statuses = new Set(certs.map((c) => c.status))
  const headline = certs.length ? (HEADLINE_ORDER.find((s) => statuses.has(s)) ?? 'none') : 'none'
  const valid = certs.filter((c) => c.status === 'active' || c.status === 'expiring').map((c) => c.notAfter).sort()
  return { headline, count: certs.length, nextExpiry: valid[0] ?? null, statuses }
}

export function decide(identity: Identity, d: TenantData, certificate?: Certificate): Decision {
  return evaluatePolicy(identity, d.rules, d.defaults, d.vlans, { certificate, now: now() })
}

/** One row per identity with its decision and certificate summary, computed per row. */
export function useUserRows(): UserRow[] {
  const d = useTenantData()
  return useMemo(() => {
    const certsBy = groupBy(d.certificates.filter((c) => c.identityId), (c) => c.identityId!)
    const devicesBy = groupBy(d.devices, (x) => x.identityId)
    const vlanById = new Map(d.vlans.map((v) => [v.id, v]))
    return d.identities.map((identity, index) => {
      const decision = decide(identity, d)
      const certs = certsBy.get(identity.id) ?? []
      return {
        key: `${identity.id}~${index}`,
        index,
        identity,
        decision,
        certs,
        devices: devicesBy.get(identity.id) ?? [],
        cert: summarizeCerts(certs),
        vlan: decision.vlanId ? (vlanById.get(decision.vlanId) ?? null) : null,
      }
    })
  }, [d])
}

export function useLookups() {
  const d = useTenantData()
  return useMemo(() => {
    const identityById = new Map<string, Identity>()
    for (const i of d.identities) if (!identityById.has(i.id)) identityById.set(i.id, i)
    return {
      identityById,
      groupById: new Map(d.groups.map((g) => [g.id, g])),
      vlanById: new Map(d.vlans.map((v) => [v.id, v])),
      ruleById: new Map(d.rules.map((r) => [r.id, r])),
      nasById: new Map(d.radiusClients.map((n) => [n.id, n])),
      deviceById: new Map(d.devices.map((x) => [x.id, x])),
      caById: new Map(d.cas.map((c) => [c.id, c])),
      templateById: new Map(d.templates.map((t) => [t.id, t])),
    }
  }, [d])
}

export function groupBy<T, K>(xs: T[], key: (x: T) => K): Map<K, T[]> {
  const out = new Map<K, T[]>()
  for (const x of xs) {
    const k = key(x)
    const arr = out.get(k)
    if (arr) arr.push(x)
    else out.set(k, [x])
  }
  return out
}

// ── Health ──────────────────────────────────────────────────────────────────

const SEVERITY: Record<HealthState, number> = { ok: 0, unconfigured: 1, degraded: 2, down: 3 }
export const worstHealth = (states: HealthState[]): HealthState => states.reduce((w, s) => (SEVERITY[s] > SEVERITY[w] ? s : w), 'ok' as HealthState)

export function tenantHealth(t: Tenant, controllers?: RadiusClient[]): { state: HealthState; label: string } {
  if (t.status === 'setup') return { state: 'unconfigured', label: 'Setup in progress' }
  const issues: string[] = []
  if (t.health.radius !== 'ok') issues.push('RADIUS')
  if (t.health.pki !== 'ok') issues.push('PKI')
  if (t.health.directory !== 'ok') issues.push('directory')
  const degradedNas = controllers?.filter((c) => c.status === 'degraded' || c.status === 'down').length ?? 0
  if (degradedNas) issues.push(degradedNas === 1 ? '1 controller' : `${degradedNas} controllers`)
  const state = worstHealth([t.health.radius, t.health.pki, t.health.directory, ...(controllers ?? []).map((c) => (c.status === 'unconfigured' ? 'ok' : c.status))])
  if (!issues.length) return { state: 'ok', label: 'Healthy' }
  return { state: state === 'ok' ? 'degraded' : state, label: `Degraded: ${issues.join(', ')}` }
}

// ── Auth event helpers ──────────────────────────────────────────────────────

export function eventsInLast24h(events: AuthEvent[]): AuthEvent[] {
  const start = now().getTime() - 24 * 3600_000
  return events.filter((e) => new Date(e.at).getTime() > start)
}

/** Distinct identities authenticating per hour, 24 buckets ending at the demo clock. */
export function hourlyDistinctUsers(events: AuthEvent[]) {
  const end = now().getTime()
  return Array.from({ length: 24 }, (_, h) => {
    const hourEnd = end - (23 - h) * 3600_000
    const hourStart = hourEnd - 3600_000
    const ids = new Set<string>()
    for (const e of events) {
      const t = new Date(e.at).getTime()
      if (t > hourStart && t <= hourEnd && e.identityId) ids.add(e.identityId)
    }
    return { hourEnd: new Date(hourEnd), value: ids.size }
  })
}

/** Certificates still authenticating whose expiry falls within each of the next `days` days. */
export function expiryForecast(certs: Certificate[], days = 30) {
  const start = now().getTime()
  return Array.from({ length: days }, (_, i) => {
    const dayStart = start + i * 864e5
    const dayEnd = dayStart + 864e5
    const items = certs.filter((c) => (c.status === 'active' || c.status === 'expiring') && new Date(c.notAfter).getTime() >= dayStart && new Date(c.notAfter).getTime() < dayEnd)
    return { day: new Date(dayStart), value: items.length }
  })
}

export function initials(name: string): string {
  const parts = name.split(/\s+/).filter(Boolean)
  return ((parts[0]?.[0] ?? '') + (parts[parts.length - 1]?.[0] ?? '')).toUpperCase()
}

/** A random shared secret (shown once). Never persisted by the prototype. */
export function generateSecret(length = 32): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

export function enrollmentToken(): string {
  const bytes = new Uint8Array(9)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(36).padStart(2, '0')).join('').slice(0, 14)
}
