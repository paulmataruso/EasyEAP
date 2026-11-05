// Concept F helpers: derived data, small module-level stores (recently viewed, intents,
// pending enrollments, toasts) and formatting. Nothing here invents data: every figure is
// computed from the synthetic prototype store.
import { createContext, useContext, useSyncExternalStore } from 'react'
import { now } from '@/prototype/store'
import { daysUntil, relativeTime } from '@/ui/lib'
import { certStatusLabels, platformLabels } from '@/domain/explain'
import type { AuthEvent, Certificate, CertStatus, Decision, HealthState, Identity, KeyOrigin, Platform, Tenant, Vlan } from '@/domain/types'

// ── Portal container (Radix portals must render inside the scoped root) ─────
export const PortalContext = createContext<HTMLElement | null>(null)
export const usePortal = () => useContext(PortalContext) ?? undefined

// ── Tiny external store ──────────────────────────────────────────────────
function createStore<T>(initial: T) {
  let value = initial
  const listeners = new Set<() => void>()
  return {
    get: () => value,
    set: (next: T | ((prev: T) => T)) => {
      value = typeof next === 'function' ? (next as (p: T) => T)(value) : next
      listeners.forEach((l) => l())
    },
    subscribe: (l: () => void) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
  }
}
function useStoreValue<T>(store: ReturnType<typeof createStore<T>>) {
  return useSyncExternalStore(store.subscribe, store.get, store.get)
}

// Recently viewed records, per tenant
export interface RecentItem { kind: 'identity' | 'certificate' | 'controller'; id: string; label: string; sub: string }
const recentStore = createStore<Record<string, RecentItem[]>>({})
export function pushRecent(tenantId: string, item: RecentItem) {
  recentStore.set((prev) => {
    const list = (prev[tenantId] ?? []).filter((r) => r.id !== item.id)
    return { ...prev, [tenantId]: [item, ...list].slice(0, 5) }
  })
}
export const useRecent = (tenantId: string) => useStoreValue(recentStore)[tenantId] ?? []

// One-shot intents carried across navigation (e.g. open the issue dialog on arrival)
export interface Intent { issueFor?: string; certFilter?: 'expiring' | 'expired' | 'revoked' | 'active' }
export const intentStore = createStore<Intent>({})
export const useIntent = () => useStoreValue(intentStore)

// Enrollment links created in this session (prototype stops at "link created")
export interface PendingEnrollment { id: string; identityId: string; deviceName: string; platform: Platform; keyMode: 'device' | 'server'; link: string; createdAt: string }
const pendingStore = createStore<PendingEnrollment[]>([])
export const addPending = (p: PendingEnrollment) => pendingStore.set((prev) => [p, ...prev])
export const usePending = (identityId: string) => useStoreValue(pendingStore).filter((p) => p.identityId === identityId)

// Toasts
export interface ToastItem { id: number; title: string; body?: string; tone: 'valid' | 'warn' | 'crit' | 'gold' }
export const toastStore = createStore<ToastItem[]>([])
let toastSeq = 0
export function toast(title: string, body?: string, tone: ToastItem['tone'] = 'valid') {
  toastStore.set((prev) => [...prev, { id: ++toastSeq, title, body, tone }])
}
export const useToasts = () => useStoreValue(toastStore)

// ── Formatting ───────────────────────────────────────────────────────────
/** Relative time for events that happened in the past. Store mutations stamp real wall-clock
 *  time, which can sit after the fixed demo clock; those read as "just now". */
export function ago(iso: string | null): string {
  if (!iso) return 'Never'
  return new Date(iso).getTime() > now().getTime() ? 'just now' : relativeTime(iso, now())
}
export const remainingDays = (iso: string) => daysUntil(iso, now())
export function remainingLabel(c: Pick<Certificate, 'notAfter' | 'status'>): string {
  if (c.status === 'revoked') return 'Revoked'
  const d = remainingDays(c.notAfter)
  if (d < 0) return `${-d} d ago`
  if (d === 0) return 'Today'
  return `${d} d`
}
export const shortSerial = (s: string) => `${s.slice(0, 4)} ${s.slice(4, 8)} ${s.slice(8, 12)}…`
export const formatSeconds = (s: number | null) => (s === null ? '—' : s < 90 ? `${s} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`)

export function tenantCode(t: Pick<Tenant, 'name'>): string {
  const words = t.name.replace(/[^A-Za-z ]/g, '').split(/\s+/).filter(Boolean)
  const code = words.length >= 3 ? words.slice(0, 3).map((w) => w[0]).join('') : (words[0].slice(0, 2) + (words[1]?.[0] ?? words[0][2] ?? 'X'))
  return code.toUpperCase()
}
export const tenantShort = (t: Pick<Tenant, 'name'>) => t.name.split(' ')[0]

export function monogram(t: Pick<Tenant, 'name'>) {
  const w = t.name.split(' ')
  return (w[0][0] + (w[1]?.[0] ?? '')).toUpperCase()
}

// ── Tones ───────────────────────────────────────────────────────────────
export type Tone = 'valid' | 'warn' | 'crit' | 'neutral' | 'gold'
export const healthTone: Record<HealthState, Tone> = { ok: 'valid', degraded: 'warn', down: 'crit', unconfigured: 'neutral' }
export const healthLabel: Record<HealthState, string> = { ok: 'Healthy', degraded: 'Degraded', down: 'Down', unconfigured: 'Not configured' }
export const certTone: Record<CertStatus, Tone> = { active: 'valid', expiring: 'warn', expired: 'crit', revoked: 'crit', pending: 'neutral' }
export const certLabel = certStatusLabels
export const toneRank: Record<Tone, number> = { crit: 3, warn: 2, neutral: 1, gold: 0, valid: 0 }
export const worstTone = (tones: Tone[]): Tone => tones.reduce<Tone>((w, t) => (toneRank[t] > toneRank[w] ? t : w), 'valid')
export const riskOf = (t: Tone) => t

export const keyOriginLabel: Record<KeyOrigin, string> = {
  device: 'Generated on the device',
  browser: 'Generated in the enrollment browser',
  csr: 'Generated by the device (CSR)',
  server: 'Generated by EasyEAP (admin mode)',
}

/** Short form for data pages: "ECDSA P-256 · key made on device" */
export const keyOriginShort: Record<KeyOrigin, string> = {
  device: 'key made on device',
  browser: 'key made in enrollment browser',
  csr: 'key from device CSR',
  server: 'key made by EasyEAP',
}

export const certShortLabel: Record<CertStatus, string> = { active: 'Active', expiring: 'Expiring', expired: 'Expired', revoked: 'Revoked', pending: 'Pending' }

export const platformLabel = (p: Platform | null | undefined) => (p ? platformLabels[p] : 'Server')

export const vlanVar = (v: Pick<Vlan, 'color'> | undefined) => (v ? `var(--f-vlan-${v.color})` : 'var(--f-neutral)')

// ── Derived per-identity summary ────────────────────────────────────────
export interface CertSummary { lead: CertStatus | null; count: number; soonest: Certificate | null; byStatus: Partial<Record<CertStatus, number>> }
/** Lead status = the one an admin should act on first: expiring beats active; with no live
 *  certificate, expired beats revoked. */
export function summarizeCerts(certs: Certificate[]): CertSummary {
  const byStatus: Partial<Record<CertStatus, number>> = {}
  for (const c of certs) byStatus[c.status] = (byStatus[c.status] ?? 0) + 1
  if (!certs.length) return { lead: null, count: 0, soonest: null, byStatus }
  const live = certs.filter((c) => c.status === 'active' || c.status === 'expiring')
  const soonest = [...live].sort((a, b) => a.notAfter.localeCompare(b.notAfter))[0] ?? null
  const lead: CertStatus = byStatus.expiring ? 'expiring' : live.length ? 'active' : byStatus.expired ? 'expired' : byStatus.revoked ? 'revoked' : 'pending'
  return { lead, count: certs.length, soonest, byStatus }
}

/** Short reason for a decision, for table snippets. */
export function decisionReason(d: Decision, ruleName: (id: string) => string): string {
  if (d.outcome === 'allow') return d.decidingRuleId ? ruleName(d.decidingRuleId) : 'Tenant default'
  const gate = d.steps.find((s) => (s.kind === 'account' || s.kind === 'certificate') && !s.ok)
  if (gate && gate.kind === 'account') return gate.detail.replace('Directory account is ', 'Account ')
  if (gate && gate.kind === 'certificate') return 'Certificate rejected'
  if (d.decidingRuleId) return ruleName(d.decidingRuleId)
  return 'No rule matched'
}

/** Success rate over a set of auth events. */
export function successRate(events: AuthEvent[]) {
  if (!events.length) return null
  return events.filter((e) => e.result === 'accept').length / events.length
}

export function identityName(identities: Identity[], id: string | null) {
  return identities.find((i) => i.id === id)?.displayName ?? 'Unknown user'
}

export function randomSecret(length = 32) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

export function randomToken() {
  const alphabet = 'ABCDEFGHJKMNPQRSTVWXYZ23456789'
  const bytes = new Uint8Array(12)
  crypto.getRandomValues(bytes)
  const s = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`
}

export const auditLabels: Record<string, string> = {
  'certificate.issue': 'Certificate issued',
  'certificate.revoke': 'Certificate revoked',
  'directory.sync': 'Directory synchronised',
  'directory.sync.failed': 'Directory sync failed',
  'pki.crl.publish': 'CRL published',
  'policy.rule.update': 'Access rule changed',
  'policy.rule.reorder': 'Access rules reordered',
  'radius.client.rotate_secret': 'Shared secret rotated',
  'radius.client.create': 'Controller registered',
  'tenant.create': 'Tenant created',
  'admin.role.grant': 'Administrator role granted',
}
