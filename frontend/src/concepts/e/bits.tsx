import { useEffect } from 'react'
import { Ban, CircleCheck, CircleDashed, CircleX, Laptop, Monitor, Smartphone, Tablet, Terminal, TriangleExclamationPoint } from 'lucide-react'
import type { AccessRule, AuthEvent, Certificate, CertStatus, Decision, Identity, Platform, RadiusClient } from '@/domain/types'
import { certStatusLabels, failureExplanations } from '@/domain/explain'
import { generateSampleData, type SampleData } from '@/prototype/sample-data/generate'
import { now, useTenantData, useTenants } from '@/prototype/store'
import { daysUntil } from '@/ui/lib'
import { STATUS } from './theme'

// The synthetic directory can contain two people with the same username (and so the same identity
// id). Links carry the objectGUID as a suffix only when the id is ambiguous.
export function userKey(i: Identity, all: Identity[]) {
  return all.filter((x) => x.id === i.id).length > 1 ? `${i.id}~${i.objectGuid}` : i.id
}
export function findUser(entityId: string | undefined, all: Identity[]) {
  if (!entityId) return undefined
  const [id, guid] = entityId.split('~')
  return all.find((i) => i.id === id && (!guid || i.objectGuid === guid))
}

export const CERT_RANK: Record<CertStatus, number> = { expired: 0, revoked: 1, expiring: 2, pending: 3, active: 4 }

export function CertStatusMark({ cert, short }: { cert: Pick<Certificate, 'status' | 'notAfter'>; short?: boolean }) {
  const s = cert.status
  const days = daysUntil(cert.notAfter, now())
  const icon =
    s === 'active' ? <CircleCheck color={STATUS.ok.hex} aria-hidden /> :
    s === 'expiring' ? <TriangleExclamationPoint color={STATUS.degraded.hex} aria-hidden /> :
    s === 'expired' ? <CircleX color={STATUS.down.hex} aria-hidden /> :
    s === 'revoked' ? <Ban color={STATUS.down.hex} aria-hidden /> : <CircleDashed color={STATUS.unconfigured.hex} aria-hidden />
  const label = s === 'expiring' && !short ? `Expires in ${days} d` : certStatusLabels[s]
  return <span className="e-state">{icon}<span>{label}</span></span>
}

export const PLATFORM_ICON: Record<Platform, typeof Monitor> = { windows: Monitor, macos: Laptop, ios: Tablet, android: Smartphone, linux: Terminal }

export function AccessMark({ decision }: { decision: Decision | undefined }) {
  if (!decision) return null
  return decision.outcome === 'allow'
    ? <span className="e-state"><CircleCheck color={STATUS.ok.hex} aria-hidden /><span>Allowed</span></span>
    : <span className="e-state"><CircleX color={STATUS.down.hex} aria-hidden /><span>Denied</span></span>
}

/** One-line plain-language reason for a decision. */
export function decisionReason(decision: Decision, rules: AccessRule[]): string {
  const acct = decision.steps.find((s) => s.kind === 'account')
  if (acct && acct.kind === 'account' && !acct.ok) return acct.detail
  const cert = decision.steps.find((s) => s.kind === 'certificate')
  if (cert && cert.kind === 'certificate' && !cert.ok) return cert.detail
  const rule = rules.find((r) => r.id === decision.decidingRuleId)
  if (rule) return `${rule.action === 'deny' ? 'Denied' : 'Allowed'} by “${rule.name}”`
  return 'No rule matched; tenant default applies'
}

export function failureTitle(e: AuthEvent) {
  return e.failureCode ? failureExplanations[e.failureCode].title : null
}

export function certSummary(certs: Certificate[]) {
  const live = certs.filter((c) => c.status === 'active' || c.status === 'expiring')
  const worst = [...certs].sort((a, b) => CERT_RANK[a.status] - CERT_RANK[b.status] || a.notAfter.localeCompare(b.notAfter))
  return { live, worst: worst[0] ?? null, rank: certs.length ? Math.min(...certs.map((c) => CERT_RANK[c.status])) : 5 }
}

// ── Portfolio stats per tenant ──────────────────────────────────────────────
export interface TenantStats {
  users: number
  expiring: number
  events: number
  accepts: number
  controllers: number
  degradedControllers: number
  serverCert: boolean
  rules: number
  issuingCa: boolean
}
let base: SampleData | null = null
const liveStats = new Map<string, TenantStats>()

function statsFrom(x: { identities: Identity[]; certificates: Certificate[]; authEvents: AuthEvent[]; radiusClients: RadiusClient[]; rules: AccessRule[]; cas: { role: string }[]; serverCert: boolean }): TenantStats {
  const since = now().getTime() - 24 * 3600_000
  const ev = x.authEvents.filter((e) => new Date(e.at).getTime() > since)
  return {
    users: x.identities.length,
    expiring: x.certificates.filter((c) => c.identityId && c.status === 'expiring').length,
    events: ev.length,
    accepts: ev.filter((e) => e.result === 'accept').length,
    controllers: x.radiusClients.length,
    degradedControllers: x.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down').length,
    serverCert: x.serverCert,
    rules: x.rules.length,
    issuingCa: x.cas.some((c) => c.role === 'issuing'),
  }
}

export function tenantStats(id: string): TenantStats {
  const l = liveStats.get(id)
  if (l) return l
  base ??= generateSampleData()
  const by = <T extends { tenantId: string | null }>(xs: T[]) => xs.filter((v) => v.tenantId === id)
  return statsFrom({ identities: by(base.identities), certificates: by(base.certificates), authEvents: by(base.authEvents), radiusClients: by(base.radiusClients), rules: by(base.rules), cas: by(base.cas), serverCert: !!base.radiusSettings[id]?.serverCertificateId })
}

/** Records the current tenant's live numbers so the portfolio reflects this session's changes. */
export function useRecordTenantStats() {
  const d = useTenantData()
  const { current } = useTenants()
  useEffect(() => {
    liveStats.set(current.id, statsFrom({ identities: d.identities, certificates: d.certificates, authEvents: d.authEvents, radiusClients: d.radiusClients, rules: d.rules, cas: d.cas, serverCert: !!d.radiusSettings?.serverCertificateId }))
  }, [d, current.id])
}
