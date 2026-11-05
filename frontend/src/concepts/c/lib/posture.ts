// Derives what needs attention, setup progress and the one-sentence posture for a tenant.
// Pure functions over a tenant's data bundle so the dashboard (live store) and the MSP portfolio
// (every tenant) use the same rules.
import type { useTenantData } from '@/prototype/store'
import { now } from '@/prototype/store'
import { failureExplanations } from '@/domain/explain'
import type { Decision, FailureCode, Tenant } from '@/domain/types'
import type { ScreenId } from '../../contract'
import type { Intent } from '../app/context'
import { ageOf, firstName, plural, possessive } from './format'

export type TenantData = ReturnType<typeof useTenantData>

export interface AttentionItem {
  id: string
  tone: 'crit' | 'warn' | 'info'
  title: string
  detail: string
  action?: { label: string; screen: ScreenId; intent?: Intent }
}

/** Rejections where EasyEAP did exactly what policy says; not something to fix. */
export const INTENDED_REJECTIONS: FailureCode[] = ['account_disabled', 'cert_revoked', 'policy_deny', 'identity_unauthorized']

export interface SetupStep {
  id: string
  title: string
  detail: string
  done: boolean
  action?: { label: string; screen: ScreenId; intent?: Intent }
}

export function setupSteps(tenant: Tenant, d: TenantData): SetupStep[] {
  const root = d.cas.find((c) => c.role === 'root')
  return [
    { id: 'tenant', title: 'Create the tenant', detail: `${tenant.domain} registered`, done: true },
    { id: 'pki', title: 'Initialise the PKI', detail: root ? `${root.commonName} kept offline, issuing CA online` : 'Create an offline root and an issuing CA', done: d.cas.length >= 2 },
    { id: 'directory', title: 'Connect Active Directory', detail: 'LDAPS bind account and the groups to synchronise', done: tenant.health.directory !== 'unconfigured' },
    { id: 'policy', title: 'Define VLANs and access rules', detail: `${plural(d.vlans.length, 'VLAN')}, ${plural(d.rules.length, 'rule')}`, done: d.rules.length > 0 && d.vlans.length > 0, action: { label: 'Review policies', screen: 'policies' } },
    { id: 'server-cert', title: 'Issue the RADIUS server certificate', detail: `Devices check this name: ${d.radiusSettings?.serverHostname ?? 'radius server'}`, done: Boolean(d.radiusSettings?.serverCertificateId), action: { label: 'Open RADIUS', screen: 'radius', intent: { radius: { focus: 'server' } } } },
    { id: 'controller', title: 'Add a wireless controller', detail: 'Register the WLC or UniFi controller as a RADIUS client', done: d.radiusClients.length > 0, action: { label: 'Add controller', screen: 'radius', intent: { radius: { add: true } } } },
    { id: 'first-cert', title: 'Issue the first Wi-Fi certificate', detail: 'Send an enrollment link to one person to prove the path end to end', done: d.certificates.some((c) => c.identityId), action: { label: 'Choose a person', screen: 'users' } },
  ]
}

export function failureBreakdown(d: TenantData) {
  const counts = new Map<FailureCode, number>()
  for (const e of d.authEvents) if (e.failureCode) counts.set(e.failureCode, (counts.get(e.failureCode) ?? 0) + 1)
  return [...counts.entries()].sort((a, b) => b[1] - a[1])
}

export function attentionFor(tenant: Tenant, d: TenantData): AttentionItem[] {
  const items: AttentionItem[] = []
  const nowMs = now().getTime()

  if (tenant.status === 'setup') {
    const remaining = setupSteps(tenant, d).filter((s) => !s.done)
    for (const step of remaining) items.push({ id: `setup-${step.id}`, tone: 'info', title: step.title, detail: step.detail, action: step.action })
    return items
  }

  const snapshotAge = tenant.health.authzSnapshotAgeSeconds
  if (snapshotAge !== null && snapshotAge > d.defaults.maxSnapshotAgeSeconds) {
    items.push({ id: 'snapshot', tone: 'crit', title: 'RADIUS is denying everyone: authorization data is out of date', detail: failureExplanations.snapshot_stale.fix, action: { label: 'Open RADIUS', screen: 'radius' } })
  }

  for (const c of d.radiusClients.filter((x) => x.status === 'degraded' || x.status === 'down')) {
    items.push({
      id: `nas-${c.id}`,
      tone: c.status === 'down' ? 'crit' : 'warn',
      title: c.status === 'down' ? `${c.name} is not responding` : `${c.name} is degraded`,
      detail: `No RADIUS requests for ${ageOf(c.lastRequestAt)}. People at ${c.site} may be failing to join; check the controller can reach ${d.radiusSettings?.serverHostname ?? 'the RADIUS server'} on UDP ${d.radiusSettings?.authPort ?? 1812}.`,
      action: { label: 'Review controller', screen: 'radius', intent: { radius: { expand: c.id } } },
    })
  }

  if (tenant.health.directory === 'degraded' || tenant.health.directory === 'down') {
    const failure = d.audit.find((a) => a.action === 'directory.sync.failed' && a.tenantId === tenant.id)
    items.push({
      id: 'directory',
      tone: tenant.health.directory === 'down' ? 'crit' : 'warn',
      title: `Directory sync has failed for ${ageOf(tenant.health.lastDirectorySync)}`,
      detail: `${failure ? `${failure.detail}. ` : ''}RADIUS keeps using the last good copy until it is older than ${Math.round(d.defaults.maxSnapshotAgeSeconds / 3600)} hours, then denies everyone.`,
      action: { label: 'View people', screen: 'users' },
    })
  }

  const expiring = d.certificates.filter((c) => c.status === 'expiring' && c.identityId).sort((a, b) => a.notAfter.localeCompare(b.notAfter))
  if (expiring.length) {
    const soonest = expiring[0]
    const owner = d.identities.find((i) => i.id === soonest.identityId)
    const device = d.devices.find((x) => x.id === soonest.deviceId)
    const days = Math.max(1, Math.ceil((new Date(soonest.notAfter).getTime() - nowMs) / 864e5))
    items.push({
      id: 'expiring',
      tone: 'warn',
      title: `${plural(expiring.length, 'certificate')} expire within 30 days`,
      detail: `The soonest is ${device ? device.name : owner ? `${possessive(firstName(owner.displayName))} device` : soonest.commonName}, in ${plural(days, 'day')}. People renew from their enrollment page; nothing changes on the network until a certificate lapses.`,
      action: { label: 'Review expiring', screen: 'certificates', intent: { certificates: { status: 'expiring' } } },
    })
  }

  const fixable = failureBreakdown(d).filter(([code]) => !INTENDED_REJECTIONS.includes(code))
  const fixableTotal = fixable.reduce((s, [, n]) => s + n, 0)
  if (d.authEvents.length && fixableTotal >= 5 && fixableTotal / d.authEvents.length >= 0.04) {
    const top = fixable.slice(0, 2).map(([code, n]) => `${failureExplanations[code].title.toLowerCase()} (${n})`)
    items.push({
      id: 'failures',
      tone: 'warn',
      title: `${plural(fixableTotal, 'authentication')} failed for fixable reasons in 24 hours`,
      detail: `Most often: ${top.join(' and ')}. Rejections from disabled accounts and revoked certificates are not counted; those are policy working as intended.`,
      action: { label: 'See why', screen: 'dashboard', intent: { dashboard: { focus: 'failures' } } },
    })
  }
  return items
}

export interface Posture {
  /** First clause, e.g. "Harborview Logistics is healthy." */
  state: string
  /** Second clause, e.g. "3 things need attention." */
  rest: string
  tone: 'ok' | 'warn' | 'crit' | 'setup'
}

export function postureOf(tenant: Tenant, items: AttentionItem[]): Posture {
  if (tenant.status === 'setup') {
    return { state: `${tenant.name} is still being set up.`, rest: `${plural(items.length, 'step')} ${items.length === 1 ? 'remains' : 'remain'}.`, tone: 'setup' }
  }
  const services = [tenant.health.radius, tenant.health.pki, tenant.health.directory]
  const rest = items.length === 0 ? 'Nothing needs attention.' : `${items.length === 1 ? 'One thing needs' : `${items.length} things need`} attention.`
  if (services.includes('down') || items.some((i) => i.tone === 'crit')) return { state: `${tenant.name} has a problem.`, rest, tone: 'crit' }
  if (services.includes('degraded')) return { state: `${tenant.name} is degraded.`, rest, tone: 'warn' }
  return { state: `${tenant.name} is healthy.`, rest, tone: 'ok' }
}

/** Best certificate summary for a person: the most urgent valid certificate, else the latest state. */
export function certificateSummaryFor(identityId: string, d: TenantData) {
  const certs = d.certificates.filter((c) => c.identityId === identityId)
  if (!certs.length) return { status: 'none' as const, cert: null, count: 0 }
  const rank = { expiring: 0, active: 1, expired: 2, pending: 3, revoked: 4 } as const
  const sorted = [...certs].sort((a, b) => rank[a.status] - rank[b.status] || a.notAfter.localeCompare(b.notAfter))
  return { status: sorted[0].status, cert: sorted[0], count: certs.length }
}

/** Why a decision denied, in one clause ("account is disabled", "Block former employees"). */
export function denialReason(decision: Decision, ruleName: (id: string) => string | undefined): string {
  if (decision.outcome === 'allow') return ''
  const account = decision.steps.find((s) => s.kind === 'account' && !s.ok)
  if (account && account.kind === 'account') return account.detail.replace('Directory account is', 'Account').trim()
  const cert = decision.steps.find((s) => s.kind === 'certificate' && !s.ok)
  if (cert) return 'Certificate not valid'
  if (decision.decidingRuleId) return `Deny rule: ${ruleName(decision.decidingRuleId) ?? 'unknown rule'}`
  return 'No rule matched'
}
