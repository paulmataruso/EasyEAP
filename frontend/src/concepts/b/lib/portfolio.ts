// Cross-tenant summaries for the MSP portfolio and the tenant tab strip.
// The prototype store only exposes the *current* tenant's collections, so other tenants are seeded
// from the same deterministic synthetic generator and replaced by live store data whenever a tenant
// has been current in this session. Production replaces this module with a portfolio API call.
import { generateSampleData } from '@/prototype/sample-data/generate'
import { evaluatePolicy } from '@/domain/policy'
import { now } from '@/prototype/store'
import type { ScreenId } from '@/concepts/contract'
import type { AccessRule, AuditEvent, AuthEvent, Certificate, CertificateAuthority, Identity, PolicyDefaults, RadiusClient, RadiusSettings, Tenant, Vlan } from '@/domain/types'

export interface TenantSummary {
  tenantId: string
  users: number
  authorized: number
  certificates: { total: number; active: number; expiring: number; expired: number; revoked: number }
  auth: { total: number; accepts: number; rejects: number; successRate: number | null }
  controllers: { total: number; ok: number; degraded: number; down: number; unhealthy: Array<{ name: string; site: string; lastRequestAt: string | null }> }
  lastDirectoryError: string | null
  rules: number
  vlans: number
  hasRoot: boolean
  hasIssuingCa: boolean
  serverCertificate: boolean
  lastEventAt: string | null
}

export interface SummaryInput {
  tenantId: string
  identities: Identity[]
  certificates: Certificate[]
  authEvents: AuthEvent[]
  radiusClients: RadiusClient[]
  rules: AccessRule[]
  vlans: Vlan[]
  cas: CertificateAuthority[]
  radiusSettings: RadiusSettings | undefined
  audit: AuditEvent[]
}

export function summarize(d: SummaryInput, authorized: number): TenantSummary {
  const certs = d.certificates.filter((c) => c.identityId)
  const accepts = d.authEvents.filter((e) => e.result === 'accept').length
  return {
    tenantId: d.tenantId,
    users: d.identities.length,
    authorized,
    certificates: {
      total: certs.length,
      active: certs.filter((c) => c.status === 'active').length,
      expiring: certs.filter((c) => c.status === 'expiring').length,
      expired: certs.filter((c) => c.status === 'expired').length,
      revoked: certs.filter((c) => c.status === 'revoked').length,
    },
    auth: { total: d.authEvents.length, accepts, rejects: d.authEvents.length - accepts, successRate: d.authEvents.length ? accepts / d.authEvents.length : null },
    controllers: {
      total: d.radiusClients.length,
      ok: d.radiusClients.filter((c) => c.status === 'ok').length,
      degraded: d.radiusClients.filter((c) => c.status === 'degraded').length,
      down: d.radiusClients.filter((c) => c.status === 'down').length,
      unhealthy: d.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down').map((c) => ({ name: c.name, site: c.site, lastRequestAt: c.lastRequestAt })),
    },
    lastDirectoryError: d.audit.find((a) => a.tenantId === d.tenantId && a.action === 'directory.sync.failed')?.detail ?? null,
    rules: d.rules.filter((r) => r.enabled).length,
    vlans: d.vlans.length,
    hasRoot: d.cas.some((c) => c.role === 'root'),
    hasIssuingCa: d.cas.some((c) => c.role === 'issuing'),
    serverCertificate: Boolean(d.radiusSettings?.serverCertificateId),
    lastEventAt: d.authEvents.reduce<string | null>((m, e) => (!m || e.at > m ? e.at : m), null),
  }
}

let seeded: Map<string, TenantSummary> | null = null
/** Deterministic per-tenant summaries from the synthetic generator (computed once). */
export function seedSummaries(): Map<string, TenantSummary> {
  if (seeded) return seeded
  const data = generateSampleData()
  const out = new Map<string, TenantSummary>()
  for (const t of data.tenants) {
    const by = <T extends { tenantId: string | null }>(xs: T[]) => xs.filter((x) => x.tenantId === t.id)
    const identities = by(data.identities)
    const rules = by(data.rules)
    const vlans = by(data.vlans)
    const defaults: PolicyDefaults = data.defaults[t.id] ?? { defaultAction: 'deny', defaultVlanId: null, maxSnapshotAgeSeconds: 86400 }
    const authorized = identities.filter((i) => evaluatePolicy(i, rules, defaults, vlans, { now: now() }).outcome === 'allow').length
    out.set(
      t.id,
      summarize(
        { tenantId: t.id, identities, certificates: by(data.certificates), authEvents: by(data.authEvents), radiusClients: by(data.radiusClients), rules, vlans, cas: by(data.cas), radiusSettings: data.radiusSettings[t.id], audit: by(data.audit) },
        authorized,
      ),
    )
  }
  seeded = out
  return out
}

export interface SetupStep {
  id: string
  label: string
  hint: string
  done: boolean
  screen: ScreenId
}

/** Onboarding checklist derived from what actually exists for the tenant. */
export function setupSteps(t: Tenant, s: TenantSummary): SetupStep[] {
  return [
    { id: 'created', label: 'Tenant created', hint: 'Workspace, audit trail and admin roles exist.', done: true, screen: 'tenants' },
    { id: 'pki', label: 'PKI initialised', hint: 'Offline root CA and an online issuing CA.', done: s.hasRoot && s.hasIssuingCa, screen: 'certificates' },
    { id: 'policy', label: 'VLANs and access rules defined', hint: 'At least one enabled rule and one VLAN.', done: s.rules > 0 && s.vlans > 0, screen: 'policies' },
    { id: 'directory', label: 'Connect Active Directory', hint: 'Add LDAPS bind credentials and run the first sync.', done: t.health.directory !== 'unconfigured', screen: 'users' },
    { id: 'server-cert', label: 'Issue the RADIUS server certificate', hint: 'Devices verify this name before sending their certificate.', done: s.serverCertificate, screen: 'radius' },
    { id: 'controller', label: 'Register a wireless controller', hint: 'Add the controller and paste its shared secret.', done: s.controllers.total > 0, screen: 'radius' },
    { id: 'first-cert', label: 'Issue the first Wi-Fi certificate', hint: 'Pick a user and send them an enrollment link.', done: s.certificates.total > 0, screen: 'users' },
  ]
}
