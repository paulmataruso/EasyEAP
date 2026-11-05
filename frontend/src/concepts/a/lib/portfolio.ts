// Portfolio (MSP) aggregates across tenants.
// The shared store only exposes the *current* tenant's collections, so the current tenant is
// computed live from the store and the others from the deterministic seed snapshot
// (generateSampleData() is seeded, so it returns exactly the data the store started with).
// A shared `usePortfolio()` hook in the store would make every tenant live; see the report.
import { useMemo } from 'react'
import { evaluatePolicy } from '@/domain/policy'
import type { AuthEvent, Certificate, CertificateAuthority, DirectoryGroup, Identity, RadiusClient, RadiusSettings, Tenant } from '@/domain/types'
import { DEMO_NOW, generateSampleData, type SampleData } from '@/prototype/sample-data/generate'
import { useTenantData, useTenants } from '@/prototype/store'

export interface SetupStep {
  id: string
  label: string
  detail: string
  done: boolean
}

export interface TenantSummary {
  tenant: Tenant
  users: number
  authorized: number
  expiring: number
  certificates: number
  events24h: number
  accepts24h: number
  successRate: number | null
  controllers: RadiusClient[]
  steps: SetupStep[]
  live: boolean
}

let seed: SampleData | null = null
const getSeed = () => (seed ??= generateSampleData())

interface Slice {
  identities: Identity[]
  groups: DirectoryGroup[]
  certificates: Certificate[]
  cas: CertificateAuthority[]
  radiusClients: RadiusClient[]
  radiusSettings: RadiusSettings | undefined
  authEvents: AuthEvent[]
  rules: SampleData['rules']
  vlans: SampleData['vlans']
  defaults: SampleData['defaults'][string]
}

export function setupSteps(t: Tenant, s: Pick<Slice, 'cas' | 'certificates' | 'radiusClients' | 'radiusSettings' | 'identities'>): SetupStep[] {
  const hasRoot = s.cas.some((c) => c.role === 'root')
  const hasIssuing = s.cas.some((c) => c.role === 'issuing')
  const userCerts = s.certificates.filter((c) => c.identityId).length
  return [
    { id: 'tenant', label: 'Create tenant', detail: `${t.name} · ${t.domain}`, done: true },
    { id: 'pki', label: 'Initialise PKI', detail: hasRoot && hasIssuing ? 'Offline root and issuing CA created' : 'Create the offline root and issuing CA', done: hasRoot && hasIssuing },
    { id: 'directory', label: 'Connect Active Directory', detail: t.health.lastDirectorySync ? 'LDAPS bind and first sync complete' : 'Add LDAPS bind credentials and run the first sync', done: t.health.directory !== 'unconfigured' && !!t.health.lastDirectorySync },
    { id: 'server-cert', label: 'Issue the RADIUS server certificate', detail: s.radiusSettings?.serverCertificateId ? `radius.${t.domain}` : `Issue radius.${t.domain} from the issuing CA`, done: !!s.radiusSettings?.serverCertificateId },
    { id: 'controller', label: 'Add a wireless controller', detail: s.radiusClients.length ? `${s.radiusClients.length} registered` : 'Register a controller and copy its shared secret', done: s.radiusClients.length > 0 },
    { id: 'first-cert', label: 'Issue the first Wi-Fi certificate', detail: userCerts ? `${userCerts} issued` : 'Enroll one device end to end to prove the setup', done: userCerts > 0 },
  ]
}

function summarize(t: Tenant, s: Slice, live: boolean): TenantSummary {
  const start = DEMO_NOW.getTime() - 24 * 3600_000
  const ev = s.authEvents.filter((e) => new Date(e.at).getTime() > start)
  const accepts = ev.filter((e) => e.result === 'accept').length
  const authorized = s.identities.filter((i) => evaluatePolicy(i, s.rules, s.defaults, s.vlans, { now: DEMO_NOW }).outcome === 'allow').length
  const certs = s.certificates.filter((c) => c.identityId)
  return {
    tenant: t,
    users: s.identities.length,
    authorized,
    expiring: certs.filter((c) => c.status === 'expiring').length,
    certificates: certs.length,
    events24h: ev.length,
    accepts24h: accepts,
    successRate: ev.length ? accepts / ev.length : null,
    controllers: s.radiusClients,
    steps: setupSteps(t, s),
    live,
  }
}

function seedSlice(tenantId: string): Slice {
  const d = getSeed()
  const by = <T extends { tenantId: string | null }>(xs: T[]) => xs.filter((x) => x.tenantId === tenantId)
  return {
    identities: by(d.identities),
    groups: by(d.groups),
    certificates: by(d.certificates),
    cas: by(d.cas),
    radiusClients: by(d.radiusClients),
    radiusSettings: d.radiusSettings[tenantId],
    authEvents: by(d.authEvents),
    rules: by(d.rules).sort((a, b) => a.priority - b.priority),
    vlans: by(d.vlans),
    defaults: d.defaults[tenantId] ?? { defaultAction: 'deny', defaultVlanId: null, maxSnapshotAgeSeconds: 86400 },
  }
}

export function usePortfolio(): TenantSummary[] {
  const { tenants, current } = useTenants()
  const live = useTenantData()
  return useMemo(
    () =>
      tenants.map((t) =>
        t.id === current.id
          ? summarize(t, { ...live, radiusSettings: live.radiusSettings }, true)
          : summarize(t, seedSlice(t.id), false),
      ),
    [tenants, current.id, live],
  )
}

export function useSetupSteps(): SetupStep[] {
  const { current } = useTenants()
  const d = useTenantData()
  return useMemo(() => setupSteps(current, d), [current, d])
}
