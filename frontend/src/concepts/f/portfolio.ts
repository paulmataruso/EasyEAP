// Cross-tenant figures for the MSP portfolio. The prototype store only exposes the current
// tenant, so other tenants are read from the same deterministic generator the store seeds from,
// overlaid with live figures for any tenant visited in this session (so revocations etc. show).
import { evaluatePolicy } from '@/domain/policy'
import { DEMO_NOW, generateSampleData, type SampleData } from '@/prototype/sample-data/generate'
import type { useTenantData } from '@/prototype/store'

type TenantData = ReturnType<typeof useTenantData>

export interface SetupStep { key: string; label: string; done: boolean; hint: string }
export interface TenantStats {
  users: number
  authorized: number
  expiring: number
  expired: number
  events: number
  successRate: number | null
  controllers: number
  controllersDegraded: number
  setup: SetupStep[]
}

export function computeStats(d: Pick<TenantData, 'identities' | 'rules' | 'defaults' | 'vlans' | 'certificates' | 'authEvents' | 'radiusClients' | 'radiusSettings' | 'cas'>, directoryConfigured: boolean): TenantStats {
  const authorized = d.identities.filter((i) => evaluatePolicy(i, d.rules, d.defaults, d.vlans, { now: DEMO_NOW }).outcome === 'allow').length
  const userCerts = d.certificates.filter((c) => c.identityId)
  const accepts = d.authEvents.filter((e) => e.result === 'accept').length
  const setup: SetupStep[] = [
    { key: 'pki', label: 'Initialise PKI (offline root + issuing CA)', done: d.cas.some((c) => c.role === 'root') && d.cas.some((c) => c.role === 'issuing'), hint: 'Creates the tenant’s own certificate authorities.' },
    { key: 'directory', label: 'Connect Active Directory', done: directoryConfigured, hint: 'LDAPS bind account and base DN; groups drive VLAN assignment.' },
    { key: 'server-cert', label: 'Issue the RADIUS server certificate', done: !!d.radiusSettings?.serverCertificateId, hint: `Devices check this name: ${d.radiusSettings?.serverHostname ?? 'radius.<domain>'}.` },
    { key: 'controller', label: 'Register a wireless controller', done: d.radiusClients.length > 0, hint: 'Adds the controller as a RADIUS client and generates its shared secret.' },
    { key: 'enroll', label: 'Enroll the first device', done: userCerts.length > 0, hint: 'Issue a Wi-Fi certificate from any user’s record.' },
  ]
  return {
    users: d.identities.length,
    authorized,
    expiring: userCerts.filter((c) => c.status === 'expiring').length,
    expired: userCerts.filter((c) => c.status === 'expired').length,
    events: d.authEvents.length,
    successRate: d.authEvents.length ? accepts / d.authEvents.length : null,
    controllers: d.radiusClients.length,
    controllersDegraded: d.radiusClients.filter((n) => n.status === 'degraded' || n.status === 'down').length,
    setup,
  }
}

let seed: SampleData | null = null
const live = new Map<string, TenantStats>()

export function recordLiveStats(tenantId: string, stats: TenantStats) {
  live.set(tenantId, stats)
}

export function statsFor(tenantId: string, directoryConfigured: boolean): TenantStats {
  const cached = live.get(tenantId)
  if (cached) return cached
  seed ??= generateSampleData()
  const s = seed
  const by = <T extends { tenantId: string | null }>(xs: T[]) => xs.filter((x) => x.tenantId === tenantId)
  return computeStats(
    {
      identities: by(s.identities),
      rules: by(s.rules).sort((a, b) => a.priority - b.priority),
      defaults: s.defaults[tenantId],
      vlans: by(s.vlans),
      certificates: by(s.certificates),
      authEvents: by(s.authEvents),
      radiusClients: by(s.radiusClients),
      radiusSettings: s.radiusSettings[tenantId],
      cas: by(s.cas),
    },
    directoryConfigured,
  )
}
