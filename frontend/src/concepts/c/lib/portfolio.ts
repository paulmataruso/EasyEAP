// Cross-tenant view for the MSP portfolio.
//
// The prototype store only exposes the *current* tenant. For the portfolio we combine:
//   1. live data for the current tenant (passed in),
//   2. the last live snapshot of any tenant visited this session (mutations only happen while a
//      tenant is current, so that snapshot is exact),
//   3. the deterministic seed for tenants not yet visited.
// A shared `usePortfolio()` hook in the store would replace this (noted in the build report).
import { useEffect } from 'react'
import { generateSampleData, type SampleData } from '@/prototype/sample-data/generate'
import { evaluatePolicy } from '@/domain/policy'
import { now, useTenantData } from '@/prototype/store'
import type { Tenant } from '@/domain/types'
import { attentionFor, setupSteps, type TenantData } from './posture'

let seed: SampleData | null = null
const visited = new Map<string, TenantData>()

function seedBundle(tenantId: string): TenantData {
  seed ??= generateSampleData()
  const s = seed
  const by = <T extends { tenantId: string | null }>(xs: T[]) => xs.filter((x) => x.tenantId === tenantId)
  return {
    tenantId,
    identities: by(s.identities),
    groups: by(s.groups),
    devices: by(s.devices),
    cas: by(s.cas),
    templates: by(s.templates),
    certificates: by(s.certificates),
    vlans: by(s.vlans).sort((a, b) => a.vlanId - b.vlanId),
    rules: by(s.rules).sort((a, b) => a.priority - b.priority),
    defaults: s.defaults[tenantId] ?? { defaultAction: 'deny', defaultVlanId: null, maxSnapshotAgeSeconds: 86400 },
    radiusClients: by(s.radiusClients),
    radiusSettings: s.radiusSettings[tenantId],
    authEvents: by(s.authEvents),
    audit: s.audit.filter((a) => a.tenantId === tenantId || a.tenantId === null),
  }
}

/** Call once in the shell: remembers the live bundle of whichever tenant is current. */
export function useRememberCurrentTenant() {
  const d = useTenantData()
  useEffect(() => {
    visited.set(d.tenantId, d)
  }, [d])
}

export interface TenantSummary {
  tenant: Tenant
  users: number
  allowed: number
  expiring: number
  validCerts: number
  authTotal: number
  successRate: number | null
  controllers: number
  controllersQuiet: number
  attention: number
  setup: { done: number; total: number; remaining: ReturnType<typeof setupSteps>; completed: ReturnType<typeof setupSteps> }
}

export function summarize(tenant: Tenant, live: TenantData | null): TenantSummary {
  const d = live && live.tenantId === tenant.id ? live : (visited.get(tenant.id) ?? seedBundle(tenant.id))
  // Same keyed-by-id semantics as the store's useMetrics, so numbers agree across screens.
  const decisions = new Map(d.identities.map((i) => [i.id, evaluatePolicy(i, d.rules, d.defaults, d.vlans, { now: now() })]))
  const allowed = d.identities.filter((i) => decisions.get(i.id)?.outcome === 'allow').length
  const certs = d.certificates.filter((c) => c.identityId)
  const accepts = d.authEvents.filter((e) => e.result === 'accept').length
  const steps = setupSteps(tenant, d)
  return {
    tenant,
    users: d.identities.length,
    allowed,
    expiring: certs.filter((c) => c.status === 'expiring').length,
    validCerts: certs.filter((c) => c.status === 'active' || c.status === 'expiring').length,
    authTotal: d.authEvents.length,
    successRate: d.authEvents.length ? accepts / d.authEvents.length : null,
    controllers: d.radiusClients.length,
    controllersQuiet: d.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down').length,
    attention: tenant.status === 'setup' ? 0 : attentionFor(tenant, d).length,
    setup: { done: steps.filter((s) => s.done).length, total: steps.length, remaining: steps.filter((s) => !s.done), completed: steps.filter((s) => s.done) },
  }
}
