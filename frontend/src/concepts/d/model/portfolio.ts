// Portfolio snapshots for the MSP view. The store only exposes the current tenant, so other
// tenants start from the deterministic sample data and are replaced by live snapshots
// as soon as they have been the current tenant in this session.
import { useEffect, useMemo } from 'react'
import { evaluatePolicy } from '@/domain/policy'
import { generateSampleData } from '@/prototype/sample-data/generate'
import { now, useMetrics, useTenantData } from '@/prototype/store'
import { snapshotFrom, type TenantSnapshot } from './derive'

let baseline: Map<string, TenantSnapshot> | null = null
const live = new Map<string, TenantSnapshot>()

function computeBaseline() {
  const data = generateSampleData()
  const out = new Map<string, TenantSnapshot>()
  for (const t of data.tenants) {
    const by = <T extends { tenantId: string | null }>(xs: T[]) => xs.filter((x) => x.tenantId === t.id)
    const identities = by(data.identities)
    const rules = by(data.rules)
    const vlans = by(data.vlans)
    const defaults = data.defaults[t.id]
    const allowed = identities.filter((i) => evaluatePolicy(i, rules, defaults, vlans, { now: now() }).outcome === 'allow').length
    out.set(t.id, snapshotFrom({ identities, allowed, certificates: by(data.certificates), authEvents: by(data.authEvents), radiusClients: by(data.radiusClients), hasServerCert: !!data.radiusSettings[t.id]?.serverCertificateId }))
  }
  return out
}

export function portfolioSnapshot(tenantId: string): TenantSnapshot | undefined {
  if (live.has(tenantId)) return live.get(tenantId)
  baseline ??= computeBaseline()
  return baseline.get(tenantId)
}

export function useLiveSnapshot(): TenantSnapshot {
  const d = useTenantData()
  const m = useMetrics()
  return useMemo(
    () => snapshotFrom({ identities: d.identities, allowed: m.authorized, certificates: d.certificates, authEvents: d.authEvents, radiusClients: d.radiusClients, hasServerCert: !!d.radiusSettings?.serverCertificateId }),
    [d, m.authorized],
  )
}

/** Mounted once in the shell: keeps the current tenant's snapshot fresh for the portfolio. */
export function useRecordSnapshot() {
  const d = useTenantData()
  const snap = useLiveSnapshot()
  useEffect(() => { live.set(d.tenantId, snap) }, [d.tenantId, snap])
}
