// In-memory store for the design prototypes. Every concept reads data through these hooks,
// so all six render identical synthetic data and the same interactions mutate it.
import { createContext, useContext, useMemo, useReducer, type ReactNode } from 'react'
import { DEMO_NOW, generateSampleData, type SampleData } from './sample-data/generate'
import { evaluatePolicy } from '@/domain/policy'
import type { AccessRule, Certificate, Decision, Identity, RadiusClient, RevocationReason } from '@/domain/types'

interface State extends SampleData {
  tenantId: string
}

type Action =
  | { type: 'tenant.switch'; tenantId: string }
  | { type: 'certificate.revoke'; id: string; reason: RevocationReason }
  | { type: 'rule.move'; id: string; direction: -1 | 1 }
  | { type: 'rule.toggle'; id: string }
  | { type: 'radiusClient.add'; client: Omit<RadiusClient, 'id' | 'tenantId' | 'secretSetAt' | 'lastRequestAt' | 'status'> }
  | { type: 'radiusClient.rotate'; id: string }

const ACTOR = 'm.okafor@brightline.example'

function audit(state: State, action: string, target: string, detail: string): State {
  return {
    ...state,
    audit: [{ id: `au-${state.audit.length + 1}-${Date.now()}`, tenantId: state.tenantId, at: new Date().toISOString(), actor: ACTOR, action, target, detail }, ...state.audit],
  }
}

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'tenant.switch':
      return { ...state, tenantId: action.tenantId }
    case 'certificate.revoke': {
      const cert = state.certificates.find((c) => c.id === action.id)
      if (!cert || cert.status === 'revoked') return state
      const next = { ...state, certificates: state.certificates.map((c) => (c.id === action.id ? { ...c, status: 'revoked' as const, revokedAt: new Date().toISOString(), revocationReason: action.reason, revokedBy: ACTOR } : c)) }
      return audit(next, 'certificate.revoke', cert.commonName, `Revoked serial ${cert.serial} (${action.reason}); CRL regenerated, authorization snapshot updated`)
    }
    case 'rule.move': {
      const tenantRules = state.rules.filter((r) => r.tenantId === state.tenantId).sort((a, b) => a.priority - b.priority)
      const idx = tenantRules.findIndex((r) => r.id === action.id)
      const swap = tenantRules[idx + action.direction]
      if (idx < 0 || !swap) return state
      const a = tenantRules[idx]
      const rules = state.rules.map((r) => (r.id === a.id ? { ...r, priority: swap.priority } : r.id === swap.id ? { ...r, priority: a.priority } : r))
      return audit({ ...state, rules }, 'policy.rule.reorder', a.name, `Moved ${action.direction < 0 ? 'up' : 'down'} to priority ${swap.priority}`)
    }
    case 'rule.toggle': {
      const rule = state.rules.find((r) => r.id === action.id)
      if (!rule) return state
      const rules = state.rules.map((r) => (r.id === action.id ? { ...r, enabled: !r.enabled } : r))
      return audit({ ...state, rules }, 'policy.rule.update', rule.name, rule.enabled ? 'Disabled' : 'Enabled')
    }
    case 'radiusClient.add': {
      const id = `${state.tenantId}:nas-${state.radiusClients.length}-${Date.now()}`
      const client: RadiusClient = { ...action.client, id, tenantId: state.tenantId, secretSetAt: new Date().toISOString(), lastRequestAt: null, status: 'unconfigured' }
      return audit({ ...state, radiusClients: [...state.radiusClients, client] }, 'radius.client.create', client.name, `Registered ${client.address}`)
    }
    case 'radiusClient.rotate': {
      const c = state.radiusClients.find((x) => x.id === action.id)
      if (!c) return state
      return audit({ ...state, radiusClients: state.radiusClients.map((x) => (x.id === action.id ? { ...x, secretSetAt: new Date().toISOString() } : x)) }, 'radius.client.rotate_secret', c.name, 'Shared secret rotated')
    }
  }
}

const StoreContext = createContext<{ state: State; dispatch: (a: Action) => void } | null>(null)

export function PrototypeStoreProvider({ children, initialTenantId = 't-harborview' }: { children: ReactNode; initialTenantId?: string }) {
  const [state, dispatch] = useReducer(reducer, undefined, () => ({ ...generateSampleData(), tenantId: initialTenantId }))
  return <StoreContext.Provider value={{ state, dispatch }}>{children}</StoreContext.Provider>
}

function useStore() {
  const ctx = useContext(StoreContext)
  if (!ctx) throw new Error('PrototypeStoreProvider missing')
  return ctx
}

export const now = () => DEMO_NOW

// ── Hooks used by every concept ────────────────────────────────────────────

export function useTenants() {
  const { state, dispatch } = useStore()
  const current = state.tenants.find((t) => t.id === state.tenantId)!
  return { tenants: state.tenants, current, switchTenant: (tenantId: string) => dispatch({ type: 'tenant.switch', tenantId }) }
}

/** All tenant-scoped collections for the current tenant. */
export function useTenantData() {
  const { state } = useStore()
  return useMemo(() => {
    const t = state.tenantId
    const by = <T extends { tenantId: string | null }>(xs: T[]) => xs.filter((x) => x.tenantId === t)
    return {
      tenantId: t,
      identities: by(state.identities),
      groups: by(state.groups),
      devices: by(state.devices),
      cas: by(state.cas),
      templates: by(state.templates),
      certificates: by(state.certificates),
      vlans: by(state.vlans).sort((a, b) => a.vlanId - b.vlanId),
      rules: by(state.rules).sort((a, b) => a.priority - b.priority),
      defaults: state.defaults[t] ?? { defaultAction: 'deny' as const, defaultVlanId: null, maxSnapshotAgeSeconds: 86400 },
      radiusClients: by(state.radiusClients),
      radiusSettings: state.radiusSettings[t],
      authEvents: by(state.authEvents),
      audit: state.audit.filter((a) => a.tenantId === t || a.tenantId === null),
    }
  }, [state])
}

export function useActions() {
  const { dispatch } = useStore()
  return {
    revokeCertificate: (id: string, reason: RevocationReason) => dispatch({ type: 'certificate.revoke', id, reason }),
    moveRule: (id: string, direction: -1 | 1) => dispatch({ type: 'rule.move', id, direction }),
    toggleRule: (id: string) => dispatch({ type: 'rule.toggle', id }),
    addRadiusClient: (client: Omit<RadiusClient, 'id' | 'tenantId' | 'secretSetAt' | 'lastRequestAt' | 'status'>) => dispatch({ type: 'radiusClient.add', client }),
    rotateSecret: (id: string) => dispatch({ type: 'radiusClient.rotate', id }),
  }
}

/** Decision (allow/deny, VLAN, trace) for one identity under the current rules. */
export function useDecision(identity: Identity | undefined, certificate?: Certificate): Decision | null {
  const d = useTenantData()
  return useMemo(
    () => (identity ? evaluatePolicy(identity, d.rules, d.defaults, d.vlans, { certificate, now: DEMO_NOW }) : null),
    [identity, certificate, d.rules, d.defaults, d.vlans],
  )
}

export function useDecisions(): Map<string, Decision> {
  const d = useTenantData()
  return useMemo(() => new Map(d.identities.map((i) => [i.id, evaluatePolicy(i, d.rules, d.defaults, d.vlans, { now: DEMO_NOW })])), [d.identities, d.rules, d.defaults, d.vlans])
}

/** Dashboard metrics derived from the data (nothing invented). */
export function useMetrics() {
  const d = useTenantData()
  const decisions = useDecisions()
  return useMemo(() => {
    const ev = d.authEvents
    const accepts = ev.filter((e) => e.result === 'accept').length
    const hourly = Array.from({ length: 24 }, (_, h) => {
      const end = DEMO_NOW.getTime() - (23 - h) * 3600_000
      const start = end - 3600_000
      const inHour = ev.filter((e) => { const t = new Date(e.at).getTime(); return t > start && t <= end })
      return { hourEnd: new Date(end), accept: inHour.filter((e) => e.result === 'accept').length, reject: inHour.filter((e) => e.result === 'reject').length }
    })
    const failureCounts = new Map<string, number>()
    for (const e of ev) if (e.failureCode) failureCounts.set(e.failureCode, (failureCounts.get(e.failureCode) ?? 0) + 1)
    const vlanCounts = new Map<string, number>()
    for (const e of ev) if (e.vlanId) vlanCounts.set(e.vlanId, (vlanCounts.get(e.vlanId) ?? 0) + 1)
    const certs = d.certificates.filter((c) => c.identityId)
    const authorized = d.identities.filter((i) => decisions.get(i.id)?.outcome === 'allow').length
    return {
      users: d.identities.length,
      authorized,
      unauthorized: d.identities.length - authorized,
      certificates: {
        total: certs.length,
        active: certs.filter((c) => c.status === 'active').length,
        expiring: certs.filter((c) => c.status === 'expiring').length,
        expired: certs.filter((c) => c.status === 'expired').length,
        revoked: certs.filter((c) => c.status === 'revoked').length,
      },
      auth: { total: ev.length, accepts, rejects: ev.length - accepts, successRate: ev.length ? accepts / ev.length : null, hourly },
      failures: [...failureCounts.entries()].sort((a, b) => b[1] - a[1]),
      vlanUsage: [...vlanCounts.entries()].sort((a, b) => b[1] - a[1]),
      activeRadiusClients: d.radiusClients.filter((n) => n.status === 'ok').length,
    }
  }, [d, decisions])
}

export type PrototypeRule = AccessRule
