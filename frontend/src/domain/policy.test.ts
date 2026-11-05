// Runs the same precedence fixtures as backend/tests/test_policy_engine.py, so the console's
// "Test a user" simulation and the server that builds the RADIUS snapshot can never disagree.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, test } from 'vitest'
import { evaluatePolicy } from './policy'
import type { AccessRule, Certificate, CertPurpose, Identity, Vlan } from './types'

interface Case {
  name: string
  account: Identity['accountState']
  groups: string[]
  purpose?: CertPurpose
  cert?: { status: Certificate['status']; not_after: string; purpose: CertPurpose }
  default?: { action: 'allow' | 'deny'; vlan: number | null }
  expect: { outcome: 'allow' | 'deny'; vlan: number | null; rule: string | null; reason: string | null }
}
const FIX = JSON.parse(readFileSync(resolve(__dirname, '../../../backend/tests/fixtures/policy_cases.json'), 'utf8')) as {
  now: string
  rules: Array<{ id: string; name: string; priority: number; enabled: boolean; action: 'allow' | 'deny'; groups: string[]; purposes: CertPurpose[]; vlan: number | null }>
  cases: Case[]
}
const NOW = new Date(FIX.now)
const vlanNumbers = new Set<number>([...FIX.rules.map((r) => r.vlan), ...FIX.cases.map((c) => c.default?.vlan ?? null)].filter((v): v is number => v !== null))
const VLANS: Vlan[] = [...vlanNumbers].map((n) => ({ id: `v${n}`, tenantId: 't', vlanId: n, name: `VLAN ${n}`, description: '', color: 'blue' }))
const RULES: AccessRule[] = FIX.rules.map((r) => ({
  id: r.id, tenantId: 't', name: r.name, priority: r.priority, enabled: r.enabled, action: r.action, groupIds: r.groups,
  purposes: r.purposes, vlanId: r.vlan === null ? null : `v${r.vlan}`, extraAttributes: [], description: '',
}))

describe('policy precedence (shared fixtures)', () => {
  test.each(FIX.cases)('$name', (c) => {
    const identity: Identity = {
      id: 'u', tenantId: 't', source: 'ad', displayName: 'U', username: 'u', upn: null, email: null, department: null, title: null,
      accountState: c.account, groupIds: c.groups, lastAuthAt: null, lastSyncedAt: null, objectGuid: null,
    }
    const certificate = c.cert ? ({ serial: 'ABC', status: c.cert.status, notAfter: c.cert.not_after } as Certificate) : undefined
    const def = c.default ?? { action: 'deny', vlan: null }
    const d = evaluatePolicy(identity, RULES, { defaultAction: def.action, defaultVlanId: def.vlan === null ? null : `v${def.vlan}`, maxSnapshotAgeSeconds: 86400 }, VLANS, {
      certificate, certificatePurpose: c.cert?.purpose ?? c.purpose, now: NOW,
    })
    expect(d.outcome).toBe(c.expect.outcome)
    expect(d.decidingRuleId).toBe(c.expect.rule)
    expect(d.vlanId ? VLANS.find((v) => v.id === d.vlanId)!.vlanId : null).toBe(c.expect.vlan)
    if (d.outcome === 'deny') expect(d.attributes).toEqual([])
    else if (c.expect.vlan !== null) expect(d.attributes).toContainEqual({ name: 'Tunnel-Private-Group-ID', value: String(c.expect.vlan) })
  })
})
