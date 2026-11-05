import type {
  AccessRule,
  Certificate,
  CertPurpose,
  Decision,
  DecisionStep,
  Identity,
  PolicyDefaults,
  RadiusAttribute,
  Vlan,
} from './types'

/**
 * Deterministic access-policy evaluation. This is the reference algorithm documented in
 * ARCHITECTURE.md §Policy precedence; the canonical implementation lives in
 * backend/app/policy/engine.py and both are tested against the same fixtures.
 *
 * Order:
 *  1. Account gate: disabled / locked / deleted accounts are denied. Not overridable.
 *  2. Certificate gate (when a certificate is supplied): revoked / expired are denied.
 *  3. Any enabled Deny rule matching any of the identity's groups denies.
 *  4. Otherwise the enabled Allow rule with the lowest priority wins (ties: lowest id).
 *  5. Otherwise the tenant default applies (deny unless configured).
 */
export function evaluatePolicy(
  identity: Identity,
  rules: AccessRule[],
  defaults: PolicyDefaults,
  vlans: Vlan[],
  options: { certificate?: Certificate; certificatePurpose?: CertPurpose; now: Date },
): Decision {
  const steps: DecisionStep[] = []
  const base = { identityId: identity.id, computedAt: options.now.toISOString() }
  const deny = (decidingRuleId: string | null): Decision => ({
    ...base,
    outcome: 'deny',
    decidingRuleId,
    vlanId: null,
    attributes: [],
    steps,
  })

  if (identity.accountState !== 'enabled') {
    steps.push({ kind: 'account', ok: false, detail: `Directory account is ${identity.accountState}` })
    return deny(null)
  }
  steps.push({ kind: 'account', ok: true, detail: 'Directory account is enabled' })

  const cert = options.certificate
  if (cert) {
    if (cert.status === 'revoked') {
      steps.push({ kind: 'certificate', ok: false, detail: `Certificate ${cert.serial} is revoked` })
      return deny(null)
    }
    if (new Date(cert.notAfter) <= options.now) {
      steps.push({ kind: 'certificate', ok: false, detail: `Certificate ${cert.serial} has expired` })
      return deny(null)
    }
    steps.push({ kind: 'certificate', ok: true, detail: `Certificate ${cert.serial} is valid` })
  }

  const groups = new Set(identity.groupIds)
  const ordered = [...rules]
    .filter((r) => r.enabled)
    .sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id))

  const matches = (r: AccessRule) => r.groupIds.some((g) => groups.has(g))
  const purpose = options.certificatePurpose
  const purposeOk = (r: AccessRule) => !purpose || r.purposes.length === 0 || r.purposes.includes(purpose)

  const denyRule = ordered.find((r) => r.action === 'deny' && matches(r) && purposeOk(r))
  for (const r of ordered) {
    const matched = matches(r) && purposeOk(r)
    steps.push({
      kind: 'rule',
      ruleId: r.id,
      matched,
      action: r.action,
      detail: matched ? `Matched “${r.name}”` : `No matching group for “${r.name}”`,
    })
  }
  if (denyRule) return deny(denyRule.id)

  const allowRule = ordered.find((r) => r.action === 'allow' && matches(r) && purposeOk(r))
  if (allowRule) {
    return {
      ...base,
      outcome: 'allow',
      decidingRuleId: allowRule.id,
      vlanId: allowRule.vlanId,
      attributes: vlanAttributes(vlans.find((v) => v.id === allowRule.vlanId), allowRule.extraAttributes),
      steps,
    }
  }

  steps.push({ kind: 'default', action: defaults.defaultAction, detail: 'No rule matched; tenant default applies' })
  if (defaults.defaultAction === 'deny') return deny(null)
  return {
    ...base,
    outcome: 'allow',
    decidingRuleId: null,
    vlanId: defaults.defaultVlanId,
    attributes: vlanAttributes(vlans.find((v) => v.id === defaults.defaultVlanId), []),
    steps,
  }
}

/** Standard RFC 3580 dynamic VLAN reply attributes. */
export function vlanAttributes(vlan: Vlan | undefined, extra: RadiusAttribute[]): RadiusAttribute[] {
  if (!vlan) return extra
  return [
    { name: 'Tunnel-Type', value: 'VLAN (13)' },
    { name: 'Tunnel-Medium-Type', value: 'IEEE-802 (6)' },
    { name: 'Tunnel-Private-Group-ID', value: String(vlan.vlanId) },
    ...extra,
  ]
}
