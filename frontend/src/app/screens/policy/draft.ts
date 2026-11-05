// The staged policy draft. Every rule edit (add, edit, delete, enable/disable, reorder) and the tenant default live
// here until the draft is previewed and published. Removed rules stay in the list, marked, so they can be restored.
import type { DraftBody, ExtraAttribute, PolicyResponse, Rule, RuleAction, RuleGroup } from '../../api/policy'

export interface DraftRule {
  /** Stable local key: the live rule id, or "new-<n>" for rules added in this draft. */
  key: string
  /** Live rule id; null for rules added in this draft. */
  id: string | null
  name: string
  description: string
  enabled: boolean
  action: RuleAction
  vlan_ref: string | null
  groups: RuleGroup[]
  purposes: string[]
  extra_attributes: ExtraAttribute[]
  removed?: boolean
}

export interface Draft {
  /** All rules in evaluation order (the order is what publish sends; Deny rules keep their slots). */
  rules: DraftRule[]
  default_action: RuleAction
  default_vlan_ref: string | null
}

export const ruleToDraft = (r: Rule): DraftRule => ({
  key: r.id, id: r.id, name: r.name, description: r.description, enabled: r.enabled, action: r.action, vlan_ref: r.vlan_ref,
  groups: r.groups.map((g) => ({ ...g })), purposes: [...r.purposes], extra_attributes: r.extra_attributes.map((a) => ({ ...a })),
})

export const draftFromLive = (p: PolicyResponse): Draft => ({
  rules: p.rules.map(ruleToDraft),
  default_action: p.settings.default_action,
  default_vlan_ref: p.settings.default_vlan_ref,
})

let seq = 0
export const newKey = () => `new-${Date.now().toString(36)}-${++seq}`

/** The body for POST /policy/preview and /policy/publish. Removed rules are left out; order is evaluation order. */
export function draftBody(d: Draft, revision: string): DraftBody {
  return {
    revision,
    rules: d.rules.filter((r) => !r.removed).map((r) => ({
      id: r.id, name: r.name.trim(), description: r.description, enabled: r.enabled, action: r.action,
      vlan_ref: r.action === 'allow' ? r.vlan_ref : null,
      group_ids: r.groups.map((g) => g.id), purposes: r.purposes,
      extra_attributes: r.action === 'allow' ? r.extra_attributes : [],
    })),
    default_action: d.default_action,
    default_vlan_ref: d.default_action === 'allow' ? d.default_vlan_ref : null,
  }
}

/** Ledger/preview id of each submitted rule: its live id, or "draft-<index>" for new rules (backend draft_inputs). */
export function submittedIds(d: Draft): Map<string, string> {
  const out = new Map<string, string>()
  d.rules.filter((r) => !r.removed).forEach((r, i) => out.set(r.key, r.id ?? `draft-${i}`))
  return out
}

// ── Diff against the live policy ─────────────────────────────────────────

export type FieldName = 'name' | 'description' | 'enabled' | 'action' | 'vlan' | 'groups' | 'purposes' | 'attributes'
export const fieldLabels: Record<FieldName, string> = {
  name: 'name', description: 'description', enabled: 'enabled', action: 'action', vlan: 'VLAN', groups: 'groups', purposes: 'certificate types', attributes: 'reply attributes',
}

const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().join('|') === [...b].sort().join('|')
const sameAttrs = (a: ExtraAttribute[], b: ExtraAttribute[]) => JSON.stringify(a.map((x) => [x.name, x.value])) === JSON.stringify(b.map((x) => [x.name, x.value]))

export function changedFields(live: Rule, d: DraftRule): FieldName[] {
  const f: FieldName[] = []
  if (live.name !== d.name.trim()) f.push('name')
  if (live.description !== d.description) f.push('description')
  if (live.action !== d.action) f.push('action')
  if (live.enabled !== d.enabled) f.push('enabled')
  if (d.action === 'allow' && live.vlan_ref !== d.vlan_ref) f.push('vlan')
  if (!sameSet(live.groups.map((g) => g.id), d.groups.map((g) => g.id))) f.push('groups')
  if (!sameSet(live.purposes, d.purposes)) f.push('purposes')
  if (d.action === 'allow' && !sameAttrs(live.extra_attributes, d.extra_attributes)) f.push('attributes')
  return f
}

export type RuleStatus = 'new' | 'removed' | 'edited' | 'moved' | 'same'
export interface RuleDiff { status: RuleStatus; fields: FieldName[]; moved: boolean }

/** Which surviving live Allow rules changed position relative to each other. */
function movedAllowRules(live: PolicyResponse, d: Draft): Set<string> {
  const draftOrder = d.rules.filter((r) => !r.removed && r.id && r.action === 'allow').map((r) => r.id as string)
  const keep = new Set(draftOrder)
  const liveOrder = live.rules.filter((r) => r.action === 'allow' && keep.has(r.id)).map((r) => r.id)
  const draftSame = draftOrder.filter((id) => liveOrder.includes(id))
  const moved = new Set<string>()
  draftSame.forEach((id, i) => { if (liveOrder[i] !== id) moved.add(id) })
  return moved
}

export function diffDraft(live: PolicyResponse, d: Draft) {
  const byId = new Map(live.rules.map((r) => [r.id, r]))
  const moved = movedAllowRules(live, d)
  const rules = new Map<string, RuleDiff>()
  for (const r of d.rules) {
    if (!r.id) { rules.set(r.key, { status: r.removed ? 'same' : 'new', fields: [], moved: false }); continue }
    const lr = byId.get(r.id)
    if (!lr) { rules.set(r.key, { status: 'new', fields: [], moved: false }); continue }
    if (r.removed) { rules.set(r.key, { status: 'removed', fields: [], moved: false }); continue }
    const fields = changedFields(lr, r)
    const m = moved.has(r.id)
    rules.set(r.key, { status: fields.length ? 'edited' : m ? 'moved' : 'same', fields, moved: m })
  }
  const defaultChanged = live.settings.default_action !== d.default_action
    || (d.default_action === 'allow' && live.settings.default_vlan_ref !== d.default_vlan_ref)
  const ruleChanges = [...rules.values()].filter((x) => x.status !== 'same').length
  return { rules, defaultChanged, count: ruleChanges + (defaultChanged ? 1 : 0) }
}

export type DraftDiff = ReturnType<typeof diffDraft>

/** Plain-language list of what the draft changes, for the publish confirmation and the conflict recovery panel. */
export interface ChangeLine { key: string; kind: 'added' | 'removed' | 'edited' | 'moved' | 'default'; text: string; rule?: DraftRule }

export function describeChanges(live: PolicyResponse, d: Draft, vlanLabel: (ref: string | null) => string): ChangeLine[] {
  const diff = diffDraft(live, d)
  const lines: ChangeLine[] = []
  for (const r of d.rules) {
    const x = diff.rules.get(r.key)
    if (!x || x.status === 'same') continue
    const what = r.action === 'allow' ? `Allow → ${vlanLabel(r.vlan_ref)}` : 'Deny'
    if (x.status === 'new') lines.push({ key: r.key, kind: 'added', text: `Add “${r.name}” (${what}, ${r.groups.map((g) => g.name).join(', ') || 'no groups'})`, rule: r })
    else if (x.status === 'removed') lines.push({ key: r.key, kind: 'removed', text: `Remove “${r.name}”`, rule: r })
    else if (x.status === 'edited') lines.push({ key: r.key, kind: 'edited', text: `Change “${r.name}”: ${x.fields.map((f) => (f === 'enabled' ? (r.enabled ? 'enable' : 'disable') : fieldLabels[f])).join(', ')}${x.moved ? '; moved' : ''}`, rule: r })
    else if (x.status === 'moved') {
      const pos = d.rules.filter((y) => !y.removed && y.action === 'allow').findIndex((y) => y.key === r.key) + 1
      lines.push({ key: r.key, kind: 'moved', text: `Move “${r.name}” to Allow position ${pos}`, rule: r })
    }
  }
  if (diff.defaultChanged) {
    lines.push({ key: 'default', kind: 'default', text: `When no rule matches: ${live.settings.default_action === 'allow' ? `Allow → ${vlanLabel(live.settings.default_vlan_ref)}` : 'Deny'} → ${d.default_action === 'allow' ? `Allow → ${vlanLabel(d.default_vlan_ref)}` : 'Deny'}` })
  }
  return lines
}

// ── Edits ────────────────────────────────────────────────────────────────

/**
 * Move an Allow rule one place up or down among the Allow rules that will be published: it is taken out and put
 * back directly before (or after) its neighbour, so every other rule keeps its place. Deny rules never move.
 */
export function moveAllow(d: Draft, key: string, dir: -1 | 1): Draft {
  const slots = d.rules.map((r, i) => ({ r, i })).filter(({ r }) => r.action === 'allow' && !r.removed)
  const p = slots.findIndex(({ r }) => r.key === key)
  const q = p + dir
  if (p < 0 || q < 0 || q >= slots.length) return d
  const moving = d.rules[slots[p].i]
  const neighbour = d.rules[slots[q].i]
  const rules = d.rules.filter((r) => r.key !== key)
  const at = rules.findIndex((r) => r.key === neighbour.key)
  rules.splice(dir === -1 ? at : at + 1, 0, moving)
  return { ...d, rules }
}

export const upsertRule = (d: Draft, rule: DraftRule): Draft => {
  const i = d.rules.findIndex((r) => r.key === rule.key)
  if (i < 0) return { ...d, rules: [...d.rules, rule] }
  const rules = [...d.rules]
  rules[i] = rule
  return { ...d, rules }
}

export const patchRule = (d: Draft, key: string, patch: Partial<DraftRule>): Draft =>
  ({ ...d, rules: d.rules.map((r) => (r.key === key ? { ...r, ...patch } : r)) })

/** Delete: new rules disappear; live rules are marked removed so they can be restored until publish. */
export const removeRule = (d: Draft, key: string): Draft => {
  const r = d.rules.find((x) => x.key === key)
  if (!r) return d
  return r.id ? patchRule(d, key, { removed: true }) : { ...d, rules: d.rules.filter((x) => x.key !== key) }
}

/** Put one rule's fields back to the live version (its position is kept). */
export function revertRule(d: Draft, live: PolicyResponse, key: string): Draft {
  const lr = live.rules.find((r) => r.id === key)
  return lr ? patchRule(d, key, { ...ruleToDraft(lr), removed: false }) : d
}

/** Replay one change from an abandoned draft onto a fresh draft (conflict recovery). Returns null when it can't apply. */
export function replayChange(d: Draft, line: ChangeLine, old: Draft): Draft | null {
  if (line.kind === 'default') return { ...d, default_action: old.default_action, default_vlan_ref: old.default_vlan_ref }
  const r = line.rule
  if (!r) return null
  if (line.kind === 'added') return d.rules.some((x) => x.key === r.key) ? null : { ...d, rules: [...d.rules, { ...r, key: newKey(), id: null }] }
  const target = d.rules.find((x) => x.id === r.id)
  if (!target) return null
  if (line.kind === 'removed') return removeRule(d, target.key)
  if (line.kind === 'edited') return patchRule(d, target.key, { ...r, key: target.key, id: target.id, removed: false })
  return null
}

/** A snapshot of the draft that identifies it for preview staleness. */
export const draftSignature = (d: Draft, revision: string) => JSON.stringify(draftBody(d, revision))
