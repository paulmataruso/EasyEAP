// Small pieces shared by the policy screen: rule action/outcome chips, diff markers, VLAN lookups, ledger inputs.
import { useMemo } from 'react'
import { ArrowUpDown, PencilLine, Plus, ShieldCheck, ShieldX, Trash2 } from 'lucide-react'
import { useDirectoryGroups } from '../../api/directory'
import type { BriefOutcome, Rule, Vlan } from '../../api/policy'
import { Chip, VlanTag } from '../../ui'
import type { LedgerRule, LedgerVlan } from '../../ui/ledger'
import { reasonText } from '../../ui/ledger'
import { fieldLabels, submittedIds, type Draft, type DraftRule, type RuleDiff } from './draft'

/** Relative time for something that has already happened: server/browser clock skew never shows it in the future. */

export const vlanByRef = (vlans: Vlan[], ref: string | null | undefined) => (ref ? vlans.find((v) => v.id === ref) : undefined)
export const vlanByNumber = (vlans: Vlan[], n: number | null | undefined) => (n === null || n === undefined ? undefined : vlans.find((v) => v.vlan_id === n))
export const vlanText = (vlans: Vlan[], ref: string | null | undefined) => {
  const v = vlanByRef(vlans, ref)
  return v ? `VLAN ${v.vlan_id} ${v.name}` : 'no VLAN'
}

export function VlanRef({ vlans, vref }: { vlans: Vlan[]; vref: string | null }) {
  const v = vlanByRef(vlans, vref)
  if (!v) return <Chip tone="crit">No VLAN chosen</Chip>
  return <VlanTag vlanId={v.vlan_id} name={v.name} color={v.color} />
}

export function ActionChip({ action }: { action: 'allow' | 'deny' }) {
  return action === 'allow'
    ? <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>Allow</Chip>
    : <Chip tone="crit" icon={<ShieldX aria-hidden />}>Deny</Chip>
}

/** Visible draft marker on a rule (icon + text, never colour alone). */
export function DiffChip({ diff, enabled }: { diff: RuleDiff | undefined; enabled?: boolean }) {
  if (!diff || diff.status === 'same') return null
  if (diff.status === 'new') return <Chip tone="gold" icon={<Plus aria-hidden />}>New in draft</Chip>
  if (diff.status === 'removed') return <Chip tone="crit" icon={<Trash2 aria-hidden />}>Removed in draft</Chip>
  if (diff.status === 'moved') return <Chip tone="neutral" icon={<ArrowUpDown aria-hidden />}>Moved in draft</Chip>
  const fields = diff.fields.map((f) => (f === 'enabled' ? (enabled === false ? 'disabled' : 'enabled') : fieldLabels[f])).join(', ')
  return <Chip tone="warn" icon={<PencilLine aria-hidden />} title={`Changed in draft: ${fields}${diff.moved ? '; moved' : ''}`}>Changed: {fields}{diff.moved ? ' · moved' : ''}</Chip>
}

export const purposeLabel = (p: string[]) => {
  const s = new Set(p)
  if (s.size === 0 || (s.has('user') && s.has('device'))) return 'any certificate'
  return s.has('user') ? 'user certificates only' : 'device certificates only'
}

export const ledgerVlans = (vlans: Vlan[]): LedgerVlan[] => vlans.map((v) => ({ vlan_id: v.vlan_id, name: v.name, color: v.color }))

export const ledgerRulesFromLive = (rules: Rule[]): LedgerRule[] =>
  rules.map((r) => ({ id: r.id, name: r.name, action: r.action, priority: r.priority, enabled: r.enabled, groups: r.groups.map((g) => ({ id: g.id, name: g.name })) }))

/** Ledger rules for a preview trace: ids as the backend named them (live id, or draft-<index> for new rules). */
export function ledgerRulesFromDraft(d: Draft): LedgerRule[] {
  const ids = submittedIds(d)
  return d.rules.filter((r) => !r.removed).map((r: DraftRule, i) => ({
    id: ids.get(r.key) as string, name: r.name, action: r.action, priority: (i + 1) * 10, enabled: r.enabled,
    groups: r.groups.map((g) => ({ id: g.id, name: g.name })),
  }))
}

/** "Allowed · VLAN 120 Corporate" / "Denied" for a preview before/after. */
export function BriefOutcomeView({ o, vlans }: { o: BriefOutcome; vlans: Vlan[] }) {
  if (o.outcome === 'allow') {
    const v = vlanByNumber(vlans, o.vlan_id)
    return (
      <span className="inline-flex flex-wrap items-center gap-1.5">
        <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>Allowed</Chip>
        {o.vlan_id !== null && <VlanTag vlanId={o.vlan_id} name={v?.name} color={v?.color} />}
      </span>
    )
  }
  return <Chip tone="crit" icon={<ShieldX aria-hidden />}>Denied</Chip>
}

/** Which rule (or the default) decides a preview outcome, in words. */
export function decidedBy(o: BriefOutcome): string {
  if (o.rule_name) return `“${o.rule_name}”`
  if (o.reason_code === 'identity_unauthorized') return 'the default (Deny)'
  if (o.reason_code === 'account_disabled') return 'account state'
  if (o.outcome === 'allow') return 'the default (Allow)'
  return reasonText[o.reason_code ?? ''] ?? 'the default'
}

/** Where each group comes from (AD or local), so two groups with the same name can be told apart. */
export type GroupSourceOf = (id: string) => string | undefined
export function useGroupSources(tid: string): GroupSourceOf {
  const q = useDirectoryGroups(tid)
  return useMemo(() => {
    const m = new Map((q.data?.groups ?? []).map((g) => [g.id, g.source]))
    return (id: string) => m.get(id)
  }, [q.data])
}
export const groupName = (name: string, source: string | undefined) => (source === 'local' ? `${name} (local)` : name)
