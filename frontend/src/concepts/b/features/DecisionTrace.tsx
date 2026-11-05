import { Ban, CircleCheck, CircleMinus, CircleX, ShieldCheck } from 'lucide-react'
import type { AccessRule, Decision, DirectoryGroup, Vlan } from '@/domain/types'
import { cn } from '@/ui/lib'
import { VlanChip } from '../ui/Badge'

type Row =
  | { kind: 'gate'; label: string; ok: boolean; detail: string }
  | { kind: 'rule'; rule: AccessRule; matched: boolean; state: 'decided' | 'shadowed' | 'nomatch' | 'matched-deny-loser' }
  | { kind: 'default'; action: 'allow' | 'deny'; detail: string }
  | { kind: 'heading'; label: string; hint: string }

/**
 * Renders a policy decision as the evaluation pipeline: account gate → certificate gate →
 * deny rules (always first) → allow rules by priority → tenant default. The deciding step is marked.
 */
export function DecisionTrace({ decision, rules, vlans, groups, compact = false }: { decision: Decision; rules: AccessRule[]; vlans: Vlan[]; groups?: DirectoryGroup[]; compact?: boolean }) {
  const byId = new Map(rules.map((r) => [r.id, r]))
  const rows: Row[] = []
  const ruleSteps = decision.steps.filter((s) => s.kind === 'rule')
  for (const s of decision.steps) {
    if (s.kind === 'account') rows.push({ kind: 'gate', label: 'Directory account', ok: s.ok, detail: s.detail })
    if (s.kind === 'certificate') rows.push({ kind: 'gate', label: 'Certificate', ok: s.ok, detail: s.detail })
  }
  const denySteps = ruleSteps.filter((s) => s.kind === 'rule' && s.action === 'deny')
  const allowSteps = ruleSteps.filter((s) => s.kind === 'rule' && s.action === 'allow')
  const deciding = decision.decidingRuleId
  if (ruleSteps.length) {
    rows.push({ kind: 'heading', label: 'Deny rules', hint: 'Evaluated first. Any match denies, whatever its position.' })
    for (const s of denySteps) {
      if (s.kind !== 'rule') continue
      const rule = byId.get(s.ruleId)
      if (rule) rows.push({ kind: 'rule', rule, matched: s.matched, state: s.ruleId === deciding ? 'decided' : s.matched ? 'shadowed' : 'nomatch' })
    }
    rows.push({ kind: 'heading', label: 'Allow rules', hint: 'Lowest priority number wins.' })
    for (const s of allowSteps) {
      if (s.kind !== 'rule') continue
      const rule = byId.get(s.ruleId)
      const denyWon = decision.outcome === 'deny' && deciding && byId.get(deciding)?.action === 'deny'
      if (rule) rows.push({ kind: 'rule', rule, matched: s.matched, state: s.ruleId === deciding ? 'decided' : s.matched ? (denyWon ? 'matched-deny-loser' : 'shadowed') : 'nomatch' })
    }
  }
  const def = decision.steps.find((s) => s.kind === 'default')
  if (def && def.kind === 'default') rows.push({ kind: 'default', action: def.action, detail: def.detail })
  const gateFailed = decision.steps.some((s) => (s.kind === 'account' || s.kind === 'certificate') && !s.ok)
  const groupName = (id: string) => groups?.find((g) => g.id === id)?.name ?? id.split(':g-')[1]

  return (
    <ol className="relative space-y-px" aria-label="Decision trace">
      {rows.map((row, i) => {
        if (row.kind === 'heading')
          return (
            <li key={i} className="flex items-baseline gap-2 px-2 pb-1 pt-3 first:pt-0">
              <span className="b-label shrink-0 whitespace-nowrap">{row.label}</span>
              {!compact && <span className="b-t3 text-[12px]">{row.hint}</span>}
            </li>
          )
        if (row.kind === 'gate')
          return (
            <li key={i} className={cn('flex items-start gap-2.5 rounded px-2 py-1.5', !row.ok && 'bg-[rgba(248,113,113,0.07)]')}>
              {row.ok ? <CircleCheck className="b-ink-ok mt-0.5 size-4 shrink-0" aria-hidden /> : <CircleX className="b-ink-crit mt-0.5 size-4 shrink-0" aria-hidden />}
              <div className="min-w-0">
                <p className="font-medium text-[var(--b-text)]">
                  {row.label} <span className={row.ok ? 'b-ink-ok' : 'b-ink-crit'}>{row.ok ? 'passed' : 'failed: access denied'}</span>
                </p>
                <p className="b-t2 text-[12.5px]">{row.detail}</p>
              </div>
            </li>
          )
        if (row.kind === 'default')
          return (
            <li key={i} className="flex items-start gap-2.5 rounded bg-[var(--b-cyan-wash)] px-2 py-1.5">
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[var(--b-cyan)]" aria-hidden />
              <div>
                <p className="font-medium text-[var(--b-text)]">
                  Tenant default: {row.action === 'deny' ? 'Deny' : 'Allow'} <span className="b-badge b-tone-info ml-1">Decided</span>
                </p>
                <p className="b-t2 text-[12.5px]">{row.detail}</p>
              </div>
            </li>
          )
        const { rule, state } = row
        const vlan = vlans.find((v) => v.id === rule.vlanId)
        const Icon = state === 'decided' ? (rule.action === 'deny' ? Ban : CircleCheck) : row.matched ? CircleCheck : CircleMinus
        return (
          <li key={i} className={cn('flex items-start gap-2.5 rounded px-2 py-1.5', state === 'decided' && 'bg-[var(--b-cyan-wash)] ring-1 ring-[rgba(34,211,238,0.35)] ring-inset')}>
            <Icon
              className={cn('mt-0.5 size-4 shrink-0', state === 'decided' ? (rule.action === 'deny' ? 'b-ink-crit' : 'b-ink-ok') : row.matched ? 'text-[var(--b-text-2)]' : 'text-[var(--b-text-3)]')}
              aria-hidden
            />
            <div className="min-w-0 flex-1">
              <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="b-cond b-num w-6 shrink-0 text-[13px] font-semibold text-[var(--b-text-3)]">{rule.priority}</span>
                <span className={cn('font-medium', state === 'nomatch' ? 'text-[var(--b-text-2)]' : 'text-[var(--b-text)]')}>{rule.name}</span>
                {state === 'decided' && <span className="b-badge b-tone-info">Decided</span>}
                {rule.action === 'allow' && vlan && !compact && <VlanChip vlan={vlan} showName={false} />}
              </p>
              <p className="b-t3 pl-8 text-[12px]">
                {state === 'decided' && (rule.action === 'deny' ? 'Matched a denied group. Deny rules always win.' : 'First matching Allow rule by priority.')}
                {state === 'shadowed' && 'Also matches, but an earlier rule decided.'}
                {state === 'matched-deny-loser' && 'Matches, but a Deny rule overrides it.'}
                {state === 'nomatch' && `No matching group (${rule.groupIds.map(groupName).join(', ')})`}
              </p>
            </div>
          </li>
        )
      })}
      {gateFailed && (
        <li className="b-t3 px-2 pt-2 text-[12px]">Access rules were not evaluated: a failed gate denies before any rule runs.</li>
      )}
    </ol>
  )
}

/** RADIUS reply attributes as a compact mono table. */
export function AttributeTable({ attributes }: { attributes: Array<{ name: string; value: string }> }) {
  if (!attributes.length) return <p className="b-t3 text-[12.5px]">No reply attributes: the request is rejected (Access-Reject).</p>
  return (
    <table className="w-full text-[12.5px]">
      <caption className="sr-only">RADIUS reply attributes</caption>
      <thead>
        <tr className="text-left">
          <th className="b-label pb-1 font-semibold">Attribute</th>
          <th className="b-label pb-1 font-semibold">Value</th>
        </tr>
      </thead>
      <tbody>
        {attributes.map((a) => (
          <tr key={a.name} className="border-t border-[var(--b-line-soft)]">
            <td className="b-mono py-1.5 pr-3 text-[var(--b-text)]">{a.name}</td>
            <td className="b-mono py-1.5 text-[var(--b-cyan)]">{a.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
