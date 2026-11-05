import { Ban, CircleCheck, CircleDot, CircleMinus, CircleX, ShieldCheck } from 'lucide-react'
import type { Decision, DecisionStep, Identity } from '@/domain/types'
import { cn } from '@/ui/lib'
import { RuleActionPill, VlanChip } from '../ui/badges'
import { Mono } from '../ui/primitives'
import { useLookups } from '../lib/model'

type RuleStep = Extract<DecisionStep, { kind: 'rule' }>

export function decisionHeadline(decision: Decision, ruleName: (id: string) => string | undefined): { title: string; detail: string } {
  const account = decision.steps.find((s) => s.kind === 'account')
  const cert = decision.steps.find((s) => s.kind === 'certificate')
  if (decision.outcome === 'allow') {
    return decision.decidingRuleId
      ? { title: 'Allowed', detail: `Decided by “${ruleName(decision.decidingRuleId) ?? 'rule'}”, the first matching Allow rule.` }
      : { title: 'Allowed', detail: 'No rule matched; the tenant default allows access.' }
  }
  if (account && !account.ok) return { title: 'Denied', detail: `${account.detail}. Account checks run before any rule and cannot be overridden.` }
  if (cert && !cert.ok) return { title: 'Denied', detail: `${cert.detail}.` }
  if (decision.decidingRuleId) return { title: 'Denied', detail: `Denied by “${ruleName(decision.decidingRuleId) ?? 'rule'}”. Deny rules always win over Allow rules.` }
  return { title: 'Denied', detail: 'No rule matched one of this user’s groups, and the tenant default is Deny.' }
}

/** Full, ordered explanation of an access decision. */
export function DecisionTrace({ decision, identity, compact = false }: { decision: Decision; identity: Identity; compact?: boolean }) {
  const { ruleById, groupById, vlanById } = useLookups()
  const headline = decisionHeadline(decision, (id) => ruleById.get(id)?.name)
  const vlan = decision.vlanId ? vlanById.get(decision.vlanId) : null
  const ruleSteps = decision.steps.filter((s): s is RuleStep => s.kind === 'rule')
  const denySteps = ruleSteps.filter((s) => s.action === 'deny')
  const allowSteps = ruleSteps.filter((s) => s.action === 'allow')
  const account = decision.steps.find((s) => s.kind === 'account')
  const cert = decision.steps.find((s) => s.kind === 'certificate')
  const def = decision.steps.find((s) => s.kind === 'default')
  const userGroups = new Set(identity.groupIds)
  const allowed = decision.outcome === 'allow'

  const renderRow = (step: RuleStep) => {
    const rule = ruleById.get(step.ruleId)
    const deciding = decision.decidingRuleId === step.ruleId
    const matchedGroups = rule?.groupIds.filter((g) => userGroups.has(g)).map((g) => groupById.get(g)?.name ?? g) ?? []
    const Icon = deciding ? (step.action === 'deny' ? Ban : CircleCheck) : step.matched ? CircleDot : CircleMinus
    const color = deciding ? (step.action === 'deny' ? 'text-[var(--a-danger-text)]' : 'text-[var(--a-ok-text)]') : step.matched ? 'text-[var(--a-text-2)]' : 'text-[var(--a-text-3)]'
    const note = deciding ? 'Decided here' : step.matched ? (step.action === 'allow' && decision.outcome === 'allow' ? 'Matched, but an earlier rule decided' : 'Matched') : 'No matching group'
    return (
      <li key={step.ruleId} className={cn('flex items-start gap-3 rounded-lg px-3 py-2', deciding && 'bg-white/[0.05] ring-1 ring-white/10')}>
        <Icon className={cn('mt-0.5 size-4 shrink-0', color)} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className={cn('text-[14px] font-medium', step.matched ? 'text-[var(--a-text)]' : 'text-[var(--a-text-2)]')}>{rule?.name ?? step.ruleId}</span>
            {!compact && rule && <span className="a-num text-[12px] text-[var(--a-text-3)]">priority {rule.priority}</span>}
          </div>
          <p className={cn('text-[12px]', deciding ? (step.action === 'deny' ? 'text-[var(--a-danger-text)]' : 'text-[var(--a-ok-text)]') : 'text-[var(--a-text-3)]')}>
            {note}
            {step.matched && matchedGroups.length > 0 && <span className="text-[var(--a-text-3)]"> · via {matchedGroups.join(', ')}</span>}
          </p>
        </div>
        {rule?.vlanId && !compact && <VlanChip vlan={vlanById.get(rule.vlanId)} compact />}
      </li>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className={cn('flex items-start gap-3 rounded-[10px] border p-3.5', allowed ? 'border-[rgba(74,222,128,0.22)] bg-[rgba(34,197,94,0.07)]' : 'border-[rgba(248,113,113,0.24)] bg-[rgba(239,68,68,0.07)]')}>
        {allowed ? <CircleCheck className="mt-0.5 size-5 shrink-0 text-[var(--a-ok-text)]" aria-hidden /> : <CircleX className="mt-0.5 size-5 shrink-0 text-[var(--a-danger-text)]" aria-hidden />}
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2 text-[15px] font-semibold text-[var(--a-text)]">
            {headline.title}
            {allowed && vlan && (
              <>
                <span className="font-normal text-[var(--a-text-3)]">on</span>
                <VlanChip vlan={vlan} />
              </>
            )}
          </p>
          <p className="mt-0.5 text-[13px] text-[var(--a-text-2)]">{headline.detail}</p>
        </div>
      </div>

      <ol className="flex flex-col gap-3" aria-label="Decision trace">
        <li>
          <p className="mb-1 text-[12px] font-medium text-[var(--a-text-3)]">1 · Account and certificate checks</p>
          <ul className="flex flex-col gap-0.5">
            {account && (
              <li className="flex items-start gap-3 px-3 py-1.5">
                {account.ok ? <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[var(--a-ok-text)]" aria-hidden /> : <CircleX className="mt-0.5 size-4 shrink-0 text-[var(--a-danger-text)]" aria-hidden />}
                <span className="text-[14px] text-[var(--a-text-2)]">{account.detail}</span>
              </li>
            )}
            {cert && (
              <li className="flex items-start gap-3 px-3 py-1.5">
                {cert.ok ? <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[var(--a-ok-text)]" aria-hidden /> : <CircleX className="mt-0.5 size-4 shrink-0 text-[var(--a-danger-text)]" aria-hidden />}
                <span className="text-[14px] text-[var(--a-text-2)]">{cert.detail}</span>
              </li>
            )}
          </ul>
        </li>
        {account?.ok !== false && cert?.ok !== false ? (
          <>
            <li>
              <p className="mb-1 text-[12px] font-medium text-[var(--a-text-3)]">2 · Deny rules, checked first: any match denies</p>
              {denySteps.length ? (
                <ul className="flex flex-col gap-0.5">
                  {denySteps.map(renderRow)}
                </ul>
              ) : (
                <p className="px-3 text-[13px] text-[var(--a-text-3)]">No enabled Deny rules.</p>
              )}
            </li>
            <li>
              <p className="mb-1 text-[12px] font-medium text-[var(--a-text-3)]">3 · Allow rules, top to bottom: first match decides</p>
              {decision.outcome === 'deny' && decision.decidingRuleId ? (
                <p className="px-3 text-[13px] text-[var(--a-text-3)]">Skipped: a Deny rule already decided.</p>
              ) : (
                <ul className="flex flex-col gap-0.5">
                  {allowSteps.map(renderRow)}
                </ul>
              )}
            </li>
            {def && (
              <li>
                <p className="mb-1 text-[12px] font-medium text-[var(--a-text-3)]">4 · Tenant default</p>
                <p className="flex items-center gap-2 px-3 text-[14px] text-[var(--a-text-2)]">
                  <RuleActionPill action={def.action} /> {def.detail}
                </p>
              </li>
            )}
          </>
        ) : (
          <li className="px-3 text-[13px] text-[var(--a-text-3)]">Rules were not evaluated: the account or certificate check failed first.</li>
        )}
      </ol>

      {decision.attributes.length > 0 && (
        <div>
          <p className="mb-1.5 text-[12px] font-medium text-[var(--a-text-3)]">RADIUS reply attributes</p>
          <table className="w-full text-left text-[13px]">
            <caption className="sr-only">RADIUS attributes returned in Access-Accept</caption>
            <tbody>
              {decision.attributes.map((a) => (
                <tr key={a.name} className="border-b border-white/[0.06] last:border-0">
                  <th scope="row" className="py-1.5 pr-4 font-normal">
                    <Mono className="text-[var(--a-text-2)]">{a.name}</Mono>
                  </th>
                  <td className="py-1.5 text-right">
                    <Mono className="text-[var(--a-text)]">{a.value}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
