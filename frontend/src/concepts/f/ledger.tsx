import { useState, type ReactNode } from 'react'
import { Ban, Check, ChevronDown, Minus, Stamp, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import type { AccessRule, Certificate, Decision, DirectoryGroup, Identity, RadiusAttribute, Vlan } from '@/domain/types'
import { decisionReason } from './lib'
import { AccessChip, Chip, VlanTag } from './ui'

type Mark = 'pass' | 'fail' | 'skip' | 'decides'

function Marker({ mark }: { mark: Mark }) {
  const cls = {
    pass: 'border-[rgba(45,212,191,0.55)] text-[var(--f-valid)]',
    fail: 'border-[rgba(244,63,94,0.6)] text-[var(--f-crit-ink)]',
    skip: 'border-[var(--f-line-2)] text-[var(--f-ink-3)]',
    decides: 'border-[rgba(226,194,117,0.7)] text-[var(--f-gold)] bg-[rgba(226,194,117,0.1)]',
  }[mark]
  const icon = { pass: <Check aria-hidden />, fail: <X aria-hidden />, skip: <Minus aria-hidden />, decides: <Stamp aria-hidden /> }[mark]
  return <span className={cn('relative z-[1] grid size-[22px] place-items-center rounded-full border bg-[var(--f-panel-solid)] [&_svg]:size-3', cls)}>{icon}</span>
}

function Entry({ mark, title, detail, result, last }: { mark: Mark; title: ReactNode; detail?: ReactNode; result: ReactNode; last?: boolean }) {
  return (
    <li className="relative grid grid-cols-[22px_minmax(0,1fr)_auto] gap-x-3 pb-3.5">
      {!last && <span aria-hidden className="absolute left-[10.5px] top-[22px] bottom-0 w-px bg-[var(--f-line-2)]" />}
      <Marker mark={mark} />
      <div className="min-w-0 pt-[2px]">
        <p className="text-[13.5px] font-medium leading-snug">{title}</p>
        {detail && <p className="f-small f-ink-2 mt-0.5">{detail}</p>}
      </div>
      <span className="f-small f-ink-3 whitespace-nowrap pt-[3px] text-right">{result}</span>
    </li>
  )
}

/**
 * Every access decision as an auditable ledger: account gate → certificate gate → deny rules →
 * allow rules in precedence → tenant default → outcome with the RADIUS reply.
 */
export function DecisionLedger({ decision, identity, rules, groups, vlans, certificate, showAttributes = true }: {
  decision: Decision
  identity: Identity
  rules: AccessRule[]
  groups: DirectoryGroup[]
  vlans: Vlan[]
  certificate?: Certificate
  showAttributes?: boolean
}) {
  const [showUnmatched, setShowUnmatched] = useState(false)
  const groupName = (id: string) => groups.find((g) => g.id === id)?.name ?? id
  const ruleById = (id: string) => rules.find((r) => r.id === id)
  const memberOf = (r: AccessRule) => r.groupIds.filter((g) => identity.groupIds.includes(g)).map(groupName)
  const vlan = vlans.find((v) => v.id === decision.vlanId)
  const disabled = rules.filter((r) => !r.enabled).length

  const account = decision.steps.find((s) => s.kind === 'account')
  const cert = decision.steps.find((s) => s.kind === 'certificate')
  const ruleSteps = decision.steps.filter((s): s is Extract<typeof s, { kind: 'rule' }> => s.kind === 'rule')
  const def = decision.steps.find((s) => s.kind === 'default')
  const denyMatched = ruleSteps.filter((s) => s.action === 'deny' && s.matched)
  const allowMatched = ruleSteps.filter((s) => s.action === 'allow' && s.matched)
  const unmatched = ruleSteps.filter((s) => !s.matched)
  const gated = (account && account.kind === 'account' && !account.ok) || (cert && cert.kind === 'certificate' && !cert.ok)

  const entries: ReactNode[] = []
  if (account && account.kind === 'account') {
    entries.push(
      <Entry
        key="acct"
        mark={account.ok ? 'pass' : 'fail'}
        title={account.ok ? 'Account enabled' : `Account ${identity.accountState}`}
        detail={account.ok ? (identity.source === 'ad' ? 'Active Directory reports the account as enabled.' : 'Local account is enabled.') : 'Disabled, locked and deleted accounts are always denied. No rule can override this.'}
        result={account.ok ? 'Pass' : 'Stops here'}
      />,
    )
  }
  if (cert && cert.kind === 'certificate') {
    entries.push(
      <Entry key="cert" mark={cert.ok ? 'pass' : 'fail'} title={cert.ok ? 'Certificate valid' : cert.detail} detail={cert.ok ? `Serial ${certificate?.serial.slice(0, 12)}… chains to this tenant’s issuing CA.` : 'Revoked and expired certificates are rejected before any rule is checked.'} result={cert.ok ? 'Pass' : 'Stops here'} />,
    )
  }
  if (!gated) {
    for (const s of denyMatched) {
      const r = ruleById(s.ruleId)
      entries.push(
        <Entry key={s.ruleId} mark={s.ruleId === decision.decidingRuleId ? 'decides' : 'fail'} title={<>Deny rule “{r?.name}” matched</>} detail={<>Member of {memberOf(r!).join(', ')}. Deny rules always win, wherever they sit in the order.</>} result={s.ruleId === decision.decidingRuleId ? 'Decides' : 'Matched'} />,
      )
    }
    allowMatched.forEach((s) => {
      const r = ruleById(s.ruleId)
      const decides = s.ruleId === decision.decidingRuleId
      const shadowed = decision.outcome === 'deny'
      entries.push(
        <Entry
          key={s.ruleId}
          mark={decides ? 'decides' : 'skip'}
          title={<>Rule “{r?.name}” · Allow</>}
          detail={
            decides ? (
              <>Member of {memberOf(r!).join(', ')} · priority {r?.priority}</>
            ) : shadowed ? (
              <>Matched, but a Deny rule already decided.</>
            ) : (
              <>Also matched (priority {r?.priority}); a higher-precedence rule decided.</>
            )
          }
          result={decides ? 'Decides' : 'Not used'}
        />,
      )
    })
    if (def && def.kind === 'default') {
      entries.push(<Entry key="def" mark="decides" title={`No rule matched · tenant default: ${def.action === 'deny' ? 'Deny' : 'Allow'}`} detail="None of the user’s groups appear in an enabled rule." result="Decides" />)
    }
  }

  return (
    <div>
      <ol className="list-none p-0" aria-label="Decision ledger">
        {entries}
        <li className="relative grid grid-cols-[22px_minmax(0,1fr)] gap-x-3">
          <span className={cn('relative z-[1] grid size-[22px] place-items-center rounded-full [&_svg]:size-3', decision.outcome === 'allow' ? 'bg-[var(--f-valid)] text-[#04201c]' : 'bg-[var(--f-crit)] text-white')} aria-hidden>
            {decision.outcome === 'allow' ? <Check /> : <Ban />}
          </span>
          <div className="min-w-0">
            <p className="flex flex-wrap items-center gap-2 text-[15px] font-semibold">
              {decision.outcome === 'allow' ? 'Access-Accept' : 'Access-Reject'}
              {decision.outcome === 'allow' && vlan && (
                <>
                  <span className="f-ink-3 font-normal">to</span>
                  <span className="text-[15px]">VLAN <VlanTag vlan={vlan} /></span>
                </>
              )}
            </p>
            {decision.outcome === 'deny' && <p className="f-small f-ink-2 mt-0.5">Decided by: {decisionReason(decision, (id) => ruleById(id)?.name ?? id)}</p>}
          </div>
        </li>
      </ol>

      {(unmatched.length > 0 || disabled > 0 || gated) && (
        <div className="mt-3 pl-[34px]">
          {gated ? (
            <p className="f-small f-ink-3">Access rules were not evaluated.</p>
          ) : (
            <>
              <button type="button" className="f-small f-ink-2 inline-flex items-center gap-1 rounded hover:text-[var(--f-ink)]" aria-expanded={showUnmatched} onClick={() => setShowUnmatched((v) => !v)}>
                <ChevronDown className={cn('size-3.5 transition-transform', showUnmatched && 'rotate-180')} aria-hidden />
                {unmatched.length} {unmatched.length === 1 ? 'rule' : 'rules'} did not match{disabled > 0 && ` · ${disabled} disabled ${disabled === 1 ? 'rule' : 'rules'} skipped`}
              </button>
              {showUnmatched && (
                <ul className="f-small f-ink-2 mt-2 space-y-1">
                  {unmatched.map((s) => {
                    const r = ruleById(s.ruleId)
                    return (
                      <li key={s.ruleId} className="flex items-center gap-2">
                        <Minus className="size-3 f-ink-3" aria-hidden />
                        <span>{r?.name}</span>
                        <span className="f-ink-3">· {r?.action === 'deny' ? 'Deny' : 'Allow'} · needs {r?.groupIds.map(groupName).join(' or ')}</span>
                      </li>
                    )
                  })}
                </ul>
              )}
            </>
          )}
        </div>
      )}

      {showAttributes && decision.outcome === 'allow' && decision.attributes.length > 0 && <AttributeTable attributes={decision.attributes} className="mt-4" />}
    </div>
  )
}

export function AttributeTable({ attributes, className }: { attributes: RadiusAttribute[]; className?: string }) {
  return (
    <div className={cn('overflow-x-auto rounded-[8px] border border-[var(--f-line)] bg-[rgba(6,9,17,0.45)]', className)}>
      <table className="f-table">
        <caption className="sr-only">RADIUS reply attributes</caption>
        <thead>
          <tr>
            <th className="pt-2.5">Reply attribute</th>
            <th className="pt-2.5">Value</th>
          </tr>
        </thead>
        <tbody>
          {attributes.map((a) => (
            <tr key={a.name}>
              <td className="f-mono text-[12.5px]">{a.name}</td>
              <td className="f-mono text-[12.5px] f-ink-2">{a.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** One-line decision for table rows: outcome, then what decided it. */
export function DecisionSnippet({ decision, rules, compact }: { decision: Decision; rules: AccessRule[]; compact?: boolean }) {
  const reason = decisionReason(decision, (id) => rules.find((r) => r.id === id)?.name ?? id)
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      <AccessChip outcome={decision.outcome} />
      {!compact && <span className="f-small f-ink-2 truncate">{reason}</span>}
    </span>
  )
}

export function RuleOutcome({ rule, vlans }: { rule: AccessRule; vlans: Vlan[] }) {
  return rule.action === 'deny' ? <Chip tone="crit" icon={<Ban aria-hidden />}>Reject</Chip> : <VlanTag vlan={vlans.find((v) => v.id === rule.vlanId)} />
}
