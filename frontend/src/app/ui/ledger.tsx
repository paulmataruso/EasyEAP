// The decision ledger: account gate → certificate gate → deny rules → allow rules in precedence → tenant default →
// Access-Accept/Reject with the RFC 3580 reply. Reads the same on the user record, in Test-a-user and in the policy
// preview. Input is the backend's decision trace (Outcome.steps) plus the rules it refers to.
import { useState, type ReactNode } from 'react'
import { Ban, Check, ChevronDown, Minus, Stamp, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import type { Outcome, RadiusAttribute } from '../api/types'
import { remaining } from '../lib/format'
import { VlanTag } from './index'

export interface LedgerRule { id: string; name: string; action: 'allow' | 'deny'; priority: number; enabled: boolean; groups: Array<{ id: string; name: string }> }
export interface LedgerVlan { vlan_id: number; name: string; color: string }
/** A valid certificate on record, used as evidence for the certificate gate where the ledger has one (the user record). */
export interface LedgerCert { name: string; not_after: string }

export const reasonText: Record<string, string> = {
  account_disabled: 'Account is disabled, locked or deleted',
  cert_revoked: 'Certificate was revoked',
  cert_expired: 'Certificate has expired',
  cert_unknown: 'Certificate not issued by EasyEAP',
  unknown_ca: 'Certificate from an untrusted authority',
  policy_deny: 'Denied by an access rule',
  identity_unauthorized: 'No rule grants access, and the tenant default is Deny',
  snapshot_stale: 'RADIUS authorization data is out of date (fail closed)',
}

type Mark = 'pass' | 'fail' | 'skip' | 'decides'

function Marker({ mark }: { mark: Mark }) {
  const cls = {
    pass: 'border-[rgba(45,212,191,0.55)] text-[var(--ee-valid)]',
    fail: 'border-[rgba(244,63,94,0.6)] text-[var(--ee-crit-ink)]',
    skip: 'border-[var(--ee-line-2)] text-[var(--ee-ink-3)]',
    decides: 'border-[rgba(226,194,117,0.7)] text-[var(--ee-gold)] bg-[rgba(226,194,117,0.1)]',
  }[mark]
  const icon = { pass: <Check aria-hidden />, fail: <X aria-hidden />, skip: <Minus aria-hidden />, decides: <Stamp aria-hidden /> }[mark]
  return <span className={cn('relative z-[1] grid size-[22px] place-items-center rounded-full border bg-[var(--ee-panel-solid)] [&_svg]:size-3', cls)}>{icon}</span>
}

function Entry({ mark, title, detail, result, last }: { mark: Mark; title: ReactNode; detail?: ReactNode; result: ReactNode; last?: boolean }) {
  const label = { pass: 'Passed', fail: 'Failed', skip: 'Not used', decides: 'Decides' }[mark]
  return (
    <li className="relative grid grid-cols-[22px_minmax(0,1fr)_auto] gap-x-3 pb-3.5">
      {!last && <span aria-hidden className="absolute left-[10.5px] top-[22px] bottom-0 w-px bg-[var(--ee-line-2)]" />}
      <Marker mark={mark} />
      <div className="min-w-0 pt-[2px]">
        <p className="text-[13.5px] font-medium leading-snug"><span className="sr-only">{label}: </span>{title}</p>
        {detail && <p className="ee-small ee-ink-2 mt-0.5">{detail}</p>}
      </div>
      <span className="ee-small ee-ink-3 whitespace-nowrap pt-[3px] text-right" aria-hidden>{result}</span>
    </li>
  )
}

export function DecisionLedger({ outcome, rules, identityGroups, vlans, accountState = 'enabled', source = 'ad', showAttributes = true, policyOnly, certificates }: {
  outcome: Outcome
  rules: LedgerRule[]
  identityGroups: Array<{ id: string; name: string }>
  vlans: LedgerVlan[]
  accountState?: string
  source?: string
  showAttributes?: boolean
  /** Evaluated without a concrete certificate (preview or Test a user): say so, so "allowed" isn't read as "can connect". */
  policyOnly?: boolean
  /** With `policyOnly`: the valid certificates on record for this decision. The certificate gate is then evaluated
   *  against them instead of assumed, so the ledger agrees with the certificate list beside it. */
  certificates?: LedgerCert[]
}) {
  const [showUnmatched, setShowUnmatched] = useState(false)
  const ruleById = (id?: string) => rules.find((r) => r.id === id)
  const mine = new Set(identityGroups.map((g) => g.id))
  const memberOf = (r: LedgerRule | undefined) => (r ? r.groups.filter((g) => mine.has(g.id)).map((g) => g.name) : [])
  const vlan = vlans.find((v) => v.vlan_id === outcome.vlan_id)
  const disabled = rules.filter((r) => !r.enabled).length

  const account = outcome.steps.find((s) => s.kind === 'account')
  const cert = outcome.steps.find((s) => s.kind === 'certificate')
  const ruleSteps = outcome.steps.filter((s) => s.kind === 'rule')
  const def = outcome.steps.find((s) => s.kind === 'default')
  const denyMatched = ruleSteps.filter((s) => s.action === 'deny' && s.matched)
  const allowMatched = ruleSteps.filter((s) => s.action === 'allow' && s.matched)
  const unmatched = ruleSteps.filter((s) => !s.matched)
  const gated = (account && !account.ok) || (cert && !cert.ok)

  const entries: ReactNode[] = []
  if (account) {
    entries.push(<Entry key="acct" mark={account.ok ? 'pass' : 'fail'}
      title={account.ok ? 'Account enabled' : `Account ${accountState}`}
      detail={account.ok ? (source === 'ad' ? 'Active Directory reports the account as enabled.' : 'Local account is enabled.') : 'Disabled, locked and deleted accounts are always denied. No rule can override this.'}
      result={account.ok ? 'Pass' : 'Stops here'} />)
  }
  if (cert) {
    entries.push(<Entry key="cert" mark={cert.ok ? 'pass' : 'fail'} title={cert.ok ? 'Certificate valid' : cert.detail}
      detail={cert.ok ? cert.detail : 'Revoked and expired certificates are rejected before any rule is checked.'} result={cert.ok ? 'Pass' : 'Stops here'} />)
  } else if (policyOnly && account?.ok && certificates) {
    const [first, ...more] = [...certificates].sort((a, b) => b.not_after.localeCompare(a.not_after))
    entries.push(first
      ? <Entry key="cert" mark="pass" title="Certificate valid"
          detail={<>{first.name} · valid for {remaining(first.not_after)}{more.length > 0 && <> · and {more.length} more</>}</>} result="Pass" />
      : <Entry key="cert" mark="fail" title="No valid certificate"
          detail="RADIUS rejects every connection until a certificate is issued to one of this user’s devices. The rules below show what would apply then." result="Needs one" />)
  } else if (policyOnly && account?.ok) {
    entries.push(<Entry key="cert" mark="skip" title="Certificate not checked here" detail="This evaluates the policy only. At connection time RADIUS also requires a valid certificate issued to this user." result="Assumed valid" />)
  }
  if (!gated) {
    for (const s of denyMatched) {
      const r = ruleById(s.ruleId)
      const decides = s.ruleId === outcome.deciding_rule_id
      entries.push(<Entry key={s.ruleId} mark={decides ? 'decides' : 'fail'} title={<>Deny rule “{r?.name ?? 'deleted rule'}” matched</>}
        detail={<>Member of {memberOf(r).join(', ') || 'a matching group'}. Deny rules always win, wherever they sit in the order.</>} result={decides ? 'Decides' : 'Matched'} />)
    }
    for (const s of allowMatched) {
      const r = ruleById(s.ruleId)
      const decides = s.ruleId === outcome.deciding_rule_id
      entries.push(<Entry key={s.ruleId} mark={decides ? 'decides' : 'skip'} title={<>Rule “{r?.name ?? 'deleted rule'}” · Allow</>}
        detail={decides ? <>Member of {memberOf(r).join(', ')} · position {rules.filter((x) => x.action === 'allow' && x.enabled).findIndex((x) => x.id === r?.id) + 1} among Allow rules</>
          : outcome.outcome === 'deny' ? <>Matched, but a Deny rule already decided.</> : <>Also matched; an Allow rule higher in the order decided.</>}
        result={decides ? 'Decides' : 'Not used'} />)
    }
    if (def) {
      entries.push(<Entry key="def" mark="decides" title={`No rule matched · tenant default: ${def.action === 'allow' ? 'Allow' : 'Deny'}`} detail="None of the user’s groups appear in an enabled rule." result="Decides" />)
    }
  }

  const allow = outcome.outcome === 'allow'
  return (
    <div>
      <ol className="list-none p-0" aria-label="Decision ledger">
        {entries}
        <li className="relative grid grid-cols-[22px_minmax(0,1fr)] gap-x-3">
          <span className={cn('relative z-[1] grid size-[22px] place-items-center rounded-full [&_svg]:size-3', allow ? 'bg-[var(--ee-valid)] text-[#04201c]' : 'bg-[var(--ee-crit)] text-white')} aria-hidden>
            {allow ? <Check /> : <Ban />}
          </span>
          <div className="min-w-0">
            <p className="flex flex-wrap items-center gap-2 text-[15px] font-semibold">
              {allow ? 'Access-Accept' : 'Access-Reject'}
              {allow && outcome.vlan_id !== null && (
                <>
                  <span className="ee-ink-3 font-normal">to VLAN</span>
                  <VlanTag vlanId={outcome.vlan_id} name={vlan?.name} color={vlan?.color} />
                </>
              )}
            </p>
            {allow && certificates && certificates.length === 0 && account?.ok && <p className="ee-small ee-ink-2 mt-0.5">Once a valid certificate is installed. Until then RADIUS sends Access-Reject.</p>}
            {!allow && <p className="ee-small ee-ink-2 mt-0.5">{outcome.reason_code === 'policy_deny' && ruleById(outcome.deciding_rule_id ?? undefined) ? `Denied by “${ruleById(outcome.deciding_rule_id ?? undefined)!.name}”` : reasonText[outcome.reason_code ?? ''] ?? outcome.reason_code}</p>}
          </div>
        </li>
      </ol>

      {(unmatched.length > 0 || disabled > 0 || gated) && (
        <div className="mt-3 pl-[34px]">
          {gated ? (
            <p className="ee-small ee-ink-3">Access rules were not evaluated.</p>
          ) : (
            <>
              <button type="button" className="ee-small ee-ink-2 inline-flex items-center gap-1 rounded hover:text-[var(--ee-ink)]" aria-expanded={showUnmatched} onClick={() => setShowUnmatched((v) => !v)}>
                <ChevronDown className={cn('size-3.5 transition-transform', showUnmatched && 'rotate-180')} aria-hidden />
                {unmatched.length} {unmatched.length === 1 ? 'rule' : 'rules'} did not match{disabled > 0 && ` · ${disabled} disabled ${disabled === 1 ? 'rule' : 'rules'} skipped`}
              </button>
              {showUnmatched && (
                <ul className="ee-small ee-ink-2 mt-2 space-y-1">
                  {unmatched.map((s) => {
                    const r = ruleById(s.ruleId)
                    return (
                      <li key={s.ruleId} className="flex items-center gap-2">
                        <Minus className="size-3 ee-ink-3" aria-hidden />
                        <span>{r?.name ?? 'deleted rule'}</span>
                        <span className="ee-ink-3">· {r?.action === 'deny' ? 'Deny' : 'Allow'} · needs {r?.groups.map((g) => g.name).join(' or ') || 'a group'}</span>
                      </li>
                    )
                  })}
                </ul>
              )}
            </>
          )}
        </div>
      )}

      {showAttributes && allow && outcome.attributes.length > 0 && <AttributeTable attributes={outcome.attributes} className="mt-4" />}
    </div>
  )
}

export function AttributeTable({ attributes, className }: { attributes: RadiusAttribute[]; className?: string }) {
  return (
    <div className={cn('overflow-x-auto rounded-[8px] border border-[var(--ee-line)] bg-[rgba(6,9,17,0.45)]', className)}>
      <table className="ee-table">
        <caption className="sr-only">RADIUS reply attributes</caption>
        <thead><tr><th className="pt-2.5">Reply attribute</th><th className="pt-2.5">Value</th></tr></thead>
        <tbody>
          {attributes.map((a) => (
            <tr key={a.name}><td className="ee-mono text-[12.5px]">{a.name}</td><td className="ee-mono text-[12.5px] ee-ink-2">{a.value}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
