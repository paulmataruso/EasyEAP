import { CircleCheck, CircleMinus, CircleX } from 'lucide-react'
import type { AccessRule, Decision, DirectoryGroup, Identity, Vlan } from '@/domain/types'
import { VlanTag } from '../ui/Vlan'
import { AccessMark } from '../ui/Status'

interface Props {
  decision: Decision
  identity: Identity
  rules: AccessRule[]
  vlans: Vlan[]
  groups: DirectoryGroup[]
}

/** Every step the policy engine took, in evaluation order, with the deciding step marked. */
export function DecisionTrace({ decision, identity, rules, vlans, groups }: Props) {
  const groupName = (id: string) => groups.find((g) => g.id === id)?.name ?? id
  const denyWon = decision.outcome === 'deny' && decision.decidingRuleId !== null
  return (
    <ol className="c-trace" aria-label="Decision trace">
      {decision.steps.map((step, i) => {
        if (step.kind === 'account' || step.kind === 'certificate') {
          return (
            <li key={i} className={step.ok ? 'is-pass' : 'is-fail'}>
              {step.ok ? <CircleCheck size={17} aria-hidden="true" /> : <CircleX size={17} aria-hidden="true" />}
              <span className="c-trace-title">{step.detail}</span>
              <span className="c-trace-detail">
                {step.kind === 'account'
                  ? step.ok
                    ? `${identity.source === 'ad' ? 'Active Directory' : 'Local account'} reports ${identity.username} as enabled.`
                    : 'Disabled, locked and deleted accounts are always denied. No rule can override this.'
                  : step.ok
                    ? 'Not revoked and within its validity period.'
                    : 'Revoked and expired certificates are always denied.'}
              </span>
              {!step.ok ? <span className="c-trace-tag"><span className="c-tag is-strong">Decided</span></span> : null}
            </li>
          )
        }
        if (step.kind === 'rule') {
          const rule = rules.find((r) => r.id === step.ruleId)
          const deciding = decision.decidingRuleId === step.ruleId
          const matchedGroups = rule ? rule.groupIds.filter((g) => identity.groupIds.includes(g)).map(groupName) : []
          const vlan = rule?.vlanId ? vlans.find((v) => v.id === rule.vlanId) : null
          const cls = !step.matched ? 'is-skip' : step.action === 'deny' ? 'is-fail' : deciding ? 'is-pass' : 'is-skip'
          let detail: string
          if (!step.matched) detail = rule ? `Needs ${rule.groupIds.map(groupName).join(' or ')}` : 'Not matched'
          else if (deciding) detail = `Matched ${matchedGroups.join(', ')}${step.action === 'deny' ? '. Deny rules win over every Allow rule.' : ''}`
          else if (step.action === 'allow' && denyWon) detail = `Matched ${matchedGroups.join(', ')}, but a Deny rule already applies.`
          else detail = `Matched ${matchedGroups.join(', ')}, but a higher rule decided first.`
          return (
            <li key={i} className={cls}>
              {!step.matched ? <CircleMinus size={17} aria-hidden="true" /> : step.action === 'deny' ? <CircleX size={17} aria-hidden="true" /> : <CircleCheck size={17} aria-hidden="true" />}
              <span className="c-trace-title">
                {rule?.name ?? step.ruleId}
                <span className="c-faint" style={{ fontWeight: 400 }}>
                  {' '}
                  · {step.action === 'deny' ? 'Deny' : 'Allow'}
                  {vlan ? (
                    <>
                      {' '}
                      to <span className="c-nowrap">VLAN {vlan.vlanId}</span>
                    </>
                  ) : null}
                </span>
              </span>
              <span className="c-trace-detail">{detail}</span>
              {deciding ? <span className="c-trace-tag"><span className="c-tag is-strong">Decided</span></span> : null}
            </li>
          )
        }
        return (
          <li key={i} className={step.action === 'allow' ? 'is-pass' : 'is-fail'}>
            {step.action === 'allow' ? <CircleCheck size={17} aria-hidden="true" /> : <CircleX size={17} aria-hidden="true" />}
            <span className="c-trace-title">Tenant default: {step.action === 'allow' ? 'Allow' : 'Deny'}</span>
            <span className="c-trace-detail">{step.detail}. Unmatched people fail safe.</span>
            <span className="c-trace-tag"><span className="c-tag is-strong">Decided</span></span>
          </li>
        )
      })}
    </ol>
  )
}

/** "Allowed · VLAN 120 IT Infrastructure" verdict line. */
export function Verdict({ decision, vlans }: { decision: Decision; vlans: Vlan[] }) {
  const vlan = vlans.find((v) => v.id === decision.vlanId)
  return (
    <div className="c-verdict">
      <AccessMark outcome={decision.outcome} />
      {decision.outcome === 'allow' ? <VlanTag vlan={vlan} /> : <span className="c-muted" style={{ fontSize: 15 }}>No VLAN is sent; RADIUS replies Access-Reject.</span>}
    </div>
  )
}

/** RADIUS reply attributes the decision produces. */
export function ReplyAttributes({ decision }: { decision: Decision }) {
  if (decision.outcome === 'deny' || decision.attributes.length === 0) {
    return <p className="c-muted c-small" style={{ margin: 0 }}>Access-Reject carries no reply attributes.</p>
  }
  return (
    <dl className="c-attr">
      {decision.attributes.map((a) => (
        <div key={a.name} style={{ display: 'contents' }}>
          <dt>{a.name}</dt>
          <dd>{a.value}</dd>
        </div>
      ))}
    </dl>
  )
}
