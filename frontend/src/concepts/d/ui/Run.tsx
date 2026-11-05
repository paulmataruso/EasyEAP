import { Ban, CircleCheck, UserX } from 'lucide-react'
import type { AccessRule, Decision, DirectoryGroup, Identity, Vlan } from '@/domain/types'
import { cn } from '@/ui/lib'
import { ruleTone, vlanTone, type Tone } from '../model/codes'
import { GroupTape, RuleTape, VlanTape } from './Tape'

/** 2px colour run. `trace` plays the one authored motion: the run lights from its source to its end. */
export function Run({ tone, dim, trace, className }: { tone: Tone; dim?: boolean; trace?: boolean; className?: string }) {
  return <span aria-hidden="true" className={cn('d-run', trace && 'd-run-trace', className)} data-tone={tone} data-dim={dim || undefined} />
}

/**
 * The decision drawn as one colour run: the user's matching groups → the deciding rule → the VLAN.
 * The same colours appear on the policy screen, so the path can be followed by label and colour.
 */
export function DecisionRun({ identity, decision, rules, vlans, groups, traceKey }: {
  identity: Identity
  decision: Decision
  rules: AccessRule[]
  vlans: Vlan[]
  groups: DirectoryGroup[]
  /** Changing this replays the trace motion. */
  traceKey?: string
}) {
  const rule = rules.find((r) => r.id === decision.decidingRuleId) ?? null
  const vlan = vlans.find((v) => v.id === decision.vlanId) ?? null
  const tone: Tone = rule ? ruleTone(rule, vlans) : decision.outcome === 'allow' ? vlanTone(vlan) : 'deny'
  const accountStep = decision.steps.find((s) => s.kind === 'account')
  const certStep = decision.steps.find((s) => s.kind === 'certificate' && !s.ok)
  const matched = rule ? groups.filter((g) => rule.groupIds.includes(g.id) && identity.groupIds.includes(g.id)) : []
  const memberGroups = groups.filter((g) => identity.groupIds.includes(g.id))

  let source
  if (accountStep && !accountStep.ok) {
    source = <span className="d-terminal"><UserX aria-hidden="true" className="size-3.5" />{accountStep.detail}</span>
  } else if (certStep) {
    source = <span className="d-terminal"><Ban aria-hidden="true" className="size-3.5" />{certStep.detail}</span>
  } else {
    const shown = matched.length ? matched : memberGroups
    source = (
      <span className="d-tapes">
        {shown.map((g) => <GroupTape key={g.id} group={g} rules={rules} vlans={vlans} />)}
        {!shown.length && <span className="d-terminal">No directory groups</span>}
      </span>
    )
  }

  return (
    <div className="d-runbox" key={traceKey}>
    <div className="d-runline flex-wrap gap-y-2" role="group" aria-label={`Decision path: ${decision.outcome === 'allow' ? `allowed onto VLAN ${vlan?.vlanId ?? 'default'}` : 'denied'}${rule ? ` by rule ${rule.name}` : ''}`}>
      {source}
      <Run tone={tone} trace />
      {rule ? <RuleTape rule={rule} vlans={vlans} /> : <span className="d-terminal">{decision.steps.some((s) => s.kind === 'default') ? 'Tenant default' : 'Gate'}</span>}
      <Run tone={tone} trace />
      {decision.outcome === 'allow' && vlan ? (
        <span className="inline-flex items-center gap-2">
          <VlanTape vlan={vlan} />
          <span className="d-status" data-tone="ok"><CircleCheck aria-hidden="true" />Access-Accept</span>
        </span>
      ) : decision.outcome === 'allow' ? (
        <span className="d-status" data-tone="ok"><CircleCheck aria-hidden="true" />Access-Accept, no VLAN</span>
      ) : (
        <span className="d-status" data-tone="crit"><Ban aria-hidden="true" />Access-Reject</span>
      )}
    </div>
    </div>
  )
}
