import { ArrowDown, ArrowUp, Ban, CircleCheck, CircleMinus, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { AccessRule, Decision } from '@/domain/types'
import { evaluatePolicy } from '@/domain/policy'
import { now, useDecision, useDecisions, useTenantData, useTenants } from '@/prototype/store'
import { useConceptActions } from '../model/actions'
import type { ScreenId } from '../../contract'
import { ruleTone, siteCode, vlanTone } from '../model/codes'
import { SelectField, Toggle } from '../ui/Controls'
import { DecisionRun, Run } from '../ui/Run'
import { SegmentBar } from '../ui/Charts'
import { EmptyState, KV, MetaSep, Notice, PageHeader, Section } from '../ui/Section'
import { StatusMark } from '../ui/Status'
import { GroupTape, RuleTape, Tape, VlanTape } from '../ui/Tape'
import { useToast } from '../ui/Toast'

type Nav = (s: ScreenId, id?: string) => void

export function Policies({ navigate }: { navigate: Nav }) {
  const { current } = useTenants()
  const d = useTenantData()
  const decisions = useDecisions()
  const { moveRule, toggleRule } = useConceptActions()
  const toast = useToast()

  const sorted = useMemo(() => [...d.identities].sort((a, b) => a.displayName.localeCompare(b.displayName)), [d.identities])
  const defaultPick = useMemo(() => {
    const multi = sorted.find((i) => d.rules.filter((r) => r.enabled && r.action === 'allow' && r.groupIds.some((g) => i.groupIds.includes(g))).length >= 2 && i.accountState === 'enabled' && decisions.get(i.id)?.outcome === 'allow')
    return (multi ?? sorted[0])?.id ?? ''
  }, [sorted, d.rules, decisions])
  const [picked, setPicked] = useState<string>('')
  const testId = picked && d.identities.some((i) => i.id === picked) ? picked : defaultPick
  const identity = d.identities.find((i) => i.id === testId)
  const decision = useDecision(identity)
  const [confirm, setConfirm] = useState<string | null>(null)

  /** How many identities would change outcome or VLAN under a hypothetical rule set. */
  const impact = (next: AccessRule[]) =>
    d.identities.filter((i) => {
      const a = decisions.get(i.id)
      const b = evaluatePolicy(i, next, d.defaults, d.vlans, { now: now() })
      return a?.outcome !== b.outcome || a?.vlanId !== b.vlanId
    }).length

  const decidedBy = (ruleId: string) => d.identities.filter((i) => decisions.get(i.id)?.decidingRuleId === ruleId).length
  const stepFor = (ruleId: string) => decision?.steps.find((s) => s.kind === 'rule' && s.ruleId === ruleId) as Extract<Decision['steps'][number], { kind: 'rule' }> | undefined

  const doToggle = (r: AccessRule) => {
    const n = impact(d.rules.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)))
    toggleRule(r.id)
    setConfirm(null)
    toast({ title: `“${r.name}” ${r.enabled ? 'disabled' : 'enabled'}`, description: n ? `${n} ${n === 1 ? 'user’s' : 'users’'} access changed. The RADIUS snapshot reloads within seconds.` : 'No user’s access changed.' })
  }
  const doMove = (r: AccessRule, dir: -1 | 1) => {
    const idx = d.rules.findIndex((x) => x.id === r.id)
    const swap = d.rules[idx + dir]
    if (!swap) return
    const next = d.rules.map((x) => (x.id === r.id ? { ...x, priority: swap.priority } : x.id === swap.id ? { ...x, priority: r.priority } : x))
    const n = impact(next)
    moveRule(r.id, dir)
    toast({ title: `“${r.name}” moved ${dir < 0 ? 'up' : 'down'}`, description: n ? `${n} ${n === 1 ? 'user now lands' : 'users now land'} on a different VLAN.` : r.action === 'deny' ? 'Deny rules win from any position; no access changed.' : 'No user’s access changed.' })
  }

  const landing = d.vlans.map((v) => ({ key: v.id, label: `VLAN ${v.vlanId} ${v.name}`, value: d.identities.filter((i) => decisions.get(i.id)?.vlanId === v.id).length, colorClass: `bg-${vlanTone(v)}` }))
  const denied = d.identities.filter((i) => decisions.get(i.id)?.outcome === 'deny').length
  const defaultVlan = d.vlans.find((v) => v.id === d.defaults.defaultVlanId)

  return (
    <>
      <PageHeader
        title="VLAN policies"
        meta={<><span className="tnum">{d.vlans.length} VLANs</span><MetaSep /><span className="tnum">{d.rules.filter((r) => r.enabled).length} of {d.rules.length} rules enabled</span><MetaSep /><span>Default: {d.defaults.defaultAction === 'deny' ? 'deny' : `allow onto VLAN ${defaultVlan?.vlanId}`}</span></>}
      />

      <Section id="vlans" title="VLANs" description="Each VLAN keeps its field colour on every screen: tapes, runs, charts.">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 pt-3 pb-1">
          <span className="text-[12.5px] text-[var(--d-ink-2)]">Where {d.identities.length} users land</span>
          <SegmentBar className="min-w-[200px] flex-1" parts={[...landing, { key: 'deny', label: 'Denied', value: denied, colorClass: 'bg-deny' }]} label="Where users land" />
        </div>
        <div className="d-table-wrap">
          <table className="d-table">
            <caption className="sr-only">VLANs</caption>
            <thead><tr className="d-th-cols"><th scope="col">Label</th><th scope="col">VLAN</th><th scope="col" className="d-hide-sm">Assigned by</th><th scope="col" className="d-hide-sm">Tunnel-Private-Group-ID</th><th scope="col" data-align="right">Users</th></tr></thead>
            <tbody>
              {d.vlans.map((v, i) => (
                <tr key={v.id}>
                  <td><VlanTape vlan={v} /></td>
                  <td><span className="flex items-center gap-2.5"><i aria-hidden="true" className={`inline-block h-2.5 w-2.5 rounded-sm bg-${vlanTone(v)}`} /><span className="font-medium">{v.name}</span></span><span className="d-sub pl-5">{v.description}</span></td>
                  <td className="d-hide-sm"><span className="d-tapes">{d.rules.filter((r) => r.vlanId === v.id).map((r) => <RuleTape key={r.id} rule={r} vlans={d.vlans} size="sm" />)}{!d.rules.some((r) => r.vlanId === v.id) && <span className="ink-3">No rule</span>}</span></td>
                  <td className="d-hide-sm mono">{v.vlanId}</td>
                  <td data-align="right" className="tnum">{landing[i].value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section id="test" title="Test a user" description="Pick an identity to trace its decision. The matching rule lights up below and the reply shows the exact RADIUS attributes.">
        {identity && decision ? (
          <div className="grid gap-4 pt-4">
            <div className="flex flex-wrap items-end gap-x-6 gap-y-4">
              <SelectField
                label="Identity"
                value={testId}
                onChange={setPicked}
                width={260}
                options={sorted.filter((i, n, xs) => xs.findIndex((x) => x.id === i.id) === n).map((i) => ({ value: i.id, label: `${i.displayName} · ${i.department ?? i.source}` }))}
              />
              <div className="d-test-run">
                <DecisionRun identity={identity} decision={decision} rules={d.rules} vlans={d.vlans} groups={d.groups} traceKey={testId + d.rules.map((r) => r.id + r.priority + r.enabled).join()} />
              </div>
            </div>
            <div className="d-grid-even !gap-8">
              <div>
                <h3 className="d-h3 pb-1">Result</h3>
                <KV items={[
                  ['Outcome', decision.outcome === 'allow' ? <StatusMark key="o" tone="ok">Access-Accept</StatusMark> : <StatusMark key="o" tone="crit" icon={<Ban aria-hidden="true" />}>Access-Reject</StatusMark>],
                  ['Decided by', decision.decidingRuleId ? <RuleTape key="r" rule={d.rules.find((r) => r.id === decision.decidingRuleId)!} vlans={d.vlans} /> : identity.accountState !== 'enabled' ? `Account gate (${identity.accountState})` : 'Tenant default'],
                  ['VLAN', decision.vlanId ? <VlanTape key="v" vlan={d.vlans.find((v) => v.id === decision.vlanId)} /> : 'None'],
                  ['Groups', <span key="g" className="d-tapes">{d.groups.filter((g) => identity.groupIds.includes(g.id)).map((g) => <GroupTape key={g.id} group={g} rules={d.rules} vlans={d.vlans} size="sm" off={!!decision.decidingRuleId && !d.rules.find((r) => r.id === decision.decidingRuleId)?.groupIds.includes(g.id)} />)}</span>],
                ]} />
                <button type="button" className="d-btn d-btn--ghost d-btn--sm mt-2" onClick={() => navigate('user', identity.id)}>Open {identity.displayName.split(' ')[0]}’s record</button>
              </div>
              <div>
                <h3 className="d-h3 pb-1">RADIUS reply attributes</h3>
                {decision.attributes.length ? (
                  <KV items={decision.attributes.map((a) => [<span key="n" className="mono">{a.name}</span>, <span key="v" className="mono">{a.value}</span>])} />
                ) : (
                  <p className="border-b border-[var(--d-line)] py-2 text-[13px] text-[var(--d-ink-2)]">Access-Reject carries no VLAN attributes.</p>
                )}
              </div>
            </div>
          </div>
        ) : (
          <EmptyState title="No identities to test">Connect the directory or create a local account first.</EmptyState>
        )}
      </Section>

      <Section id="rules" title="Access rules" description="Precedence order. The first matching allow rule assigns the VLAN; changes reach RADIUS within seconds.">
        <div className="pt-3 pb-1">
          <Notice tone="info" icon={<ShieldAlert aria-hidden="true" />}>
            <strong>Deny rules always win.</strong> Any enabled deny rule that matches one of a user’s groups rejects them, wherever it sits in the list. Disabled, locked or deleted directory accounts are rejected before any rule is read.
          </Notice>
        </div>
        <div className="d-table-wrap">
          <table className="d-table">
            <caption className="sr-only">Access rules in precedence order{identity ? `, highlighted for ${identity.displayName}` : ''}</caption>
            <thead>
              <tr className="d-th-cols">
                <th scope="col" style={{ width: 36 }}>#</th>
                <th scope="col">Rule</th>
                <th scope="col">Action</th>
                <th scope="col" style={{ minWidth: 300 }}>Groups → VLAN</th>
                <th scope="col" data-align="right" className="d-hide-sm">Decides</th>
                <th scope="col">Enabled</th>
                <th scope="col" data-align="right">Order</th>
              </tr>
            </thead>
            <tbody>
              {d.rules.map((r, idx) => {
                const step = stepFor(r.id)
                const deciding = decision?.decidingRuleId === r.id
                const dim = !!decision && (!step || !step.matched) && r.enabled
                const tone = ruleTone(r, d.vlans)
                const vlan = d.vlans.find((v) => v.id === r.vlanId)
                const confirming = confirm === r.id
                return (
                  <tr key={r.id} aria-selected={decision ? deciding : undefined} data-dim={dim || !r.enabled || undefined}>
                    <td className="tnum ink-2">{idx + 1}</td>
                    <td>
                      <span className="flex flex-wrap items-center gap-2"><RuleTape rule={r} vlans={d.vlans} size="sm" /><span className="font-medium">{r.name}</span></span>
                      {(r.description || r.action === 'deny') && <span className="d-sub max-w-[46ch]">{r.description}{r.action === 'deny' ? ' Checked first regardless of position.' : ''}</span>}
                      {decision && step?.matched && <span className="mt-1 block text-[12px]" style={{ color: deciding ? 'var(--d-signal)' : 'var(--d-ink-3)' }}>{deciding ? `Decides ${identity?.displayName}` : decision.outcome === 'deny' ? 'Matches, overridden by deny' : 'Matches, lower precedence'}</span>}
                    </td>
                    <td>{r.action === 'allow' ? <StatusMark tone="ok" icon={<CircleCheck aria-hidden="true" />}>Allow</StatusMark> : <StatusMark tone="crit" icon={<Ban aria-hidden="true" />}>Deny</StatusMark>}</td>
                    <td>
                      <div className="d-runline">
                        <span className="d-tapes max-w-[60%]">
                          {r.groupIds.map((gid) => {
                            const g = d.groups.find((x) => x.id === gid)
                            const member = identity?.groupIds.includes(gid)
                            return g ? <GroupTape key={gid} group={g} rules={d.rules} vlans={d.vlans} size="sm" off={!!decision && !member} /> : null
                          })}
                        </span>
                        <Run tone={r.enabled ? tone : 'white'} dim={!r.enabled} trace={deciding} key={deciding ? `t-${testId}` : 'static'} />
                        {r.action === 'allow' && vlan ? <VlanTape vlan={vlan} size="sm" /> : <span className="d-terminal !h-[18px] !text-[11.5px]"><Ban aria-hidden="true" className="size-3" />Reject</span>}
                      </div>
                    </td>
                    <td data-align="right" className="tnum d-hide-sm">{decidedBy(r.id)}</td>
                    <td>
                      {confirming ? (
                        <span className="flex flex-wrap items-center gap-1.5" role="group" aria-label={`Confirm disabling ${r.name}`}>
                          <button type="button" className="d-btn d-btn--sm d-btn--danger" autoFocus onClick={() => doToggle(r)}>Disable</button>
                          <button type="button" className="d-btn d-btn--sm d-btn--ghost" onClick={() => setConfirm(null)}>Keep</button>
                        </span>
                      ) : (
                        <Toggle checked={r.enabled} label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`} onChange={() => {
                          if (r.enabled && r.action === 'deny') setConfirm(r.id)
                          else doToggle(r)
                        }} />
                      )}
                      {confirming && <span className="mt-1 block max-w-[24ch] text-[12px] text-[var(--d-warn)]">{impact(d.rules.map((x) => (x.id === r.id ? { ...x, enabled: false } : x)))} users would gain access.</span>}
                    </td>
                    <td data-align="right">
                      <span className="inline-flex gap-1">
                        <button type="button" className="d-btn d-btn--sm d-btn--icon" disabled={idx === 0} onClick={() => doMove(r, -1)} aria-label={`Move ${r.name} up`}><ArrowUp aria-hidden="true" /></button>
                        <button type="button" className="d-btn d-btn--sm d-btn--icon" disabled={idx === d.rules.length - 1} onClick={() => doMove(r, 1)} aria-label={`Move ${r.name} down`}><ArrowDown aria-hidden="true" /></button>
                      </span>
                    </td>
                  </tr>
                )
              })}
              <tr aria-selected={decision ? !decision.decidingRuleId && identity?.accountState === 'enabled' : undefined} data-dim={decision ? !!decision.decidingRuleId || identity?.accountState !== 'enabled' || undefined : undefined}>
                <td className="ink-3"><CircleMinus aria-hidden="true" className="size-4" /></td>
                <td><span className="flex items-center gap-2"><Tape code={{ site: siteCode(current), body: 'DEFAULT' }} tone={d.defaults.defaultAction === 'deny' ? 'deny' : 'white'} size="sm" /><span className="font-medium">No rule matched</span></span><span className="d-sub">Tenant default. Missing or stale authorization data also denies.</span></td>
                <td>{d.defaults.defaultAction === 'deny' ? <StatusMark tone="crit" icon={<Ban aria-hidden="true" />}>Deny</StatusMark> : <StatusMark tone="ok">Allow</StatusMark>}</td>
                <td>
                  <div className="d-runline">
                    <span className="d-terminal !h-[18px] !text-[11.5px]">Any other identity</span>
                    <Run tone={defaultVlan ? vlanTone(defaultVlan) : 'deny'} />
                    {defaultVlan ? <VlanTape vlan={defaultVlan} size="sm" /> : <span className="d-terminal !h-[18px] !text-[11.5px]"><Ban aria-hidden="true" className="size-3" />Reject</span>}
                  </div>
                </td>
                <td data-align="right" className="tnum d-hide-sm">{d.identities.filter((i) => { const x = decisions.get(i.id); return x && !x.decidingRuleId && i.accountState === 'enabled' }).length}</td>
                <td colSpan={2} className="ink-3 text-[12.5px]">Fixed</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[12.5px] text-[var(--d-ink-2)]">Group tapes take the colour of the rule that decides for that group, so a group and its VLAN read as one run. {current.name} groups without a rule stay on white tape.</p>
      </Section>
    </>
  )
}
