import { useId, useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Ban, FlaskConical, Info } from 'lucide-react'
import { useActions, useDecision, useDecisions, useTenantData, useTenants } from '@/prototype/store'
import { certStatusLabels } from '@/domain/explain'
import { cn, formatDuration } from '@/ui/lib'
import { PageHeader } from '../ui/PageHeader'
import { Notice, Panel, PanelHead } from '../ui/Panel'
import { IconButton } from '../ui/Button'
import { RuleActionBadge, VlanChip } from '../ui/Badge'
import { Field, SelectBox, Toggle } from '../ui/Field'
import { DecisionTrace, AttributeTable } from '../features/DecisionTrace'
import { IdentityPicker } from '../features/IdentityPicker'
import { useIntent } from '../shell/context'
import { VLAN_HEX } from '../lib/vlan'

export function PoliciesScreen() {
  const { current } = useTenants()
  const d = useTenantData()
  const decisions = useDecisions()
  const { moveRule, toggleRule } = useActions()
  const [announce, setAnnounce] = useState('')
  useIntent('policies')

  const decidedBy = useMemo(() => {
    const m = new Map<string, number>()
    for (const dec of decisions.values()) if (dec.decidingRuleId) m.set(dec.decidingRuleId, (m.get(dec.decidingRuleId) ?? 0) + 1)
    return m
  }, [decisions])
  const vlanUsers = useMemo(() => {
    const m = new Map<string, number>()
    for (const dec of decisions.values()) if (dec.vlanId) m.set(dec.vlanId, (m.get(dec.vlanId) ?? 0) + 1)
    return m
  }, [decisions])
  const groupName = (id: string) => d.groups.find((g) => g.id === id)?.name ?? id
  const denied = [...decisions.values()].filter((x) => x.outcome === 'deny').length
  const rules = d.rules

  return (
    <>
      <PageHeader title="VLAN policies" context={`${rules.filter((r) => r.enabled).length} of ${rules.length} rules enabled · ${decisions.size - denied} users allowed, ${denied} denied · ${current.name}`} />
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(380px,430px)]">
        <div className="min-w-0 space-y-3">
          <Panel id="b-sec-rules" aria-labelledby="rules-title">
            <PanelHead id="rules-title" title="Access rules" meta="in precedence order" />
            <div className="border-b border-[var(--b-line)] p-3">
              <Notice tone="info" icon={Ban} title="Deny rules always win">
                Any enabled Deny rule that matches one of a user’s groups denies access, wherever it sits in the list. Allow rules are then checked by priority, lowest number first; the first match sets the VLAN. Disabled rules are skipped.
              </Notice>
            </div>
            <div className="b-table-wrap">
              <table className="b-table" aria-label="Access rules in precedence order">
                <thead className="!static">
                  <tr>
                    <th scope="col" style={{ width: 44 }}>
                      #
                    </th>
                    <th scope="col" style={{ width: 52 }}>
                      On
                    </th>
                    <th scope="col">Rule</th>
                    <th scope="col">Action</th>
                    <th scope="col">Groups</th>
                    <th scope="col">VLAN</th>
                    <th scope="col" data-align="end">
                      Decides
                    </th>
                    <th scope="col" data-align="end">
                      <span className="sr-only">Reorder</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r, i) => {
                    const vlan = d.vlans.find((v) => v.id === r.vlanId)
                    const decides = decidedBy.get(r.id) ?? 0
                    return (
                      <tr key={r.id} className={cn(!r.enabled && '[&>td]:text-[var(--b-text-3)]')}>
                        <td>
                          <span className="b-cond b-num text-[14px] font-semibold text-[var(--b-text-2)]">{r.priority}</span>
                        </td>
                        <td>
                          <Toggle
                            checked={r.enabled}
                            label={`${r.enabled ? 'Disable' : 'Enable'} rule “${r.name}”`}
                            onChange={() => {
                              toggleRule(r.id)
                              setAnnounce(`${r.name} ${r.enabled ? 'disabled' : 'enabled'}`)
                            }}
                          />
                        </td>
                        <td className="!whitespace-normal" style={{ paddingTop: 6, paddingBottom: 6 }}>
                          <span className={cn('block font-medium', r.enabled ? 'text-[var(--b-text)]' : 'text-[var(--b-text-2)]')}>
                            {r.name}
                          </span>
                          <span className="block max-w-[320px] text-[12px] leading-snug text-[var(--b-text-3)]">
                            {!r.enabled && <span className="font-medium text-[var(--b-text-2)]">Disabled · </span>}
                            {r.action === 'deny' ? 'Wins over every Allow rule, regardless of position.' : r.description || 'No description'}
                          </span>
                        </td>
                        <td>
                          <RuleActionBadge action={r.action} />
                        </td>
                        <td className="!whitespace-normal" style={{ paddingTop: 6, paddingBottom: 6 }}>
                          <span className="flex max-w-[220px] flex-wrap gap-1">
                            {r.groupIds.map((g) => (
                              <span key={g} className="b-chip">
                                {groupName(g)}
                              </span>
                            ))}
                          </span>
                        </td>
                        <td>{r.action === 'allow' ? <VlanChip vlan={vlan} /> : <span className="text-[var(--b-text-3)]">—</span>}</td>
                        <td data-align="end">
                          <span className="b-num" title={`${decides} users are currently decided by this rule`}>
                            {r.enabled ? `${decides} ${decides === 1 ? 'user' : 'users'}` : '—'}
                          </span>
                        </td>
                        <td data-align="end">
                          <span className="inline-flex gap-0.5">
                            <IconButton
                              icon={ArrowUp}
                              label={`Move “${r.name}” up`}
                              disabled={i === 0}
                              onClick={() => {
                                moveRule(r.id, -1)
                                setAnnounce(`${r.name} moved up to priority ${rules[i - 1]?.priority}`)
                              }}
                            />
                            <IconButton
                              icon={ArrowDown}
                              label={`Move “${r.name}” down`}
                              disabled={i === rules.length - 1}
                              onClick={() => {
                                moveRule(r.id, 1)
                                setAnnounce(`${r.name} moved down to priority ${rules[i + 1]?.priority}`)
                              }}
                            />
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
                <tfoot>
                  <tr>
                    <td colSpan={8} className="!h-auto border-t border-[var(--b-line)] bg-[var(--b-panel-head)] px-3 py-2.5 !whitespace-normal">
                      <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 text-[12.5px]">
                        <span className="flex items-center gap-2">
                          <span className="text-[var(--b-text-2)]">No rule matches</span>
                          <RuleActionBadge action={d.defaults.defaultAction} />
                          <span className="text-[var(--b-text-3)]">tenant default{d.defaults.defaultVlanId ? ` · VLAN ${d.vlans.find((v) => v.id === d.defaults.defaultVlanId)?.vlanId}` : ''}</span>
                        </span>
                        <span className="flex items-center gap-2">
                          <span className="text-[var(--b-text-2)]">Authorization data older than {formatDuration(d.defaults.maxSnapshotAgeSeconds)}</span>
                          <RuleActionBadge action="deny" />
                          <span className="text-[var(--b-text-3)]">fail-safe</span>
                        </span>
                      </div>
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>
            <p className="sr-only" aria-live="polite">
              {announce}
            </p>
          </Panel>

          <Panel id="b-sec-vlans" aria-labelledby="vlans-title">
            <PanelHead id="vlans-title" title="VLANs" meta="colour-coded the same way on every screen" />
            <ul className="b-divide-y">
              {d.vlans.map((v) => {
                const assigning = rules.filter((r) => r.vlanId === v.id && r.enabled && r.action === 'allow')
                return (
                  <li key={v.id} className="grid grid-cols-[14px_48px_minmax(0,1fr)] items-start gap-x-3 px-3 py-2.5 sm:grid-cols-[14px_48px_minmax(0,1fr)_minmax(0,1fr)_90px]">
                    <i className="mt-1 size-3.5 rounded-[3px]" style={{ background: VLAN_HEX[v.color] }} aria-hidden />
                    <span className="b-figure text-[19px] text-[var(--b-text)]">{v.vlanId}</span>
                    <span className="min-w-0">
                      <span className="block font-medium text-[var(--b-text)]">{v.name}</span>
                      <span className="block text-[12px] text-[var(--b-text-2)]">{v.description}</span>
                    </span>
                    <span className="col-start-3 min-w-0 text-[12px] text-[var(--b-text-2)] sm:col-start-auto">
                      {assigning.length ? `Assigned by ${assigning.map((r) => `“${r.name}”`).join(', ')}` : 'No enabled rule assigns it'}
                      <span className="b-mono mt-0.5 block text-[11px] text-[var(--b-text-3)]">Tunnel-Private-Group-ID = {v.vlanId}</span>
                    </span>
                    <span className="b-num col-start-3 text-[12.5px] sm:col-start-auto sm:text-right">
                      <span className="b-cond text-[15px] font-semibold text-[var(--b-text)]">{vlanUsers.get(v.id) ?? 0}</span> <span className="text-[var(--b-text-2)]">users</span>
                    </span>
                  </li>
                )
              })}
            </ul>
          </Panel>
        </div>
        <div className="min-w-0 xl:sticky xl:top-[calc(var(--b-header-h)+12px)] xl:self-start">
          <TestUser />
        </div>
      </div>
    </>
  )
}

/** Pick an identity (and optionally one of its certificates) and run it through the live policy. */
function TestUser() {
  const d = useTenantData()
  const decisions = useDecisions()
  const certId = useId()
  const defaultIdentity = useMemo(() => d.identities.find((i) => i.groupIds.some((g) => g.endsWith(':g-net'))) ?? d.identities[0], [d.identities])
  const [identityId, setIdentityId] = useState<string | null>(null)
  const identity = d.identities.find((i) => i.id === identityId) ?? defaultIdentity
  const certs = d.certificates.filter((c) => c.identityId === identity?.id)
  const [certChoice, setCertChoice] = useState<string>('none')
  const cert = certs.find((c) => c.id === certChoice)
  const decision = useDecision(identity, cert)
  const vlan = d.vlans.find((v) => v.id === decision?.vlanId)
  const rule = d.rules.find((r) => r.id === decision?.decidingRuleId)

  return (
    <Panel id="b-sec-test" aria-labelledby="test-title">
      <PanelHead id="test-title" title="Test a user" meta="live against the rules on the left" actions={<FlaskConical className="size-4 text-[var(--b-text-3)]" aria-hidden />} />
      <div className="space-y-3 p-3">
        {d.identities.length === 0 ? (
          <p className="b-t2 text-[12.5px]">No identities yet. Connect Active Directory to test real users.</p>
        ) : (
          <>
            <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-1">
              <Field label="User">
                <IdentityPicker
                  identities={d.identities}
                  value={identity}
                  decisions={decisions}
                  onChange={(id) => {
                    setIdentityId(id)
                    setCertChoice('none')
                  }}
                />
              </Field>
              <Field label="Presenting certificate" htmlFor={certId}>
                <SelectBox
                  id={certId}
                  value={certChoice}
                  onChange={setCertChoice}
                  options={[{ value: 'none', label: 'Policy only (no certificate check)' }, ...certs.map((c) => ({ value: c.id, label: `${d.devices.find((x) => x.id === c.deviceId)?.name ?? c.serial.slice(0, 8)}`, hint: certStatusLabels[c.status] }))]}
                />
              </Field>
            </div>
            {decision && (
              <div className="rounded-md border border-[var(--b-line)]">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-[var(--b-line)] px-3 py-2.5">
                  <span className={`b-figure text-[22px] ${decision.outcome === 'allow' ? 'b-ink-ok' : 'b-ink-crit'}`}>{decision.outcome === 'allow' ? 'Access-Accept' : 'Access-Reject'}</span>
                  {vlan && <VlanChip vlan={vlan} />}
                  <span className="w-full text-[12.5px] text-[var(--b-text-2)]">
                    Decided by <span className="text-[var(--b-text)]">{rule ? `“${rule.name}”` : decision.steps.some((s) => (s.kind === 'account' || s.kind === 'certificate') && !s.ok) ? 'a failed gate' : 'the tenant default'}</span>
                  </span>
                </div>
                <div className="px-1 py-2">
                  <DecisionTrace decision={decision} rules={d.rules} vlans={d.vlans} groups={d.groups} compact />
                </div>
                <div className="border-t border-[var(--b-line)] px-3 py-2.5">
                  <h3 className="b-label mb-1">RADIUS reply attributes</h3>
                  <AttributeTable attributes={decision.attributes} />
                </div>
              </div>
            )}
            <p className="flex items-start gap-2 text-[12px] text-[var(--b-text-3)]">
              <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              Reorder or toggle a rule and this result updates immediately; RADIUS picks the change up with the next authorization snapshot.
            </p>
          </>
        )}
      </div>
    </Panel>
  )
}
