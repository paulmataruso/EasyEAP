import { useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Ban, Info } from 'lucide-react'
import { cn } from '@/ui/lib'
import { useActions, useDecision, useMetrics, useTenantData } from '@/prototype/store'
import { DecisionLedger, RuleOutcome } from '../ledger'
import { certLabel, vlanVar } from '../lib'
import type { Navigate } from '../shell'
import { ActionChip, Btn, Chip, Empty, FSelect, FSwitch, PageHeader, Panel, SectionHeader, Tip, VlanTag } from '../ui'

export function PoliciesScreen({ entityId, navigate }: { entityId?: string; navigate: Navigate }) {
  const d = useTenantData()
  const m = useMetrics()
  const { moveRule, toggleRule } = useActions()
  const [announce, setAnnounce] = useState('')
  const defaultId = d.identities.find((i) => i.id === entityId)?.id ?? d.identities.find((i) => i.id.endsWith(':u-pnatarajan'))?.id ?? d.identities[0]?.id ?? ''
  const [testId, setTestId] = useState(defaultId)
  const [certId, setCertId] = useState('none')
  const identity = d.identities.find((i) => i.id === testId) ?? d.identities.find((i) => i.id === defaultId)
  const certs = d.certificates.filter((c) => c.identityId === identity?.id)
  const cert = certs.find((c) => c.id === certId)
  const decision = useDecision(identity, cert)
  const groupName = (id: string) => d.groups.find((g) => g.id === id)?.name ?? id
  const usage = useMemo(() => new Map(m.vlanUsage), [m.vlanUsage])
  const maxUsage = Math.max(1, ...m.vlanUsage.map(([, n]) => n))
  const enabledDeny = d.rules.filter((r) => r.enabled && r.action === 'deny').length

  const move = (id: string, dir: -1 | 1, name: string, idx: number) => {
    moveRule(id, dir)
    setAnnounce(`${name} moved to position ${idx + 1 + dir}`)
  }

  return (
    <div>
      <PageHeader
        title="VLAN policies"
        lede={<>{d.rules.length} access rules · {d.vlans.length} VLANs · when nothing matches: <span className="font-semibold text-[var(--f-ink)]">{d.defaults.defaultAction === 'deny' ? 'Deny' : 'Allow'}</span></>}
      />
      <p className="sr-only" aria-live="polite">{announce}</p>

      <section aria-labelledby="f-vlan-h">
        <SectionHeader id="f-vlan-h" title="VLANs" meta="Colour-coded the same everywhere in EasyEAP" />
        <div className="overflow-x-auto">
          <table className="f-table">
            <caption className="sr-only">VLANs with the rules that assign them and accepted requests in the last 24 hours</caption>
            <thead><tr><th>VLAN</th><th>Name</th><th>Purpose</th><th>Assigned by</th><th className="w-[30%]">Accepted, last 24 h</th></tr></thead>
            <tbody>
              {d.vlans.map((v) => {
                const n = usage.get(v.id) ?? 0
                const by = d.rules.filter((r) => r.vlanId === v.id)
                return (
                  <tr key={v.id}>
                    <td><VlanTag vlan={v} withName={false} /></td>
                    <td className="whitespace-nowrap font-medium">{v.name}</td>
                    <td className="f-ink-2">{v.description}</td>
                    <td className="f-ink-2">{by.length ? by.map((r) => r.name).join(', ') : <span className="f-ink-3">No rule</span>}</td>
                    <td>
                      <Tip content={<span><span className="f-num font-semibold">{n}</span> accepted requests placed on VLAN {v.vlanId}{m.auth.accepts ? ` · ${Math.round((n / m.auth.accepts) * 100)}% of accepts` : ''}</span>}>
                        <div tabIndex={0} className="flex items-center gap-3 rounded-[4px] outline-offset-4">
                          <span className="block h-[6px] flex-1 rounded-[3px] bg-[rgba(237,234,227,0.06)]">
                            <span className="block h-full rounded-[3px]" style={{ width: `${(n / maxUsage) * 100}%`, background: vlanVar(v) }} />
                          </span>
                          <span className="f-num w-8 text-right text-[13px] font-semibold">{n}</span>
                        </div>
                      </Tip>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      <div className="mt-10 grid items-start gap-x-10 gap-y-10 xl:grid-cols-12">
        <section className="min-w-0 xl:col-span-7" aria-labelledby="f-rules-h">
          <SectionHeader id="f-rules-h" title="Access rules" meta="Evaluated top to bottom" />
          <div className="mb-4 flex gap-3 rounded-[8px] border border-[var(--f-line-2)] px-4 py-3 text-[13px]">
            <Info className="mt-0.5 size-4 shrink-0 text-[var(--f-gold)]" aria-hidden />
            <p className="f-ink-2"><span className="font-semibold text-[var(--f-ink)]">Deny rules always win.</span> If any enabled Deny rule matches one of the user’s groups, RADIUS rejects them, wherever that rule sits in the order. Among Allow rules, the first match decides the VLAN. Disabled, locked and deleted accounts are rejected before any rule runs.</p>
          </div>
          {d.rules.length === 0 ? (
            <Empty title="No access rules yet">Every request falls through to the default and is {d.defaults.defaultAction === 'deny' ? 'rejected' : 'accepted'}.</Empty>
          ) : (
            <ol className="f-divide border-y border-[var(--f-line)]" aria-label="Access rules in precedence order">
              {d.rules.map((r, i) => (
                <li key={r.id} className={cn('grid grid-cols-[28px_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-2 py-3.5 sm:grid-cols-[28px_minmax(0,1fr)_auto_auto]', !r.enabled && 'opacity-60')}>
                  <span className="f-num pt-[3px] text-[13px] f-ink-3" aria-label={`Position ${i + 1}`}>{i + 1}</span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[14px] font-semibold">{r.name}</span>
                      <ActionChip action={r.action} />
                      {!r.enabled && <Chip tone="neutral">Disabled</Chip>}
                    </div>
                    {r.description && <p className="f-small f-ink-2 mt-0.5">{r.description}</p>}
                    <p className="f-small mt-1.5 flex flex-wrap items-center gap-1.5">
                      <span className="f-ink-3">When member of</span>
                      {r.groupIds.map((g) => <span key={g} className="f-tag">{groupName(g)}</span>)}
                      <span className="f-ink-3">→</span>
                      <RuleOutcome rule={r} vlans={d.vlans} />
                      {r.extraAttributes.map((a) => <span key={a.name} className="f-tag f-mono text-[11.5px]">{a.name}={a.value}</span>)}
                    </p>
                  </div>
                  <div className="flex items-center gap-1 sm:pt-0.5">
                    <Btn size="sm" variant="ghost" icon aria-label={`Move “${r.name}” up`} disabled={i === 0} onClick={() => move(r.id, -1, r.name, i)}><ArrowUp aria-hidden /></Btn>
                    <Btn size="sm" variant="ghost" icon aria-label={`Move “${r.name}” down`} disabled={i === d.rules.length - 1} onClick={() => move(r.id, 1, r.name, i)}><ArrowDown aria-hidden /></Btn>
                  </div>
                  <div className="col-start-3 row-start-1 flex items-center gap-2 pt-1 sm:col-start-4">
                    <FSwitch checked={r.enabled} onChange={() => { toggleRule(r.id); setAnnounce(`${r.name} ${r.enabled ? 'disabled' : 'enabled'}`) }} label={`${r.enabled ? 'Disable' : 'Enable'} “${r.name}”`} />
                  </div>
                </li>
              ))}
              <li className="grid grid-cols-[28px_minmax(0,1fr)] gap-x-3 py-3.5">
                <span className="pt-[3px] f-ink-3"><Ban className="size-4" aria-hidden /></span>
                <div>
                  <p className="text-[14px] font-semibold">Default · {d.defaults.defaultAction === 'deny' ? 'Deny' : 'Allow'}</p>
                  <p className="f-small f-ink-2 mt-0.5">When no enabled rule matches, RADIUS {d.defaults.defaultAction === 'deny' ? 'sends Access-Reject' : 'accepts on the default VLAN'}. Missing or stale authorization data also denies (fail-safe).</p>
                </div>
              </li>
            </ol>
          )}
          {enabledDeny > 0 && <p className="f-small f-ink-3 mt-3">Moving a Deny rule changes its position only; it still overrides every Allow rule.</p>}
        </section>

        <section className="min-w-0 xl:sticky xl:top-8 xl:col-span-5" aria-labelledby="f-test-h">
          <Panel risk={decision ? (decision.outcome === 'allow' ? 'valid' : 'crit') : undefined} className="px-5 py-5">
            <SectionHeader id="f-test-h" title="Test a user" meta="Uses the rules as they are now" />
            {!identity ? (
              <Empty title="No users to test">Connect a directory or add a local account first.</Empty>
            ) : (
              <>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="flex flex-col gap-1.5">
                    <span className="text-[13px] font-semibold" id="f-test-user">User</span>
                    <FSelect label="User to test" value={identity.id} onChange={(v) => { setTestId(v); setCertId('none') }} options={d.identities.filter((i, idx, all) => all.findIndex((x) => x.id === i.id) === idx).sort((a, b) => a.displayName.localeCompare(b.displayName)).map((i) => ({ value: i.id, label: i.displayName }))} className="w-full" />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <span className="text-[13px] font-semibold">Presenting</span>
                    <FSelect
                      label="Certificate to present"
                      value={cert ? cert.id : 'none'}
                      onChange={setCertId}
                      options={[{ value: 'none', label: 'Policy only, no certificate' }, ...certs.map((c) => ({ value: c.id, label: `${d.devices.find((x) => x.id === c.deviceId)?.name ?? c.serial.slice(0, 8)} · ${certLabel[c.status]}` }))]}
                      className="w-full"
                    />
                  </div>
                </div>
                <p className="f-small f-ink-3 mt-2">{identity.upn} · {identity.groupIds.map(groupName).join(', ')}</p>
                {decision && (
                  <div className="mt-5">
                    <DecisionLedger decision={decision} identity={identity} rules={d.rules} groups={d.groups} vlans={d.vlans} certificate={cert} />
                    {decision.outcome === 'allow' && decision.vlanId && (
                      <p className="f-small f-ink-2 mt-3">The controller places the client on VLAN <VlanTag vlan={d.vlans.find((v) => v.id === decision.vlanId)} withName={false} /> using the RFC 3580 tunnel attributes above.</p>
                    )}
                    <div className="mt-4">
                      <Btn size="sm" variant="ghost" onClick={() => navigate('user', identity.id)}>Open {identity.displayName.split(' ')[0]}’s record</Btn>
                    </div>
                  </div>
                )}
              </>
            )}
          </Panel>
        </section>
      </div>
    </div>
  )
}
