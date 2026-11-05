import { useId, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { Popover } from 'radix-ui'
import { Check, ChevronDown, Info, Waypoints, X } from 'lucide-react'
import { useActions, useDecision, useTenantData } from '@/prototype/store'
import type { Identity } from '@/domain/types'
import { certStatusLabels } from '@/domain/explain'
import { formatSerial } from '@/ui/lib'
import { PolicyRoute } from '../PolicyRoute'
import { buildRouteData } from '../routes'
import { decisionReason, findUser, userKey } from '../bits'
import { LINE } from '../theme'
import { Button, Callout, LineBullet, PageHeader, Panel, RejectBullet, Select, VolumeGlyph, useE, useIntent } from '../ui'

export function Policies() {
  const d = useTenantData()
  const { moveRule, toggleRule } = useActions()
  const { toast } = useE()
  const [testId, setTestId] = useState<string | null>(null)
  const [certId, setCertId] = useState<string>('none')
  const testRef = useRef<HTMLDivElement>(null)
  const identity = findUser(testId ?? undefined, d.identities)
  const certs = d.certificates.filter((c) => c.identityId === identity?.id)
  const cert = certs.find((c) => c.id === certId)
  const decision = useDecision(identity, cert)
  const route = useMemo(() => buildRouteData(d.radiusClients, d.vlans, d.authEvents), [d.radiusClients, d.vlans, d.authEvents])

  useIntent('policies.test', (i) => {
    if (i.identityId) { setTestId(i.identityId); setCertId('none') }
    requestAnimationFrame(() => requestAnimationFrame(() => { testRef.current?.scrollIntoView({ block: 'start' }); testRef.current?.querySelector<HTMLElement>('button')?.focus() }))
  })

  const vlan = d.vlans.find((v) => v.id === decision?.vlanId)
  const enabled = d.rules.filter((r) => r.enabled).length

  return (
    <>
      <PageHeader title="VLAN policies" meta={<><span className="num">{d.rules.length} rules, {enabled} enabled</span><span aria-hidden className="t3">·</span><span>Default {d.defaults.defaultAction}</span><span aria-hidden className="t3">·</span><span>RADIUS evaluates the latest authorization snapshot; every decision records the rule that made it</span></>} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="xl:col-span-7" title="Access rules" desc={identity ? `Showing ${identity.displayName}’s route. It runs solid to the stop that decides and fades after.` : 'Rules are stops on one route, in the order RADIUS checks them. Reorder within a group or switch a rule off; changes apply on the next snapshot.'}
          actions={identity ? <Button size="sm" variant="ghost" onClick={() => setTestId(null)}><X />Clear test</Button> : undefined}>
          <div className="px-3 pb-3">
            <Callout className="mx-1 mb-2" icon={<Info aria-hidden />}>
              <p><strong>Deny rules always win.</strong> <span className="t2">Every enabled deny rule is checked before any allow rule, so moving a deny rule lower never lets someone through. Disabled, locked or deleted accounts are denied before any rule.</span></p>
            </Callout>
            <PolicyRoute
              rules={d.rules}
              vlans={d.vlans}
              groups={d.groups}
              defaults={d.defaults}
              decision={decision}
              editable
              showCertGate={!!cert}
              onMove={(id, dir) => moveRule(id, dir)}
              onToggle={(id) => { const r = d.rules.find((x) => x.id === id); toggleRule(id); if (r) toast({ title: `${r.name} ${r.enabled ? 'disabled' : 'enabled'}`, body: 'Recorded in the audit trail. RADIUS picks it up with the next authorization snapshot.', tone: r.enabled ? 'warn' : 'ok' }) }}
            />
          </div>
        </Panel>

        <div className="flex min-w-0 flex-col gap-4 xl:col-span-5">
          <div ref={testRef} className="scroll-mt-20">
            <Panel title="Test a user" desc="Runs the real evaluation against the current rules without changing anything.">
              <div className="space-y-3 px-4 pb-4">
                <div>
                  <p className="e-label mb-1.5">Identity</p>
                  <IdentityPicker identities={d.identities} value={testId} onChange={(id) => { setTestId(id); setCertId('none') }} />
                </div>
                {identity && certs.length > 0 && (
                  <div>
                    <p className="e-label mb-1.5">Certificate (optional)</p>
                    <Select label="Certificate" value={certId} onValueChange={setCertId} className="w-full"
                      options={[{ value: 'none', label: 'Groups only, no certificate check' }, ...certs.map((c) => ({ value: c.id, label: `${d.devices.find((x) => x.id === c.deviceId)?.name ?? 'Device'} · ${certStatusLabels[c.status]} · ${formatSerial(c.serial).slice(0, 9)}` }))]} />
                  </div>
                )}
                {decision && identity ? (
                  <div className="rounded-lg border border-[var(--e-hair)] bg-[var(--e-ground)] p-3.5">
                    <div className="flex items-center gap-3">
                      {decision.outcome === 'allow' ? (vlan ? <LineBullet vlan={vlan} size={34} /> : null) : <RejectBullet size={34} />}
                      <div className="min-w-0">
                        <p className="text-[17px] font-bold leading-snug">{decision.outcome === 'allow' ? <>Allowed{vlan ? <> on VLAN {vlan.vlanId} · {vlan.name}</> : ''}</> : 'Denied: Access-Reject'}</p>
                        <p className="t2 text-[13px]">{decisionReason(decision, d.rules)}</p>
                      </div>
                    </div>
                    <div className="mt-3 border-t border-[var(--e-hair)] pt-3">
                      <p className="e-label mb-1.5">RADIUS reply attributes</p>
                      {decision.attributes.length ? (
                        <table className="mono w-full text-[12px]">
                          <tbody>
                            {decision.attributes.map((a) => <tr key={a.name}><td className="t2 py-0.5 pr-3">{a.name}</td><td className="py-0.5 text-right">{a.value}</td></tr>)}
                          </tbody>
                        </table>
                      ) : <p className="t2 text-[12.5px]">None: an Access-Reject carries no VLAN attributes.</p>}
                    </div>
                  </div>
                ) : (
                  <p className="t2 flex items-center gap-2 text-[13px]"><Waypoints size={16} aria-hidden />Pick someone to draw their route through the rules.</p>
                )}
              </div>
            </Panel>
          </div>

          <Panel title="VLANs" desc="Each VLAN is a line, coloured the same on every screen.">
            <ul className="e-divide border-t border-[var(--e-hair)]">
              {d.vlans.map((v) => {
                const rules = d.rules.filter((r) => r.vlanId === v.id)
                const vol = route.outcomes.find((o) => o.key === v.id)?.total ?? 0
                return (
                  <li key={v.id} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5">
                    <LineBullet vlan={v} size={26} />
                    <div className="min-w-0">
                      <p className="text-[13.5px] font-semibold">{v.name} <span className="t2 font-normal">· VLAN {v.vlanId}</span></p>
                      <p className="t2 truncate text-[12.5px]">{v.description}{rules.length ? ` · via ${rules.map((r) => r.name).join(', ')}` : ' · no rule routes here'}</p>
                    </div>
                    <span className="inline-flex items-center gap-2 text-[12.5px]" title={`${vol} authentications in 24 hours`}>
                      <VolumeGlyph count={vol} color={LINE[v.color].hex} />
                      <span className="num w-7 text-right">{vol}</span>
                    </span>
                  </li>
                )
              })}
            </ul>
            <p className="t2 border-t border-[var(--e-hair)] px-4 py-2.5 text-[12px]">Line weight: 24-hour authentications on the shared ramp. Dashed: configured, no traffic.</p>
          </Panel>
        </div>
      </div>
    </>
  )
}

function IdentityPicker({ identities, value, onChange }: { identities: Identity[]; value: string | null; onChange: (id: string) => void }) {
  const { container } = useE()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const listId = useId()
  const sel = findUser(value ?? undefined, identities)
  const results = useMemo(() => {
    const t = q.trim().toLowerCase()
    return identities.filter((i) => !t || `${i.displayName} ${i.upn} ${i.department}`.toLowerCase().includes(t)).slice(0, 50)
  }, [q, identities])
  const pick = (i: Identity | undefined) => { if (!i) return; onChange(userKey(i, identities)); setOpen(false); setQ('') }
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(results.length - 1, a + 1)) }
    if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)) }
    if (e.key === 'Enter') { e.preventDefault(); pick(results[active]) }
  }
  return (
    <Popover.Root open={open} onOpenChange={(o) => { setOpen(o); setActive(0) }}>
      <Popover.Trigger className="e-select-trigger w-full" aria-label={sel ? `Identity: ${sel.displayName}. Change` : 'Choose an identity'}>
        <span className={sel ? '' : 't2'}>{sel ? `${sel.displayName} · ${sel.upn}` : 'Choose a user…'}</span>
        <ChevronDown size={15} className="t2" aria-hidden />
      </Popover.Trigger>
      <Popover.Portal container={container}>
        <Popover.Content className="e-menu !p-0" sideOffset={6} align="start" style={{ width: 'var(--radix-popover-trigger-width)' }}>
          <div className="border-b border-[var(--e-hair)] p-2">
            <input autoFocus className="e-input" placeholder="Search name, UPN, department" value={q} onChange={(e) => { setQ(e.target.value); setActive(0) }} onKeyDown={onKey}
              role="combobox" aria-expanded="true" aria-controls={listId} aria-activedescendant={results[active] ? `${listId}-${results[active].objectGuid ?? active}` : undefined} aria-label="Search identities" />
          </div>
          <div id={listId} role="listbox" aria-label="Identities" className="max-h-[300px] overflow-y-auto p-1.5">
            {results.length === 0 && <p className="t2 px-3 py-6 text-center text-[13px]">No user matches “{q}”.</p>}
            {results.map((i, idx) => (
              <div key={userKey(i, identities)} id={`${listId}-${i.objectGuid ?? idx}`} role="option" aria-selected={idx === active} className="e-menu-item" data-highlighted={idx === active ? '' : undefined} onPointerMove={() => setActive(idx)} onClick={() => pick(i)}>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-semibold">{i.displayName}</span>
                  <span className="t2 block truncate text-[12px]">{i.upn} · {i.department}{i.accountState !== 'enabled' ? ` · ${i.accountState}` : ''}</span>
                </span>
                {sel === i && <Check size={15} aria-hidden />}
              </div>
            ))}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
