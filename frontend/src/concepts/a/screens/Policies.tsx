import { useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Ban, CircleHelp, FlaskConical } from 'lucide-react'
import { useActions, useTenantData } from '@/prototype/store'
import { cn } from '@/ui/lib'
import { RuleActionPill, VlanChip } from '../ui/badges'
import { SelectField, Toggle } from '../ui/fields'
import { EmptyState, IconButton, PageHeader, Panel, Tag } from '../ui/primitives'
import { vlanHex } from '../lib/vlan'
import { useLookups, useUserRows } from '../lib/model'
import { DecisionTrace } from '../features/DecisionTrace'
import { useNav } from '../shell/nav'

export function Policies() {
  const d = useTenantData()
  const rows = useUserRows()
  const { groupById, vlanById } = useLookups()
  const { moveRule, toggleRule } = useActions()
  const { entityId, navigate } = useNav()
  const [announce, setAnnounce] = useState('')

  const preset = entityId ? rows.find((r) => r.identity.id === entityId) : undefined
  const [pickedKey, setPickedKey] = useState<string>(preset?.key ?? '')
  // Pre-filled so the tester always shows a decision; pick anyone to re-run it.
  const picked = rows.find((r) => r.key === pickedKey) ?? preset ?? rows[0] ?? null

  const usersOnVlan = useMemo(() => {
    const m = new Map<string, number>()
    for (const r of rows) if (r.decision.outcome === 'allow' && r.decision.vlanId) m.set(r.decision.vlanId, (m.get(r.decision.vlanId) ?? 0) + 1)
    return m
  }, [rows])
  const deniedCount = rows.filter((r) => r.decision.outcome === 'deny').length
  const enabled = d.rules.filter((r) => r.enabled)

  const move = (id: string, name: string, idx: number, dir: -1 | 1) => {
    moveRule(id, dir)
    setAnnounce(`Moved “${name}” to position ${idx + 1 + dir}.`)
  }

  return (
    <>
      <PageHeader
        title="VLAN policies"
        description={`${enabled.length} enabled rules decide who joins Wi-Fi and which VLAN they land on. ${rows.length - deniedCount} of ${rows.length} users are allowed today.`}
      />
      <p className="sr-only" aria-live="polite">
        {announce}
      </p>

      <div className="grid items-start gap-4 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-4 xl:col-span-8">
          <Panel title="Access rules" description="Evaluated on every authentication, in this order. Changes reach RADIUS within seconds.">
            <div className="mx-[18px] mb-3 flex gap-3 rounded-[10px] border border-[rgba(56,189,248,0.22)] bg-[rgba(56,189,248,0.06)] p-3.5">
              <Ban className="mt-0.5 size-4 shrink-0 text-[var(--a-info-text)]" aria-hidden />
              <div className="text-[13px] text-[var(--a-text-2)]">
                <p className="text-[14px] font-semibold text-[var(--a-text)]">Deny rules always win</p>
                <p className="mt-0.5">
                  Every enabled Deny rule is checked first. If one matches any of the user’s groups, access is denied, wherever the rule sits in this list. Otherwise the first matching Allow rule from the top assigns the VLAN. Disabled, locked and deleted accounts are denied before any rule runs.
                </p>
              </div>
            </div>
            <ol className="border-t border-[var(--a-line)]" aria-label="Rules in precedence order">
              {d.rules.map((r, i) => {
                const vlan = r.vlanId ? vlanById.get(r.vlanId) : null
                return (
                  <li key={r.id} className={cn('flex flex-wrap items-start gap-x-3 gap-y-2 border-b border-[var(--a-line)] px-[18px] py-3 transition-opacity', !r.enabled && 'opacity-60')}>
                    <span className="a-num mt-0.5 grid size-7 shrink-0 place-items-center rounded-md border border-white/10 bg-white/[0.04] text-[12px] font-semibold text-[var(--a-text-2)]" aria-label={`Position ${i + 1}`}>
                      {i + 1}
                    </span>
                    <div className="min-w-0 flex-1 basis-[260px]">
                      <div className="flex flex-wrap items-center gap-2">
                        <RuleActionPill action={r.action} />
                        <span className="text-[14px] font-semibold text-[var(--a-text)]">{r.name}</span>
                        {!r.enabled && <span className="text-[12px] text-[var(--a-text-3)]">Disabled</span>}
                      </div>
                      {r.description && <p className="mt-0.5 text-[13px] text-[var(--a-text-3)]">{r.description}</p>}
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        <span className="text-[12px] text-[var(--a-text-3)]">Groups</span>
                        {r.groupIds.map((g) => (
                          <Tag key={g}>{groupById.get(g)?.name ?? g}</Tag>
                        ))}
                        {r.extraAttributes.map((a) => (
                          <Tag key={a.name} className="a-mono !text-[11px]">
                            {a.name}={a.value}
                          </Tag>
                        ))}
                      </div>
                    </div>
                    <div className="ml-10 flex shrink-0 items-center gap-3 sm:ml-0">
                      {r.action === 'allow' ? <VlanChip vlan={vlan} /> : <span className="text-[12px] text-[var(--a-text-3)]">Checked first</span>}
                      <span className="flex items-center gap-1">
                        <Toggle checked={r.enabled} onChange={() => toggleRule(r.id)} label={`${r.enabled ? 'Disable' : 'Enable'} “${r.name}”`} />
                        <span className="mx-1 h-5 w-px bg-white/10" aria-hidden />
                        <IconButton label={`Move “${r.name}” up`} icon={ArrowUp} disabled={i === 0} onClick={() => move(r.id, r.name, i, -1)} />
                        <IconButton label={`Move “${r.name}” down`} icon={ArrowDown} disabled={i === d.rules.length - 1} onClick={() => move(r.id, r.name, i, 1)} />
                      </span>
                    </div>
                  </li>
                )
              })}
              <li className="flex items-center gap-3 px-[18px] py-3">
                <span className="grid size-7 shrink-0 place-items-center rounded-md border border-dashed border-white/20 text-[var(--a-text-3)]" aria-hidden>
                  <CircleHelp className="size-3.5" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-[14px] font-semibold text-[var(--a-text)]">Default action: {d.defaults.defaultAction === 'deny' ? 'Deny' : 'Allow'}</p>
                  <p className="text-[13px] text-[var(--a-text-3)]">
                    When no rule matches. {d.defaults.defaultAction === 'deny' ? 'Fails secure: unknown groups never get Wi-Fi.' : 'Unmatched users land on the default VLAN.'}
                  </p>
                </div>
                <RuleActionPill action={d.defaults.defaultAction} />
              </li>
            </ol>
          </Panel>

          <Panel title="VLANs" description="Colour-coded the same way everywhere in EasyEAP.">
            <ul className="grid border-t border-[var(--a-line)] sm:grid-cols-2">
              {d.vlans.map((v, i) => {
                const ruleCount = d.rules.filter((r) => r.vlanId === v.id && r.enabled).length
                return (
                  <li key={v.id} className={cn('flex items-start gap-3 border-b border-[var(--a-line)] px-[18px] py-3', i % 2 === 0 && 'sm:border-r')}>
                    <span className="mt-1 size-3 shrink-0 rounded-[3px]" style={{ background: vlanHex(v) }} aria-hidden />
                    <div className="min-w-0 flex-1">
                      <p className="flex items-baseline gap-2">
                        <span className="a-num text-[15px] font-semibold text-[var(--a-text)]">VLAN {v.vlanId}</span>
                        <span className="text-[14px] text-[var(--a-text-2)]">{v.name}</span>
                      </p>
                      <p className="text-[13px] text-[var(--a-text-3)]">{v.description}</p>
                      <p className="a-num mt-1 text-[12px] text-[var(--a-text-3)]">
                        {usersOnVlan.get(v.id) ?? 0} users land here · {ruleCount} {ruleCount === 1 ? 'rule' : 'rules'}
                      </p>
                    </div>
                  </li>
                )
              })}
            </ul>
          </Panel>
        </div>

        {/* Test a user: record depth — it evaluates one identity. */}
        <section aria-labelledby="a-test-title" className="a-panel a-depth-record min-w-0 xl:sticky xl:top-[calc(var(--a-topbar-h)+16px)] xl:col-span-4">
          <header className="a-panel-head">
            <div>
              <h2 id="a-test-title" className="a-panel-title flex items-center gap-2">
                <FlaskConical className="size-4 text-[var(--a-text-3)]" aria-hidden />
                Test a user
              </h2>
              <p className="a-panel-desc">Runs the rules above for one person. Nothing is sent to RADIUS.</p>
            </div>
          </header>
          <div className="px-[18px] pb-5">
            <SelectField
              label="User"
              value={picked?.key ?? ''}
              placeholder="Choose a user"
              onChange={(k) => {
                setPickedKey(k)
                const r = rows.find((x) => x.key === k)
                if (r) navigate('policies', r.identity.id)
              }}
              triggerClassName="w-full"
              options={rows.map((r) => ({ value: r.key, label: `${r.identity.displayName} · ${r.identity.department ?? r.identity.source}`, short: r.identity.displayName }))}
            />
            <div className="mt-4">
              {picked ? (
                <DecisionTrace decision={picked.decision} identity={picked.identity} compact />
              ) : (
                <EmptyState icon={FlaskConical} title="Pick someone to test" className="!py-6">
                  See the decision, the rule that made it and the RADIUS attributes the controller receives.
                </EmptyState>
              )}
            </div>
          </div>
        </section>
      </div>
    </>
  )
}
