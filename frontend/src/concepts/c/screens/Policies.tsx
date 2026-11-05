import { useEffect, useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Lock, ShieldAlert, Users } from 'lucide-react'
import { useActions, useDecision, useDecisions, useTenantData } from '@/prototype/store'
import type { AccessRule, Vlan } from '@/domain/types'
import { certStatusLabels } from '@/domain/explain'
import type { Intent } from '../app/context'
import { IconButton } from '../ui/Button'
import { DataTable, type ColumnDef } from '../ui/DataTable'
import { Field, SelectInput, Toggle } from '../ui/Field'
import { Empty, Lede, Note, Section } from '../ui/Layout'
import { VlanTag } from '../ui/Vlan'
import { DecisionTrace, ReplyAttributes, Verdict } from '../parts/DecisionTrace'
import { plural } from '../lib/format'

export function PoliciesScreen({ intent }: { intent: Intent }) {
  const d = useTenantData()
  const decisions = useDecisions()
  const { moveRule, toggleRule } = useActions()
  const [announce, setAnnounce] = useState('')

  useEffect(() => {
    const focus = intent.policies?.focus
    if (focus) document.getElementById(`c-pol-${focus}`)?.scrollIntoView({ block: 'start' })
  }, [intent])

  const enabled = d.rules.filter((r) => r.enabled)
  const usedVlans = new Set(enabled.map((r) => r.vlanId).filter(Boolean))
  const people = (vlan: Vlan) => [...decisions.values()].filter((x) => x.outcome === 'allow' && x.vlanId === vlan.id).length
  const groupName = (id: string) => d.groups.find((g) => g.id === id)?.name ?? id

  const vlanColumns: ColumnDef<Vlan>[] = [
    { key: 'vlan', header: 'VLAN', cell: (v) => <VlanTag vlan={v} /> },
    { key: 'desc', header: 'Purpose', hide: 'md', cell: (v) => <span className="c-muted">{v.description}</span> },
    {
      key: 'rules',
      header: 'Assigned by',
      hide: 'lg',
      cell: (v) => {
        const rs = d.rules.filter((r) => r.vlanId === v.id)
        return rs.length ? <span className="c-muted">{rs.map((r) => r.name).join(', ')}</span> : <span className="c-faint">No rule</span>
      },
    },
    { key: 'people', header: 'People', align: 'end', cell: (v) => <span className="tnum">{people(v)}</span> },
  ]

  return (
    <>
      <Lede
        page="VLAN policies"
        state={
          <>
            <strong>{plural(enabled.length, 'rule')}</strong> place people on {plural(usedVlans.size, 'VLAN')}.
          </>
        }
        rest={`Anyone unmatched is ${d.defaults.defaultAction === 'deny' ? 'denied' : 'allowed'}.`}
        detail="Changes apply to the next authentication: RADIUS reloads the authorization snapshot within seconds."
      />

      <Section id="c-pol-vlans" title="VLANs" description="Each VLAN keeps its colour everywhere in EasyEAP. People counts reflect today’s decisions.">
        <DataTable caption="VLANs" columns={vlanColumns} rows={d.vlans} rowKey={(v) => v.id} empty={<Empty icon={Users} title="No VLANs defined" />} />
      </Section>

      <div className="c-split is-inspector">
        <Section id="c-pol-rules" title="Access rules" description="Evaluated in this order. Move a rule to change which Allow rule wins.">
          <Note icon={ShieldAlert}>
            <strong>Deny rules always win.</strong> EasyEAP checks every enabled Deny rule first, wherever it sits in the list. If one matches any of a person’s groups, access is denied, whatever the Allow rules say. Otherwise the first matching Allow rule, top to bottom, decides the VLAN.
          </Note>
          <p className="sr-only" aria-live="polite">
            {announce}
          </p>
          <ol className="c-list" style={{ marginTop: 20 }}>
            {d.rules.map((r, i) => (
              <RuleRow
                key={r.id}
                rule={r}
                index={i}
                total={d.rules.length}
                vlan={d.vlans.find((v) => v.id === r.vlanId)}
                groups={r.groupIds.map(groupName)}
                onMove={(dir) => {
                  moveRule(r.id, dir)
                  setAnnounce(`Moved “${r.name}” to position ${i + 1 + dir}.`)
                }}
                onToggle={() => {
                  toggleRule(r.id)
                  setAnnounce(`“${r.name}” ${r.enabled ? 'disabled' : 'enabled'}.`)
                }}
              />
            ))}
            <li>
              <div className="c-listrow" style={{ gap: 16, padding: '14px 0' }}>
                <span className="c-faint" style={{ width: 28, textAlign: 'center', flex: 'none' }}>
                  <Lock size={16} aria-hidden="true" />
                </span>
                <span className="c-listrow-main">
                  <span style={{ fontWeight: 500 }}>If no rule matches: {d.defaults.defaultAction === 'deny' ? 'Deny' : 'Allow'}</span>
                  <span className="c-cell-secondary">Tenant default. Missing or stale authorization data also denies; EasyEAP fails safe.</span>
                </span>
                <span className={d.defaults.defaultAction === 'deny' ? 'c-tag is-outline' : 'c-tag'}>{d.defaults.defaultAction === 'deny' ? 'Deny' : 'Allow'}</span>
              </div>
            </li>
          </ol>
        </Section>
        <aside className="c-inspector" aria-label="Test a user" style={{ marginTop: 56 }}>
          <TestUser initialId={intent.policies?.testIdentityId} />
        </aside>
      </div>
    </>
  )
}

function RuleRow({ rule: r, index, total, vlan, groups, onMove, onToggle }: { rule: AccessRule; index: number; total: number; vlan?: Vlan; groups: string[]; onMove: (dir: -1 | 1) => void; onToggle: () => void }) {
  return (
    <li>
      <div className="c-listrow" style={{ gap: 16, padding: '14px 0', alignItems: 'flex-start', opacity: r.enabled ? 1 : 0.62, transition: 'opacity 200ms' }}>
        <span className="c-faint tnum" style={{ width: 28, textAlign: 'center', flex: 'none', paddingTop: 2 }} aria-label={`Position ${index + 1}`}>
          {index + 1}
        </span>
        <span className="c-listrow-main">
          <span style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '4px 10px' }}>
            <span style={{ fontWeight: 500 }}>{r.name}</span>
            {r.action === 'deny' ? <span className="c-tag is-outline">Checked first</span> : null}
            {!r.enabled ? <span className="c-tag">Disabled</span> : null}
          </span>
          <span className="c-cell-secondary">
            {groups.join(' or ')}
            {r.description ? ` · ${r.description}` : ''}
          </span>
          <span style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 14px', marginTop: 8, alignItems: 'center' }}>
            {r.action === 'deny' ? (
              <span className="c-status" data-tone="crit">
                <ShieldAlert size={15} aria-hidden="true" />
                Deny
              </span>
            ) : (
              <>
                <span className="c-muted c-small">Allow on</span>
                <VlanTag vlan={vlan} />
              </>
            )}
            {r.extraAttributes.map((a) => (
              <span key={a.name} className="c-tag c-mono" style={{ fontSize: 12 }}>
                {a.name}={a.value}
              </span>
            ))}
          </span>
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 'none' }}>
          <Toggle checked={r.enabled} onChange={onToggle} label={`${r.enabled ? 'Disable' : 'Enable'} “${r.name}”`} />
          <span style={{ width: 8 }} />
          <IconButton label={`Move “${r.name}” up`} onClick={() => onMove(-1)} disabled={index === 0}>
            <ArrowUp size={16} aria-hidden="true" />
          </IconButton>
          <IconButton label={`Move “${r.name}” down`} onClick={() => onMove(1)} disabled={index === total - 1}>
            <ArrowDown size={16} aria-hidden="true" />
          </IconButton>
        </span>
      </div>
    </li>
  )
}

function TestUser({ initialId }: { initialId?: string }) {
  const d = useTenantData()
  // Select values are positions: identity ids in the seed data are not guaranteed unique.
  const sorted = useMemo(() => d.identities.map((identity, index) => ({ identity, index })).sort((a, b) => a.identity.displayName.localeCompare(b.identity.displayName)), [d.identities])
  const [selected, setSelected] = useState(() => String(Math.max(0, d.identities.findIndex((i) => i.id === initialId))))
  const [certId, setCertId] = useState('none')
  const identity = d.identities[Number(selected)]
  const certs = d.certificates.filter((c) => c.identityId === identity?.id)
  const cert = certs.find((c) => c.id === certId)
  const decision = useDecision(identity, cert)
  const rule = d.rules.find((r) => r.id === decision?.decidingRuleId)

  return (
    <section id="c-pol-test" aria-labelledby="c-pol-test-h">
      <h2 id="c-pol-test-h" style={{ margin: 0, fontSize: 21, fontWeight: 400, letterSpacing: '-0.012em' }}>
        Test a user
      </h2>
      <p className="c-muted c-small" style={{ margin: '6px 0 20px' }}>
        Runs the rules above, in their current order, exactly as RADIUS evaluates the next authentication.
      </p>
      {!identity ? (
        <Empty icon={Users} title="No people to test">People appear once the directory is connected.</Empty>
      ) : (
        <div style={{ display: 'grid', gap: 16 }}>
          <Field label="Person" htmlFor="c-test-person">
            <SelectInput
              id="c-test-person"
              value={selected}
              onChange={(v) => {
                setSelected(v)
                setCertId('none')
              }}
              options={sorted.map(({ identity: i, index }) => ({ value: String(index), label: i.displayName, description: [i.department, i.accountState !== 'enabled' ? `account ${i.accountState}` : null].filter(Boolean).join(' · ') }))}
            />
          </Field>
          <Field label="Certificate presented" htmlFor="c-test-cert" hint="Optional: include the certificate gate (revoked and expired certificates are denied).">
            <SelectInput
              id="c-test-cert"
              value={certId}
              onChange={setCertId}
              options={[{ value: 'none', label: 'Policy only, no certificate' }, ...certs.map((c) => ({ value: c.id, label: d.devices.find((x) => x.id === c.deviceId)?.name ?? c.commonName, description: certStatusLabels[c.status] }))]}
            />
          </Field>
          {decision ? (
            <div style={{ display: 'grid', gap: 18, marginTop: 8 }}>
              <div style={{ paddingTop: 18, borderTop: '1px solid var(--c-hairline)' }}>
                <Verdict decision={decision} vlans={d.vlans} />
                <p className="c-muted c-small" style={{ margin: '8px 0 0' }}>
                  {rule ? `Decided by “${rule.name}”.` : decision.steps.some((s) => (s.kind === 'account' || s.kind === 'certificate') && !s.ok) ? 'Decided before any rule was checked.' : 'Decided by the tenant default.'}
                </p>
              </div>
              <div>
                <h3 className="c-h3" style={{ marginBottom: 6 }}>
                  RADIUS reply
                </h3>
                <ReplyAttributes decision={decision} />
              </div>
              <div>
                <h3 className="c-h3" style={{ marginBottom: 4 }}>
                  Trace
                </h3>
                <DecisionTrace decision={decision} identity={identity} rules={d.rules} vlans={d.vlans} groups={d.groups} />
              </div>
            </div>
          ) : null}
        </div>
      )}
    </section>
  )
}

