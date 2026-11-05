import { ArrowLeft, Ban, Building2, ChevronLeft, ChevronRight, CircleCheck, CircleMinus, FilePlus2, KeyRound, Laptop, Monitor, Smartphone, Tablet, Terminal, UserSearch } from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import type { Certificate, DecisionStep, Device, Platform } from '@/domain/types'
import { failureExplanations, platformLabels } from '@/domain/explain'
import { useDecision, useTenantData, useTenants } from '@/prototype/store'
import { formatDate, formatSerial } from '@/ui/lib'
import type { ScreenId } from '../../contract'
import { userCode } from '../model/codes'
import { relTime } from '../model/derive'
import { useViewState } from '../model/state'
import { IssueCertificateDialog } from '../flows/IssueCertificateDialog'
import { RevokeDialog } from '../flows/RevokeDialog'
import { DecisionRun } from '../ui/Run'
import { EmptyState, KV, MetaSep, PageHeader, Section } from '../ui/Section'
import { CertStatusMark, Remaining, StatusMark } from '../ui/Status'
import { DataTable, type TableColumn } from '../ui/Table'
import { CertTape, GroupTape, NasTape, RuleTape, Tape, VlanTape } from '../ui/Tape'

type Nav = (s: ScreenId, id?: string) => void

const PLATFORM_ICON: Record<Platform, ReactNode> = {
  windows: <Laptop aria-hidden="true" />, macos: <Monitor aria-hidden="true" />, ios: <Tablet aria-hidden="true" />, android: <Smartphone aria-hidden="true" />, linux: <Terminal aria-hidden="true" />,
}
const KEY_ORIGIN: Record<Certificate['keyOrigin'], string> = { device: 'On device', browser: 'On device (profile)', csr: 'On device (CSR)', server: 'Server-generated' }

interface DeviceRow { device: Device; cert: Certificate | null; index: number }

function isTyping(el: EventTarget | null) {
  const t = el as HTMLElement | null
  return !!t && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName) || !!t.closest('[role="dialog"], [role="listbox"], [role="menu"]'))
}

export function UserDetail({ entityId, navigate }: { entityId?: string; navigate: Nav }) {
  const { current } = useTenants()
  const d = useTenantData()
  const vs = useViewState()
  const identity = d.identities.find((i) => i.id === entityId)
  const decision = useDecision(identity)
  const [issueOpen, setIssueOpen] = useState(false)
  const [revoke, setRevoke] = useState<Certificate | null>(null)

  const order = useMemo(() => {
    if (vs.userOrder.length && entityId && vs.userOrder.includes(entityId)) return vs.userOrder
    return [...d.identities].sort((a, b) => a.displayName.localeCompare(b.displayName)).map((i) => i.id)
  }, [vs.userOrder, entityId, d.identities])
  const pos = entityId ? order.indexOf(entityId) : -1
  const prev = pos > 0 ? order[pos - 1] : null
  const next = pos >= 0 && pos < order.length - 1 ? order[pos + 1] : null

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target) || document.querySelector('[role="dialog"]')) return
      if (e.key === 'j' && next) { e.preventDefault(); navigate('user', next) }
      else if (e.key === 'k' && prev) { e.preventDefault(); navigate('user', prev) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [next, prev, navigate])

  if (!identity) {
    const wanted = (entityId ?? '').split(':u-')[1] ?? ''
    const similar = d.identities.filter((i) => wanted && i.username[0] === wanted[0])
    const recent = [...d.identities].filter((i) => i.lastAuthAt).sort((a, b) => (b.lastAuthAt ?? '').localeCompare(a.lastAuthAt ?? ''))
    const suggestions = [...similar.map((i) => ({ i, why: 'Similar username' })), ...recent.map((i) => ({ i, why: `Authenticated ${relTime(i.lastAuthAt).toLowerCase()}` }))]
      .filter((s, idx, all) => all.findIndex((x) => x.i.id === s.i.id) === idx)
      .slice(0, 5)
    return (
      <>
        <PageHeader title="User not found" lead={<button type="button" className="d-btn d-btn--ghost d-btn--icon mt-0.5" aria-label="Back to users" onClick={() => navigate('users')}><ArrowLeft aria-hidden="true" /></button>} meta={<><span>{current.name}</span><MetaSep /><span className="mono">{entityId}</span></>} />
        <EmptyState icon={<UserSearch className="d-empty-icon" aria-hidden="true" />} title={`No identity “${wanted || entityId || 'unknown'}” in ${current.name}`} action={<button type="button" className="d-btn d-btn--sm" onClick={() => navigate('users')}>Open the user list</button>}>
          The account may have been removed by the last directory sync, or the link belongs to another tenant.
        </EmptyState>
        {suggestions.length > 0 && (
          <Section title="Did you mean" description={`Accounts in ${current.name} with a similar username, then the most recently active.`}>
            <DataTable
              caption="Suggested accounts"
              rows={suggestions.map((s, index) => ({ ...s, index }))}
              rowKey={(r) => `${r.i.id}#${r.index}`}
              onRowClick={(r) => navigate('user', r.i.id)}
              columns={[
                { key: 'label', header: 'Label', cell: (r) => <Tape code={userCode(r.i)} size="sm" /> },
                { key: 'name', header: 'Name', cell: (r) => <><button type="button" className="d-rowlink" onClick={() => navigate('user', r.i.id)}>{r.i.displayName}</button><span className="d-sub">{r.i.upn}</span></> },
                { key: 'dept', header: 'Department', hideSm: true, cell: (r) => r.i.department ?? <span className="ink-3">—</span> },
                { key: 'why', header: 'Why it is listed', align: 'right', cell: (r) => <span className="ink-2 nowrap">{r.why}</span> },
              ]}
            />
          </Section>
        )}
      </>
    )
  }

  const groups = d.groups.filter((g) => identity.groupIds.includes(g.id))
  const deviceRows: DeviceRow[] = d.devices.filter((x) => x.identityId === identity.id).map((device, index) => ({ device, cert: d.certificates.find((c) => c.deviceId === device.id) ?? null, index }))
  const events = d.authEvents.filter((e) => e.identityId === identity.id).slice(0, 8)
  const vlan = d.vlans.find((v) => v.id === decision?.vlanId)

  const deviceCols: TableColumn<DeviceRow>[] = [
    {
      key: 'device', header: 'Device',
      cell: (r) => (
        <span className="flex items-center gap-2.5">
          <span className="text-[var(--d-ink-3)] [&>svg]:size-4">{PLATFORM_ICON[r.device.platform]}</span>
          <span className="min-w-0">
            <span className="block font-medium">{r.device.name}</span>
            <span className="d-sub">{platformLabels[r.device.platform]} · <span className="mono">{r.device.lastSeenMac ?? 'MAC not seen'}</span></span>
          </span>
        </span>
      ),
    },
    { key: 'cert', header: 'Certificate', cell: (r) => (r.cert ? <CertTape cert={r.cert} size="sm" onClick={() => { vs.setCertInspect(r.cert!.id); navigate('certificates') }} /> : <span className="ink-3">None</span>) },
    { key: 'status', header: 'Status', cell: (r) => <CertStatusMark status={r.cert?.status ?? 'none'} /> },
    { key: 'key', header: 'Private key', hideSm: true, cell: (r) => (r.cert ? <span className={r.cert.keyOrigin === 'server' ? 'text-[var(--d-warn)]' : 'ink-2'}>{KEY_ORIGIN[r.cert.keyOrigin]}</span> : <span className="ink-3">—</span>) },
    { key: 'issued', header: 'Issued', hideSm: true, cell: (r) => <span className="ink-2 tnum nowrap">{r.cert ? formatDate(r.cert.notBefore) : '—'}</span> },
    {
      key: 'action', header: <span className="sr-only">Actions</span>,
      cell: (r) => (r.cert && r.cert.status !== 'revoked' ? (
        <button type="button" className="d-btn d-btn--sm" onClick={() => setRevoke(r.cert)} aria-label={`Revoke certificate for ${r.device.name}`}>Revoke</button>
      ) : r.cert?.status === 'revoked' ? <span className="ink-3 text-[12.5px]">{relTime(r.cert.revokedAt)}</span> : null),
    },
    { key: 'remaining', header: 'Remaining', align: 'right', cell: (r) => (r.cert ? <Remaining cert={r.cert} /> : <span className="d-remaining" data-tone="off">—</span>) },
  ]

  const stepIcon = (s: DecisionStep, deciding: boolean) => {
    if (s.kind === 'rule') return s.matched ? (s.action === 'deny' ? <Ban aria-label="Matched deny rule" className="size-4 text-[var(--d-crit)]" /> : deciding ? <CircleCheck aria-label="Matched, decided" className="size-4 text-[var(--d-signal)]" /> : <CircleCheck aria-label="Matched, outranked" className="size-4 text-[var(--d-ink-3)]" />) : <CircleMinus aria-label="Not matched" className="size-4 text-[var(--d-ink-3)]" />
    if (s.kind === 'default') return s.action === 'deny' ? <Ban aria-label="Default deny" className="size-4 text-[var(--d-crit)]" /> : <CircleCheck aria-label="Default allow" className="size-4 text-[var(--d-signal)]" />
    return s.ok ? <CircleCheck aria-label="Passed" className="size-4 text-[var(--d-signal)]" /> : <Ban aria-label="Failed" className="size-4 text-[var(--d-crit)]" />
  }

  return (
    <>
      <PageHeader
        lead={<button type="button" className="d-btn d-btn--ghost d-btn--icon mt-0.5" aria-label="Back to users" onClick={() => navigate('users')}><ArrowLeft aria-hidden="true" /></button>}
        title={identity.displayName}
        meta={
          <>
            <Tape code={userCode(identity)} size="sm" />
            <span className="mono">{identity.upn ?? identity.username}</span>
            <MetaSep />
            <span className="inline-flex items-center gap-1.5">{identity.source === 'ad' ? <><Building2 aria-hidden="true" className="size-3.5" />Active Directory</> : <><KeyRound aria-hidden="true" className="size-3.5" />Local account</>}</span>
            <MetaSep />
            {identity.accountState === 'enabled' ? <StatusMark tone="ok">Account enabled</StatusMark> : <StatusMark tone="crit">Account {identity.accountState}</StatusMark>}
          </>
        }
        actions={
          <>
            <div className="flex items-center gap-1" role="group" aria-label="Move between users">
              <button type="button" className="d-btn d-btn--icon" disabled={!prev} onClick={() => prev && navigate('user', prev)} aria-label="Previous user (k)"><ChevronLeft aria-hidden="true" /></button>
              <span className="tnum px-1 text-[12.5px] text-[var(--d-ink-2)]">{pos + 1} of {order.length}</span>
              <button type="button" className="d-btn d-btn--icon" disabled={!next} onClick={() => next && navigate('user', next)} aria-label="Next user (j)"><ChevronRight aria-hidden="true" /></button>
              <span className="d-hide-sm ml-1 inline-flex items-center gap-1 text-[12px] text-[var(--d-ink-3)]"><kbd className="d-kbd">k</kbd><kbd className="d-kbd">j</kbd></span>
            </div>
            <button type="button" className="d-btn d-btn--primary" onClick={() => setIssueOpen(true)} disabled={identity.accountState === 'deleted'}>
              <FilePlus2 aria-hidden="true" />Issue Wi-Fi certificate
            </button>
          </>
        }
      />

      <div className="d-grid-2">
        <div className="min-w-0">
          <Section id="decision" title="Access decision" description={decision ? (decision.outcome === 'allow' ? `Allowed onto VLAN ${vlan?.vlanId ?? '—'} ${vlan?.name ?? ''}. Follow the run from group to rule to VLAN; the same colours appear on the policy screen.` : 'Denied. RADIUS answers Access-Reject; the trace below shows which check stopped it.') : undefined}>
            {decision && (
              <>
                <div className="border-b border-[var(--d-line)] py-4">
                  <DecisionRun identity={identity} decision={decision} rules={d.rules} vlans={d.vlans} groups={d.groups} traceKey={identity.id} />
                </div>
                <div className="d-grid-even !gap-8 pt-1">
                  <div>
                    <h3 className="d-h3 pt-3 pb-1">Decision trace</h3>
                    <ol className="d-rows">
                      {decision.steps.map((s, i) => {
                        const rule = s.kind === 'rule' ? d.rules.find((r) => r.id === s.ruleId) : undefined
                        const deciding = s.kind === 'rule' && s.ruleId === decision.decidingRuleId
                        return (
                          <li key={i} className="flex items-start gap-2.5 py-2 text-[13px]">
                            <span className="mt-0.5">{stepIcon(s, deciding)}</span>
                            <span className="min-w-0 flex-1">
                              <span className={deciding ? 'font-semibold' : s.kind === 'rule' && !s.matched ? 'text-[var(--d-ink-2)]' : ''}>
                                {s.kind === 'rule' ? rule?.name ?? s.detail : s.detail}
                              </span>
                              {deciding && <span className="ml-2 text-[12px] text-[var(--d-signal)]">Decided</span>}
                              {s.kind === 'rule' && s.matched && !deciding && <span className="ml-2 text-[12px] text-[var(--d-ink-3)]">{decision.outcome === 'deny' ? 'Overridden by deny' : 'Lower precedence'}</span>}
                            </span>
                            {rule && <RuleTape rule={rule} vlans={d.vlans} size="sm" />}
                          </li>
                        )
                      })}
                    </ol>
                    <p className="mt-2 text-[12.5px] text-[var(--d-ink-2)]">Deny rules are checked before any allow rule and always win.</p>
                  </div>
                  <div>
                    <h3 className="d-h3 pt-3 pb-1">RADIUS reply</h3>
                    {decision.attributes.length ? (
                      <KV items={decision.attributes.map((a) => [<span className="mono" key="n">{a.name}</span>, <span className="mono" key="v">{a.value}</span>])} />
                    ) : (
                      <p className="border-b border-[var(--d-line)] py-2 text-[13px] text-[var(--d-ink-2)]">Access-Reject carries no attributes.</p>
                    )}
                  </div>
                </div>
              </>
            )}
          </Section>

        </div>
        <div className="min-w-0">
          <Section id="directory" title="Directory">
            <KV items={[
              ['UPN', <span className="mono" key="u">{identity.upn ?? '—'}</span>],
              ['Email', identity.email ?? '—'],
              ['Department', identity.department ?? '—'],
              ['Title', identity.title ?? '—'],
              ['Account', identity.accountState === 'enabled' ? 'Enabled' : <span className="text-[var(--d-crit-ink)]" key="a">{identity.accountState[0].toUpperCase() + identity.accountState.slice(1)} in Active Directory</span>],
              ['sAMAccountName', <span className="mono" key="s">{identity.username}</span>],
              ['Object GUID', <span className="mono text-[11px]" key="g">{identity.objectGuid ?? '—'}</span>],
              ['Last synced', relTime(identity.lastSyncedAt)],
              ['Last authenticated', relTime(identity.lastAuthAt)],
            ]} />
          </Section>
        </div>
      </div>

      <Section id="devices" title="Devices and certificates" description={`${deviceRows.length} ${deviceRows.length === 1 ? 'device' : 'devices'}. One certificate per device, each revocable on its own.`}>
        <DataTable
          caption="Devices and certificates"
          columns={deviceCols}
          rows={deviceRows}
          rowKey={(r) => `${r.device.id}#${r.index}`}
          empty={
            <EmptyState title="No devices enrolled yet" action={<button type="button" className="d-btn d-btn--sm" onClick={() => setIssueOpen(true)} disabled={identity.accountState === 'deleted'}>Issue Wi-Fi certificate</button>}>
              Issue a certificate to create an enrollment link for {identity.displayName.split(' ')[0]}’s first device.
            </EmptyState>
          }
        />
      </Section>


      <div className="d-grid-2">
        <div className="min-w-0">
          <Section id="auth" title="Recent authentications" description="Last 24 hours, newest first. Rejections are translated into what happened and how to fix it.">
            {events.length === 0 ? (
              <EmptyState title="No authentication attempts in the last 24 hours">
                {deviceRows.length ? 'Their devices haven’t tried to join the network today.' : 'Nothing to show until a device is enrolled.'}
              </EmptyState>
            ) : (
              <ol className="d-rows">
                {events.map((e) => {
                  const nas = d.radiusClients.find((n) => n.id === e.nasClientId)
                  const dev = d.devices.find((x) => x.id === e.deviceId)
                  const exp = e.failureCode ? failureExplanations[e.failureCode] : null
                  const ev = d.vlans.find((v) => v.id === e.vlanId)
                  return (
                    <li key={e.id} className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 py-3">
                      <span className="tnum pt-0.5 text-[12.5px] text-[var(--d-ink-2)]">{new Date(e.at).toISOString().slice(11, 16)}</span>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                          {e.result === 'accept' ? <StatusMark tone="ok">Accepted</StatusMark> : <StatusMark tone="crit">{exp?.title ?? 'Rejected'}</StatusMark>}
                          {ev && <VlanTape vlan={ev} size="sm" />}
                          {nas && <NasTape nas={nas} all={d.radiusClients} size="sm" />}
                          <span className="text-[12.5px] text-[var(--d-ink-2)]">{dev?.name ?? 'Unknown device'} · <span className="mono">{e.ssid}</span></span>
                        </div>
                        {exp && (
                          <>
                            <p className="mt-1.5 max-w-[70ch] text-[13px] text-[var(--d-ink-2)]">{exp.explanation} <span className="text-[var(--d-ink)]">{exp.fix}</span></p>
                            <details className="mt-1.5 text-[12.5px]">
                              <summary className="cursor-pointer text-[var(--d-ink-2)] hover:text-[var(--d-ink)]">Technical details</summary>
                              <div className="d-code mt-2 !py-2 !text-[11.5px]">
                                {e.rawMessage}{'\n'}<span className="c-dim">Calling-Station-Id</span> {e.callingStationId}{'\n'}<span className="c-dim">Called-Station-Id </span> {e.calledStationId}{e.certSerial ? <>{'\n'}<span className="c-dim">Certificate serial </span> {formatSerial(e.certSerial)}</> : null}
                              </div>
                            </details>
                          </>
                        )}
                      </div>
                    </li>
                  )
                })}
              </ol>
            )}
          </Section>
        </div>
        <div className="min-w-0">
          <Section id="groups" title="Groups" description="Each tape is coloured by where a member of only that group would land.">
            <ul className="d-rows">
              {groups.map((g) => (
                <li key={g.id} className="flex items-center justify-between gap-3 py-2">
                  <span className="min-w-0">
                    <span className="block text-[13.5px]">{g.name}</span>
                    <span className="d-sub tnum">{g.memberCount} members</span>
                  </span>
                  <GroupTape group={g} rules={d.rules} vlans={d.vlans} onClick={() => { vs.setUsers({ query: '', source: 'all', access: 'all', cert: 'all', group: g.id }); navigate('users') }} />
                </li>
              ))}
              {!groups.length && <li className="py-3 text-[13px] text-[var(--d-ink-2)]">Not a member of any synchronised group.</li>}
            </ul>
          </Section>
        </div>
      </div>

      <IssueCertificateDialog identity={identity} open={issueOpen} onOpenChange={setIssueOpen} />
      <RevokeDialog cert={revoke} open={!!revoke} onOpenChange={(o) => !o && setRevoke(null)} />
    </>
  )
}
