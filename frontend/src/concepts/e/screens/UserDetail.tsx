import { useState } from 'react'
import { Collapsible } from 'radix-ui'
import { ArrowLeft, Building, ChevronRight, ShieldCheck, UserRound, UserX, Waypoints } from 'lucide-react'
import { useDecision, useTenantData, useTenants, now } from '@/prototype/store'
import type { Certificate, Identity } from '@/domain/types'
import { failureExplanations, platformLabels, revocationReasonLabels } from '@/domain/explain'
import { daysUntil, formatDate, formatDateTime, formatSerial } from '@/ui/lib'
import { DataTable } from '../DataTable'
import { Inspector } from '../Inspector'
import { PolicyRoute } from '../PolicyRoute'
import { IssueCertificateForm, RevokeDialog } from '../flows'
import { CertStatusMark, PLATFORM_ICON, decisionReason, findUser } from '../bits'
import { SCREENS } from '../../contract'
import { ago, isSession } from '../theme'
import { Button, Callout, EmptyState, LineBullet, PageHeader, Panel, RejectBullet, StatusMark, VlanRef, useE, useIntent } from '../ui'

const KEY_ORIGIN: Record<Certificate['keyOrigin'], string> = { device: 'On device', browser: 'In browser (on device)', csr: 'Signing request', server: 'Server-generated' }

export function UserDetail({ entityId }: { entityId?: string }) {
  const d = useTenantData()
  const { current } = useTenants()
  const { go } = useE()
  const exact = findUser(entityId, d.identities)
  // The contract's sample id is not present in the generated directory; resolve it to the closest
  // real user (same username initial, enrolled devices) and say so, rather than show a dead end.
  const isSample = entityId === SCREENS.find((s) => s.id === 'user')?.sampleEntity
  const fallback = !exact && isSample ? closestUser(entityId!, d.identities, d.devices.map((x) => x.identityId)) : undefined
  const identity = exact ?? fallback
  const decision = useDecision(identity)
  const [issueOpen, setIssueOpen] = useState(false)
  const [revoke, setRevoke] = useState<Certificate | null>(null)
  useIntent('issue', () => setIssueOpen(true))

  if (!identity) {
    return (
      <>
        <PageHeader title="User not found" />
        <Panel>
          <EmptyState icon={<UserX />} title={`This user is not in ${current.name}`}
            body="The link may point to another tenant, or the account was removed by the last directory sync. Users are scoped to the selected network."
            action={<Button variant="primary" onClick={() => go('users')}><ArrowLeft />Back to users</Button>} />
        </Panel>
      </>
    )
  }

  const first = identity.displayName.split(' ')[0]
  const devices = d.devices.filter((x) => x.identityId === identity.id)
  const certs = d.certificates.filter((c) => c.identityId === identity.id)
  const events = d.authEvents.filter((e) => e.identityId === identity.id).slice(0, 8)
  const groups = identity.groupIds.map((g) => d.groups.find((x) => x.id === g)).filter(Boolean)
  const vlan = d.vlans.find((v) => v.id === decision?.vlanId)
  const rule = d.rules.find((r) => r.id === decision?.decidingRuleId)
  const rows = certs.map((c) => ({ c, dev: devices.find((x) => x.id === c.deviceId) })).sort((a, b) => (a.dev?.name ?? '').localeCompare(b.dev?.name ?? '') || b.c.notBefore.localeCompare(a.c.notBefore))

  return (
    <>
      {fallback && (
        <Callout className="mt-4" icon={<UserX aria-hidden />}>
          No user with ID <span className="mono">{entityId!.split(':').pop()}</span> in {current.name}. Showing the closest match, {fallback.displayName}.
        </Callout>
      )}
      <div className="pt-4">
        <button type="button" className="t2 inline-flex items-center gap-1.5 rounded-md text-[13px] hover:text-[var(--e-text)]" onClick={() => go('users')}><ArrowLeft size={15} aria-hidden />Users</button>
      </div>
      <PageHeader
        title={identity.displayName}
        meta={<>
          <span className="mono">{identity.upn ?? identity.username}</span>
          {identity.source === 'ad' ? <span className="e-tag"><Building aria-hidden />Active Directory</span> : <span className="e-tag"><UserRound aria-hidden />Local account</span>}
          <StatusMark state={identity.accountState === 'enabled' ? 'ok' : 'down'} label={`Account ${identity.accountState}`} />
        </>}
        actions={<>
          <Button variant="secondary" onClick={() => go('policies', { intent: { kind: 'policies.test', identityId: identity.id } })}><Waypoints />Test in policy</Button>
          <Button variant="primary" onClick={() => setIssueOpen(true)} disabled={identity.accountState !== 'enabled'} title={identity.accountState !== 'enabled' ? 'Enable the directory account before issuing a certificate' : undefined}><ShieldCheck />Issue Wi-Fi certificate</Button>
        </>}
      />

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-12">
        <Panel className="xl:col-span-7" title="Access decision" desc="Evaluated now against the current rules, exactly as RADIUS will on the next connection.">
          {decision && (
            <div className="px-4 pb-4">
              <div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-[var(--e-hair)] bg-[var(--e-ground)] p-3.5">
                {decision.outcome === 'allow' ? (vlan ? <LineBullet vlan={vlan} size={36} /> : null) : <RejectBullet size={36} />}
                <div className="min-w-0 flex-1">
                  <p className="text-[18px] font-bold leading-snug">{decision.outcome === 'allow' ? <>Allowed{vlan ? <> on VLAN {vlan.vlanId} · {vlan.name}</> : ' with no VLAN'}</> : 'Denied'}</p>
                  <p className="t2 text-[13px]">{decisionReason(decision, d.rules)}{rule ? ` (priority ${rule.priority})` : ''}</p>
                </div>
                {decision.attributes.length > 0 && (
                  <dl className="mono text-[11.5px] leading-relaxed t2">
                    {decision.attributes.map((a) => <div key={a.name}><dt className="inline">{a.name}</dt> = <dd className="inline text-[var(--e-text)]">{a.value}</dd></div>)}
                  </dl>
                )}
              </div>
              <PolicyRoute rules={d.rules} vlans={d.vlans} groups={d.groups} defaults={d.defaults} decision={decision} />
            </div>
          )}
        </Panel>

        <div className="flex min-w-0 flex-col gap-4 xl:col-span-5">
        <Panel title="Directory" desc={identity.source === 'ad' ? `Synced ${ago(identity.lastSyncedAt)} from ${current.domain}` : 'Local account, managed in EasyEAP'}>
          <dl className="e-dl px-4 pb-2">
            <dt>UPN</dt><dd className="mono">{identity.upn ?? '—'}</dd>
            <dt>Username</dt><dd className="mono">{identity.username}</dd>
            <dt>Email</dt><dd>{identity.email ?? '—'}</dd>
            <dt>Department</dt><dd>{identity.department ?? '—'}</dd>
            <dt>Title</dt><dd>{identity.title ?? '—'}</dd>
            <dt>Account state</dt><dd><StatusMark state={identity.accountState === 'enabled' ? 'ok' : 'down'} label={identity.accountState[0].toUpperCase() + identity.accountState.slice(1)} /></dd>
            <dt>Last authentication</dt><dd>{ago(identity.lastAuthAt)}</dd>
            {identity.objectGuid && <><dt>objectGUID</dt><dd className="mono text-[12px]">{identity.objectGuid}</dd></>}
          </dl>
          <div className="border-t border-[var(--e-hair)] px-4 py-3">
            <h3 className="mb-2 text-[13px] font-bold">Groups <span className="t2 font-normal">({groups.length}, including nested)</span></h3>
            <ul className="flex flex-wrap gap-1.5">
              {groups.map((g) => {
                const r = d.rules.find((x) => x.enabled && x.groupIds.includes(g!.id))
                const v = d.vlans.find((x) => x.id === r?.vlanId)
                return (
                  <li key={g!.id} className="e-tag !h-7 !pl-1.5" title={g!.dn}>
                    {r?.action === 'deny' ? <RejectBullet size={18} /> : v ? <LineBullet vlan={v} size={18} /> : <span className="inline-block size-[18px] rounded-full border border-dashed border-[var(--e-text-3)]" aria-hidden />}
                    {g!.name}
                  </li>
                )
              })}
            </ul>
            <p className="t2 mt-2 text-[12px]">Each group shows the line its first matching rule routes to.</p>
          </div>
        </Panel>
        <Panel title="Recent authentications" desc="Failures are explained in plain language; the RADIUS message is under technical details.">
          {events.length === 0 ? <EmptyState title={`No authentications from ${first} in the last 24 hours`} body={identity.lastAuthAt ? `Last seen ${ago(identity.lastAuthAt)}.` : 'This user has never connected.'} /> : (
            <ol className="e-divide border-t border-[var(--e-hair)]">
              {events.map((e) => {
                const v = d.vlans.find((x) => x.id === e.vlanId)
                const x = e.failureCode ? failureExplanations[e.failureCode] : null
                const nas = d.radiusClients.find((c) => c.id === e.nasClientId)
                const dev = d.devices.find((dv) => dv.id === e.deviceId)
                return (
                  <li key={e.id} className="grid grid-cols-1 gap-x-4 gap-y-1 px-4 py-3 text-[13px] md:grid-cols-[150px_minmax(0,1fr)]">
                    <div>
                      <StatusMark state={e.result === 'accept' ? 'ok' : 'down'} label={e.result === 'accept' ? 'Accepted' : 'Rejected'} />
                      <p className="t2 num text-[12px]">{formatDateTime(e.at)}</p>
                    </div>
                    <div className="min-w-0">
                      {e.result === 'accept' ? (
                        <p className="flex flex-wrap items-center gap-2">Connected to <VlanRef vlan={v} /> <span className="t2">via {nas?.name ?? 'unknown controller'} · {e.ssid}{dev ? ` · ${dev.name}` : ''}</span></p>
                      ) : x ? (
                        <>
                          <p className="font-semibold">{x.title}</p>
                          <p className="t2">{x.explanation}</p>
                          <p className="mt-0.5"><span className="font-semibold">Fix: </span>{x.fix}</p>
                        </>
                      ) : <p>Rejected</p>}
                      <Collapsible.Root>
                        <Collapsible.Trigger className="t2 group mt-1 inline-flex items-center gap-1 rounded text-[12px] hover:text-[var(--e-text)]">
                          <ChevronRight size={13} className="transition-transform group-data-[state=open]:rotate-90" aria-hidden />Technical details
                        </Collapsible.Trigger>
                        <Collapsible.Content>
                          <dl className="mono mt-1.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-0.5 rounded-md bg-[#070A11] p-2.5 text-[11.5px] text-[var(--e-text-2)]">
                            {e.rawMessage && <><dt>Module</dt><dd className="break-all text-[var(--e-text)]">{e.rawMessage}</dd></>}
                            <dt>Certificate</dt><dd className="break-all">{e.certSerial ? formatSerial(e.certSerial) : '—'}</dd>
                            <dt>Calling-Station-Id</dt><dd>{e.callingStationId ?? '—'}</dd>
                            <dt>Called-Station-Id</dt><dd className="break-all">{e.calledStationId ?? '—'}</dd>
                            <dt>NAS</dt><dd>{nas ? `${nas.name} (${nas.address})` : '—'}</dd>
                          </dl>
                        </Collapsible.Content>
                      </Collapsible.Root>
                    </div>
                  </li>
                )
              })}
            </ol>
          )}
        </Panel>
        </div>
      </div>

      <Panel className="mt-4" title="Devices and certificates" desc={`One certificate per device. Revoking one leaves ${first}’s other devices connected.`}>
        <DataTable
          caption="Devices and certificates"
          rows={rows}
          rowKey={(r) => r.c.id}
          empty={<EmptyState icon={<ShieldCheck />} title={`${first} has no Wi-Fi certificates yet`} body="Issue one per device. The private key is generated on the device by default." action={<Button variant="primary" onClick={() => setIssueOpen(true)}><ShieldCheck />Issue Wi-Fi certificate</Button>} />}
          columns={[
            { key: 'dev', header: 'Device', cell: ({ dev }) => {
              const Icon = dev ? PLATFORM_ICON[dev.platform] : ShieldCheck
              return (
                <div className="flex min-w-0 items-center gap-2.5 py-1.5">
                  <Icon size={16} className="t2 shrink-0" aria-hidden />
                  <div className="min-w-0">
                    <p className="truncate font-semibold">{dev?.name ?? 'Unknown device'}</p>
                    <p className="t2 text-[12px]">{dev ? platformLabels[dev.platform] : ''}{dev?.lastSeenMac ? <> · <span className="mono">{dev.lastSeenMac}</span></> : ''}</p>
                  </div>
                </div>
              )
            } },
            { key: 'serial', header: 'Serial', hideBelow: 'lg', cell: ({ c }) => <span className="mono t2 text-[12px]">{formatSerial(c.serial).slice(0, 19)}…</span> },
            { key: 'status', header: 'Status', cell: ({ c }) => (
              <div className="py-1.5">
                <CertStatusMark cert={c} />
                {c.status === 'revoked' && <span className="t2 block text-[12px]">{c.revocationReason ? revocationReasonLabels[c.revocationReason] : ''} · {ago(c.revokedAt, isSession(`rev:${c.id}`))}</span>}
              </div>
            ) },
            { key: 'exp', header: 'Expires', hideBelow: 'md', cell: ({ c }) => <span className="num">{formatDate(c.notAfter)}<span className="t2 block text-[12px]">{daysUntil(c.notAfter, now()) >= 0 ? `in ${daysUntil(c.notAfter, now())} days` : `${-daysUntil(c.notAfter, now())} days ago`}</span></span> },
            { key: 'key', header: 'Private key', hideBelow: 'xl', cell: ({ c }) => <span className="t2">{KEY_ORIGIN[c.keyOrigin]}</span> },
            { key: 'act', header: <span className="sr-only">Actions</span>, align: 'right', cell: ({ c, dev }) => (c.status === 'active' || c.status === 'expiring') ? <Button size="sm" variant="secondary" onClick={() => setRevoke(c)} aria-label={`Revoke certificate for ${dev?.name ?? c.commonName}`}>Revoke</Button> : null },
          ]}
        />
      </Panel>

      <Inspector open={issueOpen} onClose={() => setIssueOpen(false)} title="Issue Wi-Fi certificate" subtitle={`For ${identity.displayName} · ${identity.upn}`} label="Issue Wi-Fi certificate">
        <IssueCertificateForm key={String(issueOpen)} identity={identity} onDone={() => setIssueOpen(false)} />
      </Inspector>
      <RevokeDialog cert={revoke} open={!!revoke} onOpenChange={(o) => !o && setRevoke(null)} deviceName={devices.find((x) => x.id === revoke?.deviceId)?.name} />
    </>
  )
}

function closestUser(entityId: string, all: Identity[], withDevices: string[]): Identity | undefined {
  const wanted = entityId.split(':u-').pop() ?? ''
  const pool = all.filter((i) => i.accountState === 'enabled' && withDevices.includes(i.id))
  return pool.find((i) => i.username === wanted) ?? pool.filter((i) => i.username[0] === wanted[0]).sort((a, b) => a.displayName.localeCompare(b.displayName))[0] ?? pool[0]
}
