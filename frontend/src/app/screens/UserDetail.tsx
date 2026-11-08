// One user: who they are, whether they can connect now and why, their certificates and devices, pending enrollment
// links, and recent authentications. GET /api/tenants/{tid}/identities/{id} (routers/identities.py).
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Ban, Building, CircleCheck, Download, FilePlus, FlaskConical, Hourglass, Link2, MonitorCog, Pencil, PlugZap, ShieldX, UserRoundCheck, X } from 'lucide-react'
import { ApiError, filenameFrom, saveBlob } from '../api/client'
import { useTenant } from '../api/tenant'
import {
  cancelEnrollment, disconnectIdentity, downloadPackage, invalidatePeople, updateIdentity, useDirectory, useDirectoryGroups, useIdentities, useIdentity, usePolicy, useRadius,
  type AuthEvent, type Certificate, type IdentityDetail, type IdentityEnrollment,
} from '../api/people'
import type { EnforcementStatus, Outcome } from '../api/types'
import { paths, targetPath } from '../routes'
import {
  AccessStateChip, Btn, Callout, CertChip, Chip, EDialog, Empty, ErrorState, errorMessage, Field, LoadingBlock, PageHeader, Panel, PlatformIcon, platformLabels,
  SectionHeader, SourceTag, toast, VlanTag, type Tone,
} from '../ui'
import { DecisionLedger, reasonText } from '../ui/ledger'
import { ago, duration, fmtDate, fmtDateTime, fmtSerial, plural, relative, remaining } from '../lib/format'
import { pushRecent } from '../lib/recent'
import { useNow } from '../lib/useNow'
import { saveSetupAgain, ShowLinkDialog } from './people/GiveAgain'
import { IssueDialog } from './people/IssueDialog'
import { RevokeDialog } from './people/RevokeDialog'
import { WindowsSetupDialog } from './people/WindowsSetupDialog'
import { AccountChip, EventList, GroupPicker, joinNames, keyOrigin, keyStorage, reasonLabel } from './people/shared'

const first = (name: string) => name.split(' ')[0] || name
const statusRank: Record<string, number> = { active: 0, expiring: 1, expired: 2, revoked: 3 }
const sameOutcome = (a: Outcome, b: Outcome) => a.outcome === b.outcome && a.vlan_id === b.vlan_id && a.deciding_rule_id === b.deciding_rule_id && a.reason_code === b.reason_code

/** Last success, plus a newer rejection when there is one, so the header never says "never" above a failed attempt. */
function LastConnection({ lastAuth, latest, now }: { lastAuth: string | null; latest: AuthEvent | undefined; now: Date }) {
  const rejected = latest && latest.result === 'reject' && (!lastAuth || new Date(latest.at) > new Date(lastAuth)) ? latest : null
  const when = (iso: string) => <time dateTime={iso} title={fmtDateTime(iso)}>{ago(iso, now)}</time>
  return (
    <span className="ee-small ee-ink-2">
      {lastAuth ? <>Last authenticated {when(lastAuth)}</> : rejected ? 'No successful connection' : 'Never authenticated'}
      {rejected && <> · <span className="text-[var(--ee-crit-ink)]">last attempt rejected {when(rejected.at)}</span></>}
    </span>
  )
}

export default function UserDetail() {
  const { id = '' } = useParams()
  const { tid, tenant, can } = useTenant()
  const q = useIdentity(tid, id)
  const [params, setParams] = useSearchParams()
  const [issueOpen, setIssueOpen] = useState(false)
  const canIssue = can('certificates:issue') && can('enrollment:manage')

  // Intent: users/:id?issue=1 opens "Issue certificate", then the parameter is cleared.
  useEffect(() => {
    if (params.get('issue') !== '1' || !q.data) return
    if (canIssue) setIssueOpen(true)
    else toast('You can’t issue certificates', 'Your role doesn’t include issuing certificates. Ask a Tenant, PKI or Wi-Fi Administrator.', 'warn')
    setParams((p) => { const n = new URLSearchParams(p); n.delete('issue'); return n }, { replace: true })
  }, [params, q.data, canIssue, setParams])

  useEffect(() => {
    if (q.data) pushRecent(tid, { kind: 'identity', id: q.data.id, label: q.data.display_name, sub: q.data.upn ?? q.data.email ?? q.data.username })
  }, [tid, q.data])

  if (q.isLoading) return <div><BackLink tid={tid} /><LoadingBlock rows={6} label="Loading user" /></div>
  if (q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      return (
        <div>
          <BackLink tid={tid} />
          <PageHeader title="User not found" lede={`No user in ${tenant.name} matches this link. A directory sync may have removed the account, or the link is from another tenant.`} />
          <Link to={paths.users(tid)} className="ee-btn">Search users</Link>
        </div>
      )
    }
    return <div><BackLink tid={tid} /><ErrorState error={q.error} onRetry={() => q.refetch()} /></div>
  }
  if (!q.data) return null
  return <UserRecord key={q.data.id} identity={q.data} issueOpen={issueOpen} setIssueOpen={setIssueOpen} canIssue={canIssue} />
}

function BackLink({ tid }: { tid: string }) {
  return (
    <Link to={paths.users(tid)} className="ee-btn ee-btn-ghost ee-btn-sm mb-4 -ml-2.5 inline-flex"><ArrowLeft aria-hidden />All users</Link>
  )
}

function UserRecord({ identity: u, issueOpen, setIssueOpen, canIssue }: { identity: IdentityDetail; issueOpen: boolean; setIssueOpen: (o: boolean) => void; canIssue: boolean }) {
  const { tid, tenant, can } = useTenant()
  const now = useNow()
  const policy = usePolicy(tid)
  const directory = useDirectory(tid, u.source === 'ad')
  // The list endpoint carries the backend's own "can connect" (stored decisions for active certificates) and whether
  // the tenant is enforceable, so the record reads exactly what RADIUS would apply.
  const listQ = useIdentities(tid, { q: u.username, state: u.account_state === 'deleted' ? 'deleted' : undefined, page_size: 200 })
  const listed = listQ.data?.items.find((i) => i.id === u.id)
  const enforceable = listQ.data?.enforceable
  const enforcement = listQ.data?.enforcement_status
  const missing = listQ.data?.enforcement_missing ?? []

  const [revoking, setRevoking] = useState<Certificate | null>(null)
  const [disconnectOpen, setDisconnectOpen] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const [stateOpen, setStateOpen] = useState(false)
  const certRefs = useRef<Record<string, HTMLAnchorElement | null>>({})
  // Issue dialog returns focus to the header button (also when it was opened by ?issue=1).
  const issueBtn = useRef<HTMLButtonElement | null>(null)
  const focusAfterRevoke = useRef<HTMLElement | null>(null)
  const [setupOpen, setSetupOpen] = useState(false)
  const setupBtn = useRef<HTMLButtonElement | null>(null)

  const certs = useMemo(() => [...u.certificates].sort((a, b) => (statusRank[a.status] ?? 9) - (statusRank[b.status] ?? 9) || b.not_after.localeCompare(a.not_after)), [u.certificates])
  const live = certs.filter((c) => c.status === 'active' || c.status === 'expiring')
  const pending = u.enrollments.filter((e) => e.status === 'pending')
  const past = u.enrollments.filter((e) => e.status !== 'pending')
  const rules = policy.data?.rules ?? []
  const vlans = policy.data?.vlans ?? []
  const deviceDiffers = !sameOutcome(u.access.user, u.access.device)
  // Evidence for the ledger's certificate gate: the valid certificates on record, split by purpose when the two decide differently.
  const evidence = (purpose?: 'user' | 'device') => live.filter((c) => !purpose || c.purpose === purpose).map((c) => ({ name: c.device?.name ?? c.common_name, not_after: c.not_after }))
  const isLocal = u.source === 'local'
  const canWrite = can('identities:write')
  const syncEvery = directory.data?.config?.sync_interval_minutes

  return (
    <div>
      <BackLink tid={tid} />
      <PageHeader
        title={u.display_name}
        lede={<span className="break-words">{[u.upn ?? u.username, u.email && u.email !== u.upn ? u.email : null, u.title, u.department].filter(Boolean).join(' · ')}</span>}
        actions={
          <>
            <Link to={paths.policy(tid, { test: u.id })} className="ee-btn"><FlaskConical aria-hidden />Test access</Link>
            {canWrite && <Btn onClick={() => setDisconnectOpen(true)}><PlugZap aria-hidden />Disconnect</Btn>}
            {canIssue && u.account_state === 'enabled' && <Btn ref={setupBtn} onClick={() => setSetupOpen(true)}><MonitorCog aria-hidden />Windows setup</Btn>}
            {canIssue && <Btn ref={issueBtn} variant="primary" onClick={() => setIssueOpen(true)}><FilePlus aria-hidden />Issue certificate</Btn>}
          </>
        }
      >
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
          <SourceTag source={u.source} />
          <AccountChip state={u.account_state} />
          <LastConnection lastAuth={u.last_auth_at} latest={u.events[0]} now={now} />
          <span className="ee-small ee-ink-3 hidden sm:inline" aria-hidden>·</span>
          <span className="ee-small ee-ink-2 basis-full sm:basis-auto">
            {isLocal ? 'Local account, managed in EasyEAP'
              : u.last_synced_at ? <>Synced from Active Directory <time dateTime={u.last_synced_at} title={fmtDateTime(u.last_synced_at)}>{ago(u.last_synced_at, now)}</time></> : 'Not yet synced from Active Directory'}
          </span>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="ee-label mr-1">Groups</span>
          {u.groups.length === 0 ? <span className="ee-small ee-ink-3">None</span> : u.groups.map((g) => <span key={g.id} className="ee-tag">{g.name}</span>)}
          {isLocal && canWrite && <Btn size="sm" variant="ghost" onClick={() => setEditOpen(true)}><Pencil aria-hidden />Edit</Btn>}
          {isLocal && canWrite && (
            u.account_state === 'enabled'
              ? <Btn size="sm" variant="ghost" onClick={() => setStateOpen(true)}><Ban aria-hidden />Disable account</Btn>
              : <Btn size="sm" variant="ghost" onClick={() => setStateOpen(true)}><UserRoundCheck aria-hidden />Enable account</Btn>
          )}
        </div>
        {!isLocal && (
          <p className="ee-small ee-ink-3 mt-2 max-w-[75ch]">
            <Building className="mr-1 inline size-3.5 align-[-2px]" aria-hidden />
            Account state and groups come from Active Directory. Changes made there arrive with the next sync{syncEvery ? ` (every ${plural(syncEvery, 'minute')})` : ''}.{' '}
            <Link to={paths.directory(tid)} className="underline hover:text-[var(--ee-ink)]">Open Directory</Link>
          </p>
        )}
      </PageHeader>

      <AccessStatement u={u} live={live} listed={listed} enforceable={enforceable} enforcement={enforcement} missing={missing} loading={listQ.isLoading} rules={rules} vlans={vlans} tenantName={tenant.name}
        onIssue={canIssue ? () => setIssueOpen(true) : undefined} />

      <div className="mt-6 grid items-start gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
        <Panel className="px-5 py-4" aria-labelledby="ud-why">
          <SectionHeader id="ud-why" title="Why this decision" meta="Account, certificates on record and access rules" />
          {policy.isLoading ? <LoadingBlock rows={4} label="Loading rules" />
            : policy.error ? <ErrorState error={policy.error} onRetry={() => policy.refetch()} title="Access rules couldn’t be loaded" />
              : (
                <div className="space-y-6">
                  <div>
                    {deviceDiffers && <h3 className="ee-h3 mb-2.5">User certificates</h3>}
                    <DecisionLedger outcome={u.access.user} rules={rules} vlans={vlans} identityGroups={u.groups} accountState={u.account_state} source={u.source} policyOnly certificates={evidence(deviceDiffers ? 'user' : undefined)} />
                  </div>
                  {deviceDiffers && (
                    <div className="border-t border-[var(--ee-line)] pt-4">
                      <h3 className="ee-h3 mb-2.5">Device certificates</h3>
                      <DecisionLedger outcome={u.access.device} rules={rules} vlans={vlans} identityGroups={u.groups} accountState={u.account_state} source={u.source} policyOnly certificates={evidence('device')} />
                    </div>
                  )}
                </div>
              )}
        </Panel>

        <div className="min-w-0 space-y-6">
          <Panel className="px-5 py-4" aria-labelledby="ud-certs">
            <SectionHeader id="ud-certs" title="Certificates and devices" meta={certs.length ? `${live.length} valid of ${certs.length}` : undefined} />
            {certs.length === 0 ? (
              <Empty icon={<FilePlus aria-hidden />} title="No certificates yet"
                action={canIssue && u.account_state === 'enabled' ? <Btn variant="primary" onClick={() => setIssueOpen(true)}><FilePlus aria-hidden />Issue certificate</Btn> : undefined}>
                {u.account_state === 'enabled' ? `${first(u.display_name)} has no Wi-Fi certificate. Each device gets its own.` : `${first(u.display_name)} has no Wi-Fi certificate. The account is ${u.account_state}, so it can’t be enrolled until it is enabled.`}
              </Empty>
            ) : (
              <ul className="ee-divide">
                {certs.map((c) => (
                  <CertRow key={c.id} tid={tid} c={c} now={now}
                    linkRef={(el) => { certRefs.current[c.id] = el }}
                    onRevoke={can('certificates:revoke') && c.status !== 'revoked' ? () => { focusAfterRevoke.current = certRefs.current[c.id] ?? null; setRevoking(c) } : undefined} />
                ))}
              </ul>
            )}
          </Panel>

          <EnrollmentPanel tid={tid} u={u} pending={pending} past={past} now={now} />
        </div>
      </div>

      <Panel className="mt-6 px-5 py-4" aria-labelledby="ud-events">
        <SectionHeader id="ud-events" title="Recent authentications" meta={u.events.length ? `last ${u.events.length}` : undefined} />
        <EventList tid={tid} events={u.events} now={now} vlans={vlans} deviceName={(id) => u.devices.find((d) => d.id === id)?.name ?? null}
          emptyText={`${first(u.display_name)} hasn’t tried to join Wi-Fi with an EasyEAP certificate yet.`} />
      </Panel>

      {canIssue && <IssueDialog identity={u} open={issueOpen} onOpenChange={setIssueOpen} returnFocus={issueBtn} />}
      {canIssue && <WindowsSetupDialog identity={u} open={setupOpen} onOpenChange={setSetupOpen} returnFocus={setupBtn} />}
      <RevokeDialog cert={revoking ? { ...revoking, identity: { id: u.id, display_name: u.display_name } } : null} open={!!revoking} onOpenChange={(o) => { if (!o) setRevoking(null) }}
        returnFocus={focusAfterRevoke} />
      <DisconnectDialog u={u} open={disconnectOpen} onOpenChange={setDisconnectOpen} />
      {isLocal && <EditDialog u={u} open={editOpen} onOpenChange={setEditOpen} />}
      {isLocal && <StateDialog u={u} open={stateOpen} onOpenChange={setStateOpen} />}
    </div>
  )
}

// ── Can they connect now? ───────────────────────────────────────────────
function AccessStatement({ u, live, listed, enforceable, enforcement, missing, loading, rules, vlans, tenantName, onIssue }: {
  u: IdentityDetail
  live: Certificate[]
  listed: { access: { status: 'can_connect' | 'allowed_no_certificate' | 'denied'; vlan_id: number | null; reason_code: string | null } } | undefined
  enforceable: boolean | undefined
  enforcement: EnforcementStatus | undefined
  missing: Array<{ code: string; message: string; target: string }>
  loading: boolean
  rules: Array<{ id: string; name: string }>
  vlans: Array<{ vlan_id: number; name: string; color: string }>
  tenantName: string
  onIssue?: () => void
}) {
  const { tid } = useTenant()
  const outcomeFor = (c: Certificate) => (c.purpose === 'device' ? u.access.device : u.access.user)
  const policyAllows = u.access.user.outcome === 'allow' || u.access.device.outcome === 'allow'
  const allowedLive = live.filter((c) => outcomeFor(c).outcome === 'allow')
  // Prefer the backend's status (stored decisions); fall back to the record when the list hasn't answered.
  const status = listed?.access.status ?? (u.account_state !== 'enabled' || !policyAllows ? 'denied' : allowedLive.length ? 'can_connect' : 'allowed_no_certificate')
  const decided = u.access.user.outcome === 'allow' ? u.access.user : u.access.device.outcome === 'allow' ? u.access.device : u.access.user
  const rule = rules.find((r) => r.id === decided.deciding_rule_id)
  const vlanId = listed?.access.vlan_id ?? decided.vlan_id
  const vlan = vlans.find((v) => v.vlan_id === vlanId)
  const why = rule ? <>by “{rule.name}”</> : <>by the tenant default</>

  let tone: Tone, title: ReactNode, body: ReactNode, action: ReactNode = null
  if (loading && enforceable === undefined) {
    tone = 'neutral'; title = 'Checking whether RADIUS is enforcing this tenant…'; body = null
  } else if (status === 'denied') {
    tone = 'crit'
    title = `${first(u.display_name)} can’t connect`
    const code = listed?.access.reason_code ?? decided.reason_code
    body = u.account_state !== 'enabled'
      ? <>The account is {u.account_state}. Disabled, locked and deleted accounts are always denied; no rule can override this.</>
      : code === 'policy_deny' && rules.find((r) => r.id === u.access.user.deciding_rule_id)
        ? <>Denied by the rule “{rules.find((r) => r.id === u.access.user.deciding_rule_id)!.name}”. Deny rules win wherever they sit in the order.</>
        : <>{reasonText[code ?? ''] ?? 'Denied by policy'}.{live.length > 0 && ' Their certificates are valid, but the policy rejects them.'}</>
    if (u.account_state === 'enabled') action = <Link to={paths.policy(tid)} className="ee-btn ee-btn-sm">Review access policy</Link>
  } else if (enforcement?.state === 'suspended') {
    tone = 'neutral'
    title = `${tenantName} is suspended`
    body = <>Nobody in this tenant can connect while it’s suspended. Reactivating it in <Link to={targetPath(tid, 'tenant')} className="underline hover:text-[var(--ee-ink)]">tenant settings</Link> restores access; the policy {policyAllows ? 'would allow' : 'would deny'} {first(u.display_name)}.</>
  } else if (enforceable !== false && enforcement?.tone === 'crit' && status !== 'allowed_no_certificate') {
    tone = 'crit'
    title = <>{first(u.display_name)} can’t connect right now</>
    body = <>The policy allows them {why}{live.length ? ` and they hold ${plural(live.length, 'valid certificate')}` : ''}, but RADIUS isn’t accepting anyone in {tenantName}: {enforcement.label.toLowerCase()}. {enforcement.detail} <Link to={paths.dashboard(tid)} className="underline hover:text-[var(--ee-ink)]">See the dashboard</Link>.</>
  } else if (enforceable === false) {
    tone = 'neutral'
    title = 'Not enforceable yet'
    body = (
      <>
        RADIUS isn’t enforcing {tenantName} yet, so nobody here can connect. The policy {status === 'can_connect' || policyAllows ? 'would allow' : 'would deny'} {first(u.display_name)}{live.length ? ` and they hold ${plural(live.length, 'valid certificate')}` : ''}. Still to do:
        <ul className="mt-1.5 space-y-1">
          {missing.map((m) => <li key={m.code}><Link to={targetPath(tid, m.target)} className="underline hover:text-[var(--ee-ink)]">{m.message}</Link></li>)}
        </ul>
      </>
    )
  } else if (status === 'can_connect') {
    tone = 'valid'
    title = <>{first(u.display_name)} can connect now</>
    body = <>Allowed {why}{vlanId !== null ? <> onto VLAN <VlanTag vlanId={vlanId} name={vlan?.name} color={vlan?.color} /></> : ' with the controller’s default VLAN'}, with {plural(allowedLive.length || live.length, 'valid certificate')}.</>
  } else {
    tone = 'gold'
    title = 'Allowed by policy, but no valid certificate'
    body = <>The policy allows {first(u.display_name)} {why}{vlanId !== null ? <> onto VLAN <VlanTag vlanId={vlanId} name={vlan?.name} color={vlan?.color} /></> : null}, but RADIUS needs a valid certificate on each device before it accepts a connection.</>
    action = onIssue ? <Btn size="sm" variant="primary" onClick={onIssue}><FilePlus aria-hidden />Issue certificate</Btn> : null
  }

  return (
    <Panel risk={tone} className="flex flex-wrap items-start gap-x-4 gap-y-3 px-5 py-4" aria-live="polite" aria-label="Can this user connect">
      <div className="pt-0.5">{loading && enforceable === undefined ? <span className="ee-skeleton block h-[22px] w-28" /> : <AccessStateChip status={status} enforceable={enforceable ?? true} enforcement={enforcement} />}</div>
      <div className="min-w-0 flex-1 basis-[280px]">
        <p className="text-[15px] font-semibold">{title}</p>
        {body && <div className="ee-small ee-ink-2 mt-1 max-w-[80ch]">{body}</div>}
      </div>
      {action}
    </Panel>
  )
}

// ── Certificates ────────────────────────────────────────────────────────
function CertRow({ tid, c, now, onRevoke, linkRef }: { tid: string; c: Certificate; now: Date; onRevoke?: () => void; linkRef: (el: HTMLAnchorElement | null) => void }) {
  const origin = keyOrigin(c.key_origin)
  const storage = keyStorage(c.key_storage)
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-2 py-3 first:pt-0 last:pb-0">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <PlatformIcon platform={c.device?.platform} />
          <span className="text-[13.5px] font-semibold">{c.device?.name ?? 'No device recorded'}</span>
          {c.device && <span className="ee-small ee-ink-3">{platformLabels[c.device.platform] ?? c.device.platform}</span>}
          <CertChip status={c.status} />
        </div>
        <p className="ee-small ee-ink-3 mt-1 flex flex-wrap gap-x-2">
          <Link ref={linkRef} to={paths.certificate(tid, c.id)} className="ee-mono ee-ink-2 underline decoration-[var(--ee-line-3)] hover:text-[var(--ee-ink)]" aria-label={`Open certificate ${fmtSerial(c.serial)}`}>{fmtSerial(c.serial).slice(0, 19)}…</Link>
          <span>{c.purpose === 'device' ? 'Device' : 'User'} certificate</span>
          <span title={origin.long}>Key: {origin.short}{storage && <> · <span title={storage.long}>{storage.short}</span></>}</span>
          {c.renewal_of && <span>Renewed automatically</span>}
        </p>
        {c.status === 'revoked' && (
          <p className="ee-small ee-ink-2 mt-1">Revoked {fmtDateTime(c.revoked_at)} · {reasonLabel(c.revocation_reason)}{c.revoked_by ? ` · by ${c.revoked_by}` : ''}</p>
        )}
      </div>
      <div className="flex flex-col items-end gap-2">
        <p className="ee-remaining text-[13.5px] font-semibold">
          {c.status === 'revoked' ? <span className="ee-ink-3 font-normal">Not valid</span> : remaining(c.not_after, now)}
          <span className="ee-small ee-ink-3 block font-normal">{c.status === 'revoked' ? `was to ${fmtDate(c.not_after)}` : c.status === 'expired' ? `on ${fmtDate(c.not_after)}` : `to ${fmtDate(c.not_after)}`}</span>
        </p>
        {onRevoke && <Btn size="sm" variant="danger" onClick={onRevoke}><ShieldX aria-hidden />Revoke</Btn>}
      </div>
    </li>
  )
}

// ── Enrollment links ────────────────────────────────────────────────────
const enrollmentKind = (e: IdentityEnrollment) =>
  e.method === 'server' ? 'server-generated package'
    : e.method === 'windows-setup' ? `Windows setup file · ${e.purpose === 'device' ? 'computer’s certificate' : 'user’s certificate'}`
      : 'key on device'

function EnrollmentPanel({ tid, u, pending, past, now }: { tid: string; u: IdentityDetail; pending: IdentityEnrollment[]; past: IdentityEnrollment[]; now: Date }) {
  const { can } = useTenant()
  const [showPast, setShowPast] = useState(false)
  const [cancelling, setCancelling] = useState<IdentityEnrollment | null>(null)
  const [taking, setTaking] = useState<IdentityEnrollment | null>(null)
  const [showing, setShowing] = useState<IdentityEnrollment | null>(null)
  const [saving, setSaving] = useState<string | null>(null)
  // A Windows setup file holds both its codes: one Download button, on its first waiting row.
  const fileRow = new Map<string, string>()
  for (const e of pending) if (e.method === 'windows-setup' && e.device_id && !fileRow.has(e.device_id)) fileRow.set(e.device_id, e.id)
  const fileAvailable = (e: IdentityEnrollment) => pending.some((p) => p.method === 'windows-setup' && (p.id === e.id || (!!e.device_id && p.device_id === e.device_id)) && p.link_available)
  const live = (e: IdentityEnrollment) => new Date(e.expires_at) > now
  const usable = u.account_state === 'enabled'   // a disabled account's codes wait until it's enabled again
  const kept = (e: IdentityEnrollment) => (e.method === 'windows-setup' ? fileAvailable(e) : !!e.link_available)
  const saveAgain = async (e: IdentityEnrollment) => {
    setSaving(e.id)
    await saveSetupAgain(tid, e, u.display_name)
    setSaving(null)
  }
  const statusChip = (e: IdentityEnrollment) => {
    if (e.status === 'pending' && new Date(e.expires_at) <= now) return <Chip tone="neutral" icon={<Hourglass aria-hidden />}>Expired</Chip>
    if (e.status === 'pending') return <Chip tone="gold" icon={<Hourglass aria-hidden />}>Waiting for device</Chip>
    if (e.status === 'completed') return <Chip tone="valid" icon={<CircleCheck aria-hidden />}>Completed</Chip>
    if (e.status === 'cancelled') return <Chip tone="neutral" icon={<X aria-hidden />}>Cancelled</Chip>
    return <Chip tone="neutral" icon={<Hourglass aria-hidden />}>Expired</Chip>
  }
  const row = (e: IdentityEnrollment, actions: boolean) => (
    <li key={e.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-2 py-3 first:pt-0 last:pb-0">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <PlatformIcon platform={e.platform} />
          <span className="text-[13.5px] font-semibold">{e.device_name}</span>
          <span className="ee-small ee-ink-3">{platformLabels[e.platform] ?? e.platform} · {enrollmentKind(e)}</span>
          {statusChip(e)}
        </div>
        <p className="ee-small ee-ink-3 mt-1">
          {actions && live(e) && e.method !== 'server' && !kept(e) && <span className="block">Made before EasyEAP kept {e.method === 'link' ? 'links' : 'setup files'}: it can’t be given again. If it was lost, cancel it and issue a new one.</span>}
          {actions && live(e) && kept(e) && !usable && <span className="block">The account is {u.account_state} in the directory, so this can’t be used until it’s enabled again.</span>}
          Created {fmtDateTime(e.created_at)} by {e.created_by}
          {e.status === 'pending' && <> · {new Date(e.expires_at) > now ? 'expires' : 'expired'} <time dateTime={e.expires_at} className="ee-ink-2">{fmtDateTime(e.expires_at)}</time> ({relative(e.expires_at, now)})</>}
          {e.status === 'completed' && e.completed_at && <> · completed {fmtDateTime(e.completed_at)}</>}
        </p>
      </div>
      {actions && (
        <div className="flex flex-col items-end gap-2 sm:flex-row sm:items-start">
          {e.method === 'link' && e.link_available && usable && can('enrollment:manage') && live(e) && (
            <Btn size="sm" onClick={() => setShowing(e)}><Link2 aria-hidden />Show link</Btn>
          )}
          {e.method === 'windows-setup' && (!e.device_id || fileRow.get(e.device_id) === e.id) && fileAvailable(e) && usable && can('enrollment:manage') && live(e) && (
            <Btn size="sm" onClick={() => saveAgain(e)} busy={saving === e.id}><Download aria-hidden />Download setup file</Btn>
          )}
          {e.method === 'server' && can('enrollment:server_keygen') && new Date(e.expires_at) > now && (
            <Btn size="sm" onClick={() => setTaking(e)}><Download aria-hidden />Download package</Btn>
          )}
          {can('enrollment:manage') && <Btn size="sm" variant="ghost" onClick={() => setCancelling(e)}><X aria-hidden />Cancel</Btn>}
        </div>
      )}
    </li>
  )
  return (
    <Panel className="px-5 py-4" aria-labelledby="ud-enroll">
      <SectionHeader id="ud-enroll" title="Enrollment links" meta={pending.length ? `${pending.length} pending` : undefined} />
      {pending.length === 0 ? (
        <p className="ee-small ee-ink-2">No pending links. Links you create appear here until the device enrolls, the link expires or you cancel it.</p>
      ) : (
        <>
          <ul className="ee-divide">{pending.map((e) => row(e, true))}</ul>
          <p className="ee-small ee-ink-3 mt-3">
            Lost one? <b>Show link</b> gives the same link again and <b>Download setup file</b> the same Windows setup file, with the same one-time codes:
            no new certificate is made. EasyEAP keeps each code encrypted until it’s used, cancelled or expires, and records every time it’s given again in the audit log.
            A server-generated package can be downloaded once.
          </p>
        </>
      )}
      {past.length > 0 && (
        <div className="mt-3 border-t border-[var(--ee-line)] pt-3">
          <button type="button" className="ee-small ee-ink-2 rounded hover:text-[var(--ee-ink)]" aria-expanded={showPast} onClick={() => setShowPast((v) => !v)}>
            {showPast ? 'Hide' : 'Show'} {plural(past.length, 'earlier link')}
          </button>
          {showPast && <ul className="ee-divide mt-3">{past.map((e) => row(e, false))}</ul>}
        </div>
      )}
      <CancelEnrollmentDialog tid={tid} identityName={u.display_name} e={cancelling} onClose={() => setCancelling(null)} />
      <TakePackageDialog tid={tid} e={taking} onClose={() => setTaking(null)} />
      <ShowLinkDialog tid={tid} identityName={u.display_name} e={showing} onClose={() => setShowing(null)} />
    </Panel>
  )
}

function CancelEnrollmentDialog({ tid, identityName, e, onClose }: { tid: string; identityName: string; e: IdentityEnrollment | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { setError(null); setBusy(false) }, [e?.id])
  const confirm = async () => {
    if (!e) return
    setBusy(true)
    try {
      await cancelEnrollment(tid, e.id)
      toast('Enrollment link cancelled', `${e.device_name} · ${identityName}. The link no longer works.`)
      await invalidatePeople(qc, tid)
      onClose()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }
  return (
    <EDialog open={!!e} onOpenChange={(o) => { if (!o && !busy) onClose() }} title={`Cancel the link for ${e?.device_name ?? ''}?`} risk="warn"
      description="The link stops working as soon as you cancel it. You can issue a new one at any time."
      footer={<><Btn variant="ghost" onClick={onClose} disabled={busy}>Keep link</Btn><Btn variant="danger" onClick={confirm} busy={busy}><X aria-hidden />Cancel link</Btn></>}>
      <div className="space-y-3 text-[13px] ee-ink-2">
        {error && <Callout tone="crit" title="The link wasn’t cancelled">{error}</Callout>}
        {e?.method === 'server'
          ? <p>This is a server-generated package. Cancelling deletes the stored package and revokes the certificate created for it (reason: cessation of operation), because its key was never delivered.</p>
          : <p>No certificate exists yet for this link, so nothing is revoked.</p>}
      </div>
    </EDialog>
  )
}

function TakePackageDialog({ tid, e, onClose }: { tid: string; e: IdentityEnrollment | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { setError(null); setBusy(false) }, [e?.id])
  const take = async () => {
    if (!e) return
    setBusy(true)
    try {
      const res = await downloadPackage(tid, e.id)
      saveBlob(await res.blob(), filenameFrom(res, `${e.device_name}.p12`))
      toast('Package downloaded', `${e.device_name}: the one-time download is used; the user’s link no longer works.`)
      await invalidatePeople(qc, tid)
      onClose()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }
  return (
    <EDialog open={!!e} onOpenChange={(o) => { if (!o && !busy) onClose() }} title={`Download the package for ${e?.device_name ?? ''}?`} risk="warn"
      description="For hand delivery. The package can be downloaded once."
      footer={<><Btn variant="ghost" onClick={onClose} disabled={busy}>Not now</Btn><Btn variant="primary" onClick={take} busy={busy}><Download aria-hidden />Download package</Btn></>}>
      <div className="space-y-3 text-[13px] ee-ink-2">
        {error && <Callout tone="crit" title="The package wasn’t downloaded">{error}</Callout>}
        <p>Downloading here uses up the one-time download, so the link you sent the user stops working.</p>
        <p>The PKCS#12 password was shown once, when the package was created; EasyEAP doesn’t keep it. If it’s lost, cancel this package and create a new one.</p>
      </div>
    </EDialog>
  )
}

// ── Disconnect (CoA) ────────────────────────────────────────────────────
function DisconnectDialog({ u, open, onOpenChange }: { u: IdentityDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { tid } = useTenant()
  const radius = useRadius(tid, open)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { if (open) { setError(null); setBusy(false) } }, [open])
  const clients = radius.data?.clients ?? []
  const coa = clients.filter((c) => c.coa_enabled)
  const noCoa = clients.filter((c) => !c.coa_enabled)
  const timeout = radius.data?.settings?.session_timeout_seconds ?? null
  const run = async () => {
    setBusy(true)
    try {
      const r = await disconnectIdentity(tid, u.id)
      toast(r.sessions === 0 ? 'No sessions to disconnect' : 'Disconnect requested',
        r.sessions === 0 ? `${first(u.display_name)} has no accepted sessions from the last two days.`
          : [r.queued ? `Queued for ${plural(r.queued, 'session')} on controllers with CoA; the RADIUS agent sends it within seconds.` : '',
            r.without_coa ? `${plural(r.without_coa, 'session')} on controllers without CoA stay${r.without_coa === 1 ? 's' : ''} connected until the session timeout.` : ''].filter(Boolean).join(' '),
        r.sessions > 0 && r.queued === 0 ? 'warn' : 'valid')
      onOpenChange(false)
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }
  return (
    <EDialog open={open} onOpenChange={(o) => { if (!busy) onOpenChange(o) }} title={`Disconnect ${u.display_name}?`} risk="warn"
      description="Ends their current Wi-Fi sessions through Change of Authorization (CoA)."
      footer={<><Btn variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>Cancel</Btn><Btn variant="primary" onClick={run} busy={busy}><PlugZap aria-hidden />Send disconnect</Btn></>}>
      <div className="space-y-3 text-[13px] ee-ink-2">
        {error && <Callout tone="crit" title="The disconnect wasn’t sent">{error}</Callout>}
        <p>EasyEAP finds the sessions {first(u.display_name)} opened in the last two days and queues a Disconnect-Request for each. The RADIUS agent sends it to the controller.</p>
        <p>
          {radius.isLoading ? 'Checking which controllers support CoA…'
            : clients.length === 0 ? 'This tenant has no controllers registered, so there is nothing to disconnect.'
              : <>
                {coa.length === 0
                  ? <>No controller in this tenant has CoA turned on, so no session can be ended early. Sessions continue until the session timeout{timeout ? ` (${duration(timeout)})` : ''}.</>
                  : noCoa.length === 0
                    ? <>CoA is on for {joinNames(coa)}.</>
                    : <>CoA is on for {joinNames(coa)} and off for {joinNames(noCoa)}. Sessions through {noCoa.length === 1 ? 'that controller' : 'those controllers'} continue until the session timeout{timeout ? ` (${duration(timeout)})` : ''}.</>}
              </>}
        </p>
        <Callout tone="gold">Disconnecting doesn’t block anyone. If their certificate is valid and the policy allows them, the device reconnects straight away. To keep a device off, revoke its certificate{u.source === 'local' ? ' or disable the account' : ' or disable the account in Active Directory'}.</Callout>
      </div>
    </EDialog>
  )
}

// ── Local users: edit and enable/disable ────────────────────────────────
function EditDialog({ u, open, onOpenChange }: { u: IdentityDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { tid } = useTenant()
  const qc = useQueryClient()
  const groups = useDirectoryGroups(tid, open)
  const [name, setName] = useState(u.display_name)
  const [ids, setIds] = useState<string[]>(u.groups.map((g) => g.id))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { if (open) { setName(u.display_name); setIds(u.groups.map((g) => g.id)); setError(null); setBusy(false) } }, [open, u.display_name, u.groups])
  const nameError = !name.trim() ? 'Enter a display name.' : null
  const save = async () => {
    if (nameError) return
    setBusy(true)
    try {
      await updateIdentity(tid, u.id, { display_name: name.trim(), group_ids: ids })
      toast('User updated', `${name.trim()}. Access decisions were recalculated; RADIUS applies them with its next update, normally within seconds.`)
      await invalidatePeople(qc, tid)
      onOpenChange(false)
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }
  return (
    <EDialog open={open} onOpenChange={(o) => { if (!busy) onOpenChange(o) }} title={`Edit ${u.display_name}`} wide
      description="Group changes can change which rule applies, and so the VLAN or whether access is allowed."
      footer={<><Btn variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>Cancel</Btn><Btn variant="primary" onClick={save} busy={busy} disabled={!!nameError}>Save changes</Btn></>}>
      <div className="space-y-4">
        {error && <Callout tone="crit" title="Changes weren’t saved">{error}</Callout>}
        <Field label="Display name" htmlFor="ud-name" error={nameError}>
          <input id="ud-name" className="ee-input" value={name} onChange={(e) => setName(e.target.value)} maxLength={256} autoComplete="off" />
        </Field>
        <GroupPicker groups={groups.data?.groups ?? []} value={ids} onChange={setIds} loading={groups.isLoading} />
      </div>
    </EDialog>
  )
}

function StateDialog({ u, open, onOpenChange }: { u: IdentityDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { tid } = useTenant()
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { if (open) { setError(null); setBusy(false) } }, [open])
  const disabling = u.account_state === 'enabled'
  const run = async () => {
    setBusy(true)
    try {
      await updateIdentity(tid, u.id, { account_state: disabling ? 'disabled' : 'enabled' })
      toast(disabling ? 'Account disabled' : 'Account enabled',
        disabling ? `${u.display_name}. RADIUS rejects new connections once it applies the update, normally within seconds. A CoA disconnect was queued for any of their sessions from the last two days on controllers with CoA.`
          : `${u.display_name}. Devices with a valid certificate can connect again once RADIUS applies the update.`)
      await invalidatePeople(qc, tid)
      onOpenChange(false)
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }
  return (
    <EDialog open={open} onOpenChange={(o) => { if (!busy) onOpenChange(o) }} title={disabling ? `Disable ${u.display_name}?` : `Enable ${u.display_name}?`} risk={disabling ? 'crit' : 'gold'}
      footer={<><Btn variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>Cancel</Btn>
        <Btn variant={disabling ? 'danger-solid' : 'primary'} onClick={run} busy={busy}>{disabling ? <><Ban aria-hidden />Disable account</> : <><UserRoundCheck aria-hidden />Enable account</>}</Btn></>}>
      <div className="space-y-3 text-[13px] ee-ink-2">
        {error && <Callout tone="crit" title="The account wasn’t changed">{error}</Callout>}
        {disabling ? (
          <>
            <p>Disabled accounts are always denied, whatever their certificates or groups. RADIUS rejects new connections once it applies the update, normally within seconds.</p>
            <p>EasyEAP also queues a CoA disconnect for sessions from the last two days. Devices on controllers without CoA stay connected until the session timeout.</p>
            <p>Certificates are not revoked, so enabling the account later restores access.</p>
          </>
        ) : (
          <p>Devices with a valid certificate can connect again once RADIUS applies the update, if the access rules allow {first(u.display_name)}.</p>
        )}
      </div>
    </EDialog>
  )
}
