// Users in the tenant (directory and local), with whether each can connect now.
// GET /api/tenants/{tid}/identities (routers/identities.py): q, state, group_id, enrolled, waiting, page, page_size ≤ 200.
// A link or Windows setup file still waiting for a device can be given again from here (people/GiveAgain.tsx).
import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { UserPlus, Users as UsersIcon, X } from 'lucide-react'
import { useTenant } from '../api/tenant'
import type { EnforcementStatus } from '../api/types'
import { createIdentity, invalidatePeople, useDirectory, useDirectoryGroups, useIdentities, usePolicy, type IdentityListItem, type PolicyVlan, type WaitingEnrollment } from '../api/people'
import { paths, targetPath } from '../routes'
import { AccessStateChip, Btn, Callout, EDialog, Empty, ErrorState, errorMessage, ESelect, Field, PageHeader, Panel, Seg, SourceTag, toast, VlanTag } from '../ui'
import { ago, fmtDateTime, plural } from '../lib/format'
import { useNow } from '../lib/useNow'
import { ShowLinkDialog, WaitingList } from './people/GiveAgain'
import { AccountChip, denyReason, GroupPicker, Pager, SearchBox, TableSkeleton, useUrlState } from './people/shared'

const PAGE_SIZE = 50
const STATES = [
  { value: 'any', label: 'Any account state' },
  { value: 'enabled', label: 'Enabled' },
  { value: 'disabled', label: 'Disabled' },
  { value: 'locked', label: 'Locked' },
  { value: 'deleted', label: 'Deleted in directory' },
]

export default function Users() {
  const { tid, tenant, can } = useTenant()
  const navigate = useNavigate()
  const now = useNow()
  const { values, page, set } = useUrlState(['q', 'state', 'group', 'enrolled', 'kind'] as const)
  const computers = values.kind === 'computer'
  const [createOpen, setCreateOpen] = useState(false)
  const [showing, setShowing] = useState<{ w: WaitingEnrollment; name: string } | null>(null)
  const params = {
    q: values.q || undefined,
    state: values.state || undefined,
    group_id: values.group || undefined,
    enrolled: values.enrolled === 'yes' ? true : values.enrolled === 'no' ? false : undefined,
    waiting: values.enrolled === 'waiting' ? true : undefined,
    page,
    page_size: PAGE_SIZE,
    kind: computers ? 'computer' as const : undefined,
  }
  const list = useIdentities(tid, params)
  const groups = useDirectoryGroups(tid)
  const directory = useDirectory(tid)
  const vlans = usePolicy(tid).data?.vlans ?? []
  const data = list.data
  const filtered = !!(values.q || values.state || values.group || values.enrolled)
  const clear = () => set({ q: null, state: null, group: null, enrolled: null })
  const groupList = groups.data?.groups ?? []
  const dupNames = new Set(groupList.map((g) => g.name).filter((n, i, a) => a.indexOf(n) !== i))

  return (
    <div>
      <PageHeader
        title="Users"
        lede={data ? <>{plural(data.total, filtered ? 'user matches' : 'user', filtered ? 'users match' : 'users')}{filtered ? ' these filters' : ` in ${tenant.name}`}. Access shows whether each person can connect now: allowed by policy and holding a valid certificate.</> : `People in ${tenant.name} and whether each can connect now.`}
        actions={can('identities:write') && <Btn onClick={() => setCreateOpen(true)}><UserPlus aria-hidden />Add local user</Btn>}
      />

      {data?.enforcement_status?.state === 'suspended' ? (
        <Callout tone="neutral" className="mb-5" title={`${tenant.name} is suspended: nobody can connect`}>
          Reactivate it in <Link to={targetPath(tid, 'tenant')} className="text-[var(--ee-ink)] underline underline-offset-2">tenant settings</Link> to restore access. Certificates, policy and directory data are kept.
        </Callout>
      ) : data?.enforceable && data.enforcement_status?.tone === 'crit' ? (
        <Callout tone="crit" className="mb-5" title={`${data.enforcement_status.label}: nobody in ${tenant.name} can connect right now`}>
          {data.enforcement_status.detail} Users the policy allows show as “Can’t connect now”. <Link to={paths.dashboard(tid)} className="text-[var(--ee-ink)] underline underline-offset-2">See the dashboard</Link>.
        </Callout>
      ) : data && !data.enforceable && (
        <Callout tone="warn" className="mb-5" title={`Not enforceable yet: nobody in ${tenant.name} can connect`}>
          RADIUS isn’t enforcing this tenant, so users the policy allows show as “Not enforceable yet”. Still to do:
          <ul className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
            {data.enforcement_missing.map((m) => (
              <li key={m.code}><Link to={targetPath(tid, m.target)} className="text-[var(--ee-ink)] underline underline-offset-2 hover:text-[var(--ee-gold)]">{m.message}</Link></li>
            ))}
          </ul>
        </Callout>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter users">
        <Seg label="Show" value={computers ? 'computer' : 'user'} onChange={(v) => set({ kind: v === 'computer' ? 'computer' : null, enrolled: null })}
          options={[{ value: 'user', label: 'People' }, { value: 'computer', label: 'Computers' }]} />
        <SearchBox className="w-full sm:w-[280px]" value={values.q} onChange={(v) => set({ q: v.trim() || null })} label="Search users" placeholder="Name, username, email or UPN" />
        <ESelect label="Account state" className="min-w-[180px]" value={values.state || 'any'} onChange={(v) => set({ state: v === 'any' ? null : v })} options={STATES} />
        <ESelect label="Group" className="min-w-[200px] max-w-full" value={values.group || 'any'} onChange={(v) => set({ group: v === 'any' ? null : v })}
          placeholder={groups.isLoading ? 'Loading groups…' : undefined}
          options={[{ value: 'any', label: 'Any group' }, ...groupList.map((g) => ({ value: g.id, label: `${g.name}${dupNames.has(g.name) ? (g.source === 'ad' ? ' (AD)' : ' (local)') : ''} · ${g.members}` }))]} />
        <Seg label="Enrollment" value={(values.enrolled || 'all') as 'all' | 'yes' | 'no' | 'waiting'} onChange={(v) => set({ enrolled: v === 'all' ? null : v })}
          options={[{ value: 'all', label: 'All' }, { value: 'yes', label: 'Enrolled' }, { value: 'no', label: 'Not enrolled' }, { value: 'waiting', label: 'Waiting for device' }]} />
        {filtered && <Btn size="sm" variant="ghost" onClick={clear}><X aria-hidden />Clear filters</Btn>}
      </div>

      {list.error ? (
        <ErrorState error={list.error} onRetry={() => list.refetch()} title="Users couldn’t be loaded" />
      ) : data && data.total === 0 ? (
        filtered ? (
          <Empty icon={<UsersIcon aria-hidden />} title="No users match these filters" action={<Btn onClick={clear}>Clear filters</Btn>}>
            Search matches name, username, email and UPN. Deleted directory accounts appear only under “Deleted in directory”.
          </Empty>
        ) : (
          computers ? (
            <Empty icon={<UsersIcon aria-hidden />} title={`No computers in ${tenant.name} yet`}
              action={<Link to={paths.autoenroll(tid)} className="ee-btn">Group Policy autoenrollment</Link>}>
              A domain PC appears here when it first asks EasyEAP for a certificate through Group Policy autoenrollment. Its access comes from its own AD groups.
            </Empty>
          ) : <Empty icon={<UsersIcon aria-hidden />} title={`No users in ${tenant.name} yet`}
            action={
              <div className="flex flex-wrap gap-2">
                {!directory.data?.config && <Link to={paths.directory(tid)} className="ee-btn ee-btn-primary">Connect Active Directory</Link>}
                {can('identities:write') && <Btn onClick={() => setCreateOpen(true)}><UserPlus aria-hidden />Add local user</Btn>}
              </div>
            }>
            {directory.data?.config ? 'The directory is connected but no users have synced yet. Check the last sync on the Directory page.' : 'Sync users from Active Directory, or add local accounts for people outside the directory.'}
          </Empty>
        )
      ) : (
        <Panel className="px-4 py-3 sm:px-5" aria-label="Users">
          {/* Wide screens: table. Narrow screens: stacked rows. */}
          <div className="hidden md:block">
            <table className="ee-table" aria-busy={list.isFetching || undefined}>
              <caption className="sr-only">Users and their access</caption>
              <thead>
                <tr>
                  <th className="pt-1.5">User</th>
                  <th className="pt-1.5">Access now</th>
                  <th className="pt-1.5 text-right">Certificates</th>
                  <th className="pt-1.5">Groups</th>
                  <th className="pt-1.5 text-right">Last authenticated</th>
                </tr>
              </thead>
              {!data ? <TableSkeleton cols={5} /> : (
                <tbody className={list.isPlaceholderData ? 'opacity-60' : undefined}>
                  {data.items.map((u) => (
                    <tr key={u.id} data-clickable="true" onClick={(e) => { if (!(e.target as HTMLElement).closest('a,button')) navigate(paths.user(tid, u.id)) }}>
                      <td className="min-w-[220px] max-w-[340px]">
                        <span className="flex flex-wrap items-center gap-2">
                          <Link to={paths.user(tid, u.id)} className="text-[13.5px] font-semibold hover:underline">{u.display_name}</Link>
                          <SourceTag source={u.source} />
                          {u.account_state !== 'enabled' && <AccountChip state={u.account_state} />}
                        </span>
                        <span className="ee-small ee-ink-3 block truncate">{[u.upn ?? u.username, u.department].filter(Boolean).join(' · ')}</span>
                      </td>
                      <td><AccessCell u={u} enforceable={data.enforceable} enforcement={data.enforcement_status} vlans={vlans} /></td>
                      <td className="text-right ee-num whitespace-nowrap"><CertCount u={u} /><WaitingList u={u} onShow={(w) => setShowing({ w, name: u.display_name })} align="end" /></td>
                      <td className="max-w-[260px]"><Groups u={u} /></td>
                      <td className="text-right whitespace-nowrap ee-ink-2 ee-num">
                        {u.last_auth_at ? <time dateTime={u.last_auth_at} title={fmtDateTime(u.last_auth_at)}>{ago(u.last_auth_at, now)}</time> : <span className="ee-ink-3">Never</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              )}
            </table>
          </div>
          <ul className="ee-divide md:hidden" aria-label="Users">
            {!data && Array.from({ length: 5 }, (_, i) => <li key={i} className="py-3"><span className="ee-skeleton block h-4 w-2/3" /><span className="ee-skeleton mt-2 block h-4 w-1/3" /></li>)}
            {data?.items.map((u) => (
              <li key={u.id} className="py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Link to={paths.user(tid, u.id)} className="text-[14px] font-semibold underline-offset-2 hover:underline">{u.display_name}</Link>
                  <SourceTag source={u.source} />
                  {u.account_state !== 'enabled' && <AccountChip state={u.account_state} />}
                </div>
                <p className="ee-small ee-ink-3 mt-0.5 break-all">{u.upn ?? u.username}</p>
                <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
                  <AccessCell u={u} enforceable={data.enforceable} enforcement={data.enforcement_status} vlans={vlans} />
                  <span className="ee-small ee-ink-2 ee-num"><CertCount u={u} /></span>
                </div>
                <WaitingList u={u} onShow={(w) => setShowing({ w, name: u.display_name })} />
                <p className="ee-small ee-ink-3 mt-1.5">{u.last_auth_at ? <>Last authenticated {ago(u.last_auth_at, now)}</> : 'Never authenticated'}</p>
              </li>
            ))}
          </ul>
          {data && <Pager page={page} pageSize={PAGE_SIZE} total={data.total} onPage={(p) => set({ page: p > 1 ? String(p) : null })} noun={['user', 'users']} />}
        </Panel>
      )}

      <ShowLinkDialog tid={tid} identityName={showing?.name ?? ''} e={showing?.w ?? null} onClose={() => setShowing(null)} />
      {can('identities:write') && <CreateUserDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={(id) => navigate(paths.user(tid, id))} />}
    </div>
  )
}

function AccessCell({ u, enforceable, enforcement, vlans }: { u: IdentityListItem; enforceable: boolean; enforcement?: EnforcementStatus; vlans: PolicyVlan[] }) {
  const vlan = vlans.find((v) => v.vlan_id === u.access.vlan_id)
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <AccessStateChip status={u.access.status} enforceable={enforceable} enforcement={enforcement} />
      {u.access.status !== 'denied' && u.access.vlan_id !== null && <VlanTag vlanId={u.access.vlan_id} name={vlan?.name} color={vlan?.color} />}
      {u.access.status === 'denied' && u.access.reason_code && <span className="ee-small ee-ink-3">{denyReason[u.access.reason_code] ?? u.access.reason_code}</span>}
    </span>
  )
}

function CertCount({ u }: { u: IdentityListItem }) {
  if (u.certificates === 0) return <span className="ee-ink-3">None</span>
  return <span title={`${u.active_certificates} valid, ${u.certificates} issued in total`}><span className="font-semibold">{u.active_certificates}</span><span className="ee-ink-3"> valid of {u.certificates}</span></span>
}

function Groups({ u }: { u: IdentityListItem }) {
  if (u.groups.length === 0) return <span className="ee-small ee-ink-3">No groups</span>
  const shown = u.groups.slice(0, 2)
  const rest = u.groups.length - shown.length
  return (
    <span className="flex flex-wrap items-center gap-1" title={u.groups.map((g) => g.name).join(', ')}>
      {shown.map((g) => <span key={g.id} className="ee-tag max-w-[160px]"><span className="truncate">{g.name}</span></span>)}
      {rest > 0 && <span className="ee-small ee-ink-3">+{rest}</span>}
    </span>
  )
}

// ── Add a local user ────────────────────────────────────────────────────
const USERNAME = /^[A-Za-z0-9._@-]+$/
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function CreateUserDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; onCreated: (id: string) => void }) {
  const { tid, tenant } = useTenant()
  const qc = useQueryClient()
  const groups = useDirectoryGroups(tid, open)
  const [username, setUsername] = useState('')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [ids, setIds] = useState<string[]>([])
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const reset = () => { setUsername(''); setName(''); setEmail(''); setIds([]); setTouched(false); setBusy(false); setError(null) }

  const errors = {
    username: !username.trim() ? 'Enter a username. Certificates carry it as the user’s identity.' : !USERNAME.test(username.trim()) ? 'Use letters, digits and . _ @ - only, with no spaces.' : null,
    name: !name.trim() ? 'Enter the person’s name as it should appear in lists, for example “Casey Contractor”.' : null,
    email: email.trim() && !EMAIL.test(email.trim()) ? 'That doesn’t look like an email address.' : null,
  }
  const invalid = Object.values(errors).some(Boolean)

  const submit = async (e?: FormEvent) => {
    e?.preventDefault()
    setTouched(true)
    if (invalid) return
    setBusy(true)
    setError(null)
    try {
      const created = await createIdentity(tid, { username: username.trim(), display_name: name.trim(), email: email.trim() || null, group_ids: ids })
      toast('Local user added', `${created.display_name} (${created.upn ?? created.username}). Issue a certificate from their page.`)
      await invalidatePeople(qc, tid)
      onOpenChange(false)
      reset()
      onCreated(created.id)
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  const upn = username.trim() && !username.includes('@') && tenant.domain ? `${username.trim()}@${tenant.domain}` : username.trim()
  return (
    <EDialog open={open} onOpenChange={(o) => { if (busy) return; onOpenChange(o); if (!o) reset() }} title="Add a local user" wide
      description="For people outside Active Directory, such as contractors. Local users are managed here, not by directory sync."
      footer={<><Btn variant="ghost" onClick={() => { onOpenChange(false); reset() }} disabled={busy}>Cancel</Btn><Btn variant="primary" onClick={() => submit()} busy={busy}><UserPlus aria-hidden />Add user</Btn></>}>
      <form className="space-y-4" onSubmit={submit} noValidate>
        {error && <Callout tone="crit" title="The user wasn’t added">{error}</Callout>}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Username" htmlFor="cu-username" error={touched ? errors.username : null} hint={upn ? <>Certificates name them <span className="ee-mono">{upn}</span></> : 'Letters, digits and . _ @ -'}>
            <input id="cu-username" className="ee-input ee-mono" value={username} onChange={(e) => setUsername(e.target.value)} maxLength={256} autoComplete="off" spellCheck={false} aria-invalid={touched && !!errors.username} autoFocus />
          </Field>
          <Field label="Display name" htmlFor="cu-name" error={touched ? errors.name : null}>
            <input id="cu-name" className="ee-input" value={name} onChange={(e) => setName(e.target.value)} maxLength={256} autoComplete="off" aria-invalid={touched && !!errors.name} />
          </Field>
          <div className="sm:col-span-2">
            <Field label="Email" htmlFor="cu-email" optional error={touched ? errors.email : null} hint="Added to the certificate when the template includes an email name.">
              <input id="cu-email" className="ee-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" aria-invalid={touched && !!errors.email} />
            </Field>
          </div>
        </div>
        <GroupPicker groups={groups.data?.groups ?? []} value={ids} onChange={setIds} loading={groups.isLoading} />
        <button type="submit" className="sr-only" tabIndex={-1}>Add user</button>
      </form>
    </EDialog>
  )
}
