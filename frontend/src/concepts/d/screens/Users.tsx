import { Building2, Info, KeyRound, SearchX } from 'lucide-react'
import { useCallback, useEffect, useMemo } from 'react'
import type { Certificate, Decision, Identity } from '@/domain/types'
import { useDecisions, useTenantData, useTenants } from '@/prototype/store'
import { useTable, type Column } from '@/ui/useTable'
import type { ScreenId } from '../../contract'
import { groupCode, groupTone } from '../model/codes'
import { primaryCertificate, relTime, userCertState, type UserCertState } from '../model/derive'
import { EMPTY_USERS, useViewState, type UsersFilter } from '../model/state'
import { SearchInput, Segmented, SelectField } from '../ui/Controls'
import { EmptyState, MetaSep, Notice, PageHeader } from '../ui/Section'
import { AccessMark, CertStatusMark, Remaining } from '../ui/Status'
import { DataTable, type TableColumn } from '../ui/Table'
import { RuleTape, Tape, VlanTape } from '../ui/Tape'

type Nav = (s: ScreenId, id?: string) => void

export interface UserRow {
  identity: Identity
  decision: Decision | undefined
  certs: Certificate[]
  primary: Certificate | null
  certState: UserCertState
  index: number
}

export function useUserRows(): UserRow[] {
  const d = useTenantData()
  const decisions = useDecisions()
  return useMemo(() => {
    const by = new Map<string, Certificate[]>()
    for (const c of d.certificates) if (c.identityId) by.set(c.identityId, [...(by.get(c.identityId) ?? []), c])
    return d.identities.map((identity, index) => {
      const certs = by.get(identity.id) ?? []
      return { identity, decision: decisions.get(identity.id), certs, primary: primaryCertificate(certs), certState: userCertState(certs), index }
    })
  }, [d.identities, d.certificates, decisions])
}

export function denyReason(i: Identity, dec: Decision | undefined): string | undefined {
  if (!dec || dec.outcome === 'allow') return undefined
  if (i.accountState !== 'enabled') return `Account ${i.accountState}`
  if (dec.decidingRuleId) return 'Deny rule'
  return 'No matching rule'
}

export function matchesUser(r: UserRow, f: UsersFilter): boolean {
  const i = r.identity
  if (f.source !== 'all' && i.source !== f.source) return false
  if (f.access !== 'all' && r.decision?.outcome !== f.access) return false
  if (f.group !== 'all' && !i.groupIds.includes(f.group)) return false
  if (f.cert !== 'all') {
    if (f.cert === 'none' ? r.certs.length > 0 : !r.certs.some((c) => c.status === f.cert)) return false
  }
  const q = f.query.trim().toLowerCase()
  if (q && ![i.displayName, i.username, i.upn, i.email, i.department, i.title].some((v) => v?.toLowerCase().includes(q))) return false
  return true
}

const SORT_COLUMNS: Column<UserRow>[] = [
  { key: 'name', value: (r) => r.identity.displayName },
  { key: 'source', value: (r) => r.identity.source },
  { key: 'department', value: (r) => r.identity.department },
  { key: 'access', value: (r) => (r.decision?.outcome === 'allow' ? 0 : 1) },
  { key: 'vlan', value: (r) => r.decision?.vlanId ?? null },
  { key: 'lastAuth', value: (r) => (r.identity.lastAuthAt ? new Date(r.identity.lastAuthAt).getTime() : null) },
  { key: 'cert', value: (r) => r.certState },
  { key: 'remaining', value: (r) => (r.primary && r.primary.status !== 'revoked' ? new Date(r.primary.notAfter).getTime() : null) },
]

export function Users({ navigate }: { navigate: Nav }) {
  const { current } = useTenants()
  const d = useTenantData()
  const vs = useViewState()
  const f = vs.users
  const all = useUserRows()
  const filter = useCallback((r: UserRow) => matchesUser(r, f), [f])
  const table = useTable(all, SORT_COLUMNS, { initialSort: { key: 'name', dir: 'asc' }, filter })
  const rows = table.rows
  const { setUserOrder } = vs
  const orderKey = rows.map((r) => r.identity.id).join('|')
  useEffect(() => { setUserOrder(orderKey ? orderKey.split('|') : []) }, [orderKey, setUserOrder])

  const active = f.query !== '' || f.source !== 'all' || f.access !== 'all' || f.cert !== 'all' || f.group !== 'all'
  const groupOptions = [
    { value: 'all', label: 'Any group' },
    ...d.groups.map((g) => ({ value: g.id, label: g.name, prefix: <Tape code={groupCode(g)} tone={groupTone(g.id, d.rules, d.vlans)} size="sm" /> })),
  ]

  const columns: TableColumn<UserRow>[] = [
    {
      key: 'name', header: 'Name', group: 'Identity', sortable: true,
      cell: (r) => (
        <>
          <button type="button" className="d-rowlink" onClick={() => navigate('user', r.identity.id)}>{r.identity.displayName}</button>
          <span className="d-sub">{r.identity.upn ?? r.identity.username}</span>
        </>
      ),
    },
    {
      key: 'source', header: 'Source', group: 'Identity', sortable: true, hideSm: true,
      cell: (r) => r.identity.source === 'ad'
        ? <span className="d-status"><Building2 aria-hidden="true" className="text-[var(--d-ink-3)]" />AD</span>
        : <span className="d-status"><KeyRound aria-hidden="true" className="text-[var(--d-warn)]" />Local</span>,
    },
    { key: 'department', header: 'Department', group: 'Identity', sortable: true, hideSm: true, cell: (r) => <span className="ink-2 nowrap">{r.identity.department ?? '—'}</span> },
    { key: 'access', header: 'Access', group: 'Decision', sortable: true, cell: (r) => (r.decision ? <AccessMark outcome={r.decision.outcome} reason={denyReason(r.identity, r.decision)} /> : null) },
    {
      key: 'vlan', header: 'VLAN', group: 'Decision', sortable: true,
      cell: (r) => {
        const rule = r.decision?.outcome === 'deny' ? d.rules.find((x) => x.id === r.decision?.decidingRuleId) : undefined
        return rule ? <RuleTape rule={rule} vlans={d.vlans} size="sm" /> : <VlanTape vlan={d.vlans.find((v) => v.id === r.decision?.vlanId)} size="sm" />
      },
    },
    { key: 'lastAuth', header: 'Last auth', group: 'Activity', sortable: true, hideSm: true, cell: (r) => <span className="ink-2 tnum nowrap">{relTime(r.identity.lastAuthAt)}</span> },
    {
      key: 'cert', header: 'Status', group: 'Certificate', sortable: true,
      cell: (r) => (
        <span className="inline-flex items-center gap-2">
          <CertStatusMark status={r.certState} />
          {r.certs.length > 1 && <span className="ink-3 text-[12px] tnum">+{r.certs.length - 1}</span>}
        </span>
      ),
    },
    { key: 'remaining', header: 'Remaining', group: 'Certificate', sortable: true, align: 'right', cell: (r) => (r.primary ? <Remaining cert={r.primary} /> : <span className="d-remaining" data-tone="off">—</span>) },
  ]

  return (
    <>
      <PageHeader
        title="Users"
        meta={<><span className="tnum">{d.identities.length} identities</span><MetaSep /><span className="tnum">{d.identities.filter((i) => i.source === 'ad').length} from Active Directory, {d.identities.filter((i) => i.source === 'local').length} local</span><MetaSep /><span>Directory sync {relTime(current.health.lastDirectorySync).toLowerCase()}</span></>}
      />
      {current.health.directory === 'unconfigured' && (
        <div className="mb-4">
          <Notice icon={<Info aria-hidden="true" />}>
            <strong>Active Directory isn’t connected yet.</strong> These {d.identities.length} accounts were created during setup. Connect LDAPS to import users, groups and account state; until then no one has a certificate.
          </Notice>
        </div>
      )}
      <div className="d-toolbar" role="search" aria-label="Filter users">
        <SearchInput className="w-full sm:w-64" value={f.query} onChange={(query) => vs.setUsers({ query })} placeholder="Search name, UPN, department" label="Search users" />
        <Segmented label="Source" value={f.source} onChange={(source) => vs.setUsers({ source })} options={[{ value: 'all', label: 'All sources' }, { value: 'ad', label: 'AD' }, { value: 'local', label: 'Local' }]} />
        <SelectField label="Access" hideLabel prefix="Access:" value={f.access} onChange={(access) => vs.setUsers({ access })} options={[{ value: 'all', label: 'Any' }, { value: 'allow', label: 'Allowed' }, { value: 'deny', label: 'Denied' }]} />
        <SelectField label="Certificate status" hideLabel prefix="Certificate:" value={f.cert} onChange={(cert) => vs.setUsers({ cert })} options={[{ value: 'all', label: 'Any' }, { value: 'active', label: 'Active' }, { value: 'expiring', label: 'Expiring soon' }, { value: 'expired', label: 'Expired' }, { value: 'revoked', label: 'Revoked' }, { value: 'none', label: 'No certificate' }]} />
        <SelectField label="Group" hideLabel value={f.group} onChange={(group) => vs.setUsers({ group })} options={groupOptions} width={170} />
        {active && <button type="button" className="d-btn d-btn--ghost d-btn--sm" onClick={() => vs.setUsers(EMPTY_USERS)}>Clear filters</button>}
        <span className="ml-auto text-[12.5px] text-[var(--d-ink-2)] tnum" aria-live="polite">{rows.length} of {all.length} shown</span>
      </div>
      <DataTable
        caption="Users"
        columns={columns}
        rows={rows}
        rowKey={(r) => `${r.identity.id}#${r.index}`}
        onRowClick={(r) => navigate('user', r.identity.id)}
        sort={{ sortKey: table.sort?.key, sortDir: table.sort?.dir, onSort: table.toggleSort, ariaSort: table.ariaSort }}
        empty={
          <EmptyState icon={<SearchX className="d-empty-icon" aria-hidden="true" />} title="No users match these filters" action={<button type="button" className="d-btn d-btn--sm" onClick={() => vs.setUsers(EMPTY_USERS)}>Clear filters</button>}>
            Try a different group or certificate status, or search by UPN.
          </EmptyState>
        }
      />
    </>
  )
}
