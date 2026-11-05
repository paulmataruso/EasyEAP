import { useMemo, useState } from 'react'
import { DatabaseZap, FileKey2 } from 'lucide-react'
import { now, useDecisions, useTenantData, useTenants } from '@/prototype/store'
import type { Certificate, CertStatus, Identity } from '@/domain/types'
import { certStatusLabels } from '@/domain/explain'
import { daysUntil, formatDate } from '@/ui/lib'
import { PageHeader } from '../ui/PageHeader'
import { Notice, Panel } from '../ui/Panel'
import { IconButton } from '../ui/Button'
import { AccessBadge, SourceBadge, StatusBadge, VlanChip } from '../ui/Badge'
import { Segmented } from '../ui/Field'
import { SearchInput } from '../ui/SearchInput'
import { ALL, DataTable, useDataTable, type ColumnDef } from '../ui/DataTable'
import { useInspector } from '../shell/Inspectors'
import { useIntent, useShell } from '../shell/context'
import { certTone } from '../lib/status'
import { formatAge, rel, secondsSince } from '../lib/format'
import { accountStateLabels } from '../lib/labels'

type SourceFilter = 'all' | 'ad' | 'local'
const URGENCY: CertStatus[] = ['expired', 'expiring', 'revoked', 'pending', 'active']

interface Row {
  identity: Identity
  index: number
  certs: Certificate[]
  /** Most urgent certificate status */
  certStatus: CertStatus | null
  nextExpiry: string | null
  /** Latest RADIUS event for the user, falling back to the directory's last-auth stamp */
  lastAuthAt: string | null
}

export function UsersScreen() {
  const { current } = useTenants()
  const d = useTenantData()
  const decisions = useDecisions()
  const { go } = useShell()
  const { openIssue } = useInspector()
  const [source, setSource] = useState<SourceFilter>('all')

  const rows = useMemo<Row[]>(() => {
    const byIdentity = new Map<string, Certificate[]>()
    for (const c of d.certificates) if (c.identityId) byIdentity.set(c.identityId, [...(byIdentity.get(c.identityId) ?? []), c])
    const latest = new Map<string, string>()
    for (const e of d.authEvents) if (e.identityId && (latest.get(e.identityId) ?? '') < e.at) latest.set(e.identityId, e.at)
    return d.identities.map((identity, index) => {
      const certs = byIdentity.get(identity.id) ?? []
      const certStatus = certs.length ? URGENCY.find((s) => certs.some((c) => c.status === s)) ?? null : null
      const live = certs.filter((c) => c.status === 'active' || c.status === 'expiring')
      const nextExpiry = live.length ? live.map((c) => c.notAfter).sort()[0] : null
      return { identity, index, certs, certStatus, nextExpiry, lastAuthAt: latest.get(identity.id) ?? identity.lastAuthAt }
    })
  }, [d.identities, d.certificates, d.authEvents])

  const groupName = useMemo(() => new Map(d.groups.map((g) => [g.id, g.name])), [d.groups])
  const vlanById = useMemo(() => new Map(d.vlans.map((v) => [v.id, v])), [d.vlans])

  const columns = useMemo<ColumnDef<Row>[]>(
    () => [
      {
        id: 'name',
        header: 'User',
        sticky: true,
        width: 260,
        sort: (r) => r.identity.displayName,
        search: (r) => [r.identity.displayName, r.identity.username, r.identity.upn, r.identity.email].join(' '),
        cell: (r) => (
          <span className="flex min-w-0 items-center gap-2">
            <span className="flex min-w-0 items-baseline gap-2">
              <span className="shrink-0 font-medium text-[var(--b-text)]">{r.identity.displayName}</span>
              <span className="b-mono truncate text-[11px] text-[var(--b-text-3)]">{r.identity.username}</span>
            </span>
            {r.identity.accountState !== 'enabled' && <StatusBadge tone={r.identity.accountState === 'locked' ? 'warn' : 'crit'}>{accountStateLabels[r.identity.accountState]}</StatusBadge>}
          </span>
        ),
      },
      { id: 'source', header: 'Source', width: 74, sort: (r) => r.identity.source, cell: (r) => <SourceBadge source={r.identity.source} /> },
      {
        id: 'dept',
        header: 'Department',
        className: 'hidden 2xl:table-cell',
        sort: (r) => r.identity.department,
        search: (r) => [r.identity.department, r.identity.title].join(' '),
        cell: (r) => (
          <span className="block max-w-[190px] truncate">
            {r.identity.department}
            <span className="text-[var(--b-text-3)]"> · {r.identity.title}</span>
          </span>
        ),
      },
      {
        id: 'group',
        header: 'Groups',
        filter: { kind: 'select', allLabel: 'Any group', options: d.groups.map((g) => ({ value: g.id, label: g.name, hint: String(g.memberCount) })), test: (r, v) => r.identity.groupIds.includes(v) },
        search: (r) => r.identity.groupIds.map((g) => groupName.get(g)).join(' '),
        cell: (r) => {
          const names = r.identity.groupIds.map((g) => groupName.get(g) ?? g).filter((n) => n !== 'Domain Users')
          return (
            <span className="block max-w-[180px] truncate text-[var(--b-text-2)]" title={r.identity.groupIds.map((g) => groupName.get(g)).join(', ')}>
              {names.length ? names.join(', ') : 'Domain Users'}
            </span>
          )
        },
      },
      {
        id: 'access',
        header: 'Wi-Fi access',
        width: 118,
        sort: (r) => decisions.get(r.identity.id)?.outcome ?? null,
        filter: { kind: 'select', options: [{ value: 'allow', label: 'Allowed' }, { value: 'deny', label: 'Denied' }], test: (r, v) => decisions.get(r.identity.id)?.outcome === v },
        cell: (r) => {
          const dec = decisions.get(r.identity.id)
          return dec ? <AccessBadge outcome={dec.outcome} /> : null
        },
      },
      {
        id: 'vlan',
        header: 'VLAN',
        sort: (r) => (decisions.get(r.identity.id)?.vlanId ? vlanById.get(decisions.get(r.identity.id)!.vlanId!)?.vlanId ?? null : null),
        filter: { kind: 'select', allLabel: 'Any VLAN', options: d.vlans.map((v) => ({ value: v.id, label: `${v.vlanId} · ${v.name}` })), test: (r, v) => decisions.get(r.identity.id)?.vlanId === v },
        cell: (r) => {
          const id = decisions.get(r.identity.id)?.vlanId
          return id ? <VlanChip vlan={vlanById.get(id)} /> : <span className="text-[var(--b-text-3)]">None</span>
        },
      },
      {
        id: 'certs',
        header: 'Certificates',
        sort: (r) => (r.certStatus ? URGENCY.indexOf(r.certStatus) : 99),
        filter: {
          kind: 'select',
          allLabel: 'Any status',
          options: [...(['active', 'expiring', 'expired', 'revoked'] as CertStatus[]).map((s) => ({ value: s, label: certStatusLabels[s] })), { value: 'none', label: 'No certificate' }],
          test: (r, v) => (v === 'none' ? r.certs.length === 0 : r.certs.some((c) => c.status === v)),
        },
        cell: (r) =>
          r.certStatus ? (
            <span className="flex items-center gap-2">
              <StatusBadge tone={certTone[r.certStatus]}>{certStatusLabels[r.certStatus]}</StatusBadge>
              <span className="b-num text-[12px] text-[var(--b-text-3)]">{r.certs.length > 1 ? `${r.certs.length} devices` : '1 device'}</span>
            </span>
          ) : (
            <span className="text-[var(--b-text-3)]">None</span>
          ),
      },
      {
        id: 'expiry',
        header: 'Next expiry',
        align: 'end',
        sort: (r) => r.nextExpiry,
        cell: (r) => {
          if (!r.nextExpiry) return <span className="text-[var(--b-text-3)]">—</span>
          const days = daysUntil(r.nextExpiry, now())
          return (
            <span className={`b-num ${days <= 30 ? 'b-ink-warn' : 'text-[var(--b-text-2)]'}`} title={formatDate(r.nextExpiry)}>
              {days <= 60 ? `${days} days` : formatDate(r.nextExpiry)}
            </span>
          )
        },
      },
      {
        id: 'lastAuth',
        header: 'Last auth',
        align: 'end',
        sort: (r) => r.lastAuthAt,
        cell: (r) => <span className="b-num text-[var(--b-text-2)]">{r.lastAuthAt ? rel(r.lastAuthAt) : 'Never'}</span>,
      },
      {
        id: 'actions',
        header: '',
        width: 40,
        cell: (r) =>
          r.identity.accountState === 'enabled' ? (
            <IconButton
              icon={FileKey2}
              label={`Issue Wi-Fi certificate to ${r.identity.displayName}`}
              onClick={(e) => {
                e.stopPropagation()
                openIssue(r.identity.id)
              }}
              onKeyDown={(e) => e.stopPropagation()}
            />
          ) : null,
      },
    ],
    [d.groups, d.vlans, decisions, groupName, vlanById, openIssue],
  )

  const extraFilter = useMemo(() => (source === 'all' ? undefined : (r: Row) => r.identity.source === source), [source])
  const table = useDataTable(rows, columns, { initialSort: { key: 'name', dir: 'asc' }, extraFilter })

  useIntent('users', (intent) => {
    const f = intent.filters ?? {}
    setSource((f.source as SourceFilter) ?? 'all')
    table.setFilters({ access: f.access ?? ALL, certs: f.cert ?? ALL })
    table.setQuery('')
  })

  const adCount = d.identities.filter((i) => i.source === 'ad').length
  const localCount = d.identities.length - adCount
  const syncAge = secondsSince(current.health.lastDirectorySync)

  return (
    <>
      <PageHeader
        title="Users"
        context={
          current.health.directory === 'unconfigured'
            ? `${d.identities.length} accounts · Active Directory not connected`
            : `${d.identities.length} identities · ${current.domain} synced ${syncAge === null ? 'never' : `${formatAge(syncAge)} ago`}`
        }
      />
      {current.health.directory === 'unconfigured' && (
        <Notice tone="info" icon={DatabaseZap} className="mb-3" title="Connect Active Directory to keep these accounts in sync">
          These {d.identities.length} accounts were imported during setup. Until LDAPS sync runs, group membership and account state are not refreshed, and EasyEAP denies anyone whose data is missing.
        </Notice>
      )}
      {current.health.directory === 'degraded' && (
        <Notice tone="warn" className="mb-3" title={`Directory sync failing for ${formatAge(syncAge)}`}>
          {d.audit.find((a) => a.action === 'directory.sync.failed')?.detail ?? 'The last sync did not complete.'} Group changes since then are not reflected below. Trust the LDAPS server’s issuing CA in the directory settings, then sync again.
        </Notice>
      )}
      <Panel aria-label="Users">
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--b-line)] px-3 py-2">
          <Segmented
            label="Identity source"
            value={source}
            onChange={setSource}
            options={[
              { value: 'all', label: 'All', count: d.identities.length },
              { value: 'ad', label: 'Active Directory', count: adCount },
              { value: 'local', label: 'Local', count: localCount },
            ]}
          />
          <SearchInput className="w-full sm:ml-auto sm:w-[300px]" value={table.query} onChange={table.setQuery} placeholder="Search name, username, email, group" label="Search users" />
        </div>
        <DataTable
          table={table}
          label="Users"
          noun="users"
          rowKey={(r) => `${r.identity.id}#${r.index}`}
          rowLabel={(r) => r.identity.displayName}
          onActivate={(r) => go('user', { entityId: r.identity.id })}
        />
      </Panel>
    </>
  )
}
