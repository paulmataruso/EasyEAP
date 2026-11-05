import { useMemo, useState } from 'react'
import { DropdownMenu } from 'radix-ui'
import { Copy, Ellipsis, FileBadge, FolderTree, Info, SearchX, UserRound, Waypoints } from 'lucide-react'
import type { Identity } from '@/domain/types'
import { copyText } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { AccessPill, CertStatusPill, SourceBadge, VlanChip } from '../ui/badges'
import { DataTable, useDataTable, type TableColumn } from '../ui/DataTable'
import { Segmented, SearchInput, SelectField } from '../ui/fields'
import { Avatar, Button, EmptyState, IconButton, Mono, PageHeader, Tip } from '../ui/primitives'
import { usePortalContainer } from '../ui/portal'
import { useToast } from '../ui/toast'
import { IssueCertificateDialog } from '../features/IssueCertificateDialog'
import { useLookups, useUserRows, type UserRow } from '../lib/model'
import { ago, day, expiryText } from '../lib/time'
import { useNav } from '../shell/nav'

type SourceFilter = 'all' | 'ad' | 'local'

function RowMenu({ row, onIssue }: { row: UserRow; onIssue: () => void }) {
  const container = usePortalContainer()
  const { navigate } = useNav()
  const toast = useToast()
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="a-icon-btn" aria-label={`More actions for ${row.identity.displayName}`}>
        <Ellipsis aria-hidden />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <DropdownMenu.Content align="end" sideOffset={4} className="a-menu a-overlay-glass">
          <DropdownMenu.Item className="a-menu-item" onSelect={() => navigate('user', row.identity.id)}>
            <UserRound aria-hidden /> View details
          </DropdownMenu.Item>
          <DropdownMenu.Item className="a-menu-item" onSelect={onIssue}>
            <FileBadge aria-hidden /> Issue Wi-Fi certificate
          </DropdownMenu.Item>
          <DropdownMenu.Item className="a-menu-item" onSelect={() => navigate('policies', row.identity.id)}>
            <Waypoints aria-hidden /> Test access
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="a-menu-sep" />
          <DropdownMenu.Item
            className="a-menu-item"
            onSelect={async () => {
              await copyText(row.identity.upn ?? row.identity.username)
              toast({ title: 'UPN copied', description: row.identity.upn ?? row.identity.username, tone: 'info' })
            }}
          >
            <Copy aria-hidden /> Copy UPN
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

export function Users() {
  const rows = useUserRows()
  const d = useTenantData()
  const { current } = useTenants()
  const { ruleById } = useLookups()
  const { navigate } = useNav()
  const [source, setSource] = useState<SourceFilter>('all')
  const [access, setAccess] = useState('all')
  const [cert, setCert] = useState('any')
  const [group, setGroup] = useState('all')
  const [issueFor, setIssueFor] = useState<Identity | null>(null)
  const [issueOpen, setIssueOpen] = useState(false)

  const openIssue = (i?: Identity) => {
    setIssueFor(i ?? null)
    setIssueOpen(true)
  }

  const columns = useMemo<TableColumn<UserRow>[]>(
    () => [
      {
        key: 'name',
        header: 'User',
        sortValue: (r) => r.identity.displayName,
        cell: (r) => (
          <div className="flex min-w-0 items-center gap-3">
            <Avatar name={r.identity.displayName} size={30} />
            <div className="min-w-0">
              <span className="flex items-center gap-2">
                <a
                  href={`#/c/a/user/${encodeURIComponent(r.identity.id)}`}
                  onClick={(e) => {
                    e.preventDefault()
                    navigate('user', r.identity.id)
                  }}
                  className="truncate text-[14px] font-medium text-[var(--a-text)] no-underline hover:underline"
                >
                  {r.identity.displayName}
                </a>
                {r.identity.source === 'local' && <SourceBadge source="local" className="2xl:hidden !h-5 !text-[11px]" />}
              </span>
              <Mono className="block max-w-[220px] truncate text-[12px] text-[var(--a-text-3)]">{r.identity.upn ?? r.identity.username}</Mono>
            </div>
          </div>
        ),
      },
      { key: 'source', header: 'Source', sortValue: (r) => r.identity.source, className: 'hidden 2xl:table-cell', cell: (r) => <SourceBadge source={r.identity.source} /> },
      {
        key: 'access',
        header: 'Access',
        sortValue: (r) => r.decision.outcome,
        cell: (r) => {
          const rule = r.decision.decidingRuleId ? ruleById.get(r.decision.decidingRuleId) : undefined
          const why = r.identity.accountState !== 'enabled' ? `Account ${r.identity.accountState}` : rule ? rule.name : 'No rule matched (default)'
          return (
            <Tip content={`Decided by: ${why}`}>
              <span className="inline-flex flex-col items-start gap-0.5" tabIndex={0}>
                <AccessPill outcome={r.decision.outcome} />
                <span className="max-w-[150px] truncate text-[11px] text-[var(--a-text-3)]">{why}</span>
              </span>
            </Tip>
          )
        },
      },
      { key: 'vlan', header: 'VLAN', sortValue: (r) => r.vlan?.vlanId ?? null, cell: (r) => (r.vlan ? <VlanChip vlan={r.vlan} /> : <span className="text-[13px] text-[var(--a-text-3)]">None</span>) },
      {
        key: 'cert',
        header: 'Certificate',
        sortValue: (r) => r.cert.nextExpiry ?? (r.cert.count ? 'z' : null),
        cell: (r) => (
          <div className="flex flex-col items-start gap-0.5">
            <span className="inline-flex items-center gap-1.5">
              <CertStatusPill status={r.cert.headline} />
              {r.cert.count > 1 && <span className="a-num text-[12px] text-[var(--a-text-3)]">+{r.cert.count - 1}</span>}
            </span>
            {r.cert.nextExpiry && (
              <span className="a-num text-[11px] text-[var(--a-text-3)]" title={day(r.cert.nextExpiry)}>
                {expiryText(r.cert.nextExpiry)}
              </span>
            )}
          </div>
        ),
      },
      { key: 'last', header: 'Last authenticated', sortValue: (r) => r.identity.lastAuthAt, className: 'hidden lg:table-cell', cell: (r) => <span className="a-num whitespace-nowrap">{ago(r.identity.lastAuthAt)}</span> },
      { key: 'dept', header: 'Department', sortValue: (r) => r.identity.department, className: 'hidden 2xl:table-cell', cell: (r) => r.identity.department ?? '—' },
      {
        key: 'actions',
        header: 'Actions',
        srHeader: true,
        align: 'right',
        cell: (r) => (
          <div className="a-row-actions">
            <span className="a-row-hover">
              <IconButton label={`Issue Wi-Fi certificate for ${r.identity.displayName}`} icon={FileBadge} onClick={() => openIssue(r.identity)} />
            </span>
            <RowMenu row={r} onIssue={() => openIssue(r.identity)} />
          </div>
        ),
      },
    ],
    [navigate, ruleById],
  )

  const filter = useMemo(
    () => (r: UserRow) =>
      (source === 'all' || r.identity.source === source) &&
      (access === 'all' || r.decision.outcome === access) &&
      (cert === 'any' || (cert === 'none' ? r.cert.count === 0 : r.cert.statuses.has(cert as never))) &&
      (group === 'all' || r.identity.groupIds.includes(group)),
    [source, access, cert, group],
  )
  const searchText = useMemo(() => (r: UserRow) => `${r.identity.displayName} ${r.identity.upn ?? ''} ${r.identity.username} ${r.identity.email ?? ''} ${r.identity.department ?? ''} ${r.identity.title ?? ''}`, [])
  const table = useDataTable(rows, columns, { searchText, filter, initialSort: { key: 'name', dir: 'asc' } })
  const filtered = table.query || source !== 'all' || access !== 'all' || cert !== 'any' || group !== 'all'
  const clear = () => {
    table.setQuery('')
    setSource('all')
    setAccess('all')
    setCert('any')
    setGroup('all')
  }

  const adCount = rows.filter((r) => r.identity.source === 'ad').length
  const allowed = rows.filter((r) => r.decision.outcome === 'allow').length
  const dirConnected = current.health.lastDirectorySync !== null

  return (
    <>
      <PageHeader
        title="Users"
        description={
          <>
            {allowed} of {rows.length} can join Wi-Fi · {adCount} from Active Directory (<span className="a-mono text-[13px]">{current.domain}</span>), {rows.length - adCount} local
            {dirConnected && ` · synced ${ago(current.health.lastDirectorySync)}`}
          </>
        }
        actions={
          <Button variant="primary" icon={FileBadge} onClick={() => openIssue()}>
            Issue Wi-Fi certificate
          </Button>
        }
      />

      {!dirConnected && (
        <div className="a-panel a-depth-tenant mb-4 flex items-start gap-3 px-[18px] py-3.5">
          <Info className="mt-0.5 size-4 shrink-0 text-[var(--a-info-text)]" aria-hidden />
          <p className="text-[14px] text-[var(--a-text-2)]">
            <span className="font-semibold text-[var(--a-text)]">Active Directory isn’t connected yet.</span> These {rows.length} accounts have never synced, so account state and group membership are not current. Connect the directory to finish setup.
          </p>
        </div>
      )}

      <section aria-label="User list" className="a-panel a-depth-tenant">
        <div className="flex flex-wrap items-center gap-2.5 px-[18px] py-3.5">
          <SearchInput value={table.query} onChange={table.setQuery} label="Search users" placeholder="Search name, UPN or email" className="w-full sm:w-[260px]" />
          <Segmented<SourceFilter>
            label="Identity source"
            value={source}
            onChange={setSource}
            options={[
              { value: 'all', label: 'All', count: rows.length },
              { value: 'ad', label: <><FolderTree className="size-3.5" aria-hidden />Active Directory</>, count: adCount },
              { value: 'local', label: <><UserRound className="size-3.5" aria-hidden />Local</>, count: rows.length - adCount },
            ]}
          />
          <SelectField
            label="Access"
            hideLabel
            value={access}
            onChange={setAccess}
            options={[
              { value: 'all', label: 'Any access' },
              { value: 'allow', label: 'Allowed' },
              { value: 'deny', label: 'Denied' },
            ]}
          />
          <SelectField
            label="Certificate status"
            hideLabel
            value={cert}
            onChange={setCert}
            options={[
              { value: 'any', label: 'Any certificate' },
              { value: 'active', label: 'Has active' },
              { value: 'expiring', label: 'Expiring soon' },
              { value: 'expired', label: 'Has expired' },
              { value: 'revoked', label: 'Has revoked' },
              { value: 'none', label: 'No certificate' },
            ]}
          />
          <SelectField label="Group" hideLabel value={group} onChange={setGroup} options={[{ value: 'all', label: 'Any group' }, ...d.groups.map((g) => ({ value: g.id, label: `${g.name} (${g.memberCount})`, short: g.name }))]} />
          <p className="a-num ml-auto text-[13px] text-[var(--a-text-3)]" aria-live="polite">
            {table.rows.length === rows.length ? `${rows.length} users` : `${table.rows.length} of ${rows.length} users`}
            {filtered && (
              <button type="button" className="a-link ml-3" onClick={clear}>
                Clear filters
              </button>
            )}
          </p>
        </div>
        <DataTable
          caption="Users"
          columns={columns}
          table={table}
          rowKey={(r) => r.key}
          onRowClick={(r) => navigate('user', r.identity.id)}
          empty={
            rows.length === 0 ? (
              <EmptyState icon={UserRound} title="No users yet">
                Connect Active Directory or add a local account to start issuing certificates.
              </EmptyState>
            ) : (
              <EmptyState icon={SearchX} title="No users match these filters" action={<Button onClick={clear}>Clear filters</Button>}>
                {table.query ? `Nothing matches “${table.query}” with the current filters.` : 'Try a different access, certificate or group filter.'}
              </EmptyState>
            )
          }
        />
      </section>

      <IssueCertificateDialog key={issueFor?.id ?? 'pick'} open={issueOpen} onOpenChange={setIssueOpen} identity={issueFor ?? undefined} />
    </>
  )
}
