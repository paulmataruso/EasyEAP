import { useMemo, useState } from 'react'
import { SearchX, Unplug } from 'lucide-react'
import { now, useDecisions, useTenantData, useTenants } from '@/prototype/store'
import type { Decision, Identity } from '@/domain/types'
import { daysUntil } from '@/ui/lib'
import { useTable, type Column } from '@/ui/useTable'
import { useConcept, type Intent, type UserFilters } from '../app/context'
import { Button } from '../ui/Button'
import { Cell, DataTable, type ColumnDef } from '../ui/DataTable'
import { FilterSelect, SearchInput, Segmented } from '../ui/Field'
import { Empty, Lede, Note } from '../ui/Layout'
import { AccessMark, CertMark } from '../ui/Status'
import { VlanTag } from '../ui/Vlan'
import { certificateSummaryFor, denialReason } from '../lib/posture'
import { list, plural, since } from '../lib/format'

const DEFAULT_FILTERS: UserFilters = { source: 'all', access: 'all', cert: 'all', group: 'all' }

interface Row {
  /** Unique row key: identity ids in the seed data are not guaranteed unique. */
  key: string
  identity: Identity
  decision: Decision
  cert: ReturnType<typeof certificateSummaryFor>
}

export function UsersScreen({ intent }: { intent: Intent }) {
  const { current: tenant } = useTenants()
  const d = useTenantData()
  const decisions = useDecisions()
  const { go } = useConcept()
  const [filters, setFilters] = useState<UserFilters>({ ...DEFAULT_FILTERS, ...intent.users })
  const set = (patch: Partial<UserFilters>) => setFilters((f) => ({ ...f, ...patch }))

  const rows = useMemo<Row[]>(() => d.identities.map((identity, i) => ({ key: `${identity.id}#${i}`, identity, decision: decisions.get(identity.id)!, cert: certificateSummaryFor(identity.id, d) })), [d, decisions])
  const ruleName = (id: string) => d.rules.find((r) => r.id === id)?.name
  const vlanOf = (row: Row) => d.vlans.find((v) => v.id === row.decision.vlanId)

  const filter = useMemo(
    () => (r: Row) =>
      (filters.source === 'all' || r.identity.source === filters.source) &&
      (filters.access === 'all' || r.decision.outcome === filters.access) &&
      (filters.cert === 'all' || r.cert.status === filters.cert) &&
      (filters.group === 'all' || r.identity.groupIds.includes(filters.group)),
    [filters],
  )
  const columns = useMemo<Column<Row>[]>(
    () => [
      { key: 'name', value: (r) => r.identity.displayName },
      { key: 'username', value: (r) => `${r.identity.username} ${r.identity.upn ?? ''} ${r.identity.email ?? ''}` },
      { key: 'department', value: (r) => r.identity.department },
      { key: 'access', value: (r) => (r.decision.outcome === 'allow' ? 0 : 1), searchable: false },
      { key: 'vlan', value: (r) => d.vlans.find((v) => v.id === r.decision.vlanId)?.vlanId ?? null, searchable: false },
      { key: 'cert', value: (r) => (r.cert.cert ? new Date(r.cert.cert.notAfter).getTime() : null), searchable: false },
      { key: 'lastAuth', value: (r) => (r.identity.lastAuthAt ? new Date(r.identity.lastAuthAt).getTime() : null), searchable: false },
    ],
    [d.vlans],
  )
  const table = useTable(rows, columns, { initialSort: { key: 'name', dir: 'asc' }, filter })

  // The sentence describes the population, not the current filter.
  const allowed = rows.filter((r) => r.decision.outcome === 'allow').length
  const denied = rows.filter((r) => r.decision.outcome === 'deny')
  const byAccount = denied.filter((r) => r.decision.steps.some((s) => s.kind === 'account' && !s.ok)).length
  const byRule = denied.filter((r) => r.decision.decidingRuleId).map((r) => ruleName(r.decision.decidingRuleId!) ?? '')
  const withoutCert = rows.filter((r) => r.cert.status === 'none').length
  const adCount = rows.filter((r) => r.identity.source === 'ad').length
  const localCount = rows.length - adCount
  const anyFilter = filters.source !== 'all' || filters.access !== 'all' || filters.cert !== 'all' || filters.group !== 'all' || table.query.trim() !== ''

  const byDefault = denied.length - byAccount - byRule.length
  const ruleCounts = [...new Set(byRule)].map((name) => ({ n: byRule.filter((x) => x === name).length, phrase: `by the rule “${name}”` }))
  const parts = [
    ...(byAccount ? [{ n: byAccount, phrase: 'by their directory account state' }] : []),
    ...ruleCounts,
    ...(byDefault ? [{ n: byDefault, phrase: 'because no rule matches their groups' }] : []),
  ]
  const detail =
    denied.length === 0
      ? 'Nobody is denied by policy right now.'
      : denied.length === 1
        ? `One person is denied, ${parts[0]?.phrase}.`
        : `${denied.length} are denied: ${list(parts.map((p) => `${p.n} ${p.phrase}`))}.`

  const count = (pred: (r: Row) => boolean) => rows.filter(pred).length
  const columnsDef: ColumnDef<Row>[] = [
    {
      key: 'name',
      header: 'Name',
      sortable: true,
      cell: (r) => (
        <Cell
          primary={
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <button type="button" className="c-rowlink" onClick={() => go('user', { entityId: r.identity.id })}>
                {r.identity.displayName}
              </button>
              {r.identity.source === 'local' ? <span className="c-tag is-outline">Local account</span> : null}
            </span>
          }
          secondary={`${r.identity.username}${r.identity.department ? ` · ${r.identity.department}` : ''}`}
        />
      ),
    },
    {
      key: 'access',
      header: 'Access',
      sortable: true,
      cell: (r) => <Cell primary={<AccessMark outcome={r.decision.outcome} />} secondary={r.decision.outcome === 'deny' ? denialReason(r.decision, ruleName) : undefined} />,
    },
    { key: 'vlan', header: 'VLAN', sortable: true, hide: 'sm', cell: (r) => (r.decision.outcome === 'allow' ? <VlanTag vlan={vlanOf(r)} /> : <span className="c-faint">None</span>) },
    {
      key: 'cert',
      header: 'Certificate',
      sortable: true,
      hide: 'md',
      cell: (r) => {
        const c = r.cert.cert
        const days = c ? daysUntil(c.notAfter, now()) : 0
        const sub = !c ? undefined : r.cert.status === 'expiring' || r.cert.status === 'active' ? `${days} days left` : r.cert.status === 'expired' ? `${-days} days ago` : undefined
        return <Cell primary={<CertMark status={r.cert.status} />} secondary={c ? `${sub ? `${sub} · ` : ''}${plural(r.cert.count, 'device')}` : undefined} />
      },
    },
    { key: 'lastAuth', header: 'Last authentication', sortable: true, hide: 'lg', cell: (r) => <span className="c-muted tnum">{since(r.identity.lastAuthAt)}</span> },
  ]

  return (
    <>
      <Lede
        page="Users"
        state={
          <>
            <strong>
              {allowed} of {rows.length}
            </strong>{' '}
            people can join <span className="c-nowrap">Wi-Fi</span>.
          </>
        }
        detail={rows.length ? (withoutCert === rows.length ? `${detail} No one has a certificate yet.` : detail) : undefined}
      />
      {tenant.health.directory === 'unconfigured' ? (
        <div style={{ marginTop: 20 }}>
          <Note icon={Unplug} tone="warn">
            <strong>Active Directory is not connected yet.</strong> These people come from the initial import; groups and account states refresh once the LDAPS connection is set up.
          </Note>
        </div>
      ) : null}
      <section aria-label="People" style={{ marginTop: 40 }}>
        <div className="c-filters">
          <SearchInput value={table.query} onChange={table.setQuery} placeholder="Search name, username or email" label="Search users" />
          <Segmented
            label="Source"
            value={filters.source}
            onChange={(v) => set({ source: v as UserFilters['source'] })}
            options={[
              { value: 'all', label: 'All', count: rows.length },
              { value: 'ad', label: 'Active Directory', count: adCount },
              { value: 'local', label: 'Local', count: localCount },
            ]}
          />
          <FilterSelect
            label="Access"
            value={filters.access}
            onChange={(v) => set({ access: v as UserFilters['access'] })}
            options={[
              { value: 'all', label: 'Any' },
              { value: 'allow', label: 'Allowed', count: allowed },
              { value: 'deny', label: 'Denied', count: denied.length },
            ]}
          />
          <FilterSelect
            label="Certificate"
            value={filters.cert}
            onChange={(v) => set({ cert: v as UserFilters['cert'] })}
            options={[
              { value: 'all', label: 'Any' },
              { value: 'active', label: 'Active', count: count((r) => r.cert.status === 'active') },
              { value: 'expiring', label: 'Expiring soon', count: count((r) => r.cert.status === 'expiring') },
              { value: 'expired', label: 'Expired', count: count((r) => r.cert.status === 'expired') },
              { value: 'revoked', label: 'Revoked', count: count((r) => r.cert.status === 'revoked') },
              { value: 'none', label: 'No certificate', count: withoutCert },
            ]}
          />
          <FilterSelect
            label="Group"
            value={filters.group}
            onChange={(v) => set({ group: v })}
            options={[{ value: 'all', label: 'All groups' }, ...d.groups.map((g) => ({ value: g.id, label: g.name, count: g.memberCount }))]}
          />
          {anyFilter ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setFilters(DEFAULT_FILTERS)
                table.setQuery('')
              }}
            >
              Clear filters
            </Button>
          ) : null}
        </div>
        <p className="c-results" aria-live="polite">
          {anyFilter ? `Showing ${table.rows.length} of ${plural(rows.length, 'person', 'people')}` : `Showing all ${plural(rows.length, 'person', 'people')}`}
        </p>
        <DataTable
          caption="Users and their Wi-Fi access"
          columns={columnsDef}
          rows={table.rows}
          rowKey={(r) => r.key}
          sort={table}
          onRowClick={(r) => go('user', { entityId: r.identity.id })}
          empty={
            <Empty
              icon={SearchX}
              title="No one matches these filters"
              action={
                <Button
                  size="sm"
                  onClick={() => {
                    setFilters(DEFAULT_FILTERS)
                    table.setQuery('')
                  }}
                >
                  Clear filters
                </Button>
              }
            >
              Try a shorter search, or widen the access, certificate or group filter.
            </Empty>
          }
        />
      </section>
    </>
  )
}
