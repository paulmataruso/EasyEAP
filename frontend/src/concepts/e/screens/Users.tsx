import { useMemo, useState } from 'react'
import { Building, ShieldCheck, UserRound, Users as UsersIcon, X } from 'lucide-react'
import { useTenantData, useTenants, now } from '@/prototype/store'
import { evaluatePolicy } from '@/domain/policy'
import type { CertStatus, Identity } from '@/domain/types'
import { certStatusLabels } from '@/domain/explain'
import { useTable, type Column } from '@/ui/useTable'
import { DataTable } from '../DataTable'
import { AccessMark, CertStatusMark, certSummary, decisionReason, userKey } from '../bits'
import { ago } from '../theme'
import { Button, Callout, CountChip, EmptyState, PageHeader, Panel, SearchInput, Segmented, Select, VlanRef, useE, useIntent } from '../ui'

type CertFilter = 'any' | CertStatus | 'none'

export function Users() {
  const d = useTenantData()
  const { current } = useTenants()
  // Evaluated per identity object (not by id), so two directory users sharing a username keep their own decisions.
  const decisions = useMemo(() => {
    const m = new Map<Identity, ReturnType<typeof evaluatePolicy>>()
    for (const i of d.identities) m.set(i, evaluatePolicy(i, d.rules, d.defaults, d.vlans, { now: now() }))
    return { get: (i: Identity) => m.get(i) }
  }, [d.identities, d.rules, d.defaults, d.vlans])
  const { go } = useE()
  const [source, setSource] = useState<'all' | 'ad' | 'local'>('all')
  const [access, setAccess] = useState<'any' | 'allow' | 'deny'>('any')
  const [cert, setCert] = useState<CertFilter>('any')
  const [group, setGroup] = useState<string>('all')
  const [issuing, setIssuing] = useState(false)

  useIntent('users.filter', (i) => { setSource(i.source ?? 'all'); setAccess(i.access ?? 'any'); setCert('any'); setGroup('all') })
  useIntent('issue', () => setIssuing(true))

  const certsBy = useMemo(() => {
    const m = new Map<string, typeof d.certificates>()
    for (const c of d.certificates) if (c.identityId) m.set(c.identityId, [...(m.get(c.identityId) ?? []), c])
    return m
  }, [d])
  const vlanOf = (i: Identity) => d.vlans.find((v) => v.id === decisions.get(i)?.vlanId)

  const columns = useMemo<Column<Identity>[]>(() => [
    { key: 'name', value: (i) => i.displayName },
    { key: 'upn', value: (i) => i.upn ?? i.username },
    { key: 'source', value: (i) => i.source, searchable: false },
    { key: 'dept', value: (i) => i.department ?? '' },
    { key: 'access', value: (i) => decisions.get(i)?.outcome ?? '', searchable: false },
    { key: 'vlan', value: (i) => d.vlans.find((v) => v.id === decisions.get(i)?.vlanId)?.vlanId ?? null, searchable: false },
    { key: 'cert', value: (i) => certSummary(certsBy.get(i.id) ?? []).rank, searchable: false },
    { key: 'last', value: (i) => (i.lastAuthAt ? new Date(i.lastAuthAt).getTime() : null), searchable: false },
  ], [decisions, d.vlans, certsBy])

  const filter = useMemo(() => (i: Identity) => {
    if (source !== 'all' && i.source !== source) return false
    if (access !== 'any' && decisions.get(i)?.outcome !== access) return false
    if (group !== 'all' && !i.groupIds.includes(group)) return false
    if (cert !== 'any') {
      const cs = certsBy.get(i.id) ?? []
      if (cert === 'none') return cs.length === 0
      if (!cs.some((c) => c.status === cert)) return false
    }
    return true
  }, [source, access, group, cert, decisions, certsBy])

  const t = useTable(d.identities, columns, { initialSort: { key: 'name', dir: 'asc' }, filter })
  const adCount = d.identities.filter((i) => i.source === 'ad').length
  const localCount = d.identities.length - adCount
  const filtered = source !== 'all' || access !== 'any' || cert !== 'any' || group !== 'all' || t.query
  const clear = () => { setSource('all'); setAccess('any'); setCert('any'); setGroup('all'); t.setQuery('') }

  return (
    <>
      <PageHeader
        title="Users"
        meta={<>
          <span className="num">{d.identities.length} identities</span>
          <span aria-hidden className="t3">·</span>
          <span>{adCount} from Active Directory ({current.domain})</span>
          <span aria-hidden className="t3">·</span>
          <span>{localCount} local</span>
          <span aria-hidden className="t3">·</span>
          <span>Directory synced {ago(current.health.lastDirectorySync)}</span>
        </>}
      />
      {issuing && (
        <Callout className="mb-4" icon={<ShieldCheck aria-hidden />}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p><strong>Choose a user to issue a Wi-Fi certificate.</strong> <span className="t2">Issue Wi-Fi certificate is the main action on every user’s page.</span></p>
            <Button size="sm" variant="ghost" onClick={() => setIssuing(false)}><X />Dismiss</Button>
          </div>
        </Callout>
      )}

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--e-hair)] p-3">
          <SearchInput className="w-full sm:w-[280px]" value={t.query} onChange={t.setQuery} placeholder="Search name, UPN, department" label="Search users" />
          <Segmented
            label="Identity source"
            value={source}
            onValueChange={setSource}
            options={[
              { value: 'all', label: <>All<CountChip n={d.identities.length} /></> },
              { value: 'ad', label: <><Building aria-hidden />Directory<CountChip n={adCount} /></>, ariaLabel: `Active Directory, ${adCount}` },
              { value: 'local', label: <><UserRound aria-hidden />Local<CountChip n={localCount} /></>, ariaLabel: `Local accounts, ${localCount}` },
            ]}
          />
          <Select label="Access" value={access} onValueChange={setAccess} options={[{ value: 'any', label: 'Any access' }, { value: 'allow', label: 'Allowed' }, { value: 'deny', label: 'Denied' }]} />
          <Select<CertFilter> label="Certificate status" value={cert} onValueChange={setCert} options={[{ value: 'any', label: 'Any certificate' }, ...(['active', 'expiring', 'expired', 'revoked'] as CertStatus[]).map((s) => ({ value: s, label: certStatusLabels[s] })), { value: 'none', label: 'No certificate' }]} />
          <Select label="Group" value={group} onValueChange={setGroup} options={[{ value: 'all', label: 'All groups' }, ...d.groups.map((g) => ({ value: g.id, label: `${g.name} (${g.memberCount})` }))]} />
          {filtered && <Button size="sm" variant="ghost" onClick={clear}><X />Clear filters</Button>}
          <span className="t2 ml-auto text-[12.5px] num" aria-live="polite">Showing {t.rows.length} of {d.identities.length}</span>
        </div>
        <DataTable
          caption="Users"
          rows={t.rows}
          rowKey={(i) => userKey(i, d.identities)}
          onActivate={(i) => go('user', { entityId: userKey(i, d.identities) })}
          sort={t.sort}
          onSort={t.toggleSort}
          ariaSort={t.ariaSort}
          empty={filtered
            ? <EmptyState icon={<UsersIcon />} title="No users match these filters" body="Clear a filter or search by another name or UPN." action={<Button size="sm" onClick={clear}>Clear filters</Button>} />
            : <EmptyState icon={<UsersIcon />} title="No users yet" body="Connect Active Directory to sync users, or create a local account." />}
          columns={[
            { key: 'name', header: 'User', sortable: true, cell: (i) => (
              <div className="min-w-0 py-1.5">
                <button type="button" data-row-primary className="e-rowlink block max-w-full truncate" onClick={() => go('user', { entityId: userKey(i, d.identities) })}>{i.displayName}</button>
                <span className="mono t2 block truncate text-[12px]">{i.upn ?? i.username}</span>
              </div>
            ) },
            { key: 'source', header: 'Source', sortable: true, hideBelow: 'md', cell: (i) => i.source === 'ad' ? <span className="e-tag"><Building aria-hidden />Directory</span> : <span className="e-tag"><UserRound aria-hidden />Local</span> },
            { key: 'dept', header: 'Department', sortable: true, hideBelow: 'xl', cell: (i) => <span className="t2">{i.department ?? '—'}</span> },
            { key: 'access', header: 'Access', sortable: true, cell: (i) => {
              const dec = decisions.get(i)
              return (
                <div className="py-1.5">
                  <AccessMark decision={dec} />
                  {dec?.outcome === 'deny' && <span className="t2 block max-w-[220px] truncate text-[12px]">{decisionReason(dec, d.rules)}</span>}
                </div>
              )
            } },
            { key: 'vlan', header: 'Assigned VLAN', sortable: true, cell: (i) => <VlanRef vlan={vlanOf(i)} /> },
            { key: 'cert', header: 'Certificates', sortable: true, hideBelow: 'md', cell: (i) => {
              const cs = certsBy.get(i.id) ?? []
              if (!cs.length) return <span className="t3">No certificate</span>
              const s = certSummary(cs)
              return (
                <div className="py-1.5">
                  {s.worst && <CertStatusMark cert={s.worst} />}
                  <span className="t2 block text-[12px] num">{cs.length} {cs.length === 1 ? 'device' : 'devices'} · {s.live.length} usable</span>
                </div>
              )
            } },
            { key: 'last', header: 'Last authentication', sortable: true, hideBelow: 'lg', cell: (i) => <span className="t2">{ago(i.lastAuthAt)}</span> },
          ]}
        />
      </Panel>
    </>
  )
}
