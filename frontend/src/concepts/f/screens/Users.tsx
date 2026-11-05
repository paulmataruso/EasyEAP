import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
import { ArrowLeft, Ban, Check, ChevronDown, FilePlus, FlaskConical, Hourglass, Search, Users as UsersIcon, X } from 'lucide-react'
import { cn, formatDate, formatDateTime } from '@/ui/lib'
import { now, useDecision, useTenantData, useTenants } from '@/prototype/store'
import { evaluatePolicy } from '@/domain/policy'
import { failureExplanations, platformLabels, revocationReasonLabels } from '@/domain/explain'
import type { Certificate, CertStatus, Decision, Identity, Vlan } from '@/domain/types'
import { useTable, type Column } from '@/ui/useTable'
import { Lifeline, Remaining, useIdentityMrz, MrzZone } from '../credential'
import { Guilloche } from '../guilloche'
import { DecisionLedger, DecisionSnippet } from '../ledger'
import { ago, certLabel, pushRecent, summarizeCerts, usePending, type CertSummary } from '../lib'
import { RevokeDialog } from '../dialogs'
import type { Navigate } from '../shell'
import { AccessChip, Btn, CertChip, Chip, CopyButton, Dl, Empty, FSelect, PageHeader, Panel, PlatformIcon, Seg, SectionHeader, SourceTag, SortTh, VlanTag } from '../ui'

interface Row { identity: Identity; decision: Decision; vlan: Vlan | undefined; certs: Certificate[]; summary: CertSummary }

function useRows(): Row[] {
  const d = useTenantData()
  // Evaluated per identity object rather than via useDecisions(): the synthetic data has a few
  // duplicate identity ids, and an id-keyed map would give two people the same decision.
  return useMemo(
    () =>
      d.identities.map((identity) => {
        const decision = evaluatePolicy(identity, d.rules, d.defaults, d.vlans, { now: now() })
        const certs = d.certificates.filter((c) => c.identityId === identity.id)
        return { identity, decision, vlan: d.vlans.find((v) => v.id === decision.vlanId), certs, summary: summarizeCerts(certs) }
      }),
    [d],
  )
}

const statusRank: Record<CertStatus, number> = { expired: 0, revoked: 1, expiring: 2, pending: 3, active: 4 }

const COLUMNS: Column<Row>[] = [
  { key: 'name', value: (r) => r.identity.displayName },
  { key: 'upn', value: (r) => r.identity.upn ?? r.identity.username },
  { key: 'dept', value: (r) => r.identity.department },
  { key: 'source', value: (r) => r.identity.source, searchable: false },
  { key: 'access', value: (r) => r.decision.outcome, searchable: false },
  { key: 'vlan', value: (r) => r.vlan?.vlanId ?? null, searchable: false },
  { key: 'cert', value: (r) => (r.summary.lead ? statusRank[r.summary.lead] : null), searchable: false },
  { key: 'last', value: (r) => r.identity.lastAuthAt, searchable: false },
  { key: 'remaining', value: (r) => (r.summary.soonest ? new Date(r.summary.soonest.notAfter).getTime() : null), searchable: false },
]

type CertFilter = 'any' | CertStatus | 'none'

export function UsersScreen({ navigate, onIssue }: { navigate: Navigate; onIssue: (identityId?: string) => void }) {
  const { current } = useTenants()
  const d = useTenantData()
  const rows = useRows()
  const [source, setSource] = useState<'all' | 'ad' | 'local'>('all')
  const [access, setAccess] = useState<'all' | 'allow' | 'deny'>('all')
  const [cert, setCert] = useState<CertFilter>('any')
  const [group, setGroup] = useState('any')
  const filter = useMemo(
    () => (r: Row) =>
      (source === 'all' || r.identity.source === source) &&
      (access === 'all' || r.decision.outcome === access) &&
      (cert === 'any' || (cert === 'none' ? r.certs.length === 0 : r.certs.some((c) => c.status === cert))) &&
      (group === 'any' || r.identity.groupIds.includes(group)),
    [source, access, cert, group],
  )
  const table = useTable(rows, COLUMNS, { initialSort: { key: 'name', dir: 'asc' }, filter })
  const filtered = source !== 'all' || access !== 'all' || cert !== 'any' || group !== 'any' || table.query
  const clear = () => { setSource('all'); setAccess('all'); setCert('any'); setGroup('any'); table.setQuery('') }
  const count = (pred: (r: Row) => boolean) => rows.filter(pred).length

  return (
    <div>
      <PageHeader
        title="Users"
        lede={<>{rows.length} identities in {current.name} · {count((r) => r.identity.source === 'ad')} from Active Directory, {count((r) => r.identity.source === 'local')} local</>}
        actions={<Btn variant="primary" onClick={() => onIssue()}><FilePlus aria-hidden />Issue certificate</Btn>}
      />
      {current.health.directory === 'unconfigured' && (
        <p className="f-small mb-5 max-w-[75ch] rounded-[8px] border border-[var(--f-line-2)] px-4 py-3 f-ink-2">
          <span className="font-semibold text-[var(--f-ink)]">Active Directory isn’t connected.</span> These accounts were added during setup and won’t follow AD changes until you connect the directory.
        </p>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter users">
        <div className="relative w-full sm:w-[240px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 f-ink-3" aria-hidden />
          <input className="f-input pl-9" placeholder="Name, UPN or department" value={table.query} onChange={(e) => table.setQuery(e.target.value)} aria-label="Search users" />
        </div>
        <Seg label="Source" value={source} onChange={setSource} options={[{ value: 'all', label: 'All sources' }, { value: 'ad', label: 'AD', count: count((r) => r.identity.source === 'ad') }, { value: 'local', label: 'Local', count: count((r) => r.identity.source === 'local') }]} />
        <Seg label="Access" value={access} onChange={setAccess} options={[{ value: 'all', label: 'Any access' }, { value: 'allow', label: 'Allowed', count: count((r) => r.decision.outcome === 'allow') }, { value: 'deny', label: 'Denied', count: count((r) => r.decision.outcome === 'deny') }]} />
        <FSelect label="Certificate status" value={cert} onChange={(v) => setCert(v as CertFilter)} options={[{ value: 'any', label: 'Any certificate' }, ...(['active', 'expiring', 'expired', 'revoked'] as CertStatus[]).map((s) => ({ value: s, label: `Has ${certLabel[s].toLowerCase()}` })), { value: 'none', label: 'No certificate' }]} />
        <FSelect label="Group" value={group} onChange={setGroup} options={[{ value: 'any', label: 'Any group' }, ...d.groups.map((g) => ({ value: g.id, label: `${g.name} (${g.memberCount})` }))]} />
        <span className="f-small f-ink-3 ml-auto" aria-live="polite">{table.rows.length} of {rows.length}</span>
        {filtered && <Btn size="sm" variant="ghost" onClick={clear}><X aria-hidden />Clear</Btn>}
      </div>

      {table.rows.length === 0 ? (
        <Empty icon={<UsersIcon />} title="No users match these filters" action={<Btn onClick={clear}>Clear filters</Btn>}>Try another group or certificate status, or search by UPN.</Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="f-table">
            <caption className="sr-only">Users, sortable</caption>
            <thead>
              <tr>
                <SortTh label="User" sortKey="name" table={table} />
                <SortTh label="Access decision" sortKey="access" table={table} />
                <SortTh label="VLAN" sortKey="vlan" table={table} />
                <SortTh label="Certificates" sortKey="cert" table={table} />
                <SortTh label="Last auth" sortKey="last" table={table} />
                <SortTh label="Validity left" sortKey="remaining" table={table} right />
              </tr>
            </thead>
            <tbody>
              {table.rows.map((r, idx) => (
                <tr key={`${r.identity.id}#${idx}`} data-clickable="true" onClick={() => navigate('user', r.identity.id)}>
                  <td className="min-w-[240px]">
                    <span className="flex items-center gap-2">
                      <button type="button" className="f-rowlink text-[13.5px] font-semibold hover:underline" onClick={(e) => { e.stopPropagation(); navigate('user', r.identity.id) }}>{r.identity.displayName}</button>
                      <SourceTag source={r.identity.source} />
                    </span>
                    <span className="f-small f-ink-3 block truncate">{r.identity.upn ?? r.identity.username} · {r.identity.department}</span>
                  </td>
                  <td className="max-w-[300px]"><DecisionSnippet decision={r.decision} rules={d.rules} /></td>
                  <td><VlanTag vlan={r.vlan} withName={false} /></td>
                  <td className="whitespace-nowrap">
                    {r.summary.lead ? (
                      <span className="inline-flex items-center gap-2"><CertChip status={r.summary.lead} /><span className="f-small f-ink-3">{r.certs.length > 1 ? `of ${r.certs.length}` : ''}</span></span>
                    ) : (
                      <span className="f-small f-ink-3">None</span>
                    )}
                  </td>
                  <td className="f-ink-2 whitespace-nowrap">{ago(r.identity.lastAuthAt)}</td>
                  <td className="f-right">{r.summary.soonest ? <Remaining cert={r.summary.soonest} /> : <span className="f-ink-3">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Split view: compact list + record ───────────────────────────────────
function UserList({ rows, selectedId, navigate }: { rows: Row[]; selectedId: string; navigate: Navigate }) {
  const [q, setQ] = useState('')
  const list = useMemo(() => {
    const s = q.trim().toLowerCase()
    return [...rows].sort((a, b) => a.identity.displayName.localeCompare(b.identity.displayName)).filter((r) => !s || r.identity.displayName.toLowerCase().includes(s) || (r.identity.upn ?? '').toLowerCase().includes(s))
  }, [rows, q])
  const onKey = (e: KeyboardEvent<HTMLUListElement>) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    e.preventDefault()
    const idx = list.findIndex((r) => r.identity.id === selectedId)
    const next = list[Math.max(0, Math.min(list.length - 1, idx + (e.key === 'ArrowDown' ? 1 : -1)))]
    if (next) {
      navigate('user', next.identity.id)
      requestAnimationFrame(() => document.getElementById(`f-ul-${next.identity.id}`)?.focus())
    }
  }
  return (
    <div className="flex h-full flex-col">
      <div className="relative mb-2">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 f-ink-3" aria-hidden />
        <input className="f-input pl-9" placeholder="Filter users" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter users" />
      </div>
      <p className="f-small f-ink-3 mb-1.5 px-1">{list.length} users · arrow keys move</p>
      <ul className="-mx-1 min-h-0 flex-1 overflow-y-auto px-1" onKeyDown={onKey} aria-label="Users">
        {list.map((r, idx) => {
          const sel = r.identity.id === selectedId
          return (
            <li key={`${r.identity.id}#${idx}`}>
              <button
                id={`f-ul-${r.identity.id}`}
                type="button"
                aria-current={sel ? 'true' : undefined}
                onClick={() => navigate('user', r.identity.id)}
                className={cn('grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 rounded-[7px] px-2.5 py-2 text-left hover:bg-[var(--f-hover)]', sel && 'bg-[var(--f-select)] hover:bg-[var(--f-select)]')}
              >
                <span className="min-w-0">
                  <span className={cn('block truncate text-[13.5px] font-medium', sel && 'text-[var(--f-gold)]')}>{r.identity.displayName}</span>
                  <span className="flex items-center gap-1.5 text-[12px] f-ink-3">
                    {r.decision.outcome === 'allow' ? <Check className="size-3 text-[var(--f-valid)]" aria-label="Allowed" /> : <Ban className="size-3 text-[var(--f-crit-ink)]" aria-label="Denied" />}
                    <span className="truncate">{r.vlan ? `VLAN ${r.vlan.vlanId}` : 'No VLAN'} · {r.identity.source === 'ad' ? 'AD' : 'Local'}</span>
                  </span>
                </span>
                {r.summary.soonest ? <Remaining cert={r.summary.soonest} className="text-[12.5px]" /> : <span className="text-[12.5px] f-ink-3">—</span>}
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function levenshtein(a: string, b: string) {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0]
    row[0] = i
    for (let j = 1; j <= b.length; j++) {
      const tmp = row[j]
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1))
      prev = tmp
    }
  }
  return row[b.length]
}

/** Closest username in this tenant to a record id that no longer resolves ("Did you mean"). */
function closestMatch(rows: Row[], entityId: string): Row | undefined {
  const wanted = entityId.split(':u-').pop() ?? ''
  if (!wanted) return undefined
  return [...rows].sort((a, b) => {
    const da = levenshtein(wanted, a.identity.username) - (a.identity.username[0] === wanted[0] ? 2 : 0)
    const db = levenshtein(wanted, b.identity.username) - (b.identity.username[0] === wanted[0] ? 2 : 0)
    return da - db
  })[0]
}

export function UserScreen({ entityId, navigate, onIssue }: { entityId?: string; navigate: Navigate; onIssue: (identityId?: string) => void }) {
  const rows = useRows()
  const { tenants, current, switchTenant } = useTenants()
  const exact = rows.find((r) => r.identity.id === entityId)
  const owner = tenants.find((t) => entityId?.startsWith(`${t.id}:`))
  const elsewhere = !exact && owner && owner.id !== current.id
  const fallback = !exact && !elsewhere && entityId ? closestMatch(rows, entityId) : undefined
  const row = exact ?? fallback
  if (!row) {
    return (
      <div className="max-w-xl">
        <PageHeader title={elsewhere ? `This user belongs to ${owner!.name}` : 'User not found'} lede={elsewhere ? `You are working in ${current.name}. Switch tenant to open the record.` : `No user in ${current.name} matches this link.`} />
        <div className="flex flex-wrap gap-2">
          {elsewhere && <Btn variant="primary" onClick={() => { switchTenant(owner!.id); navigate('user', entityId) }}>Switch to {owner!.name}</Btn>}
          <Btn onClick={() => navigate('users')}>Back to users</Btn>
        </div>
      </div>
    )
  }
  return (
    <div className="grid gap-8 xl:grid-cols-[300px_minmax(0,1fr)]">
      <aside className="hidden xl:block" aria-label="User list">
        <div className="sticky top-8 h-[calc(100vh-64px)]">
          <UserList rows={rows} selectedId={row.identity.id} navigate={navigate} />
        </div>
      </aside>
      <div className="min-w-0">
        {fallback && (
          <p role="status" className="f-small mb-4 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-[8px] border border-[var(--f-line-2)] px-4 py-2.5 f-ink-2">
            <span>No user “{entityId?.split(':u-').pop()}” in {current.name}; it may have been removed by a directory sync.</span>
            <span className="text-[var(--f-ink)]">Showing the closest match, {fallback.identity.displayName}.</span>
          </p>
        )}
        <UserDetail key={row.identity.id} row={row} navigate={navigate} onIssue={onIssue} />
      </div>
    </div>
  )
}

function UserDetail({ row, navigate, onIssue }: { row: Row; navigate: Navigate; onIssue: (identityId?: string) => void }) {
  const { current } = useTenants()
  const d = useTenantData()
  const { identity, decision, vlan } = row
  const pending = usePending(identity.id)
  const [revoking, setRevoking] = useState<Certificate | null>(null)
  const [openEvent, setOpenEvent] = useState<string | null>(null)
  const decidingRule = d.rules.find((r) => r.id === decision.decidingRuleId)
  const mrz = useIdentityMrz(identity, current, decision, vlan, decidingRule?.priority ?? null)
  const devices = d.devices.filter((x) => x.identityId === identity.id)
  const events = d.authEvents.filter((e) => e.identityId === identity.id).slice(0, 8)
  const groups = identity.groupIds.map((g) => d.groups.find((x) => x.id === g)).filter(Boolean)
  const tone = decision.outcome === 'allow' ? 'valid' : 'crit'
  // Trace with the soonest-expiring live certificate, so the certificate gate shows too
  const traceCert = row.summary.soonest ?? undefined
  const certDecision = useDecision(identity, traceCert) ?? decision

  useEffect(() => {
    pushRecent(current.id, { kind: 'identity', id: identity.id, label: identity.displayName, sub: identity.upn ?? identity.username })
  }, [current.id, identity.id, identity.displayName, identity.upn, identity.username])

  return (
    <div className="min-w-0 @container">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <Btn variant="ghost" size="sm" onClick={() => navigate('users')}><ArrowLeft aria-hidden />All users</Btn>
        <div className="flex flex-wrap gap-2">
          <Btn onClick={() => navigate('policies', identity.id)}><FlaskConical aria-hidden />Test access</Btn>
          <Btn variant="primary" onClick={() => onIssue(identity.id)}><FilePlus aria-hidden />Issue Wi-Fi certificate</Btn>
        </div>
      </div>

      {/* Identity data page */}
      <Panel risk={tone} className="f-credential" as="article" aria-labelledby="f-identity-h">
        <Guilloche seed={identity.objectGuid ?? identity.id} />
        <div className="grid gap-6 px-6 pb-5 pt-6 @5xl:grid-cols-[minmax(0,1fr)_260px]">
          <div className="min-w-0">
            <h1 id="f-identity-h" className="f-h1">{identity.displayName}</h1>
            <p className="f-lede mt-1">{identity.title} · {identity.department}</p>
            <div className="mt-5">
              <Dl
                cols={1}
                className="@lg:grid-cols-2 @5xl:grid-cols-3"
                items={[
                  ['User principal name', <span className="break-all">{identity.upn ?? '—'}</span>],
                  ['Username', <span className="f-mono text-[13px]">{identity.username}</span>],
                  ['Email', <span className="break-all">{identity.email ?? '—'}</span>],
                  ['Source', <span className="inline-flex items-center gap-2"><SourceTag source={identity.source} />{identity.source === 'ad' ? current.domain : 'EasyEAP'}</span>],
                  ['Account', identity.accountState === 'enabled' ? <Chip tone="valid" icon={<Check aria-hidden />}>Enabled</Chip> : <Chip tone="crit" icon={<Ban aria-hidden />}>{identity.accountState[0].toUpperCase() + identity.accountState.slice(1)}</Chip>],
                  ['Last directory sync', ago(identity.lastSyncedAt)],
                ]}
              />
            </div>
            <div className="mt-4">
              <p className="f-label mb-1.5">Directory groups</p>
              <ul className="flex flex-wrap gap-1.5">
                {groups.map((g) => <li key={g!.id} className="f-tag" title={g!.dn}>{g!.name}</li>)}
              </ul>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-[var(--f-line)] pt-5 @5xl:flex-col @5xl:flex-nowrap @5xl:items-stretch @5xl:border-l @5xl:border-t-0 @5xl:pl-6 @5xl:pt-0">
            <p className="f-label w-full @5xl:w-auto">Wi-Fi access</p>
            <div><AccessChip outcome={decision.outcome} /></div>
            {decision.outcome === 'allow' && vlan ? (
              <p className="text-[22px] font-semibold leading-tight tracking-tight">VLAN <VlanTag vlan={vlan} withName={false} className="text-[22px]" /><span className="f-ink-2 mt-0.5 block text-[14px] font-normal">{vlan.name}</span></p>
            ) : (
              <p className="text-[15px] font-semibold">Access-Reject</p>
            )}
            <p className="f-small f-ink-2">{decidingRule ? <>Decided by “{decidingRule.name}”</> : decision.outcome === 'deny' ? (identity.accountState !== 'enabled' ? 'Account gate: not overridable' : 'Tenant default: deny') : 'Tenant default'}</p>
            <p className="f-small f-ink-3 @5xl:mt-auto">Last authentication {ago(identity.lastAuthAt)}</p>
          </div>
        </div>
        <MrzZone mrz={mrz} subject={identity.displayName} />
      </Panel>

      <div className="mt-10 grid gap-x-10 gap-y-10 @4xl:grid-cols-2">
        <section aria-labelledby="f-trace-h" className="min-w-0">
          <SectionHeader id="f-trace-h" title="Why this decision" meta={traceCert ? `traced with ${d.devices.find((x) => x.id === traceCert.deviceId)?.name ?? 'certificate'}` : 'no live certificate'} />
          <DecisionLedger decision={certDecision} identity={identity} rules={d.rules} groups={d.groups} vlans={d.vlans} certificate={traceCert} />
        </section>

        <section aria-labelledby="f-dev-h" className="min-w-0">
          <SectionHeader id="f-dev-h" title="Devices and certificates" meta={`${devices.length} ${devices.length === 1 ? 'device' : 'devices'}`} />
          {devices.length === 0 && pending.length === 0 ? (
            <Empty icon={<FilePlus />} title="No enrolled devices" action={<Btn variant="primary" onClick={() => onIssue(identity.id)}>Issue Wi-Fi certificate</Btn>}>
              {identity.displayName.split(' ')[0]} has no Wi-Fi certificate yet. Each device gets its own.
            </Empty>
          ) : (
            <ul className="f-divide border-y border-[var(--f-line)]">
              {pending.map((p) => (
                <li key={p.id} className="py-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <PlatformIcon platform={p.platform} />
                    <span className="min-w-0 flex-1">
                      <span className="block text-[13.5px] font-semibold">{p.deviceName}</span>
                      <span className="block text-[12px] f-ink-3">{platformLabels[p.platform]} · {p.keyMode === 'device' ? 'key on device' : 'server-generated key'}</span>
                    </span>
                    <Chip tone="neutral" icon={<Hourglass aria-hidden />}>Waiting for device</Chip>
                    <CopyButton text={p.link} what={`enrollment link for ${p.deviceName}`} label="Copy link" />
                  </div>
                </li>
              ))}
              {devices.map((dev, idx) => {
                const certs = d.certificates.filter((c) => c.deviceId === dev.id)
                return (
                  <li key={`${dev.id}#${idx}`} className="py-3">
                    <div className="flex items-center gap-3">
                      <PlatformIcon platform={dev.platform} />
                      <span className="min-w-0 flex-1">
                        <span className="block text-[13.5px] font-semibold">{dev.name}</span>
                        <span className="block text-[12px] f-ink-3">{platformLabels[dev.platform]}{dev.lastSeenMac && <> · <span className="f-mono">{dev.lastSeenMac}</span></>}</span>
                      </span>
                    </div>
                    {certs.map((c) => (
                      <div key={c.id} className="mt-2.5 grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 pl-7 sm:grid-cols-[auto_minmax(60px,1fr)_4.5rem_auto]">
                        <span className="flex min-w-0 items-center gap-2">
                          <CertChip status={c.status} />
                          <button type="button" className="f-mono f-rowlink truncate text-[12px] f-ink-2 hover:underline" onClick={() => navigate('certificates', c.id)} aria-label={`Open certificate ${c.serial}`}>{c.serial.slice(0, 12)}…</button>
                        </span>
                        <Lifeline cert={c} className="hidden sm:block" />
                        <Remaining cert={c} />
                        {c.status === 'revoked' ? (
                          <span className="f-small f-ink-3 col-span-2 sm:col-span-1">{formatDate(c.revokedAt)} · {c.revocationReason ? revocationReasonLabels[c.revocationReason] : ''}</span>
                        ) : (
                          <Btn size="sm" variant="danger" onClick={() => setRevoking(c)}>Revoke</Btn>
                        )}
                      </div>
                    ))}
                  </li>
                )
              })}
            </ul>
          )}
        </section>
      </div>

      <section aria-labelledby="f-ev-h" className="mt-10">
        <SectionHeader id="f-ev-h" title="Recent authentications" meta={events.length ? `last ${events.length}` : undefined} />
        {events.length === 0 ? (
          <Empty title="No authentication attempts in the last 24 hours">{identity.displayName.split(' ')[0]} hasn’t tried to join Wi-Fi recently.</Empty>
        ) : (
          <ol className="f-divide border-y border-[var(--f-line)]">
            {events.map((e) => {
              const f = e.failureCode ? failureExplanations[e.failureCode] : null
              const dev = d.devices.find((x) => x.id === e.deviceId)
              const nas = d.radiusClients.find((n) => n.id === e.nasClientId)
              const open = openEvent === e.id
              return (
                <li key={e.id} className="grid gap-x-4 gap-y-1 py-3 sm:grid-cols-[110px_minmax(0,1fr)]">
                  <span className="f-num f-small f-ink-3">{formatDateTime(e.at).replace(' UTC', '')}<span className="block">{ago(e.at)}</span></span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      {e.result === 'accept' ? <Chip tone="valid" icon={<Check aria-hidden />}>Accepted</Chip> : <Chip tone="crit" icon={<X aria-hidden />}>Rejected</Chip>}
                      <span className="text-[13.5px] font-medium">{f ? f.title : <>Placed on VLAN <VlanTag vlan={d.vlans.find((v) => v.id === e.vlanId)} /></>}</span>
                    </div>
                    <p className="f-small f-ink-3 mt-1">{dev?.name ?? 'Unenrolled device'} · {e.ssid} · {nas?.name ?? 'unknown controller'}</p>
                    {f && (
                      <p className="f-small mt-1.5 max-w-[75ch] f-ink-2">{f.explanation} <span className="text-[var(--f-ink)]">Fix: {f.fix}</span></p>
                    )}
                    <button type="button" className="f-small f-ink-3 mt-1.5 inline-flex items-center gap-1 rounded hover:text-[var(--f-ink)]" aria-expanded={open} onClick={() => setOpenEvent(open ? null : e.id)}>
                      <ChevronDown className={cn('size-3.5 transition-transform', open && 'rotate-180')} aria-hidden />Technical details
                    </button>
                    {open && (
                      <dl className="f-mono mt-2 grid gap-x-4 gap-y-1 rounded-[7px] bg-[rgba(6,9,17,0.5)] px-3 py-2 text-[12px] sm:grid-cols-[150px_1fr]">
                        <dt className="f-ink-3">Module message</dt><dd className="break-words">{e.rawMessage ?? 'Access-Accept'}</dd>
                        <dt className="f-ink-3">Calling-Station-Id</dt><dd>{e.callingStationId}</dd>
                        <dt className="f-ink-3">Called-Station-Id</dt><dd className="break-all">{e.calledStationId}</dd>
                        <dt className="f-ink-3">Certificate serial</dt><dd className="break-all">{e.certSerial ?? 'none presented'}</dd>
                      </dl>
                    )}
                  </div>
                </li>
              )
            })}
          </ol>
        )}
      </section>

      {revoking && <RevokeDialog cert={revoking} subject={d.devices.find((x) => x.id === revoking.deviceId)?.name ?? identity.displayName} open={!!revoking} onOpenChange={(o) => !o && setRevoking(null)} />}
    </div>
  )
}
