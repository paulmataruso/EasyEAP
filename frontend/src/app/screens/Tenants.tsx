// MSP overview: every customer tenant, ranked by its most urgent needs-action item, with whether RADIUS can enforce
// it, the top issue and its one action, 24-hour success and certificate counts. Each row opens that tenant.
import { useMemo, type MouseEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { Building, Plus } from 'lucide-react'
import { cn } from '@/ui/lib'
import { compareRank, queueRank, useOverview, type OverviewTenant } from '../api/dashboard'
import { radiusSummary, type QueueItem } from '../api/types'
import { useSession } from '../api/session'
import { ago, fmtDateTime, fmtPercent, plural, relative } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths, targetPath } from '../routes'
import { monogram } from '../shell/Shell'
import { Empty, ErrorState, HealthDot, LoadingBlock, PageHeader, Panel, SectionHeader, SeverityChip } from '../ui'
import { EnforcementChip } from './dashboard/Enforcement'
import { ActionLink } from './dashboard/Queue'

function enforcementNote(t: OverviewTenant, now: Date): string {
  const e = t.enforcement
  if (e.status.state === 'suspended') return 'Nobody can connect'
  if (!e.enforceable) return plural(e.missing.length, 'setup step') + ' left'
  if (e.snapshot_expired && e.deadline_at) return `Failed closed ${relative(e.deadline_at, now)}`
  if (!e.auto_refresh && e.deadline_at) return `Fails closed ${relative(e.deadline_at, now)}`
  return e.snapshot_built_at ? `Snapshot built ${ago(e.snapshot_built_at, now)}` : 'No snapshot yet'
}

function TopIssue({ t, compact }: { t: OverviewTenant; compact?: boolean }) {
  const top = t.queue_top[0]
  if (!top) return <HealthDot tone="valid" label="Nothing needs action" />
  const more = t.queue_count - 1
  // A tenant in setup already says "Not enforceable yet" in its enforcement column; name the next step instead.
  const setup = top.code === 'not_enforceable' && t.enforcement.missing.length > 0
  const title = setup ? `Next setup step: ${t.enforcement.missing[0].message}` : top.title
  return (
    <div className={cn('flex min-w-0 gap-3', compact ? 'flex-col items-start' : 'items-center justify-between')}>
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <SeverityChip severity={top.severity} />
          <span className="min-w-0 text-[13px] font-medium">{title}</span>
        </div>
        {more > 0 && <p className="mt-1 text-[12px] ee-ink-3">and {plural(more, 'more item')}</p>}
      </div>
      <span onClick={(e: MouseEvent) => e.stopPropagation()} className="shrink-0">
        <ActionLink to={targetPath(t.id, top.action.target)} label={top.action.label} size="sm" />
      </span>
    </div>
  )
}

function Success({ t }: { t: OverviewTenant }) {
  const a = t.health.auth_24h
  const total = a.accept + a.reject
  if (!total) return <span className="ee-ink-3">No attempts</span>
  return (
    <span className="block">
      <span className="ee-num font-semibold">{fmtPercent(a.success_rate, 0)}</span>
      <span className="block text-[12px] ee-ink-3 ee-num">{a.accept.toLocaleString('en-GB')} of {total.toLocaleString('en-GB')} accepted</span>
    </span>
  )
}

function Certs({ t }: { t: OverviewTenant }) {
  const c = t.health.certificates
  return (
    <span className="block">
      <span className="ee-num font-semibold">{c.active.toLocaleString('en-GB')}</span><span className="ee-ink-2"> active</span>
      <span className={cn('block text-[12px] ee-num', c.expiring ? 'text-[var(--ee-warn-ink)]' : 'ee-ink-3')}>{c.expiring ? `${c.expiring} expiring soon` : 'none expiring soon'}</span>
    </span>
  )
}

const platformTarget: Record<string, () => string> = { system: paths.system, admins: paths.admins, account: paths.account }

/** Platform risks sit above the tenants: they have the widest blast radius (every tenant at once). */
function PlatformQueue({ items }: { items: QueueItem[] }) {
  if (items.length === 0) return null
  return (
    <Panel className="mb-5 px-5 py-4" risk={items.some((i) => i.severity === 'critical') ? 'crit' : 'warn'} aria-labelledby="platform-q-h">
      <SectionHeader id="platform-q-h" title="Platform needs action" meta={`${plural(items.length, 'item')} · affects every tenant`} />
      <ul className="ee-divide">
        {items.map((i) => (
          <li key={i.code} className="flex flex-col items-start gap-3 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityChip severity={i.severity} />
                <span className="text-[13.5px] font-semibold">{i.title}</span>
              </div>
              <p className="ee-small ee-ink-2 mt-1 max-w-[80ch]">{i.detail}</p>
            </div>
            <span className="shrink-0"><ActionLink to={(platformTarget[i.action.target] ?? paths.system)()} label={i.action.label} size="sm" /></span>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

export default function Tenants() {
  const { canCreateTenants, isPlatform } = useSession()
  const navigate = useNavigate()
  const now = useNow()
  const q = useOverview()

  const ranked = useMemo(() => [...(q.data?.tenants ?? [])].sort((a, b) =>
    compareRank(queueRank(a.queue_top[0]), queueRank(b.queue_top[0])) || a.name.localeCompare(b.name)), [q.data])

  const newBtn = canCreateTenants
    ? <Link to={paths.newTenant()} className="ee-btn ee-btn-primary"><Plus aria-hidden />New tenant</Link>
    : undefined
  const header = <PageHeader title="Tenants" lede={isPlatform ? 'Every customer you manage, most urgent first.' : 'The tenants you have access to, most urgent first.'} actions={newBtn} />

  if (q.isLoading) return <div>{header}<Panel className="p-5"><LoadingBlock rows={6} label="Loading tenants" /></Panel></div>
  if (q.error || !q.data) return <div>{header}<ErrorState error={q.error} onRetry={() => q.refetch()} title="Tenants couldn’t be loaded" /></div>

  const d = q.data
  const agent = d.radius_agent
  const rs = radiusSummary(agent)
  const needAction = ranked.filter((t) => t.queue_count > 0).length
  const open = (t: OverviewTenant) => navigate(paths.dashboard(t.id))

  return (
    <div>
      {header}

      <Panel className="mb-5 px-5 py-4" risk={rs.tone === 'crit' ? 'crit' : undefined}>
        <ul className="flex flex-wrap items-center gap-x-8 gap-y-3 text-[13px]">
          <li>
            <HealthDot tone={rs.tone} label={rs.label} />
            {agent && <span className="ee-ink-3" title={fmtDateTime(agent.last_seen_at)}> · heartbeat {ago(agent.last_seen_at, now)}</span>}
          </li>
          <li><span className="ee-num font-semibold">{needAction}</span><span className="ee-ink-2"> of {plural(d.totals.tenants, 'tenant')} need action</span></li>
          <li><span className="ee-ink-2">Last 24 hours: </span><span className="ee-num font-semibold">{d.totals.accept_24h.toLocaleString('en-GB')}</span><span className="ee-ink-2"> accepted, </span><span className="ee-num font-semibold">{d.totals.reject_24h.toLocaleString('en-GB')}</span><span className="ee-ink-2"> rejected</span></li>
          <li><span className="ee-num font-semibold">{d.totals.active_certificates.toLocaleString('en-GB')}</span><span className="ee-ink-2"> active certificates, </span><span className="ee-num font-semibold">{d.totals.expiring_certificates.toLocaleString('en-GB')}</span><span className="ee-ink-2"> expiring soon</span></li>
        </ul>
      </Panel>

      <PlatformQueue items={d.platform_queue ?? []} />

      {ranked.length === 0 ? (
        <Empty icon={<Building aria-hidden />} title="No tenants yet" action={newBtn}>
          {canCreateTenants ? 'Create a tenant for each customer. The setup wizard then creates its certificate authority and connects its directory.' : 'Your account doesn’t have access to any tenant. Ask the MSP owner to grant you a role.'}
        </Empty>
      ) : (
        <Panel className="p-5">
          <div className="hidden overflow-x-auto lg:block">
            <table className="ee-table">
              <caption className="sr-only">Tenants, most urgent first</caption>
              <thead>
                <tr><th>Tenant</th><th>Enforcement</th><th className="w-[44%]">Top issue</th><th>Last 24 hours</th><th>Certificates</th></tr>
              </thead>
              <tbody>
                {ranked.map((t) => (
                  <tr key={t.id} data-clickable="true" onClick={() => open(t)}>
                    <td>
                      <div className="flex min-w-0 items-center gap-3">
                        <span className="ee-monogram" aria-hidden>{monogram(t.name)}</span>
                        <div className="min-w-0">
                          <Link to={paths.dashboard(t.id)} className="block truncate font-semibold underline-offset-2 hover:underline" onClick={(e) => e.stopPropagation()}>{t.name}</Link>
                          <span className="block truncate text-[12px] ee-ink-3">{t.domain || t.slug}</span>
                        </div>
                      </div>
                    </td>
                    <td><EnforcementChip e={t.enforcement} /><span className="mt-1 block text-[12px] ee-ink-3">{enforcementNote(t, now)}</span></td>
                    <td><TopIssue t={t} /></td>
                    <td><Success t={t} /></td>
                    <td><Certs t={t} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <ul className="ee-divide lg:hidden" aria-label="Tenants, most urgent first">
            {ranked.map((t) => (
              <li key={t.id} className="py-4 first:pt-0 last:pb-0">
                <div className="flex items-start gap-3">
                  <span className="ee-monogram mt-0.5" aria-hidden>{monogram(t.name)}</span>
                  <div className="min-w-0 flex-1">
                    <Link to={paths.dashboard(t.id)} className="block truncate font-semibold underline-offset-2 hover:underline">{t.name}</Link>
                    <span className="block truncate text-[12px] ee-ink-3">{t.domain || t.slug}</span>
                  </div>
                  <EnforcementChip e={t.enforcement} />
                </div>
                <div className="mt-3"><TopIssue t={t} compact /></div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-[13px]">
                  <div><p className="ee-label">Last 24 hours</p><Success t={t} /></div>
                  <div><p className="ee-label">Certificates</p><Certs t={t} /></div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}
