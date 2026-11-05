// MSP overview: every customer tenant, ranked by its most urgent needs-action item, with whether RADIUS can enforce
// it, the top issue and its one action, 24-hour success and certificate counts. Each row opens that tenant.
import { useMemo, type MouseEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { Building, CircleAlert, CircleCheck, CircleX, Plus, TriangleAlert } from 'lucide-react'
import { cn } from '@/ui/lib'
import { compareRank, queueRank, queueTitle, useOverview, type OverviewTenant } from '../api/dashboard'
import { useSession } from '../api/session'
import { ago, fmtDateTime, fmtPercent, plural, relative } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths, targetPath } from '../routes'
import { monogram } from '../shell/Shell'
import { Chip, Empty, ErrorState, HealthDot, LoadingBlock, PageHeader, Panel, SeverityChip } from '../ui'
import { ActionLink } from './dashboard/Queue'

function EnforcementChip({ t }: { t: OverviewTenant }) {
  if (t.status === 'suspended') return <Chip tone="crit" icon={<CircleX aria-hidden />}>Suspended</Chip>
  if (!t.enforcement.enforceable) return <Chip tone="neutral" icon={<CircleAlert aria-hidden />} title="Setup isn’t finished, so nobody can connect yet">Not enforceable yet</Chip>
  if (!t.enforcement.agent_online || !t.enforcement.auto_refresh) return <Chip tone="crit" icon={<CircleX aria-hidden />}>At risk</Chip>
  if (!t.enforcement.snapshot_built_at) return <Chip tone="warn" icon={<TriangleAlert aria-hidden />} title="Nobody can connect until the first authorization snapshot is built">Waiting for snapshot</Chip>
  if (!t.enforcement.agent_in_sync) return <Chip tone="warn" icon={<TriangleAlert aria-hidden />}>Update pending</Chip>
  return <Chip tone="valid" icon={<CircleCheck aria-hidden />}>Enforcing</Chip>
}

function enforcementNote(t: OverviewTenant, now: Date): string {
  const e = t.enforcement
  if (!e.enforceable) return plural(e.missing.length, 'setup step') + ' left'
  if (!e.auto_refresh && e.deadline_at) return `Fails closed ${relative(e.deadline_at, now)}`
  return e.snapshot_built_at ? `Snapshot built ${ago(e.snapshot_built_at, now)}` : 'No snapshot yet'
}

function TopIssue({ t, compact }: { t: OverviewTenant; compact?: boolean }) {
  const top = t.queue_top[0]
  if (!top) return <HealthDot tone="valid" label="Nothing needs action" />
  const more = t.queue_count - 1
  // A tenant in setup already says "Not enforceable yet" in its enforcement column; name the next step instead.
  const setup = top.code === 'not_enforceable' && t.enforcement.missing.length > 0
  const title = setup ? `Next setup step: ${t.enforcement.missing[0].message}` : queueTitle(top)
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
  const needAction = ranked.filter((t) => t.queue_count > 0).length
  const open = (t: OverviewTenant) => navigate(paths.dashboard(t.id))

  return (
    <div>
      {header}

      <Panel className="mb-5 px-5 py-4" risk={!agent || !agent.online ? 'crit' : undefined}>
        <ul className="flex flex-wrap items-center gap-x-8 gap-y-3 text-[13px]">
          <li>
            {agent
              ? <HealthDot tone={agent.online && agent.config_ok && agent.radius_running ? 'valid' : 'crit'} label={agent.online ? (agent.config_ok && agent.radius_running ? 'RADIUS agent online' : 'RADIUS agent reporting a problem') : 'RADIUS agent not reporting'} />
              : <HealthDot tone="crit" label="RADIUS agent has never reported" />}
            {agent && <span className="ee-ink-3" title={fmtDateTime(agent.last_seen_at)}> · heartbeat {ago(agent.last_seen_at, now)}</span>}
          </li>
          <li><span className="ee-num font-semibold">{needAction}</span><span className="ee-ink-2"> of {plural(d.totals.tenants, 'tenant')} need action</span></li>
          <li><span className="ee-ink-2">Last 24 hours: </span><span className="ee-num font-semibold">{d.totals.accept_24h.toLocaleString('en-GB')}</span><span className="ee-ink-2"> accepted, </span><span className="ee-num font-semibold">{d.totals.reject_24h.toLocaleString('en-GB')}</span><span className="ee-ink-2"> rejected</span></li>
          <li><span className="ee-num font-semibold">{d.totals.active_certificates.toLocaleString('en-GB')}</span><span className="ee-ink-2"> active certificates, </span><span className="ee-num font-semibold">{d.totals.expiring_certificates.toLocaleString('en-GB')}</span><span className="ee-ink-2"> expiring soon</span></li>
        </ul>
      </Panel>

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
                    <td><EnforcementChip t={t} /><span className="mt-1 block text-[12px] ee-ink-3">{enforcementNote(t, now)}</span></td>
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
                  <EnforcementChip t={t} />
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
