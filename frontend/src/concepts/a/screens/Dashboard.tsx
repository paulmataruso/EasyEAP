import { useMemo, useState, type ReactNode } from 'react'
import { ArrowRight, CircleCheck, CircleDashed, FileBadge, FolderTree, KeyRound, Radio, Router, ShieldCheck, TriangleAlert, Waypoints } from 'lucide-react'
import type { HealthState } from '@/domain/types'
import { failureExplanations } from '@/domain/explain'
import { cn, formatDuration, formatPercent } from '@/ui/lib'
import { now, useMetrics, useTenantData, useTenants } from '@/prototype/store'
import { AuthDivergingChart, BarList, Legend, MiniColumns, MiniRateLine, SegmentBar, SERIES } from '../charts/charts'
import { AuditTimeline, RecentAuthTable } from '../features/activity'
import { IssueCertificateDialog } from '../features/IssueCertificateDialog'
import { HealthPill, healthTextClass } from '../ui/badges'
import { Button, EmptyState, PageHeader, Panel } from '../ui/primitives'
import { eventsInLast24h, expiryForecast, hourlyDistinctUsers, useUserRows } from '../lib/model'
import { vlanHex } from '../lib/vlan'
import { useSetupSteps, type SetupStep } from '../lib/portfolio'
import { ago } from '../lib/time'
import { useNav } from '../shell/nav'
import type { ScreenId } from '../../contract'

const hourRange = (end: Date) => {
  const h = (d: Date) => `${String(d.getUTCHours()).padStart(2, '0')}:00`
  return `${h(new Date(end.getTime() - 3600_000))}–${h(end)} UTC`
}

function Kpi({ title, value, unit, sub, chart, caption }: { title: string; value: ReactNode; unit?: string; sub: ReactNode; chart: ReactNode; caption: string }) {
  return (
    <section className="a-panel a-depth-tenant flex min-w-0 flex-col p-4 pb-3.5" aria-label={title}>
      <h2 className="text-[13px] font-medium text-[var(--a-text-2)]">{title}</h2>
      <p className="mt-1.5 flex items-baseline gap-1.5">
        <span className="text-[28px] leading-none font-semibold tracking-[-0.01em] text-[var(--a-text)]">{value}</span>
        {unit && <span className="text-[14px] text-[var(--a-text-3)]">{unit}</span>}
      </p>
      <div className="mt-1.5 min-h-[20px] text-[13px] text-[var(--a-text-3)]">{sub}</div>
      <div className="mt-auto pt-4">{chart}</div>
      <p className="mt-2 text-[12px] text-[var(--a-text-3)]">{caption}</p>
    </section>
  )
}

function HealthRow({ icon: Icon, title, detail, state, stateLabel, action }: { icon: typeof Radio; title: string; detail: ReactNode; state: HealthState; stateLabel?: string; action?: ReactNode }) {
  return (
    <li className="flex items-start gap-3 px-[18px] py-3">
      <span className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-lg border border-white/10 bg-white/[0.04]">
        <Icon className={cn('size-4', healthTextClass(state))} aria-hidden />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
          <p className="text-[14px] font-medium text-[var(--a-text)]">{title}</p>
          <HealthPill state={state} label={stateLabel} />
        </div>
        <div className="mt-0.5 text-[13px] text-[var(--a-text-3)]">{detail}</div>
        {action}
      </div>
    </li>
  )
}

const STEP_TARGET: Record<string, { screen: ScreenId; label: string } | undefined> = {
  'server-cert': { screen: 'certificates', label: 'Open certificates' },
  controller: { screen: 'radius', label: 'Add a controller' },
  'first-cert': { screen: 'users', label: 'Choose a user' },
}

export function SetupChecklist({ steps, tenantName }: { steps: SetupStep[]; tenantName: string }) {
  const { navigate } = useNav()
  const done = steps.filter((s) => s.done).length
  return (
    <Panel
      title={`Finish setting up ${tenantName}`}
      description={`${done} of ${steps.length} steps complete. Wi-Fi authentication starts once a controller and the RADIUS server certificate are in place.`}
      actions={
        <span className="a-num text-[13px] text-[var(--a-text-3)]">
          {Math.round((done / steps.length) * 100)}%
        </span>
      }
      className="mb-5"
    >
      <div className="px-[18px]">
        <div className="h-1.5 rounded-full bg-white/[0.07]" role="progressbar" aria-valuemin={0} aria-valuemax={steps.length} aria-valuenow={done} aria-label="Setup progress">
          <div className="h-full rounded-full bg-[var(--a-accent)]" style={{ width: `${(done / steps.length) * 100}%` }} />
        </div>
      </div>
      <ol className="grid gap-x-6 px-[18px] py-3 md:grid-cols-2 xl:grid-cols-3">
        {steps.map((s) => {
          const target = STEP_TARGET[s.id]
          return (
            <li key={s.id} className="flex items-start gap-3 border-b border-white/[0.06] py-2.5 last:border-b-0">
              {s.done ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-[var(--a-ok-text)]" aria-hidden /> : <CircleDashed className="mt-0.5 size-4 shrink-0 text-[var(--a-text-3)]" aria-hidden />}
              <div className="min-w-0 flex-1">
                <p className={cn('text-[14px] font-medium', s.done ? 'text-[var(--a-text-2)]' : 'text-[var(--a-text)]')}>
                  {s.label}
                  <span className="sr-only">{s.done ? ' (done)' : ' (to do)'}</span>
                </p>
                <p className="text-[12px] text-[var(--a-text-3)]">{s.detail}</p>
                {!s.done && target && (
                  <button type="button" className="a-link mt-1 inline-flex items-center gap-1 text-[13px]" onClick={() => navigate(target.screen)}>
                    {target.label} <ArrowRight className="size-3.5" aria-hidden />
                  </button>
                )}
              </div>
            </li>
          )
        })}
      </ol>
    </Panel>
  )
}

export function Dashboard() {
  const m = useMetrics()
  const d = useTenantData()
  const rows = useUserRows()
  const { current } = useTenants()
  const { navigate } = useNav()
  const steps = useSetupSteps()
  const [issueOpen, setIssueOpen] = useState(false)
  const setup = current.status === 'setup'

  const authorized = rows.filter((r) => r.decision.outcome === 'allow').length
  const ad = d.identities.filter((i) => i.source === 'ad').length
  const issuing = d.cas.find((c) => c.role === 'issuing')
  const root = d.cas.find((c) => c.role === 'root')
  const degraded = d.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down')
  const snapshotAge = current.health.authzSnapshotAgeSeconds
  const maxAge = d.defaults.maxSnapshotAgeSeconds

  const usersPerHour = useMemo(() => hourlyDistinctUsers(d.authEvents).map((p) => ({ label: hourRange(p.hourEnd), value: p.value })), [d.authEvents])
  const forecast = useMemo(() => expiryForecast(d.certificates.filter((c) => c.identityId)).map((p) => ({ label: p.day.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }), value: p.value })), [d.certificates])
  const expiring30 = forecast.reduce((s, x) => s + x.value, 0)
  const rate = m.auth.hourly.map((h) => ({ label: hourRange(h.hourEnd), rate: h.accept + h.reject ? h.accept / (h.accept + h.reject) : null, total: h.accept + h.reject }))
  const landed = useMemo(() => {
    const accepted = eventsInLast24h(d.authEvents).filter((e) => e.result === 'accept')
    return [...d.vlans]
      .sort((a, b) => a.vlanId - b.vlanId)
      .map((v) => ({ key: v.id, label: `VLAN ${v.vlanId} ${v.name}`, value: accepted.filter((e) => e.vlanId === v.id).length, color: vlanHex(v) }))
      .filter((s) => s.value > 0)
  }, [d.authEvents, d.vlans])
  const perNas = d.radiusClients.map((c) => ({ c, n: d.authEvents.filter((e) => e.nasClientId === c.id).length }))

  const attention = [
    ...degraded.map((c) => ({
      key: c.id,
      tone: c.status as HealthState,
      title: `${c.name} is ${c.status === 'down' ? 'down' : 'degraded'}`,
      detail: `Last RADIUS request ${ago(c.lastRequestAt)} from ${c.address} (${c.site}). Clients at ${c.site} may not be able to join Wi-Fi.`,
      action: { label: 'View controller', go: () => navigate('radius', c.id) },
    })),
    ...(current.health.directory === 'degraded' || current.health.directory === 'down'
      ? [{ key: 'dir', tone: current.health.directory, title: 'Directory sync is failing', detail: `Last successful sync ${ago(current.health.lastDirectorySync)}. Group changes in Active Directory are not reaching RADIUS.`, action: { label: 'View users', go: () => navigate('users') } }]
      : []),
  ]

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={
          <>
            {current.name} · <span className="a-mono text-[13px]">{current.domain}</span> · data as of{' '}
            <time className="a-num" dateTime={now().toISOString()}>
              {now().toISOString().slice(11, 16)} UTC
            </time>
          </>
        }
        actions={
          <>
            <Button icon={Waypoints} onClick={() => navigate('policies')}>
              Test a user’s access
            </Button>
            <Button variant="primary" icon={FileBadge} onClick={() => setIssueOpen(true)}>
              Issue Wi-Fi certificate
            </Button>
          </>
        }
      />

      {setup && <SetupChecklist steps={steps} tenantName={current.name} />}

      {attention.length > 0 && (
        <section aria-label="Needs attention" className="a-panel a-depth-tenant mb-5 border-[rgba(251,191,36,0.28)]">
          <ul className="divide-y divide-white/[0.07]">
            {attention.map((a) => (
              <li key={a.key} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-[18px] py-3">
                <TriangleAlert className={cn('size-5 shrink-0', a.tone === 'down' ? 'text-[var(--a-danger-text)]' : 'text-[var(--a-warn-text)]')} aria-hidden />
                <div className="min-w-[200px] flex-1">
                  <p className="text-[14px] font-semibold text-[var(--a-text)]">{a.title}</p>
                  <p className="text-[13px] text-[var(--a-text-2)]">{a.detail}</p>
                </div>
                <Button size="sm" onClick={a.action.go}>
                  {a.action.label}
                  <ArrowRight aria-hidden />
                </Button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          title="Wi-Fi users"
          value={rows.length}
          sub={
            <>
              <span className="text-[var(--a-ok-text)]">{authorized} authorized</span> · {rows.length - authorized} denied · {ad} AD, {rows.length - ad} local
            </>
          }
          chart={<MiniColumns data={usersPerHour} highlightLast label="Distinct users authenticating per hour, last 24 hours" unit={(n) => `${n} ${n === 1 ? 'user' : 'users'}`} emptyLabel="No authentications yet" />}
          caption="Users authenticating per hour · 24h"
        />
        <Kpi
          title="Valid certificates"
          value={m.certificates.active + m.certificates.expiring}
          sub={
            <>
              <span className={m.certificates.expiring ? 'text-[var(--a-warn-text)]' : undefined}>{m.certificates.expiring} expiring</span> · {m.certificates.expired} expired · {m.certificates.revoked} revoked
            </>
          }
          chart={<MiniColumns data={forecast} color={SERIES.expiring} label="Certificates expiring per day over the next 30 days" unit={(n) => `${n} expiring`} emptyLabel="Nothing expires in 30 days" />}
          caption={`${expiring30} expire in the next 30 days`}
        />
        <Kpi
          title="Authentication success"
          value={formatPercent(m.auth.successRate)}
          unit="24h"
          sub={
            m.auth.total ? (
              <>
                {m.auth.accepts} accepted · <span className="text-[var(--a-danger-text)]">{m.auth.rejects} rejected</span>
              </>
            ) : (
              'No authentications in 24h'
            )
          }
          chart={<MiniRateLine data={rate} label="Hourly authentication success rate, last 24 hours" emptyLabel="No attempts yet" />}
          caption="Hourly success rate · 24h"
        />
        <Kpi
          title="RADIUS clients"
          value={d.radiusClients.length ? `${m.activeRadiusClients} of ${d.radiusClients.length}` : '0'}
          unit={d.radiusClients.length ? 'active' : undefined}
          sub={degraded.length ? <span className="text-[var(--a-warn-text)]">{degraded.length} degraded</span> : d.radiusClients.length ? 'All operational' : 'No controllers registered'}
          chart={
            perNas.length ? (
              <BarList
                label="RADIUS requests per controller, last 24 hours"
                items={perNas.map(({ c, n }) => ({
                  key: c.id,
                  label: c.name,
                  value: n,
                  color: c.status === 'degraded' || c.status === 'down' ? SERIES.expiring : SERIES.neutral,
                  detail: `${c.name}: ${n} requests in 24h · last ${ago(c.lastRequestAt)}`,
                  trailing: c.status === 'degraded' || c.status === 'down' ? <TriangleAlert className="size-3.5 text-[var(--a-warn-text)]" aria-label="Degraded" /> : undefined,
                }))}
              />
            ) : (
              <Button size="sm" icon={Router} onClick={() => navigate('radius')}>
                Add a controller
              </Button>
            )
          }
          caption="Requests per controller · 24h"
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <Panel
          className="xl:col-span-8"
          title="Authentications, last 24 hours"
          description={m.auth.total ? 'Accepted above the line, rejected below. Hover or focus the chart to read each hour.' : 'Accepted and rejected attempts per hour appear here once controllers send traffic.'}
          actions={
            m.auth.total ? (
              <Legend
                items={[
                  { label: 'Accepted', color: SERIES.accept },
                  { label: 'Rejected', color: SERIES.reject },
                ]}
              />
            ) : undefined
          }
        >
          {m.auth.total ? (
            <div className="grid gap-x-8 gap-y-5 px-[18px] pt-2 pb-5 lg:grid-cols-[minmax(0,1fr)_260px]">
              <AuthDivergingChart points={m.auth.hourly} label={`Authentications per hour: ${m.auth.accepts} accepted and ${m.auth.rejects} rejected in 24 hours`} height={236} />
              <div className="min-w-0">
                <h3 className="mb-3 text-[13px] font-semibold text-[var(--a-text)]">Why authentications failed</h3>
                <BarList
                  label="Rejected authentications by cause"
                  items={m.failures.slice(0, 6).map(([code, n]) => ({
                    key: code,
                    label: failureExplanations[code as keyof typeof failureExplanations]?.title ?? code,
                    value: n,
                    color: SERIES.reject,
                    detail: `${n} rejected in 24h`,
                  }))}
                />
              </div>
              {landed.length > 0 && (
                <div className="min-w-0 border-t border-[var(--a-line)] pt-4 lg:col-span-2">
                  <h3 className="mb-2.5 text-[13px] font-semibold text-[var(--a-text)]">Where accepted clients landed</h3>
                  <SegmentBar segments={landed} unit="accepted" label="Accepted authentications by assigned VLAN, last 24 hours" />
                </div>
              )}
            </div>
          ) : (
            <EmptyState icon={Radio} title="No authentications yet">
              RADIUS has not received a request for {current.name}. Add a wireless controller and enroll a first device to see traffic here.
            </EmptyState>
          )}
        </Panel>

        <Panel className="xl:col-span-4" title="Service health" description="What RADIUS depends on to say yes.">
          <ul className="divide-y divide-white/[0.07] border-t border-[var(--a-line)]">
            <HealthRow
              icon={Radio}
              title="RADIUS service"
              state={current.health.radius}
              detail={
                <>
                  <span className="a-mono">{d.radiusSettings?.serverHostname}</span> · UDP {d.radiusSettings?.authPort}/{d.radiusSettings?.acctPort}
                </>
              }
            />
            <HealthRow
              icon={Router}
              title="Wireless controllers"
              state={!d.radiusClients.length ? 'unconfigured' : degraded.length ? 'degraded' : 'ok'}
              stateLabel={!d.radiusClients.length ? 'None yet' : degraded.length ? `${degraded.length} degraded` : `${d.radiusClients.length} operational`}
              detail={d.radiusClients.length ? `${m.activeRadiusClients} of ${d.radiusClients.length} sending requests normally` : 'Register a controller to start authenticating'}
            />
            <HealthRow
              icon={KeyRound}
              title="Authorization snapshot"
              state={snapshotAge === null ? 'unconfigured' : snapshotAge > maxAge ? 'down' : snapshotAge > maxAge / 2 ? 'degraded' : 'ok'}
              stateLabel={snapshotAge === null ? 'Not loaded' : undefined}
              detail={snapshotAge === null ? 'RADIUS has no snapshot yet' : `Loaded ${formatDuration(snapshotAge)} ago · RADIUS fails safe after ${formatDuration(maxAge)}`}
            />
            <HealthRow
              icon={ShieldCheck}
              title="PKI"
              state={current.health.pki}
              detail={
                <ul className="flex flex-col gap-0.5">
                  <li>{issuing ? `${issuing.commonName} · expires ${ago(issuing.notAfter)}` : 'No issuing CA'}</li>
                  <li>{root ? `${root.commonName} · ${root.offline ? 'key offline' : 'online'}` : 'No root CA'}</li>
                  <li>
                    CRL #{issuing?.crl?.number} · next update {ago(issuing?.crl?.nextUpdate ?? null)} · OCSP {issuing?.ocsp?.enabled ? 'enabled' : 'off'}
                  </li>
                </ul>
              }
            />
            <HealthRow
              icon={FolderTree}
              title="Active Directory"
              state={current.health.directory}
              detail={current.health.lastDirectorySync ? `Last sync ${ago(current.health.lastDirectorySync)} · ${current.domain}` : 'Not connected yet'}
            />
          </ul>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel
          title="Recent authentications"
          description="Latest attempts across all controllers. Select a row to open the user."
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate('users')}>
              All users
            </Button>
          }
        >
          {d.authEvents.length ? (
            <RecentAuthTable events={d.authEvents} limit={8} />
          ) : (
            <EmptyState icon={Radio} title="No authentications recorded">
              Events appear here seconds after a device tries to join.
            </EmptyState>
          )}
        </Panel>
        <Panel title="Certificate and audit activity" description="Who changed what, newest first.">
          <div className="border-t border-[var(--a-line)] px-[18px] py-4">
            <AuditTimeline events={d.audit} limit={6} />
          </div>
        </Panel>
      </div>

      <IssueCertificateDialog open={issueOpen} onOpenChange={setIssueOpen} />
    </>
  )
}
