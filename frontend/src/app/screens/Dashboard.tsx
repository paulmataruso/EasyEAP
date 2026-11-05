// Tenant dashboard. Leads with what breaks next (the needs-action queue), then whether RADIUS can enforce the tenant
// and when it would fail closed, then the operational picture. Every status names the age of its source data.
import { useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router'
import { ArrowRight, Inbox, KeyRound, Router, ShieldCheck } from 'lucide-react'
import { useDashboard, type DashboardResponse } from '../api/dashboard'
import { useControllers, usePolicyLite } from '../api/events'
import { useSession } from '../api/session'
import { useTenant } from '../api/tenant'
import { ago, duration, fmtDate, fmtDateTime, fmtPercent, plural, remaining } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Empty, ErrorState, HealthDot, Panel, PageHeader, SectionHeader, Skeleton, VlanTag, type Tone } from '../ui'
import { HourlyChart, RankedBars, ViewToggle, type ChartView } from './dashboard/charts'
import { EnforcementPanel, enforcementRisk } from './dashboard/Enforcement'
import { QueueEmpty, QueueRow, queueRisk } from './dashboard/Queue'
import { EventTable } from './events/EventTable'
import { eventPath } from './events/links'

const TARGET_PERM: Record<string, string> = {
  directory: 'directory:read', radius: 'radius:read', pki: 'certificates:read', certificates: 'certificates:read', events: 'events:read',
  policy: 'policy:read', users: 'identities:read', tenant: 'tenant:read', setup: 'tenant:read',
}

function Freshness({ d }: { d: DashboardResponse }) {
  const now = useNow()
  const dir = d.health.directory
  const agent = d.services.radius_agent
  const last = d.recent_events[0]?.at
  const parts: Array<[string, string | null]> = [
    [!dir.configured ? 'No directory connected' : !dir.last_sync_at ? 'Directory never synced' : `Directory ${dir.status === 'failed' ? 'sync failed' : 'synced'} ${ago(dir.last_sync_at, now)}`, dir.last_sync_at],
    [agent ? `RADIUS heartbeat ${ago(agent.last_seen_at, now)}` : 'No RADIUS heartbeat yet', agent?.last_seen_at ?? null],
    [last ? `Latest authentication ${ago(last, now)}` : 'No authentications recorded', last ?? null],
  ]
  return (
    <>
      {parts.map(([text, at], i) => (
        <span key={i}>
          {i > 0 && <span className="ee-ink-3" aria-hidden> · </span>}
          <span title={at ? fmtDateTime(at) : undefined}>{text}</span>
        </span>
      ))}
    </>
  )
}

function PanelSkeleton({ className, rows = 4 }: { className?: string; rows?: number }) {
  return (
    <Panel className={className}>
      <div className="space-y-3 p-5" aria-hidden>
        <Skeleton className="h-5 w-1/3" />
        {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className={i % 2 ? 'w-full' : 'w-4/5'} />)}
      </div>
    </Panel>
  )
}

function FooterLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="mt-3 inline-flex items-center gap-1.5 rounded text-[13px] font-medium ee-ink-2 hover:text-[var(--ee-ink)]">
      {children}<ArrowRight className="size-3.5" aria-hidden />
    </Link>
  )
}

function ServiceRow({ tone, title, status, detail, icon }: { tone: Tone; title: string; status: string; detail: ReactNode; icon: ReactNode }) {
  return (
    <li className="flex gap-3 py-3 first:pt-0 last:pb-0">
      <span className="mt-0.5 ee-ink-3 [&_svg]:size-4" aria-hidden>{icon}</span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
          <p className="text-[13px] font-medium">{title}</p>
          <HealthDot tone={tone} label={status} />
        </div>
        <p className="ee-small ee-ink-2 mt-0.5">{detail}</p>
      </div>
    </li>
  )
}

export default function Dashboard() {
  const { tid, tenant, can } = useTenant()
  const { isPlatform } = useSession()
  const navigate = useNavigate()
  const now = useNow()
  const q = useDashboard(tid)
  const policy = usePolicyLite(tid, can('policy:read'))
  const radius = useControllers(tid, can('radius:read'))
  const [chartView, setChartView] = useState<ChartView>('chart')
  const [reasonView, setReasonView] = useState<ChartView>('chart')
  const [vlanView, setVlanView] = useState<ChartView>('chart')

  const header = (
    <PageHeader title="Dashboard" lede={<>{tenant.name}{tenant.domain && <span className="ee-ink-3"> · {tenant.domain}</span>}</>}>
      {q.data && q.data.queue.length > 0 && <p className="ee-small ee-ink-2 mt-2"><Freshness d={q.data} /></p>}
    </PageHeader>
  )

  if (q.isLoading) {
    return (
      <div>
        {header}
        <div role="status" aria-label="Loading dashboard" className="grid grid-cols-1 gap-5 lg:grid-cols-12 [&>*]:min-w-0">
          <PanelSkeleton className="lg:col-span-8" rows={5} />
          <PanelSkeleton className="lg:col-span-4" rows={4} />
          <PanelSkeleton className="lg:col-span-8" rows={6} />
          <PanelSkeleton className="lg:col-span-4" rows={4} />
        </div>
      </div>
    )
  }
  if (q.error || !q.data) return <div>{header}<ErrorState error={q.error} onRetry={() => q.refetch()} title="The dashboard couldn’t be loaded" /></div>

  const d = q.data
  const canUsers = can('identities:read')
  const canCerts = can('certificates:read')
  const canEvents = can('events:read')
  const vlans = policy.data?.vlans
  const warnDays = policy.data?.settings.expiry_warning_days
  const auth = d.health.auth_24h
  const total24 = auth.accept + auth.reject
  const totalRejects = d.failure_reasons.reduce((s, r) => s + r.count, 0)
  const agent = d.services.radius_agent
  const snap = d.services.snapshot
  const ca = d.services.issuing_ca

  return (
    <div>
      {header}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12 [&>*]:min-w-0">
        {/* Needs action */}
        <Panel risk={queueRisk(d.queue)} className="lg:col-span-8" aria-labelledby="queue-h">
          <div className="p-5">
            <SectionHeader id="queue-h" title="Needs action" meta={d.queue.length ? `${plural(d.queue.length, 'item')}, most urgent first` : undefined} />
            {d.queue.length === 0 ? (
              <QueueEmpty
                freshness={<Freshness d={d} />}
                caveat={d.enforcement.enforceable && enforcementRisk(d.enforcement) !== 'valid' ? 'The Enforcement panel reports a problem that needs checking.' : undefined}
              />
            ) : (
              <ol className="ee-divide">
                {d.queue.map((item, i) => {
                  const screen = item.action.target.split(':')[0]
                  const allowed = screen === 'system' ? isPlatform : !TARGET_PERM[screen] || can(TARGET_PERM[screen])
                  return (
                    <QueueRow
                      key={item.code}
                      item={item}
                      tid={tid}
                      primary={i === 0}
                      canOpen={allowed}
                      unavailable={screen === 'system' ? 'Your MSP runs the RADIUS service. Ask them to check it.' : 'Your role can’t open this area. Ask a Tenant Administrator.'}
                    />
                  )
                })}
              </ol>
            )}
          </div>
        </Panel>

        <EnforcementPanel tid={tid} enforcement={d.enforcement} agent={agent} className="lg:col-span-4" />

        {/* Authentications over 24 h */}
        <Panel className="lg:col-span-8" aria-labelledby="auth-h">
          <div className="p-5">
            <SectionHeader
              id="auth-h"
              title="Authentications, last 24 hours"
              meta={total24 ? `${fmtPercent(auth.success_rate, 0)} accepted` : undefined}
              actions={total24 ? <ViewToggle value={chartView} onChange={setChartView} what="authentications per hour" /> : undefined}
            />
            {total24 === 0 ? (
              <Empty icon={<Inbox aria-hidden />} title="No authentication attempts in the last 24 hours" action={can('radius:read') ? <FooterLink to={paths.radius(tid)}>Check controllers</FooterLink> : undefined}>
                If devices should be connecting, check that each controller sends RADIUS requests to EasyEAP.
              </Empty>
            ) : (
              <div className={q.isFetching ? 'opacity-90 transition-opacity' : undefined}>
                <HourlyChart hourly={d.hourly} view={chartView} />
              </div>
            )}
          </div>
        </Panel>

        {/* Failure reasons */}
        <Panel className="lg:col-span-4" aria-labelledby="reasons-h">
          <div className="p-5">
            <SectionHeader id="reasons-h" title="Top failure reasons" meta="last 24 hours" actions={d.failure_reasons.length ? <ViewToggle value={reasonView} onChange={setReasonView} what="failure reasons" /> : undefined} />
            {d.failure_reasons.length === 0 ? (
              <p className="ee-small ee-ink-2">No rejected attempts in the last 24 hours.</p>
            ) : (
              <>
                <RankedBars
                  view={reasonView}
                  caption="Rejected attempts by reason, last 24 hours"
                  nameHeader="Reason"
                  unit={['rejection', 'rejections']}
                  color="var(--ee-series-reject)"
                  items={d.failure_reasons.map((r) => ({
                    key: r.reason_code ?? 'none',
                    label: r.title,
                    text: r.title,
                    value: r.count,
                    to: canEvents ? (r.reason_code ? paths.events(tid, { reason: r.reason_code }) : paths.events(tid, { result: 'reject' })) : undefined,
                    hint: 'Open these attempts in the authentication log',
                  }))}
                />
                {canEvents && <FooterLink to={paths.events(tid, { result: 'reject' })}>All {plural(totalRejects, 'rejected attempt')}</FooterLink>}
              </>
            )}
          </div>
        </Panel>

        {/* Recent authentications */}
        <Panel className={d.recent_events.length ? 'lg:col-span-8' : 'lg:col-span-8 lg:self-start'} aria-labelledby="recent-h">
          <div className="p-5">
            <SectionHeader id="recent-h" title="Recent authentications" meta={d.recent_events.length ? `latest ${d.recent_events.length}` : undefined} />
            {d.recent_events.length === 0 ? (
              <p className="ee-small ee-ink-2">No authentication attempts have been recorded for this tenant yet.</p>
            ) : (
              <>
                <EventTable
                  tid={tid}
                  compact
                  events={d.recent_events}
                  lookups={{ clients: radius.data?.clients, rules: policy.data?.rules, vlans, canUsers }}
                  onOpen={(e) => { if (canEvents) navigate(eventPath(tid, e.id)) }}
                />
                {canEvents && <FooterLink to={paths.events(tid)}>Open the authentication log</FooterLink>}
              </>
            )}
          </div>
        </Panel>

        <div className="grid grid-cols-1 content-start gap-5 lg:col-span-4 [&>*]:min-w-0">
          {/* VLAN usage */}
          <Panel aria-labelledby="vlan-h">
            <div className="p-5">
              <SectionHeader id="vlan-h" title="VLAN usage" meta="accepted, last 24 hours" actions={d.vlan_usage.length > 1 ? <ViewToggle value={vlanView} onChange={setVlanView} what="VLAN usage" /> : undefined} />
              {d.vlan_usage.length === 0 ? (
                <p className="ee-small ee-ink-2">No accepted connections were placed on a VLAN in the last 24 hours.</p>
              ) : (
                <RankedBars
                  view={vlanView}
                  caption="Accepted connections by VLAN, last 24 hours"
                  nameHeader="VLAN"
                  unit={['connection', 'connections']}
                  color="var(--ee-series-accept)"
                  items={[...d.vlan_usage].sort((a, b) => b.count - a.count).map((v) => {
                    const meta = vlans?.find((x) => x.vlan_id === v.vlan_id)
                    return { key: String(v.vlan_id), label: <VlanTag vlanId={v.vlan_id} name={v.name ?? meta?.name} color={meta?.color} />, text: `VLAN ${v.vlan_id}${v.name ? ` ${v.name}` : ''}`, value: v.count }
                  })}
                />
              )}
            </div>
          </Panel>

          {/* Expiring certificates */}
          <Panel risk={d.expiring.length ? 'warn' : undefined} aria-labelledby="exp-h">
            <div className="p-5">
              <SectionHeader id="exp-h" title="Certificates expiring soon" meta={warnDays ? `within ${warnDays} days` : undefined} />
              {d.expiring.length === 0 ? (
                <p className="ee-small ee-ink-2">No user or device certificates expire {warnDays ? `in the next ${warnDays} days` : 'within the warning window'}.</p>
              ) : (
                <>
                  <ul className="ee-divide">
                    {d.expiring.map((c) => (
                      <li key={c.id} className="flex items-start justify-between gap-3 py-2.5 first:pt-0">
                        <div className="min-w-0">
                          {c.identity
                            ? (canUsers ? <Link to={paths.user(tid, c.identity.id)} className="block truncate text-[13px] font-medium underline-offset-2 hover:underline">{c.identity.display_name}</Link> : <span className="block truncate text-[13px] font-medium">{c.identity.display_name}</span>)
                            : <span className="block truncate text-[13px] ee-ink-2">No user linked</span>}
                          {canCerts
                            ? <Link to={paths.certificate(tid, c.id)} className="block truncate text-[12px] ee-ink-3 underline-offset-2 hover:text-[var(--ee-ink)] hover:underline">{c.common_name}</Link>
                            : <span className="block truncate text-[12px] ee-ink-3">{c.common_name}</span>}
                        </div>
                        <div className="shrink-0 text-right">
                          <p className="ee-remaining text-[13px] font-semibold">{remaining(c.not_after, now)}</p>
                          <p className="text-[12px] ee-ink-3">{fmtDate(c.not_after)}</p>
                        </div>
                      </li>
                    ))}
                  </ul>
                  {canCerts && <FooterLink to={paths.certificates(tid, { status: 'expiring' })}>Review expiring certificates</FooterLink>}
                </>
              )}
            </div>
          </Panel>

          {/* Services */}
          <Panel aria-labelledby="svc-h">
            <div className="p-5">
              <SectionHeader id="svc-h" title="Services" />
              <ul className="ee-divide">
                <ServiceRow
                  icon={<Router />}
                  title="RADIUS agent"
                  tone={!agent ? 'crit' : !agent.online ? 'crit' : !agent.config_ok || !agent.radius_running ? 'crit' : 'valid'}
                  status={!agent ? 'Never reported' : !agent.online ? 'Not reporting' : !agent.radius_running ? 'RADIUS stopped' : !agent.config_ok ? 'Config rejected' : 'Online'}
                  detail={agent
                    ? <>Heartbeat {ago(agent.last_seen_at, now)}{agent.config_error ? ` · ${agent.config_error}` : agent.radius_running ? ' · RADIUS running' : ''}</>
                    : 'EasyEAP hasn’t received a heartbeat from the RADIUS agent.'}
                />
                <ServiceRow
                  icon={<ShieldCheck />}
                  title="Authorization snapshot"
                  tone={!snap.built_at ? 'warn' : snap.applied ? 'valid' : 'warn'}
                  status={!snap.built_at ? 'Not built' : snap.applied ? 'Applied' : 'Not applied yet'}
                  detail={snap.built_at
                    ? <span title={fmtDateTime(snap.built_at)}>Built {ago(snap.built_at, now)} · maximum age {duration(snap.max_age_seconds)}</span>
                    : (d.enforcement.enforceable ? 'The background worker builds it after activation and after every policy or directory change.' : 'Built once setup is finished and the tenant is activated.')}
                />
                <ServiceRow
                  icon={<KeyRound />}
                  title="Issuing CA"
                  tone={!ca ? 'neutral' : new Date(ca.not_after).getTime() - now.getTime() < 180 * 864e5 ? 'warn' : 'valid'}
                  status={!ca ? 'Not initialized' : new Date(ca.not_after).getTime() <= now.getTime() ? 'Expired' : 'Valid'}
                  detail={ca
                    ? <>{ca.common_name} · valid until {fmtDate(ca.not_after)} ({remaining(ca.not_after, now)})</>
                    : <>Run the certificate authority ceremony in <Link to={paths.setup(tid)} className="underline">setup</Link>.</>}
                />
              </ul>
              {isPlatform && <FooterLink to={paths.system()}>System health</FooterLink>}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}
