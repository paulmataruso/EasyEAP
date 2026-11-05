import { useMemo, useState, type ReactNode } from 'react'
import { ArrowRight, BadgeCheck, CalendarClock, History, Router, Table2, ChartColumn } from 'lucide-react'
import { now, useMetrics, useTenantData, useTenants } from '@/prototype/store'
import { vendorLabels } from '@/domain/explain'
import type { FailureCode } from '@/domain/types'
import { daysUntil, formatDate, formatPercent } from '@/ui/lib'
import { PageHeader } from '../ui/PageHeader'
import { EmptyState, Panel, PanelHead } from '../ui/Panel'
import { Button } from '../ui/Button'
import { StatusText } from '../ui/Badge'
import { AcceptRejectLegend, StackedColumns } from '../charts/StackedColumns'
import { FailureBars } from '../charts/FailureBars'
import { VlanBar } from '../charts/VlanBar'
import { AuthStream } from '../features/AuthStream'
import { useInspector } from '../shell/Inspectors'
import { useIntent, useShell } from '../shell/context'
import { bucketHourly } from '../lib/metrics'
import { formatAge, hhmm, pluralize, secondsSince } from '../lib/format'
import { healthLabel, healthTone } from '../lib/status'
import { classify, CONTROLLER_BUDGET, DIRECTORY_BUDGET, snapshotBudget } from '../lib/freshness'

export function Dashboard() {
  const { current } = useTenants()
  const d = useTenantData()
  const m = useMetrics()
  const { go } = useShell()
  const [failure, setFailure] = useState<FailureCode | null>(null)
  useIntent('dashboard')

  return (
    <>
      <PageHeader title="Dashboard" context={`${current.name} · ${current.domain} · last 24 hours`} />
      <div className="grid gap-3 lg:grid-cols-[minmax(320px,360px)_minmax(0,1fr)] xl:grid-cols-[minmax(330px,370px)_minmax(0,1fr)_minmax(300px,340px)]">
        <div className="h-[560px] min-w-0 lg:sticky lg:top-[calc(var(--b-header-h)+12px)] lg:h-[calc(100vh-var(--b-header-h)-88px)] lg:min-h-[520px]">
          <AuthStream failure={failure} onClearFailure={() => setFailure(null)} />
        </div>
        <div className="min-w-0 space-y-3">
          <KpiBand />
          <HourlyPanel />
          <ControllersPanel />
          <Panel id="b-sec-failures" aria-labelledby="fail-title">
            <PanelHead id="fail-title" title="Rejections by cause" meta={m.auth.rejects ? `${m.auth.rejects} in 24 h · select one to filter the stream` : undefined} />
            <div className="p-2">
              {m.failures.length ? (
                <FailureBars failures={m.failures} total={m.auth.rejects} selected={failure} onSelect={setFailure} />
              ) : (
                <p className="b-t2 px-2 py-4 text-[12.5px]">{m.auth.total ? 'No rejections in the last 24 hours.' : 'No authentication traffic yet, so there is nothing to break down.'}</p>
              )}
            </div>
          </Panel>
          <AuditPanel />
        </div>
        <div className="grid min-w-0 content-start gap-3 lg:col-span-2 lg:grid-cols-3 xl:col-span-1 xl:grid-cols-1">
          <HealthPanel />
          <Panel aria-labelledby="vlan-title">
            <PanelHead id="vlan-title" title="Accepted sessions by VLAN" meta="24 h" actions={<Button size="sm" variant="ghost" onClick={() => go('policies', { section: 'vlans' })}>VLANs</Button>} />
            <div className="b-panel-body">
              <VlanBar usage={m.vlanUsage} vlans={d.vlans} />
            </div>
          </Panel>
          <ExpiringPanel />
        </div>
      </div>
    </>
  )
}

function KpiBand() {
  const m = useMetrics()
  const d = useTenantData()
  const degraded = d.radiusClients.filter((n) => n.status !== 'ok')
  const cells = [
    {
      label: 'Wi-Fi users',
      value: m.users.toLocaleString('en-US'),
      detail: (
        <>
          {m.authorized} allowed · <span className={m.unauthorized ? 'b-ink-crit' : undefined}>{m.unauthorized} denied</span>
        </>
      ),
    },
    {
      label: 'Active certificates',
      value: m.certificates.active,
      detail: m.certificates.total ? (
        <>
          <span className={m.certificates.expiring ? 'b-ink-warn' : undefined}>{m.certificates.expiring} expiring soon</span>
        </>
      ) : (
        'none issued yet'
      ),
    },
    {
      label: 'Auth success, 24 h',
      value: formatPercent(m.auth.successRate),
      detail: m.auth.total ? (
        <>
          <span className={m.auth.rejects ? 'b-ink-crit' : undefined}>{m.auth.rejects} rejected</span> of {m.auth.total}
        </>
      ) : (
        'no requests yet'
      ),
    },
    {
      label: 'RADIUS clients active',
      value: d.radiusClients.length ? `${m.activeRadiusClients}/${d.radiusClients.length}` : '0',
      detail: degraded.length ? <span className="b-ink-warn">{degraded.map((n) => n.site.split(' ')[0]).join(', ')} degraded</span> : d.radiusClients.length ? 'all active' : 'none registered',
    },
  ]
  return (
    <Panel aria-label="Key figures">
      <div className="b-divide-x-md grid md:grid-cols-4">
        {cells.map((c) => (
          <div key={c.label} className="min-w-0 px-3.5 py-3">
            <p className="text-[12.5px] text-[var(--b-text-2)]">{c.label}</p>
            <p className="b-figure mt-1.5 text-[26px] text-[var(--b-text)]">{c.value}</p>
            <p className="b-num mt-1 truncate text-[12.5px] text-[var(--b-text-2)]">{c.detail}</p>
          </div>
        ))}
      </div>
    </Panel>
  )
}

function HourlyPanel() {
  const m = useMetrics()
  const [table, setTable] = useState(false)
  const peak = m.auth.hourly.reduce((best, p) => (p.accept + p.reject > best.accept + best.reject ? p : best), m.auth.hourly[0])
  return (
    <Panel aria-labelledby="hourly-title">
      <PanelHead
        id="hourly-title"
        title="Authentications per hour"
        meta={m.auth.total ? `${pluralize(m.auth.total, 'request')} · ${formatPercent(m.auth.successRate)} accepted` : undefined}
        actions={
          <>
            <AcceptRejectLegend />
            <Button size="sm" variant="ghost" icon={table ? ChartColumn : Table2} aria-pressed={table} onClick={() => setTable(!table)}>
              {table ? 'Chart' : 'Table'}
            </Button>
          </>
        }
      />
      <div className="px-3 pt-3 pb-2">
        {!m.auth.total ? (
          <p className="b-t2 py-8 text-center text-[12.5px]">No authentication requests in the last 24 hours.</p>
        ) : table ? (
          <div className="max-h-[230px] overflow-y-auto">
            <table className="w-full text-[12.5px]">
              <caption className="sr-only">Authentications per hour, last 24 hours</caption>
              <thead className="sticky top-0 bg-[var(--b-panel)]">
                <tr className="text-left">
                  {['Hour (UTC)', 'Accepted', 'Rejected', 'Success'].map((h, i) => (
                    <th key={h} className={`b-label py-1 font-semibold ${i ? 'text-right' : ''}`}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...m.auth.hourly].reverse().map((p) => (
                  <tr key={p.hourEnd.toISOString()} className="b-num border-t border-[var(--b-line-soft)]">
                    <td className="py-1">
                      {hhmm(new Date(p.hourEnd.getTime() - 3600_000).toISOString())}–{hhmm(p.hourEnd.toISOString())}
                    </td>
                    <td className="text-right">{p.accept}</td>
                    <td className="text-right">{p.reject}</td>
                    <td className="text-right text-[var(--b-text-2)]">{p.accept + p.reject ? formatPercent(p.accept / (p.accept + p.reject), 0) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <>
            <StackedColumns points={m.auth.hourly} height={176} label={`Authentications per hour, last 24 hours. Peak ${peak.accept + peak.reject} in the hour ending ${hhmm(peak.hourEnd.toISOString())} UTC.`} />
          </>
        )}
      </div>
    </Panel>
  )
}

function ControllersPanel() {
  const d = useTenantData()
  const { go } = useShell()
  const series = useMemo(() => d.radiusClients.map((n) => ({ nas: n, events: d.authEvents.filter((e) => e.nasClientId === n.id) })).map((s) => ({ ...s, points: bucketHourly(s.events) })), [d.radiusClients, d.authEvents])
  const shared = Math.max(1, ...series.flatMap((s) => s.points.map((p) => p.accept + p.reject)))
  return (
    <Panel id="b-sec-controllers" aria-labelledby="nas-title">
      <PanelHead
        id="nas-title"
        title="Requests by controller"
        meta={series.length ? 'per hour, shared scale' : undefined}
        actions={
          <Button size="sm" variant="ghost" iconEnd={ArrowRight} onClick={() => go('radius', { section: 'controllers' })}>
            Controllers
          </Button>
        }
      />
      {series.length === 0 ? (
        <EmptyState
          icon={Router}
          title="No wireless controllers registered"
          action={
            <Button size="sm" variant="primary" onClick={() => go('radius', { section: 'controllers' })}>
              Add a controller
            </Button>
          }
        >
          Register the tenant’s Catalyst 9800, AireOS or UniFi controller to start receiving authentication requests.
        </EmptyState>
      ) : (
        <div className={`b-divide-x-md grid ${['', 'md:grid-cols-1', 'md:grid-cols-2', 'md:grid-cols-3'][Math.min(3, series.length)]}`}>
          {series.map(({ nas, events, points }) => {
            const rejects = events.filter((e) => e.result === 'reject').length
            const silent = secondsSince(nas.lastRequestAt)
            const silentState = classify(silent, CONTROLLER_BUDGET)
            return (
              <div key={nas.id} className="min-w-0 px-3 py-3">
                <div className="flex items-start gap-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[13px] font-semibold text-[var(--b-text)]">{nas.name}</p>
                    <p className="truncate text-[12px] text-[var(--b-text-2)]">
                      {vendorLabels[nas.vendor]} · {nas.site}
                    </p>
                  </div>
                </div>
                <div className="mt-1.5 mb-2 text-[12.5px]">
                  {nas.status === 'ok' ? (
                    <StatusText tone="ok">Healthy</StatusText>
                  ) : (
                    <StatusText tone={healthTone[nas.status]}>
                      {healthLabel[nas.status]}: silent {formatAge(silent)}
                    </StatusText>
                  )}
                </div>
                <StackedColumns
                  points={points}
                  height={70}
                  yMax={shared}
                  compact
                  label={`${nas.name}: requests per hour`}
                  marker={nas.status !== 'ok' && nas.lastRequestAt && silentState !== 'fresh' ? { at: new Date(nas.lastRequestAt), label: `Last ${hhmm(nas.lastRequestAt)}` } : undefined}
                />
                <p className="b-num mt-1.5 flex flex-wrap gap-x-2 text-[12px] text-[var(--b-text-2)]">
                  <span>
                    <span className="text-[var(--b-text)]">{events.length}</span> requests
                  </span>
                  <span>
                    <span className={rejects ? 'b-ink-crit' : 'text-[var(--b-text)]'}>{rejects}</span> rejected
                  </span>
                  <span className="ml-auto">last {nas.lastRequestAt ? `${formatAge(silent)} ago` : 'never'}</span>
                </p>
                {nas.status !== 'ok' && <p className="mt-1.5 text-[12px] leading-snug text-[var(--b-text-2)]">Check the controller’s RADIUS server entry and its route to EasyEAP; clients at {nas.site} may be failing over.</p>}
              </div>
            )
          })}
        </div>
      )}
    </Panel>
  )
}

function HealthPanel() {
  const { current } = useTenants()
  const d = useTenantData()
  const issuing = d.cas.find((c) => c.role === 'issuing')
  const root = d.cas.find((c) => c.role === 'root')
  const serverCert = d.certificates.find((c) => c.id === d.radiusSettings?.serverCertificateId)
  const h = current.health
  const syncAge = secondsSince(h.lastDirectorySync)
  const syncState = classify(syncAge, DIRECTORY_BUDGET)
  const snap = h.authzSnapshotAgeSeconds
  const snapState = classify(snap, snapshotBudget(d.defaults.maxSnapshotAgeSeconds))
  const failedSync = d.audit.find((a) => a.action === 'directory.sync.failed')
  const row = (label: string, value: ReactNode, sub?: ReactNode) => (
    <div className="grid grid-cols-[92px_minmax(0,1fr)] gap-x-3 py-1.5">
      <dt className="text-[12.5px] text-[var(--b-text-2)]">{label}</dt>
      <dd className="min-w-0 text-[12.5px]">
        <div className="min-w-0">{value}</div>
        {sub && <div className="truncate text-[12px] text-[var(--b-text-3)]">{sub}</div>}
      </dd>
    </div>
  )
  return (
    <Panel id="b-sec-health" aria-labelledby="health-title">
      <PanelHead id="health-title" title="Service health" />
      <div className="b-divide-y">
        <section className="px-3 py-2" aria-label="PKI">
          <h3 className="b-label mb-0.5">PKI</h3>
          <dl>
            {row('Issuing CA', issuing ? <StatusText tone="ok">Online</StatusText> : '—', issuing && `${issuing.commonName} · until ${formatDate(issuing.notAfter)}`)}
            {row('Root CA', root ? <StatusText tone="ok">Offline (key not held)</StatusText> : '—', root && `${root.commonName} · until ${formatDate(root.notAfter)}`)}
            {row('CRL', issuing?.crl?.nextUpdate ? <span>#{issuing.crl.number} · next in <span className="b-num">{formatAge((new Date(issuing.crl.nextUpdate).getTime() - now().getTime()) / 1000)}</span></span> : '—', issuing?.crl?.lastIssued && `published ${formatAge(secondsSince(issuing.crl.lastIssued))} ago`)}
            {row('OCSP', issuing?.ocsp?.enabled ? <StatusText tone="ok">Responding</StatusText> : <StatusText tone="neutral">Not enabled</StatusText>, issuing?.ocsp?.url ?? undefined)}
          </dl>
        </section>
        <section className="px-3 py-2" aria-label="Directory">
          <h3 className="b-label mb-0.5">Active Directory</h3>
          <dl>
            {row('Status', <StatusText tone={healthTone[h.directory]}>{h.directory === 'unconfigured' ? 'Not connected' : h.directory === 'ok' ? 'Syncing' : 'Sync failing'}</StatusText>, h.directory === 'unconfigured' ? 'Add LDAPS bind credentials to start syncing' : current.domain)}
            {row(
              'Last sync',
              syncAge === null ? 'Never' : <StatusText tone={syncState === 'stale' ? 'crit' : syncState === 'aging' ? 'warn' : 'ok'}>{formatAge(syncAge)} ago</StatusText>,
              h.directory !== 'ok' && failedSync ? failedSync.detail : h.lastDirectorySync ? `${hhmm(h.lastDirectorySync)} UTC · every 15 min` : undefined,
            )}
          </dl>
        </section>
        <section className="px-3 py-2" aria-label="RADIUS">
          <h3 className="b-label mb-0.5">RADIUS</h3>
          <dl>
            {row('Status', <StatusText tone={healthTone[h.radius]}>{h.radius === 'unconfigured' ? 'Not set up' : healthLabel[h.radius]}</StatusText>, d.radiusSettings?.serverHostname)}
            {row('Snapshot', snap === null ? 'None loaded' : <StatusText tone={snapState === 'stale' ? 'crit' : snapState === 'aging' ? 'warn' : 'ok'}>{formatAge(snap)} old</StatusText>, `fails safe after ${formatAge(d.defaults.maxSnapshotAgeSeconds)}`)}
            {row('Server cert', serverCert ? <span>expires in {daysUntil(serverCert.notAfter, now())} days</span> : <StatusText tone="neutral">Not issued</StatusText>, serverCert?.commonName)}
          </dl>
        </section>
      </div>
    </Panel>
  )
}

function ExpiringPanel() {
  const d = useTenantData()
  const { openCertificate, active } = useInspector()
  const { go } = useShell()
  const expiring = d.certificates.filter((c) => c.status === 'expiring' && c.identityId).sort((a, b) => a.notAfter.localeCompare(b.notAfter))
  const top = expiring.slice(0, 6)
  return (
    <Panel id="b-sec-expiring" aria-labelledby="exp-title">
      <PanelHead id="exp-title" title="Expiring soonest" meta={expiring.length ? `${expiring.length} within 30 days` : undefined} />
      {top.length === 0 ? (
        <EmptyState icon={BadgeCheck} title="Nothing expiring in 30 days">
          {d.certificates.length ? 'Every active certificate is valid for at least another month.' : 'No certificates have been issued for this tenant yet.'}
        </EmptyState>
      ) : (
        <>
          <ul>
            {top.map((c) => {
              const dev = d.devices.find((x) => x.id === c.deviceId)
              const who = d.identities.find((i) => i.id === c.identityId)
              const days = daysUntil(c.notAfter, now())
              const isOpen = active?.kind === 'cert' && active.id === c.id
              return (
                <li key={c.id}>
                  <button type="button" onClick={() => openCertificate(c.id)} className={`flex w-full items-center gap-3 border-b border-[var(--b-line-soft)] px-3 py-2 text-left transition-colors hover:bg-[var(--b-hover)] ${isOpen ? 'bg-[#12222e]' : ''}`}>
                    <CalendarClock className={`size-4 shrink-0 ${days <= 7 ? 'b-ink-crit' : 'b-ink-warn'}`} aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] text-[var(--b-text)]">{dev?.name ?? c.commonName}</span>
                      <span className="block truncate text-[12px] text-[var(--b-text-2)]">{who?.displayName}</span>
                    </span>
                    <span className="text-right">
                      <span className="b-figure b-num block text-[17px] text-[var(--b-text)]">{days}d</span>
                      <span className="b-num block text-[11.5px] text-[var(--b-text-3)]">{formatDate(c.notAfter)}</span>
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
          <div className="px-3 py-2">
            <button type="button" className="b-link inline-flex items-center gap-1 text-[12.5px]" onClick={() => go('certificates', { section: 'inventory', filters: { status: 'expiring' } })}>
              All {expiring.length} expiring certificates <ArrowRight className="size-3.5" aria-hidden />
            </button>
          </div>
        </>
      )}
    </Panel>
  )
}

function AuditPanel() {
  const d = useTenantData()
  const rows = d.audit.slice(0, 6)
  return (
    <Panel aria-labelledby="audit-title">
      <PanelHead id="audit-title" title="Recent certificate and audit activity" actions={<History className="size-4 text-[var(--b-text-3)]" aria-hidden />} />
      {rows.length === 0 ? (
        <p className="b-t2 px-3 py-4 text-[12.5px]">No activity recorded yet.</p>
      ) : (
        <ul className="b-divide-y">
          {rows.map((a) => (
            <li key={a.id} className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 px-3 py-2">
              <span className="b-num text-[12px] text-[var(--b-text-2)]">{a.at > now().toISOString() ? 'just now' : `${formatAge(secondsSince(a.at))} ago`}</span>
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[13px]">
                  <span className="b-mono rounded bg-[var(--b-raised)] px-1.5 py-px text-[11.5px] text-[var(--b-text-2)]">{a.action}</span>
                  <span className="truncate text-[var(--b-text)]">{a.target}</span>
                </p>
                <p className="mt-0.5 line-clamp-2 text-[12.5px] text-[var(--b-text-2)]">{a.detail}</p>
                <p className="mt-0.5 text-[12px] text-[var(--b-text-3)]">{a.actor}</p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
