import { useMemo, useState, type ReactNode } from 'react'
import { ArrowRight, CircleDashed, FileKey, Router, ShieldCheck, TriangleExclamationPoint, Waypoints } from 'lucide-react'
import { useMetrics, useTenantData, useTenants, now } from '@/prototype/store'
import { failureExplanations, vendorLabels } from '@/domain/explain'
import type { AuditEvent, AuthEvent } from '@/domain/types'
import { daysUntil, formatDate, formatDateTime, formatDuration, formatPercent, formatTime } from '@/ui/lib'
import { RouteMap, type MapSelection } from '../RouteMap'
import { HourlyChart } from '../HourlyChart'
import { Inspector, InspectorSection } from '../Inspector'
import { PolicyRoute } from '../PolicyRoute'
import { REJECTED, buildRouteData, outcomeKeyOf, type Outcome, type RouteData, type Station } from '../routes'
import { DataTable } from '../DataTable'
import { STATUS, ago, isSessionAudit, plural } from '../theme'
import { Button, Callout, EmptyState, LineBullet, PageHeader, Panel, RejectBullet, StatusIcon, StatusMark, VolumeGlyph, useE } from '../ui'

export function Dashboard() {
  const { current } = useTenants()
  const d = useTenantData()
  const m = useMetrics()
  const { go } = useE()
  const data = useMemo(() => buildRouteData(d.radiusClients, d.vlans, d.authEvents), [d.radiusClients, d.vlans, d.authEvents])
  const [sel, setSel] = useState<MapSelection>(null)
  const h = current.health
  const snapshot = h.authzSnapshotAgeSeconds === null ? 'No authorization snapshot yet' : `Snapshot ${formatDuration(h.authzSnapshotAgeSeconds)} old`
  const enabledRules = d.rules.filter((r) => r.enabled).length
  const policySummary = `${enabledRules} rules · deny wins · default ${d.defaults.defaultAction}`

  const issues: Array<{ state: 'degraded' | 'down' | 'unconfigured'; text: ReactNode; action?: ReactNode }> = []
  for (const c of d.radiusClients.filter((x) => x.status === 'degraded' || x.status === 'down')) {
    issues.push({
      state: c.status as 'degraded',
      text: <><strong>{c.name}</strong> is {STATUS[c.status].label.toLowerCase()}: last request {ago(c.lastRequestAt)}, while the other controllers report within the minute.</>,
      action: <Button size="sm" variant="secondary" onClick={() => setSel({ type: 'station', id: c.id })}>Inspect station</Button>,
    })
  }
  if (h.directory === 'degraded' || h.directory === 'down') {
    const fail = d.audit.find((a) => a.action === 'directory.sync.failed')
    issues.push({ state: 'degraded', text: <><strong>Directory sync failing</strong> since {ago(h.lastDirectorySync)}{fail ? `: ${fail.detail}` : ''}. RADIUS denies when authorization data is older than {formatDuration(d.defaults.maxSnapshotAgeSeconds)}.</> })
  }
  if (current.status === 'setup') {
    issues.push({ state: 'unconfigured', text: <><strong>Setup in progress.</strong> {d.radiusClients.length === 0 ? 'No wireless controller is registered, ' : ''}{h.directory === 'unconfigured' ? 'Active Directory is not connected, ' : ''}so no one can authenticate yet.</>, action: <Button size="sm" variant="secondary" onClick={() => go('tenants')}>View setup steps</Button> })
  }

  const activeClients = d.radiusClients.filter((c) => c.status === 'ok').length
  const rate = m.auth.successRate

  return (
    <>
      <PageHeader
        title={current.name}
        meta={<>
          <span>{current.domain}</span>
          <span aria-hidden className="t3">·</span>
          <span className="num">Last 24 hours to {formatDateTime(now().toISOString())}</span>
          {current.status === 'setup' && <span className="e-tag"><CircleDashed aria-hidden />Setup in progress</span>}
        </>}
        actions={<>
          <Button variant="secondary" onClick={() => go('policies', { intent: { kind: 'policies.test' } })}><Waypoints />Test a user</Button>
          <Button variant="primary" onClick={() => go('users', { intent: { kind: 'issue' } })}><ShieldCheck />Issue Wi-Fi certificate</Button>
        </>}
      />

      {issues.length > 0 && (
        <section aria-label="Needs attention" className="mb-4 overflow-hidden rounded-[var(--e-radius)] border border-[rgba(227,179,65,0.32)] bg-[rgba(227,179,65,0.06)]">
          <ul className="e-divide">
            {issues.map((it, i) => (
              <li key={i} className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5 text-[13.5px]">
                <StatusIcon state={it.state} size={17} />
                <p className="min-w-0 flex-[1_1_240px]">{it.text}</p>
                {it.action}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Readout strip: typographic, not tiles */}
      <div className="e-strip mb-4 grid-cols-1 min-[900px]:grid-cols-5">
        <Readout label="Wi-Fi users" value={m.users} onClick={() => go('users')}>
          <button type="button" className="hover:underline" onClick={() => go('users', { intent: { kind: 'users.filter', access: 'allow' } })}><span className="num">{m.authorized}</span> authorized</button>
          <span aria-hidden className="t3 mx-1">·</span>
          <button type="button" className="hover:underline" onClick={() => go('users', { intent: { kind: 'users.filter', access: 'deny' } })}><span className="num">{m.unauthorized}</span> unauthorized</button>
        </Readout>
        <Readout label="Active device certificates" value={m.certificates.active} onClick={() => go('certificates', { intent: { kind: 'certs.filter', status: 'active' } })}>
          <button type="button" className="hover:underline" onClick={() => go('certificates', { intent: { kind: 'certs.filter', status: 'expiring' } })}><span className="num">{m.certificates.expiring}</span> expiring</button>
          <span aria-hidden className="t3 mx-1">·</span>
          <button type="button" className="hover:underline" onClick={() => go('certificates', { intent: { kind: 'certs.filter', status: 'revoked' } })}><span className="num">{m.certificates.revoked}</span> revoked</button>
          <span aria-hidden className="t3 mx-1">·</span>
          <span className="num">{m.certificates.expired}</span> expired
        </Readout>
        <Readout label="RADIUS clients active" value={<>{activeClients}<span className="t3 text-[18px] font-semibold"> / {d.radiusClients.length}</span></>} onClick={() => go('radius', { intent: { kind: 'scroll', target: 'controllers' } })}>
          {d.radiusClients.length === 0 ? 'None registered' : d.radiusClients.length - activeClients > 0 ? <span className="inline-flex items-center gap-1.5"><StatusIcon state="degraded" size={14} />{d.radiusClients.length - activeClients} degraded</span> : 'All reporting'}
        </Readout>
        <Readout label="Authorization snapshot" value={h.authzSnapshotAgeSeconds === null ? '—' : formatDuration(h.authzSnapshotAgeSeconds)} unit={h.authzSnapshotAgeSeconds === null ? undefined : 'old'}>
          Fails closed after {formatDuration(d.defaults.maxSnapshotAgeSeconds)}
        </Readout>
        <Readout label="Directory sync" value={h.lastDirectorySync ? ago(h.lastDirectorySync).replace(' ago', '') : '—'} unit={h.lastDirectorySync ? 'ago' : undefined}>
          <StatusMark state={h.directory} label={h.directory === 'ok' ? 'Active Directory connected' : h.directory === 'unconfigured' ? 'Not connected' : 'Sync failing'} />
        </Readout>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="min-w-0 xl:col-span-8">
          <RouteMap data={data} selection={sel} onSelect={setSel} policySummary={policySummary} snapshotLabel={snapshot} onAddController={() => go('radius', { entityId: 'new' })} />
        </div>
        <Panel className="xl:col-span-4" title="Authentication success" desc="Last 24 hours, all controllers" bodyClassName="px-4 pb-4">
          {rate === null ? (
            <p className="t2 text-[13px]">No authentications yet, so there is no success rate. It appears after the first request from a registered controller.</p>
          ) : (
            <div className="flex flex-wrap items-end gap-x-4 gap-y-1">
              <p className="text-[52px] font-semibold leading-none tracking-[-0.03em]">{formatPercent(rate)}</p>
              <p className="t2 pb-1.5 text-[13px]"><span className="num text-[var(--e-text)]">{m.auth.accepts}</span> accepted · <span className="num text-[var(--e-text)]">{m.auth.rejects}</span> rejected</p>
            </div>
          )}
          <div className="mt-4"><HourlyChart points={m.auth.hourly} /></div>
          <div className="mt-5">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-[13px] font-bold">Why authentications failed</h3>
              {m.failures.length > 0 && <button type="button" className="t2 text-[12.5px] hover:text-[var(--e-text)] hover:underline" onClick={() => setSel({ type: 'outcome', key: REJECTED })}>Open Rejected terminus</button>}
            </div>
            {m.failures.length === 0 ? (
              <p className="t2 text-[13px]">No failures in the last 24 hours.</p>
            ) : (
              <ul className="space-y-2">
                {m.failures.slice(0, 5).map(([code, n]) => (
                  <li key={code} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 text-[13px]">
                    <span className="truncate">{failureExplanations[code as keyof typeof failureExplanations]?.title ?? code}</span>
                    <span className="num font-semibold">{n}</span>
                    <span className="col-span-2 block h-1.5 rounded-full bg-[rgba(167,177,194,0.1)]"><span className="block h-full rounded-full bg-[#7F8CA3]" style={{ width: `${(n / m.failures[0][1]) * 100}%` }} /></span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>
      </div>

      <ServiceHealth />

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-12">
        <Panel className="xl:col-span-8" title="Recent authentications" desc="Newest first. Select a row to open the user." actions={<Button size="sm" variant="ghost" onClick={() => go('users')}>All users<ArrowRight /></Button>}>
          <RecentAuth events={d.authEvents.slice(0, 8)} />
        </Panel>
        <Panel className="xl:col-span-4" title="Certificate and audit activity" desc="Who changed what">
          <AuditList rows={d.audit.slice(0, 5)} />
        </Panel>
      </div>

      <MapInspector data={data} sel={sel} onClose={() => setSel(null)} policySummary={policySummary} snapshot={snapshot} />
    </>
  )
}

function Readout({ label, value, unit, children, onClick }: { label: string; value: ReactNode; unit?: string; children?: ReactNode; onClick?: () => void }) {
  return (
    <div>
      <p className="e-label">{label}</p>
      <p className="mt-1 text-[28px] font-semibold leading-tight tracking-[-0.02em]">
        {onClick ? <button type="button" className="rounded-md hover:underline" onClick={onClick}>{value}</button> : value}
        {unit && <span className="t2 ml-1.5 text-[14px] font-semibold tracking-normal">{unit}</span>}
      </p>
      {children && <div className="t2 mt-0.5 text-[12.5px]">{children}</div>}
    </div>
  )
}

function ServiceHealth() {
  const { current } = useTenants()
  const d = useTenantData()
  const h = current.health
  const root = d.cas.find((c) => c.role === 'root')
  const iss = d.cas.find((c) => c.role === 'issuing')
  const s = d.radiusSettings
  const serverCert = d.certificates.find((c) => c.id === s?.serverCertificateId)
  return (
    <section aria-label="Service health" className="e-strip mt-4 grid-cols-1 min-[900px]:grid-cols-3">
      <div>
        <div className="mb-2 flex items-center justify-between gap-2"><h2 className="text-[14px] font-bold">PKI</h2><StatusMark state={h.pki} /></div>
        <dl className="e-dl">
          <dt>Issuing CA</dt><dd>{iss ? <>{iss.commonName}<span className="t2 block text-[12px]">Expires {formatDate(iss.notAfter)} · in {daysUntil(iss.notAfter, now())} days</span></> : 'Not created'}</dd>
          <dt>Root CA</dt><dd>{root ? <>{root.offline ? 'Offline' : 'Online'}<span className="t2 block text-[12px]">Key not held by EasyEAP · expires {formatDate(root.notAfter)}</span></> : 'Not created'}</dd>
          <dt>CRL next update</dt><dd className="num">{iss?.crl?.nextUpdate ? <>{formatDateTime(iss.crl.nextUpdate)}<span className="t2 block text-[12px]">CRL #{iss.crl.number} published {ago(iss.crl.lastIssued)}</span></> : '—'}</dd>
          <dt>OCSP</dt><dd>{iss?.ocsp?.enabled ? 'Responding' : 'Disabled'}</dd>
        </dl>
      </div>
      <div>
        <div className="mb-2 flex items-center justify-between gap-2"><h2 className="text-[14px] font-bold">Directory</h2><StatusMark state={h.directory} label={h.directory === 'degraded' ? 'Sync failing' : undefined} /></div>
        <dl className="e-dl">
          <dt>Domain</dt><dd>{current.domain}</dd>
          <dt>Connection</dt><dd>{h.directory === 'unconfigured' ? 'Not connected' : 'LDAPS, Active Directory'}</dd>
          <dt>Last sync</dt><dd>{h.lastDirectorySync ? <>{ago(h.lastDirectorySync)}<span className="t2 block text-[12px]">{formatDateTime(h.lastDirectorySync)}</span></> : 'Never'}</dd>
          <dt>Synced users</dt><dd className="num">{d.identities.filter((i) => i.source === 'ad').length} directory · {d.identities.filter((i) => i.source === 'local').length} local</dd>
        </dl>
      </div>
      <div>
        <div className="mb-2 flex items-center justify-between gap-2"><h2 className="text-[14px] font-bold">RADIUS</h2><StatusMark state={h.radius} /></div>
        <dl className="e-dl">
          <dt>Server</dt><dd className="mono">{s?.serverHostname ?? '—'}</dd>
          <dt>Ports</dt><dd className="num">UDP {s?.authPort ?? 1812} auth · {s?.acctPort ?? 1813} acct</dd>
          <dt>Controllers</dt><dd className="num">{d.radiusClients.length === 0 ? 'None registered' : (() => { const bad = d.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down').length; return bad ? <span className="inline-flex items-center gap-1.5"><StatusIcon state="degraded" size={14} />{d.radiusClients.length - bad} of {d.radiusClients.length} reporting</span> : `All ${d.radiusClients.length} reporting` })()}</dd>
          <dt>Snapshot age</dt><dd className="num">{h.authzSnapshotAgeSeconds === null ? 'No snapshot loaded' : `${formatDuration(h.authzSnapshotAgeSeconds)} (max ${formatDuration(d.defaults.maxSnapshotAgeSeconds)})`}</dd>
          <dt>Server certificate</dt><dd>{serverCert ? <>Expires {formatDate(serverCert.notAfter)}<span className="t2 block text-[12px]">in {daysUntil(serverCert.notAfter, now())} days</span></> : <span className="inline-flex items-center gap-1.5"><StatusIcon state="unconfigured" />Not issued</span>}</dd>
        </dl>
      </div>
    </section>
  )
}

function OutcomeRef({ o }: { o: Outcome | undefined }) {
  if (!o) return <span className="t3">—</span>
  return <span className="inline-flex min-w-0 items-center gap-2">{o.reject ? <RejectBullet size={20} /> : o.vlan ? <LineBullet vlan={o.vlan} size={20} /> : null}<span className="truncate">{o.reject ? 'Rejected' : o.label}</span></span>
}

function RecentAuth({ events }: { events: AuthEvent[] }) {
  const d = useTenantData()
  const { go } = useE()
  return (
    <DataTable
      caption="Recent authentications"
      rows={events}
      rowKey={(e) => e.id}
      onActivate={(e) => e.identityId && go('user', { entityId: e.identityId })}
      empty={<EmptyState icon={<Router />} title="No authentications yet" body="Events appear here as soon as a registered controller sends its first RADIUS request." />}
      columns={[
        { key: 't', header: 'Time (UTC)', cell: (e) => <span className="num t2">{formatTime(e.at)}</span>, width: '96px' },
        { key: 'u', header: 'User', cell: (e) => { const i = d.identities.find((x) => x.id === e.identityId); return <span className="block min-w-0 truncate"><button type="button" data-row-primary className="e-rowlink" onClick={() => e.identityId && go('user', { entityId: e.identityId })}>{i?.displayName ?? e.username ?? 'Unknown'}</button></span> } },
        { key: 'r', header: 'Result', cell: (e) => <StatusMark state={e.result === 'accept' ? 'ok' : 'down'} label={e.result === 'accept' ? 'Accepted' : 'Rejected'} /> },
        { key: 'd', header: 'Destination or reason', cell: (e) => e.result === 'accept' ? <OutcomeRef o={{ key: e.vlanId ?? '', vlan: d.vlans.find((v) => v.id === e.vlanId) ?? null, label: d.vlans.find((v) => v.id === e.vlanId)?.name ?? 'No VLAN', color: '', ink: '', total: 0, reject: false }} /> : <span className="t2">{e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'}</span> },
        { key: 'n', header: 'Controller', cell: (e) => <span className="t2 truncate">{d.radiusClients.find((c) => c.id === e.nasClientId)?.name ?? '—'}</span>, hideBelow: 'lg' },
      ]}
    />
  )
}

const ACTION_LABEL: Record<string, string> = {
  'certificate.issue': 'Certificate issued',
  'certificate.revoke': 'Certificate revoked',
  'directory.sync': 'Directory synced',
  'directory.sync.failed': 'Directory sync failed',
  'pki.crl.publish': 'CRL published',
  'policy.rule.update': 'Rule changed',
  'policy.rule.reorder': 'Rule reordered',
  'radius.client.rotate_secret': 'Secret rotated',
  'radius.client.create': 'Controller registered',
  'tenant.create': 'Tenant created',
  'admin.role.grant': 'Role granted',
}

export function AuditList({ rows }: { rows: AuditEvent[] }) {
  if (!rows.length) return <EmptyState icon={<FileKey />} title="No activity yet" />
  return (
    <ol className="e-divide border-t border-[var(--e-hair)]">
      {rows.map((a) => (
        <li key={a.id} className="px-4 py-2.5">
          <div className="flex items-baseline justify-between gap-3">
            <p className="text-[13px] font-semibold">{ACTION_LABEL[a.action] ?? a.action}<span className="t2 font-normal"> · {a.target}</span>{a.tenantId === null && <span className="e-tag ml-2 !h-5 align-[1px] !text-[11px]" title="Portfolio-level change, visible in every tenant">Portfolio</span>}</p>
            <span className="t3 shrink-0 text-[12px]">{ago(a.at, isSessionAudit(a.id))}</span>
          </div>
          <p className="t2 mt-0.5 line-clamp-2 text-[12.5px]">{a.detail}</p>
          <p className="t3 mt-0.5 text-[12px]">{a.actor}</p>
        </li>
      ))}
    </ol>
  )
}

// ── Inspector for map selections ─────────────────────────────────────────
function MapInspector({ data, sel, onClose, policySummary, snapshot }: { data: RouteData; sel: MapSelection; onClose: () => void; policySummary: string; snapshot: string }) {
  const d = useTenantData()
  const { go } = useE()
  const station = sel?.type === 'station' ? data.stations.find((s) => s.id === sel.id) : undefined
  const outcome = sel?.type === 'outcome' ? data.outcomes.find((o) => o.key === sel.key) : undefined
  if (sel?.type === 'interchange') {
    return (
      <Inspector open onClose={onClose} title="EasyEAP policy" subtitle={policySummary} label="Policy interchange"
        footer={<><Button variant="secondary" onClick={() => go('policies', { intent: { kind: 'policies.test' } })}>Test a user</Button><Button variant="primary" onClick={() => go('policies')}>Edit VLAN policies</Button></>}>
        <p className="t2 mb-3 text-[13px]">Every authentication passes through this policy. The route below is the order RADIUS evaluates it in; {snapshot.toLowerCase()}.</p>
        <PolicyRoute rules={d.rules} vlans={d.vlans} groups={d.groups} defaults={d.defaults} />
      </Inspector>
    )
  }
  if (station) return <StationInspector station={station} data={data} onClose={onClose} />
  if (outcome) return <OutcomeInspector outcome={outcome} data={data} onClose={onClose} />
  return null
}

function StationInspector({ station: s, data, onClose }: { station: Station; data: RouteData; onClose: () => void }) {
  const d = useTenantData()
  const { go } = useE()
  const c = s.client
  const events = data.events.filter((e) => e.nasClientId === c.id).slice(0, 6)
  return (
    <Inspector open onClose={onClose} title={c.name} subtitle={`${c.site} · ${vendorLabels[c.vendor]}`} label="Controller station"
      footer={<Button variant="primary" onClick={() => go('radius', { entityId: c.id })}><Router />Open in RADIUS</Button>}>
      <div className="mb-4"><StatusMark state={c.status} /></div>
      {c.status === 'degraded' && (
        <Callout tone="warn" className="mb-4" icon={<TriangleExclamationPoint color={STATUS.degraded.hex} aria-hidden />}>
          <p className="font-semibold">Last request {ago(c.lastRequestAt)}</p>
          <p className="t2 mt-0.5">The other controllers reported within the minute, so this one is probably not reaching EasyEAP. Its line is drawn faded until it reports again.</p>
          <p className="mt-1.5">Check that UDP {d.radiusSettings?.authPort ?? 1812}/{d.radiusSettings?.acctPort ?? 1813} from {c.address} reaches {d.radiusSettings?.serverHostname}, and that the shared secret on the controller matches.</p>
        </Callout>
      )}
      <dl className="e-dl">
        <dt>Address</dt><dd className="mono">{c.address}</dd>
        <dt>CoA</dt><dd>{c.coaEnabled ? `Enabled · UDP ${c.coaPort}` : 'Off: revoked devices stay on until they reauthenticate'}</dd>
        <dt>Shared secret</dt><dd>Rotated {ago(c.secretSetAt)}</dd>
        <dt>Last request</dt><dd>{ago(c.lastRequestAt)}</dd>
        <dt>Accepted</dt><dd className="num">{s.accepts} of {s.total} ({s.total ? formatPercent(s.accepts / s.total) : '—'})</dd>
      </dl>
      <InspectorSection title="Routes from this station">
        {s.total === 0 ? <p className="t2 text-[13px]">No traffic in the last 24 hours. The line is dashed: configured, idle.</p> : (
          <ul className="space-y-1.5">
            {data.outcomes.filter((o) => (s.byOutcome.get(o.key) ?? 0) > 0).map((o) => {
              const n = s.byOutcome.get(o.key)!
              return (
                <li key={o.key} className="grid grid-cols-[minmax(0,1fr)_44px_40px] items-center gap-3 text-[13px]">
                  <OutcomeRef o={o} />
                  <VolumeGlyph count={n} color={o.color} form={s.form === 'degraded' ? 'degraded' : 'live'} />
                  <span className="num text-right font-semibold">{n}</span>
                </li>
              )
            })}
          </ul>
        )}
      </InspectorSection>
      <InspectorSection title="Latest events">
        <EventList events={events} />
      </InspectorSection>
    </Inspector>
  )
}

function OutcomeInspector({ outcome: o, data, onClose }: { outcome: Outcome; data: RouteData; onClose: () => void }) {
  const d = useTenantData()
  const { go } = useE()
  const events = data.events.filter((e) => outcomeKeyOf(e) === o.key)
  const rules = d.rules.filter((r) => (o.reject ? r.action === 'deny' : r.vlanId === o.key))
  const byStation = data.stations.map((s) => ({ s, n: s.byOutcome.get(o.key) ?? 0 })).filter((x) => x.n > 0)
  const reasons = new Map<string, number>()
  if (o.reject) for (const e of events) if (e.failureCode) reasons.set(e.failureCode, (reasons.get(e.failureCode) ?? 0) + 1)
  return (
    <Inspector open onClose={onClose}
      leading={o.reject ? <RejectBullet size={30} /> : o.vlan ? <LineBullet vlan={o.vlan} size={30} /> : null}
      title={o.reject ? 'Rejected' : `VLAN ${o.vlan?.vlanId} · ${o.label}`}
      subtitle={o.reject ? `${plural(o.total, 'authentication')} rejected in 24 hours` : o.vlan?.description}
      label="Route terminus"
      footer={<Button variant="primary" onClick={() => go('policies')}>Open VLAN policies</Button>}>
      {!o.reject && o.vlan && (
        <dl className="e-dl mb-1">
          <dt>Authentications</dt><dd className="num">{o.total} in 24 hours ({data.total ? formatPercent(o.total / data.total) : '0%'})</dd>
          <dt>Reply attributes</dt><dd className="mono text-[12px] leading-relaxed">Tunnel-Type = VLAN (13)<br />Tunnel-Medium-Type = IEEE-802 (6)<br />Tunnel-Private-Group-ID = {o.vlan.vlanId}</dd>
          <dt>Routed by</dt><dd>{rules.length ? rules.map((r) => <span key={r.id} className="block">P{r.priority} {r.name}{!r.enabled && ' (disabled)'}</span>) : 'No rule routes here'}</dd>
        </dl>
      )}
      {o.reject && (
        <InspectorSection title="Reasons, in plain language">
          {reasons.size === 0 ? <p className="t2 text-[13px]">No rejections in the last 24 hours.</p> : (
            <ul className="space-y-3">
              {[...reasons.entries()].sort((a, b) => b[1] - a[1]).map(([code, n]) => {
                const x = failureExplanations[code as keyof typeof failureExplanations]
                return (
                  <li key={code} className="rounded-lg border border-[var(--e-hair)] p-3 text-[13px]">
                    <div className="flex items-baseline justify-between gap-3"><p className="font-bold">{x.title}</p><span className="num font-semibold">{n}</span></div>
                    <p className="t2 mt-1">{x.explanation}</p>
                    <p className="mt-1"><span className="font-semibold">Fix: </span>{x.fix}</p>
                  </li>
                )
              })}
            </ul>
          )}
        </InspectorSection>
      )}
      <InspectorSection title="By controller">
        {byStation.length === 0 ? <p className="t2 text-[13px]">No traffic in the last 24 hours.</p> : (
          <ul className="space-y-1.5">
            {byStation.map(({ s, n }) => (
              <li key={s.id} className="grid grid-cols-[minmax(0,1fr)_44px_40px] items-center gap-3 text-[13px]">
                <span className="truncate">{s.client.name}</span>
                <VolumeGlyph count={n} color={o.color} form={s.form === 'degraded' ? 'degraded' : 'live'} />
                <span className="num text-right font-semibold">{n}</span>
              </li>
            ))}
          </ul>
        )}
      </InspectorSection>
      <InspectorSection title="Latest arrivals">
        <EventList events={events.slice(0, 6)} />
      </InspectorSection>
    </Inspector>
  )
}

function EventList({ events }: { events: AuthEvent[] }) {
  const d = useTenantData()
  const { go } = useE()
  if (!events.length) return <p className="t2 text-[13px]">No events in the last 24 hours.</p>
  return (
    <ul className="e-divide rounded-lg border border-[var(--e-hair)]">
      {events.map((e) => {
        const i = d.identities.find((x) => x.id === e.identityId)
        const v = d.vlans.find((x) => x.id === e.vlanId)
        return (
          <li key={e.id} className="flex items-center gap-3 px-3 py-2 text-[13px]">
            <span className="num t2 w-[64px] shrink-0">{formatTime(e.at)}</span>
            <button type="button" className="e-rowlink min-w-0 flex-1 truncate" onClick={() => e.identityId && go('user', { entityId: e.identityId })}>{i?.displayName ?? e.username ?? 'Unknown'}</button>
            {e.result === 'accept' ? (v ? <LineBullet vlan={v} size={20} /> : null) : <span className="t2 max-w-[150px] truncate text-[12px]">{e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'}</span>}
            <span className="sr-only">{e.result === 'accept' ? `Accepted to VLAN ${v?.vlanId ?? ''}` : 'Rejected'}</span>
          </li>
        )
      })}
    </ul>
  )
}
