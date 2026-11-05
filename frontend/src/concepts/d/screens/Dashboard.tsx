import { CircleCheck, CircleDashed, CircleX, Lock, RadioTower, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { failureExplanations } from '@/domain/explain'
import { now, useDecisions, useMetrics, useTenantData, useTenants } from '@/prototype/store'
import { daysUntil, formatDate, formatDuration, formatPercent } from '@/ui/lib'
import type { ScreenId } from '../../contract'
import { ruleCode, siteCode, vlanTone, type TapeCode } from '../model/codes'
import { auditLabel, relTime, setupSteps, snapshotFrom, utcClock } from '../model/derive'
import { EMPTY_CERTS, EMPTY_USERS, useViewState } from '../model/state'
import { HourlyChart, RankedBars, SegmentBar } from '../ui/Charts'
import { EmptyState, MetaSep, PageHeader, Section } from '../ui/Section'
import { HealthMark, StatusMark } from '../ui/Status'
import { DataTable, type TableColumn } from '../ui/Table'
import { CaTape, CertTape, NasTape, Tape, VlanTape } from '../ui/Tape'
import type { AuthEvent } from '@/domain/types'

type Nav = (s: ScreenId, id?: string) => void

interface QueueItem {
  key: string
  severity: 'crit' | 'warn' | 'setup'
  tape: ReactNode
  title: string
  detail: ReactNode
  action: { label: string; run: () => void }
}

function useNeedsAction(navigate: Nav): QueueItem[] {
  const { current } = useTenants()
  const d = useTenantData()
  const m = useMetrics()
  const decisions = useDecisions()
  const vs = useViewState()
  const site = siteCode(current)
  const items: QueueItem[] = []

  for (const n of d.radiusClients.filter((x) => x.status === 'degraded' || x.status === 'down')) {
    items.push({
      key: n.id,
      severity: n.status === 'down' ? 'crit' : 'warn',
      tape: <NasTape nas={n} all={d.radiusClients} />,
      title: `${n.name} is ${n.status === 'down' ? 'down' : 'degraded'}`,
      detail: <>No RADIUS request since {n.lastRequestAt ? `${utcClock(n.lastRequestAt)} UTC (${relTime(n.lastRequestAt).toLowerCase()})` : 'registration'}; the other controllers answer every few minutes. Check that {n.site} can reach <span className="mono">{d.radiusSettings?.serverHostname}</span> on UDP {d.radiusSettings?.authPort} and that the shared secret matches.</>,
      action: { label: 'Open controller', run: () => { vs.setRadiusSelected(n.id); navigate('radius') } },
    })
  }

  const h = current.health
  if (h.directory === 'degraded' || h.directory === 'down') {
    const failure = d.audit.find((a) => a.action === 'directory.sync.failed')
    items.push({
      key: 'directory',
      severity: 'warn',
      tape: <Tape code={{ site, body: 'DIR' }} />,
      title: `Directory sync failing, last success ${relTime(h.lastDirectorySync).toLowerCase()}`,
      detail: <>{failure ? `${failure.detail}. ` : ''}RADIUS keeps answering from the authorization snapshot loaded {formatDuration(h.authzSnapshotAgeSeconds ?? 0)} ago and fails safe (denies) once it is older than {formatDuration(d.defaults.maxSnapshotAgeSeconds)}. Install the domain controller’s issuing CA for LDAPS.</>,
      action: { label: 'Review users', run: () => navigate('users') },
    })
  }

  const userCerts = d.certificates.filter((c) => c.identityId)
  const expiring = userCerts.filter((c) => c.status === 'expiring').sort((a, b) => a.notAfter.localeCompare(b.notAfter))
  if (expiring.length) {
    const first = expiring[0]
    const dev = d.devices.find((x) => x.id === first.deviceId)
    const days = daysUntil(first.notAfter, now())
    items.push({
      key: 'expiring',
      severity: 'warn',
      tape: <CertTape cert={first} />,
      title: `${expiring.length} certificates expire within 30 days`,
      detail: <>Soonest: {dev?.name ?? first.commonName} in {days} {days === 1 ? 'day' : 'days'}. Nothing renews automatically; users renew from their enrollment link.</>,
      action: { label: 'Review expiring', run: () => { vs.setCerts({ ...EMPTY_CERTS, status: 'expiring' }); navigate('certificates') } },
    })
  }
  const expired = userCerts.filter((c) => c.status === 'expired')
  if (expired.length) {
    const rejects = d.authEvents.filter((e) => e.failureCode === 'cert_expired').length
    items.push({
      key: 'expired',
      severity: 'crit',
      tape: <CertTape cert={expired[0]} />,
      title: `${expired.length} certificates have expired`,
      detail: <>These devices are rejected at authentication{rejects ? ` (${rejects} rejections in the last 24 hours)` : ''}. Re-issue or revoke them so the list stays clean.</>,
      action: { label: 'Review expired', run: () => { vs.setCerts({ ...EMPTY_CERTS, status: 'expired' }); navigate('certificates') } },
    })
  }
  if (m.unauthorized > 0) {
    const denied = d.identities.filter((i) => decisions.get(i.id)?.outcome === 'deny')
    const byAccount = denied.filter((i) => i.accountState !== 'enabled').length
    const byRule = denied.filter((i) => decisions.get(i.id)?.decidingRuleId).length
    const denyRule = d.rules.find((r) => r.action === 'deny' && r.enabled)
    items.push({
      key: 'unauthorized',
      severity: 'warn',
      tape: denyRule ? <Tape code={ruleCode(denyRule)} tone="deny" /> : <Tape code={{ site, body: 'USR' }} />,
      title: `${m.unauthorized} ${m.unauthorized === 1 ? 'user' : 'users'} can’t join Wi-Fi`,
      detail: <>{[byAccount && `${byAccount} disabled, locked or deleted in Active Directory`, byRule && `${byRule} denied by ${denyRule ? `“${denyRule.name}”` : 'a deny rule'}`, denied.length - byAccount - byRule > 0 && `${denied.length - byAccount - byRule} match no rule`].filter(Boolean).join(' · ')}. Check these are intended before their devices are reissued.</>,
      action: { label: 'Review denied users', run: () => { vs.setUsers({ ...EMPTY_USERS, access: 'deny' }); navigate('users') } },
    })
  }
  if (current.status === 'setup') {
    const snap = snapshotFrom({ identities: d.identities, allowed: m.authorized, certificates: d.certificates, authEvents: d.authEvents, radiusClients: d.radiusClients, hasServerCert: !!d.radiusSettings?.serverCertificateId })
    const tapes: Record<string, TapeCode> = { directory: { site, body: 'DIR' }, 'server-cert': { site, body: 'CRT·SRV' }, controller: { site, body: 'NAS·01' }, 'first-cert': { site, body: 'CRT·0001' } }
    const actions: Record<string, { label: string; run: () => void }> = {
      directory: { label: 'Open users', run: () => navigate('users') },
      'server-cert': { label: 'Open RADIUS', run: () => navigate('radius') },
      controller: { label: 'Add controller', run: () => navigate('radius') },
      'first-cert': { label: 'Choose a user', run: () => navigate('users') },
    }
    for (const step of setupSteps(current, snap).filter((s) => !s.done)) {
      items.push({ key: step.key, severity: 'setup', tape: <Tape code={tapes[step.key] ?? { site, body: 'SETUP' }} />, title: step.label, detail: step.detail, action: actions[step.key] ?? { label: 'Open', run: () => navigate('tenants') } })
    }
  }
  const order = { crit: 0, warn: 1, setup: 2 }
  return items.sort((a, b) => order[a.severity] - order[b.severity])
}

const SEVERITY_ICON = {
  crit: <CircleX aria-label="Critical" className="text-[var(--d-crit)]" />,
  warn: <TriangleAlert aria-label="Warning" className="text-[var(--d-warn)]" />,
  setup: <CircleDashed aria-label="Setup step" className="text-[var(--d-ink-3)]" />,
}

export function Dashboard({ navigate }: { navigate: Nav }) {
  const { current } = useTenants()
  const d = useTenantData()
  const m = useMetrics()
  const decisions = useDecisions()
  const queue = useNeedsAction(navigate)
  const site = siteCode(current)
  const root = d.cas.find((c) => c.role === 'root')
  const iss = d.cas.find((c) => c.role === 'issuing')
  const h = current.health

  const vlanParts = d.vlans.map((v) => ({ key: v.id, label: `VLAN ${v.vlanId} ${v.name}`, value: d.identities.filter((i) => decisions.get(i.id)?.vlanId === v.id).length, colorClass: `bg-${vlanTone(v)}` }))
  const parts = [...vlanParts, { key: 'deny', label: 'Denied', value: m.unauthorized, colorClass: 'bg-deny' }]
  const degraded = d.radiusClients.filter((n) => n.status !== 'ok')

  const authCols: TableColumn<AuthEvent>[] = [
    { key: 'time', header: 'Time (UTC)', cell: (e) => <span className="tnum">{new Date(e.at).toISOString().slice(11, 19)}</span>, width: 96 },
    {
      key: 'user', header: 'User', cell: (e) => {
        const ident = d.identities.find((i) => i.id === e.identityId)
        return ident ? <button type="button" className="d-rowlink nowrap" onClick={() => navigate('user', ident.id)}>{ident.displayName}</button> : <span className="ink-2">{e.username ?? 'Unknown'}</span>
      },
    },
    {
      key: 'result', header: 'Result', cell: (e) => e.result === 'accept'
        ? <span className="inline-flex items-center gap-2 nowrap"><VlanTape vlan={d.vlans.find((v) => v.id === e.vlanId)} size="sm" /><span className="ink-2 d-hide-sm">Accepted</span></span>
        : <StatusMark tone="crit">{e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'}</StatusMark>,
    },
    { key: 'nas', header: 'Controller', hideSm: true, cell: (e) => { const n = d.radiusClients.find((x) => x.id === e.nasClientId); return n ? <NasTape nas={n} all={d.radiusClients} size="sm" /> : <span className="ink-3">—</span> } },
  ]

  return (
    <>
      <PageHeader
        title="Overview"
        meta={<><span>{current.name}</span><MetaSep /><span className="mono">{current.domain}</span><MetaSep /><span className="tnum">As of {utcClock(now().toISOString())} UTC</span></>}
      />

      <Section id="needs-action" title="Needs action" description={queue.length ? `${queue.length} ${queue.length === 1 ? 'item' : 'items'}, most urgent first. Each carries the label of the object to fix.` : undefined}>
        {queue.length === 0 ? (
          <EmptyState icon={<CircleCheck className="d-empty-icon" aria-hidden="true" />} title="Nothing needs action">Controllers, certificates, directory sync and policy all look healthy for {current.name}.</EmptyState>
        ) : (
          <ul className="d-rows">
            {queue.map((q) => (
              <li key={q.key} className="d-queue-row">
                {SEVERITY_ICON[q.severity]}
                <div className="min-w-0">
                  <p className="d-queue-title">{q.tape}<span>{q.title}</span></p>
                  <p className="d-queue-detail">{q.detail}</p>
                </div>
                <div className="d-queue-action"><button type="button" className="d-btn d-btn--sm" onClick={q.action.run}>{q.action.label}</button></div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <section id="metrics" aria-label="Metrics" className="d-section scroll-mt-6">
        <h2 className="sr-only">Metrics</h2>
        <div className="d-strip">
          <div>
            <p className="d-label">Wi-Fi users</p>
            <p className="d-fig">{m.users}</p>
            <p className="d-fig-sub"><span>{m.authorized} authorized</span><span>{m.unauthorized} unauthorized</span></p>
            <SegmentBar className="mt-3" parts={parts} label="Where users land" />
          </div>
          <div>
            <p className="d-label">Active certificates</p>
            <p className="d-fig">{m.certificates.active}</p>
            <p className="d-fig-sub"><span>{m.certificates.expiring} expiring</span><span>{m.certificates.expired} expired</span><span>{m.certificates.revoked} revoked</span></p>
          </div>
          <div>
            <p className="d-label">Auth success, 24 h</p>
            <p className="d-fig">{formatPercent(m.auth.successRate)}</p>
            <p className="d-fig-sub"><span>{m.auth.accepts} accepted</span><span>{m.auth.rejects} rejected</span></p>
          </div>
          <div>
            <p className="d-label">RADIUS clients</p>
            <p className="d-fig">{m.activeRadiusClients}<small> of {d.radiusClients.length} active</small></p>
            <p className="d-fig-sub">{degraded.length ? degraded.map((n) => <span key={n.id}>{n.name} {n.status}</span>) : <span>{d.radiusClients.length ? 'All answering' : 'None registered'}</span>}</p>
          </div>
        </div>
      </section>

      <Section id="authentication" title="Authentication, last 24 hours" description={m.auth.total ? `${m.auth.total} attempts. Rejections are explained in plain language on each user’s record.` : undefined}>
        {m.auth.total === 0 ? (
          <EmptyState icon={<RadioTower className="d-empty-icon" aria-hidden="true" />} title="No authentication attempts yet" action={<button type="button" className="d-btn d-btn--sm" onClick={() => navigate('radius')}>Add a controller</button>}>
            RADIUS hasn’t received a request for {current.name}. Register a wireless controller and point it at <span className="mono">{d.radiusSettings?.serverHostname}</span>.
          </EmptyState>
        ) : (
          <div className="d-grid-2 pt-4">
            <HourlyChart points={m.auth.hourly} height={236} />
            <div>
              <h3 className="d-h3 mb-3">Why attempts were rejected</h3>
              <RankedBars items={m.failures.slice(0, 6).map(([code, n]) => ({ key: code, label: failureExplanations[code as keyof typeof failureExplanations].title, value: n, hint: failureExplanations[code as keyof typeof failureExplanations].fix }))} />
            </div>
          </div>
        )}
      </Section>

      <Section id="system" title="System status" description="PKI, directory and RADIUS for this tenant.">
        <div className="d-table-wrap">
          <table className="d-table">
            <caption className="sr-only">System status</caption>
            <thead><tr className="d-th-cols"><th scope="col">Component</th><th scope="col">Label</th><th scope="col">State</th><th scope="col">Detail</th></tr></thead>
            <tbody>
              <tr>
                <td>RADIUS service</td>
                <td><Tape code={{ site, body: 'RAD' }} size="sm" /></td>
                <td><HealthMark state={h.radius} label={h.radius === 'ok' ? 'Authenticating' : undefined} /></td>
                <td className="ink-2">{h.authzSnapshotAgeSeconds !== null ? <>Authorization snapshot {formatDuration(h.authzSnapshotAgeSeconds)} old · {d.radiusClients.filter((n) => n.status === 'ok').length} of {d.radiusClients.length} controllers healthy</> : 'No controllers registered, server certificate not issued'}</td>
              </tr>
              {iss && (
                <tr>
                  <td>Issuing CA</td>
                  <td><CaTape ca={iss} size="sm" /></td>
                  <td><StatusMark tone="ok">Issuing</StatusMark></td>
                  <td className="ink-2">{iss.commonName} · expires {formatDate(iss.notAfter)} ({relTime(iss.notAfter).toLowerCase()})</td>
                </tr>
              )}
              {root && (
                <tr>
                  <td>Root CA</td>
                  <td><CaTape ca={root} size="sm" /></td>
                  <td><StatusMark tone="ok" icon={<Lock aria-hidden="true" />}>Offline</StatusMark></td>
                  <td className="ink-2">Private key held outside EasyEAP · valid until {formatDate(root.notAfter)}</td>
                </tr>
              )}
              {iss?.crl && (
                <tr>
                  <td>Revocation list</td>
                  <td><Tape code={{ site, body: `CRL·${iss.crl.number}` }} size="sm" /></td>
                  <td><StatusMark tone={iss.crl.nextUpdate && new Date(iss.crl.nextUpdate) > now() ? 'ok' : 'crit'}>Published</StatusMark></td>
                  <td className="ink-2">Last issued {relTime(iss.crl.lastIssued).toLowerCase()} · next update {relTime(iss.crl.nextUpdate).toLowerCase()}</td>
                </tr>
              )}
              {iss && (
                <tr>
                  <td>OCSP responder</td>
                  <td><Tape code={{ site, body: 'OCSP' }} size="sm" /></td>
                  <td>{iss.ocsp?.enabled ? <StatusMark tone="ok">Enabled</StatusMark> : <StatusMark tone="off">Off</StatusMark>}</td>
                  <td className="ink-2 mono">{iss.ocsp?.url ?? 'Clients rely on the CRL'}</td>
                </tr>
              )}
              <tr>
                <td>Active Directory</td>
                <td><Tape code={{ site, body: 'DIR' }} size="sm" /></td>
                <td><HealthMark state={h.directory} label={h.directory === 'ok' ? 'Syncing' : undefined} /></td>
                <td className="ink-2">{h.lastDirectorySync ? <>{current.domain} · last sync {relTime(h.lastDirectorySync).toLowerCase()} · {d.identities.length} users, {d.groups.length} groups</> : 'Not connected — connect LDAPS to import users and groups'}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>

      <div id="activity" className="d-grid-2 scroll-mt-6">
        <Section title="Recent authentications" actions={<button type="button" className="d-btn d-btn--ghost d-btn--sm" onClick={() => navigate('users')}>All users</button>}>
          <DataTable
            caption="Recent authentications"
            columns={authCols}
            rows={d.authEvents.slice(0, 8)}
            rowKey={(e) => e.id}
            empty={<EmptyState title="No authentications in the last 24 hours" />}
          />
        </Section>
        <Section title="Certificate and audit activity">
          {d.audit.length === 0 ? <EmptyState title="No activity recorded" /> : (
            <ol className="d-rows">
              {d.audit.slice(0, 7).map((a) => (
                <li key={a.id} className="py-2.5">
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="font-medium">{auditLabel(a)}</span>
                    <span className="tnum shrink-0 text-[12px] text-[var(--d-ink-3)]">{relTime(a.at)}</span>
                  </div>
                  <p className="mt-0.5 text-[13px]">{a.target}</p>
                  <p className="mt-0.5 text-[12.5px] text-[var(--d-ink-2)]">{a.detail} · <span className="mono text-[11px]">{a.actor}</span></p>
                </li>
              ))}
            </ol>
          )}
        </Section>
      </div>
    </>
  )
}
