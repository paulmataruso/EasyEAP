import { useEffect, useMemo, useState } from 'react'
import { ArrowRight, CircleCheck, CircleDashed, CircleX, Info, PlugZap, TriangleAlert, Wrench } from 'lucide-react'
import { now, useMetrics, useTenantData, useTenants } from '@/prototype/store'
import { failureExplanations } from '@/domain/explain'
import type { FailureCode } from '@/domain/types'
import { daysUntil, formatDate, formatPercent } from '@/ui/lib'
import { HourlyChart, HourlyTable } from '../charts/HourlyChart'
import { useConcept, type Intent } from '../app/context'
import { Button } from '../ui/Button'
import { Segmented } from '../ui/Field'
import { DefList, Empty, Lede, Note, Section } from '../ui/Layout'
import { SegmentBar } from '../ui/SegmentBar'
import { HealthMark } from '../ui/Status'
import { VlanTag } from '../ui/Vlan'
import { attentionFor, failureBreakdown, INTENDED_REJECTIONS, postureOf, type AttentionItem } from '../lib/posture'
import { auditActionLabel, count, plural, since } from '../lib/format'

/** "87 seconds" / "4 minutes" / "3 hours" for a duration in seconds. */
function spoken(seconds: number) {
  if (seconds < 90) return plural(Math.round(seconds), 'second')
  if (seconds < 5400) return plural(Math.round(seconds / 60), 'minute')
  if (seconds < 172800) return plural(Math.round(seconds / 3600), 'hour')
  return plural(Math.round(seconds / 86400), 'day')
}

export function Dashboard({ intent }: { intent: Intent }) {
  const { current: tenant } = useTenants()
  const d = useTenantData()
  const m = useMetrics()
  const items = useMemo(() => attentionFor(tenant, d), [tenant, d])
  const posture = postureOf(tenant, items)

  useEffect(() => {
    const focus = intent.dashboard?.focus
    if (focus) document.getElementById(`c-dash-${focus}`)?.scrollIntoView({ block: 'start' })
  }, [intent])

  return (
    <>
      <Lede
        page="Overview"
        state={posture.state}
        rest={posture.rest}
        meta={
          <>
            <span>{tenant.domain}</span>
            <span>{tenant.health.lastDirectorySync ? `Directory synced ${since(tenant.health.lastDirectorySync)}` : 'Directory never synced'}</span>
            <span>{plural(d.radiusClients.length, 'controller')}</span>
          </>
        }
      />
      <AttentionList items={items} setup={tenant.status === 'setup'} />
      <Metrics m={m} controllers={d.radiusClients.length} />
      <ActivityChart points={m.auth.hourly} total={m.auth.total} />
      <div className="c-split is-even">
        <Failures />
        <RecentAuth />
      </div>
      <Services />
      <RecentChanges />
    </>
  )
}

function AttentionList({ items, setup }: { items: AttentionItem[]; setup: boolean }) {
  const { go } = useConcept()
  if (!items.length) {
    return (
      <Section title="Needs attention" flush>
        <Empty icon={CircleCheck} title="Nothing needs attention">
          Every controller is reporting, no certificate expires in the next 30 days and failures are within normal levels.
        </Empty>
      </Section>
    )
  }
  return (
    <Section title={setup ? 'Remaining setup' : 'Needs attention'} flush>
      <ul className="c-list">
        {items.map((it) => {
          const Icon = it.tone === 'info' ? CircleDashed : it.tone === 'crit' ? CircleX : TriangleAlert
          return (
            <li key={it.id}>
              <div className="c-attn" data-tone={it.tone}>
                <Icon size={19} strokeWidth={1.9} aria-label={it.tone === 'crit' ? 'Critical' : it.tone === 'warn' ? 'Warning' : 'To do'} />
                <span className="c-attn-title">{it.title}</span>
                <span className="c-attn-detail">{it.detail}</span>
                {it.action ? (
                  <span className="c-attn-action">
                    <Button size="sm" variant="secondary" iconEnd={<ArrowRight size={15} aria-hidden="true" />} onClick={() => go(it.action!.screen, { intent: it.action!.intent })}>
                      {it.action.label}
                    </Button>
                  </span>
                ) : null}
              </div>
            </li>
          )
        })}
      </ul>
    </Section>
  )
}

function Metrics({ m, controllers }: { m: ReturnType<typeof useMetrics>; controllers: number }) {
  const valid = m.certificates.active + m.certificates.expiring
  return (
    <Section title="At a glance" className="c-metrics-section">
      <div className="c-metrics">
        <div>
          <h3 className="c-metric-title">Wi-Fi access</h3>
          <div className="c-metric-value">
            {count(m.authorized)}
            <small>of {count(m.users)}</small>
          </div>
          <p className="c-metric-context">
            people can join <span className="c-nowrap">Wi-Fi</span>. {m.unauthorized ? `${plural(m.unauthorized, 'person is', 'people are')} denied by account state or policy.` : 'Nobody is denied.'}
          </p>
          <SegmentBar
            label="Access decisions"
            segments={[
              { key: 'allow', label: 'Allowed', value: m.authorized, color: 'var(--c-ok)' },
              { key: 'deny', label: 'Denied', value: m.unauthorized, color: 'var(--c-crit)' },
            ]}
          />
        </div>
        <div>
          <h3 className="c-metric-title">Certificates</h3>
          <div className="c-metric-value">{count(valid)}</div>
          <p className="c-metric-context">
            {m.certificates.total ? `valid certificates; ${m.certificates.expiring} expire within 30 days.` : 'certificates issued so far. The issuing CA is ready.'}
          </p>
          <SegmentBar
            label="Certificate status"
            segments={[
              { key: 'active', label: 'Active', value: m.certificates.active, color: 'var(--c-ok)' },
              { key: 'expiring', label: 'Expiring', value: m.certificates.expiring, color: 'var(--c-warn)' },
              { key: 'expired', label: 'Expired', value: m.certificates.expired, color: 'var(--c-crit)' },
              { key: 'revoked', label: 'Revoked', value: m.certificates.revoked, color: 'var(--c-neutral)' },
            ]}
          />
        </div>
        <div>
          <h3 className="c-metric-title">Authentication, last 24 hours</h3>
          <div className="c-metric-value">{m.auth.successRate === null ? '—' : formatPercent(m.auth.successRate)}</div>
          <p className="c-metric-context">
            {m.auth.total
              ? `of ${count(m.auth.total)} attempts succeeded. ${m.activeRadiusClients} of ${controllers} controllers reporting.`
              : 'No authentication requests yet. RADIUS needs a controller to send them.'}
          </p>
          <SegmentBar
            label="Authentication results"
            segments={[
              { key: 'accept', label: 'Accepted', value: m.auth.accepts, color: 'var(--c-series-accept)' },
              { key: 'reject', label: 'Rejected', value: m.auth.rejects, color: 'var(--c-series-reject)' },
            ]}
          />
        </div>
      </div>
    </Section>
  )
}

function ActivityChart({ points, total }: { points: ReturnType<typeof useMetrics>['auth']['hourly']; total: number }) {
  const [view, setView] = useState('chart')
  const accepted = points.reduce((s, p) => s + p.accept, 0)
  const rejected = points.reduce((s, p) => s + p.reject, 0)
  return (
    <Section
      title="Authentications per hour"
      description="Every EAP-TLS attempt RADIUS answered in the last 24 hours, by hour."
      aside={total ? <Segmented label="Show as" value={view} onChange={setView} options={[{ value: 'chart', label: 'Chart' }, { value: 'table', label: 'Table' }]} /> : null}
    >
      {total === 0 ? (
        <Empty icon={PlugZap} title="No authentication requests yet">
          Requests appear here once a wireless controller is registered and pointed at this tenant’s RADIUS server.
        </Empty>
      ) : view === 'chart' ? (
        <>
          <ul className="c-legend" style={{ marginTop: 0, marginBottom: 14 }}>
            <li>
              <span className="c-key" style={{ background: 'var(--c-series-accept)' }} aria-hidden="true" />
              Accepted <b>{count(accepted)}</b>
            </li>
            <li>
              <CircleX size={13} aria-hidden="true" style={{ color: 'var(--c-crit)' }} />
              Rejected <b>{count(rejected)}</b>
            </li>
          </ul>
          <HourlyChart points={points} />
        </>
      ) : (
        <HourlyTable points={points} />
      )}
    </Section>
  )
}

function Failures() {
  const d = useTenantData()
  const rows = failureBreakdown(d)
  const [open, setOpen] = useState<FailureCode | null>(null)
  const max = rows[0]?.[1] ?? 1
  return (
    <Section id="c-dash-failures" title="Why authentications failed" description="Plain-language causes, most frequent first. Open one for the fix.">
      {rows.length === 0 ? (
        <Empty icon={CircleCheck} title={d.authEvents.length ? 'No failures in 24 hours' : 'No authentications yet'}>
          {d.authEvents.length ? 'Every attempt was accepted.' : 'Failures are explained here once devices start authenticating.'}
        </Empty>
      ) : (
        <ul className="c-list">
          {rows.map(([code, n]) => {
            const x = failureExplanations[code]
            const intended = INTENDED_REJECTIONS.includes(code)
            const isOpen = open === code
            return (
              <li key={code}>
                <button
                  type="button"
                  aria-expanded={isOpen}
                  onClick={() => setOpen(isOpen ? null : code)}
                  style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) auto', gap: '6px 16px', width: '100%', padding: '12px 0', border: 0, background: 'none', textAlign: 'left' }}
                >
                  <span style={{ fontWeight: 500 }}>
                    {x.title}
                    {intended ? <span className="c-faint" style={{ fontWeight: 400 }}> · policy working as intended</span> : null}
                  </span>
                  <span className="tnum" style={{ fontWeight: 600 }}>
                    {n}
                  </span>
                  <span style={{ height: 4, borderRadius: 4, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }} aria-hidden="true">
                    <span style={{ display: 'block', height: '100%', width: `${(n / max) * 100}%`, borderRadius: 4, background: intended ? 'var(--c-series-accept)' : 'var(--c-series-reject)' }} />
                  </span>
                  <span />
                </button>
                {isOpen ? (
                  <div className="c-expand" style={{ padding: '0 0 16px' }}>
                    <p className="c-muted" style={{ margin: '0 0 10px', maxWidth: '64ch' }}>
                      {x.explanation}
                    </p>
                    <Note icon={Wrench}>
                      <strong>{intended ? 'Expected. ' : 'To fix: '}</strong>
                      {x.fix}
                    </Note>
                  </div>
                ) : null}
              </li>
            )
          })}
        </ul>
      )}
    </Section>
  )
}

function RecentAuth() {
  const d = useTenantData()
  const { go } = useConcept()
  const events = d.authEvents.slice(0, 7)
  return (
    <Section title="Recent authentications" description="The latest requests RADIUS answered for this tenant.">
      {events.length === 0 ? (
        <Empty icon={Info} title="Nothing yet">
          Each attempt appears here with its result, the person and the VLAN they landed on.
        </Empty>
      ) : (
        <ul className="c-list">
          {events.map((e) => {
            const p = d.identities.find((i) => i.id === e.identityId)
            const v = d.vlans.find((x) => x.id === e.vlanId)
            const ok = e.result === 'accept'
            return (
              <li key={e.id}>
                <div className="c-listrow" style={{ alignItems: 'flex-start', minHeight: 0, padding: '12px 0' }}>
                  <span className="c-status" data-tone={ok ? 'ok' : 'crit'} style={{ marginTop: 2 }}>
                    {ok ? <CircleCheck size={16} aria-label="Accepted" /> : <CircleX size={16} aria-label="Rejected" />}
                  </span>
                  <span className="c-listrow-main">
                    {p ? (
                      <button type="button" className="c-rowlink" onClick={() => go('user', { entityId: p.id })}>
                        {p.displayName}
                      </button>
                    ) : (
                      <span style={{ fontWeight: 500 }}>{e.username ?? 'Unknown identity'}</span>
                    )}
                    <span className="c-cell-secondary" style={{ display: 'flex', flexWrap: 'wrap', gap: '2px 10px', alignItems: 'center' }}>
                      {ok ? (
                        <>
                          <span>Accepted on</span>
                          <VlanTag vlan={v} />
                        </>
                      ) : (
                        <span>{e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'}</span>
                      )}
                    </span>
                  </span>
                  <span className="c-faint c-small tnum" style={{ whiteSpace: 'nowrap', marginTop: 2 }}>
                    {since(e.at)}
                  </span>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </Section>
  )
}

function Services() {
  const { current: tenant } = useTenants()
  const d = useTenantData()
  const m = useMetrics()
  const root = d.cas.find((c) => c.role === 'root')
  const issuing = d.cas.find((c) => c.role === 'issuing')
  const adUsers = d.identities.filter((i) => i.source === 'ad').length
  const snapshot = tenant.health.authzSnapshotAgeSeconds
  return (
    <Section title="Services" description="What RADIUS, the certificate authority and the directory report right now.">
      <div className="c-tri">
        <div>
          <h3 className="c-h3">RADIUS</h3>
          <HealthMark state={tenant.health.radius} label={tenant.health.radius === 'ok' ? 'Authenticating' : undefined} />
          <DefList
            stacked
            className="mt-3"
            items={[
              { label: 'Authorization snapshot', value: snapshot === null ? 'Not loaded yet' : `Loaded ${spoken(snapshot)} ago; RADIUS fails safe after ${spoken(d.defaults.maxSnapshotAgeSeconds)}` },
              { label: 'Controllers', value: d.radiusClients.length ? `${m.activeRadiusClients} of ${d.radiusClients.length} reporting` : 'None registered' },
              { label: 'Listening on', value: d.radiusSettings ? <span className="tnum">UDP {d.radiusSettings.authPort} and {d.radiusSettings.acctPort}, TLS {d.radiusSettings.tlsMinVersion}+</span> : '—' },
            ]}
          />
        </div>
        <div>
          <h3 className="c-h3">Certificate authority</h3>
          <HealthMark state={tenant.health.pki} label={tenant.health.pki === 'ok' ? 'Issuing' : undefined} />
          <DefList
            stacked
            className="mt-3"
            items={[
              { label: 'Issuing CA', value: issuing ? `${issuing.commonName}, expires ${formatDate(issuing.notAfter)}` : 'Not created' },
              { label: 'Offline root', value: root ? `${root.commonName}, key held offline until ${new Date(root.notAfter).getUTCFullYear()}` : 'Not created' },
              { label: 'Revocation', value: issuing?.crl?.nextUpdate ? `CRL #${issuing.crl.number} next update in ${daysUntil(issuing.crl.nextUpdate, now()) <= 1 ? `${Math.round((new Date(issuing.crl.nextUpdate).getTime() - now().getTime()) / 3_600_000)} hours` : plural(daysUntil(issuing.crl.nextUpdate, now()), 'day')}; OCSP ${issuing.ocsp?.enabled ? 'responding' : 'off'}` : 'No CRL yet' },
            ]}
          />
        </div>
        <div>
          <h3 className="c-h3">Directory</h3>
          <HealthMark state={tenant.health.directory} label={tenant.health.directory === 'ok' ? 'Synchronising' : tenant.health.directory === 'degraded' ? 'Sync failing' : tenant.health.directory === 'unconfigured' ? 'Not connected' : undefined} />
          <DefList
            stacked
            className="mt-3"
            items={[
              { label: 'Domain', value: tenant.domain },
              { label: 'Last successful sync', value: tenant.health.lastDirectorySync ? since(tenant.health.lastDirectorySync) : 'Never' },
              { label: 'Synchronised', value: tenant.health.directory === 'unconfigured' ? 'Waiting for an LDAPS connection' : `${plural(adUsers, 'user')}, ${plural(d.groups.length, 'group')}` },
            ]}
          />
        </div>
      </div>
    </Section>
  )
}

function RecentChanges() {
  const d = useTenantData()
  const rows = d.audit.slice(0, 8)
  return (
    <Section id="c-dash-activity" title="Recent changes" description="Audit trail: who changed what, newest first.">
      {rows.length === 0 ? (
        <Empty icon={Info} title="No changes recorded" />
      ) : (
        <ul className="c-list">
          {rows.map((a) => (
            <li key={a.id}>
              <div className="c-listrow c-logrow">
                <span className="c-faint c-small tnum c-logrow-when">
                  {since(a.at)}
                </span>
                <span className="c-listrow-main">
                  <span style={{ fontWeight: 500 }}>{auditActionLabel[a.action] ?? a.action}</span>
                  <span className="c-muted"> · {a.target}</span>
                  <span className="c-cell-secondary">{a.detail}</span>
                </span>
                <span className="c-faint c-small c-hide-md" style={{ marginTop: 2 }}>
                  {a.actor === 'system' ? 'EasyEAP' : a.actor}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Section>
  )
}
