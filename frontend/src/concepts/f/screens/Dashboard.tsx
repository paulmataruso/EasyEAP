import { useMemo, useState, type ReactNode } from 'react'
import { ArrowRight, Ban, Check, CircleCheck, CircleDashed, CircleX, FilePlus, TriangleExclamationPoint, X } from 'lucide-react'
import { cn, formatDate, formatPercent, formatTime, relativeTime } from '@/ui/lib'
import { now, useMetrics, useTenantData, useTenants } from '@/prototype/store'
import { failureExplanations } from '@/domain/explain'
import type { HealthState } from '@/domain/types'
import { AuthChart, FailureBars, SegBar } from '../charts'
import { Lifeline, Remaining } from '../credential'
import { ago, auditLabels, formatSeconds, healthLabel, healthTone, intentStore, platformLabel, worstTone, type Tone } from '../lib'
import { computeStats } from '../portfolio'
import type { Navigate } from '../shell'
import { Btn, Chip, Empty, PageHeader, Panel, PlatformIcon, SectionHeader, Tip, VlanTag } from '../ui'

const toneIcon: Record<Tone, ReactNode> = {
  valid: <CircleCheck aria-hidden />,
  warn: <TriangleExclamationPoint aria-hidden />,
  crit: <CircleX aria-hidden />,
  neutral: <CircleDashed aria-hidden />,
  gold: <CircleDashed aria-hidden />,
}
const toneText: Record<Tone, string> = { valid: 'text-[var(--f-valid)]', warn: 'text-[var(--f-warn)]', crit: 'text-[var(--f-crit-ink)]', neutral: 'text-[var(--f-neutral)]', gold: 'text-[var(--f-gold)]' }

function Factor({ name, state, stateLabel, children }: { name: string; state: Tone | null; stateLabel?: string; children: ReactNode }) {
  return (
    <div className="min-w-0 px-5 py-4">
      <div className="mb-2.5 flex items-center justify-between gap-2">
        <h2 className="f-h3">{name}</h2>
        {state && <Chip tone={state} icon={toneIcon[state]}>{stateLabel}</Chip>}
      </div>
      <div className="space-y-1 text-[13px]">{children}</div>
    </div>
  )
}
const Line = ({ k, v, tone }: { k: string; v: ReactNode; tone?: string }) => (
  <p className="flex items-baseline justify-between gap-3">
    <span className="f-ink-2">{k}</span>
    <span className={cn('f-num text-right', tone)}>{v}</span>
  </p>
)

interface Risk { id: string; tone: Tone; title: string; detail: ReactNode; action: { label: string; run: () => void }; extra?: ReactNode }

export function Dashboard({ navigate, onIssue }: { navigate: Navigate; onIssue: (identityId?: string) => void }) {
  const { current } = useTenants()
  const d = useTenantData()
  const m = useMetrics()
  const [openRisk, setOpenRisk] = useState<string | null>(null)
  const t = now()
  const issuing = d.cas.find((c) => c.role === 'issuing')
  const root = d.cas.find((c) => c.role === 'root')
  const device = (id: string | null) => d.devices.find((x) => x.id === id)
  const person = (id: string | null) => d.identities.find((x) => x.id === id)

  // ── Posture factors ──
  const ctrlWorst = d.radiusClients.reduce<HealthState>((w, n) => (n.status === 'down' ? 'down' : n.status === 'degraded' && w !== 'down' ? 'degraded' : w), 'ok')
  const radiusState: HealthState = current.health.radius === 'unconfigured' || d.radiusClients.length === 0 ? 'unconfigured' : current.health.radius !== 'ok' ? current.health.radius : ctrlWorst
  const healthyCtrls = d.radiusClients.filter((n) => n.status === 'ok').length
  const crlNext = issuing?.crl?.nextUpdate ?? null
  const crlOverdue = crlNext ? new Date(crlNext) < t : false
  const pkiTone: Tone = crlOverdue ? 'crit' : healthTone[current.health.pki]
  const certTone: Tone = m.certificates.total === 0 ? 'neutral' : m.certificates.expired > 0 || m.certificates.expiring > 0 ? 'warn' : 'valid'
  const bandTone = worstTone([pkiTone, healthTone[current.health.directory], healthTone[radiusState], certTone].map((x) => (x === 'neutral' ? 'valid' : x)))
  const setup = useMemo(() => computeStats(d, current.health.directory !== 'unconfigured').setup, [d, current.health.directory])

  // ── Risk queue: what will break next, one decision each ──
  const risks: Risk[] = []
  for (const n of d.radiusClients.filter((x) => x.status === 'degraded' || x.status === 'down')) {
    risks.push({ id: n.id, tone: n.status === 'down' ? 'crit' : 'warn', title: `${n.name} is ${healthLabel[n.status].toLowerCase()}`, detail: <>Last RADIUS request {ago(n.lastRequestAt)} · {n.site}. Users there may be failing to connect.</>, action: { label: 'Check controller', run: () => navigate('radius', n.id) } })
  }
  if (current.health.directory === 'degraded' || current.health.directory === 'down') {
    const err = d.audit.find((a) => a.action === 'directory.sync.failed')
    risks.push({
      id: 'dir', tone: current.health.directory === 'down' ? 'crit' : 'warn', title: 'Directory sync is failing',
      detail: <>Last successful sync {ago(current.health.lastDirectorySync)}. Group changes in AD are not reaching RADIUS.</>,
      action: { label: openRisk === 'dir' ? 'Hide error' : 'Review error', run: () => setOpenRisk((o) => (o === 'dir' ? null : 'dir')) },
      extra: err && (
        <div className="mt-2 space-y-1.5 rounded-[7px] bg-[rgba(6,9,17,0.5)] px-3 py-2 text-[12.5px]">
          <p className="f-mono break-words text-[12px] f-ink-2">{err.detail}</p>
          <p>EasyEAP does not trust the certificate the domain controller presents for LDAPS. Add the CA that issued it to the directory connection’s trusted certificates, then run a sync.</p>
        </div>
      ),
    })
  }
  const snap = current.health.authzSnapshotAgeSeconds
  if (snap !== null && snap > d.defaults.maxSnapshotAgeSeconds * 0.5) {
    risks.push({ id: 'snap', tone: 'warn', title: 'Authorization data is ageing', detail: <>RADIUS denies everyone when its snapshot passes {formatSeconds(d.defaults.maxSnapshotAgeSeconds)}; it is {formatSeconds(snap)} old.</>, action: { label: 'Open RADIUS', run: () => navigate('radius') } })
  }
  // Expired certificates that devices keep presenting
  const expiredFails = new Map<string, number>()
  for (const e of d.authEvents) if (e.failureCode === 'cert_expired' && e.certSerial) expiredFails.set(e.certSerial, (expiredFails.get(e.certSerial) ?? 0) + 1)
  ;[...expiredFails.entries()].sort((a, b) => b[1] - a[1]).slice(0, 2).forEach(([serial, n]) => {
    const c = d.certificates.find((x) => x.serial === serial)
    if (!c) return
    const dev = device(c.deviceId)
    const who = person(c.identityId)
    risks.push({ id: `exp-${serial}`, tone: 'crit', title: `${dev?.name ?? who?.displayName} can’t connect: certificate expired`, detail: <>{n} rejected {n === 1 ? 'attempt' : 'attempts'} in 24 h · expired {relativeTime(c.notAfter, t)}</>, action: { label: 'Re-issue', run: () => onIssue(c.identityId ?? undefined) } })
  })
  const expiring = d.certificates.filter((c) => c.identityId && c.status === 'expiring').sort((a, b) => a.notAfter.localeCompare(b.notAfter))
  expiring.slice(0, 2).forEach((c) => {
    const dev = device(c.deviceId)
    risks.push({ id: c.id, tone: 'warn', title: `${dev?.name ?? 'A device'} expires ${relativeTime(c.notAfter, t)}`, detail: <>{person(c.identityId)?.displayName} · {platformLabel(dev?.platform)} · renew before it stops connecting</>, action: { label: 'Re-issue', run: () => onIssue(c.identityId ?? undefined) } })
  })
  if (expiring.length > 2) {
    risks.push({ id: 'exp-more', tone: 'warn', title: `${expiring.length - 2} more certificates expire within 30 days`, detail: <>Soonest after these: {formatDate(expiring[2].notAfter)}</>, action: { label: 'Review expiring', run: () => { intentStore.set({ certFilter: 'expiring' }); navigate('certificates') } } })
  }
  const untrusted = d.authEvents.filter((e) => e.failureCode === 'unknown_ca')
  if (untrusted.length > 0) {
    const counts = new Map<string, number>()
    for (const e of untrusted) if (e.identityId) counts.set(e.identityId, (counts.get(e.identityId) ?? 0) + 1)
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]
    const who = top ? person(top[0]) : undefined
    risks.push({ id: 'unknown-ca', tone: 'warn', title: `${untrusted.length} attempts used an untrusted certificate`, detail: <>From {counts.size} {counts.size === 1 ? 'user' : 'users'}; most from {who?.displayName}. Usually a device without an EasyEAP certificate.</>, action: { label: `Enroll ${who?.displayName.split(' ')[0] ?? 'user'}`, run: () => onIssue(top?.[0]) } })
  }
  const remaining = setup.filter((s) => !s.done)
  if (current.status === 'setup' && remaining.length) {
    risks.unshift({ id: 'setup', tone: 'gold', title: `Finish setup: ${remaining[0].label[0].toLowerCase()}${remaining[0].label.slice(1)}`, detail: <>{setup.length - remaining.length} of {setup.length} setup steps done. {remaining[0].hint}</>, action: { label: 'View setup', run: () => navigate('tenants') } })
  }
  const rank: Record<Tone, number> = { gold: 4, crit: 3, warn: 2, neutral: 1, valid: 0 }
  const queue = [...risks].sort((a, b) => rank[b.tone] - rank[a.tone]).slice(0, 5)

  const lifelines = d.certificates.filter((c) => c.identityId && (c.status === 'active' || c.status === 'expiring')).sort((a, b) => a.notAfter.localeCompare(b.notAfter)).slice(0, 6)
  const recent = d.authEvents.slice(0, 8)
  const activity = d.audit.slice(0, 6)
  const degraded = d.radiusClients.find((n) => n.status === 'degraded' || n.status === 'down')
  const marker = degraded?.lastRequestAt ? { hoursAgo: (t.getTime() - new Date(degraded.lastRequestAt).getTime()) / 3600_000, label: `${degraded.name.split(' ')[0]} WLC silent` } : null

  return (
    <div>
      <PageHeader
        title={current.name}
        lede={<>{current.domain} · {m.users} Wi-Fi users · as of {formatDate(t.toISOString())}, {formatTime(t.toISOString()).slice(0, 5)} UTC</>}
        actions={
          <>
            <Btn onClick={() => navigate('users')}>Find a user</Btn>
            <Btn variant="primary" onClick={() => onIssue()}><FilePlus aria-hidden />Issue certificate</Btn>
          </>
        }
      />

      {/* Posture band: four factors and the access split, one panel, edge tinted by the worst state */}
      <Panel risk={bandTone} className="grid divide-y divide-[var(--f-line)] sm:grid-cols-2 sm:divide-y-0 xl:grid-cols-5 [&>*]:border-[var(--f-line)] sm:[&>*:nth-child(n+3)]:border-t xl:[&>*:nth-child(n+3)]:border-t-0 xl:[&>*+*]:border-l" aria-label="Posture">
        <Factor name="Wi-Fi users" state={null}>
          <p className="f-num mb-2 text-[26px] font-semibold leading-none tracking-tight">{m.users}</p>
          <SegBar label="Access" parts={[{ value: m.authorized, color: 'var(--f-valid)', name: 'authorized' }, { value: m.unauthorized, color: 'var(--f-crit)', name: 'unauthorized' }]} />
          <div className="pt-2">
            <Line k="Authorized" v={m.authorized} />
            <Line k="Unauthorized" v={m.unauthorized} tone={m.unauthorized ? 'text-[var(--f-crit-ink)]' : undefined} />
          </div>
        </Factor>
        <Factor name="Certificates" state={certTone} stateLabel={m.certificates.total === 0 ? 'None issued' : m.certificates.expiring ? `${m.certificates.expiring} expiring` : m.certificates.expired ? `${m.certificates.expired} expired` : 'Healthy'}>
          <Line k="Active" v={m.certificates.active} />
          <Line k="Expiring in 30 days" v={m.certificates.expiring} tone={m.certificates.expiring ? 'text-[var(--f-warn-ink)]' : undefined} />
          <Line k="Expired" v={m.certificates.expired} tone={m.certificates.expired ? 'text-[var(--f-crit-ink)]' : undefined} />
          <Line k="Revoked" v={m.certificates.revoked} />
        </Factor>
        <Factor name="PKI" state={pkiTone} stateLabel={crlOverdue ? 'CRL overdue' : healthLabel[current.health.pki]}>
          <Line k="Issuing CA" v={issuing ? `to ${formatDate(issuing.notAfter)}` : '—'} />
          <Line k="Root CA" v={root?.offline ? 'Offline' : root ? 'Online' : '—'} />
          <Line k="CRL next update" v={crlNext ? relativeTime(crlNext, t) : '—'} tone={crlOverdue ? 'text-[var(--f-crit-ink)]' : undefined} />
          <Line k="OCSP" v={issuing?.ocsp?.enabled ? 'Responding' : 'Off'} />
        </Factor>
        <Factor name="Directory" state={healthTone[current.health.directory]} stateLabel={healthLabel[current.health.directory]}>
          <Line k="Source" v={current.health.directory === 'unconfigured' ? 'Not connected' : 'Active Directory'} />
          <Line k="Last sync" v={current.health.lastDirectorySync ? ago(current.health.lastDirectorySync) : 'Never'} tone={current.health.directory === 'degraded' ? 'text-[var(--f-warn-ink)]' : undefined} />
          <Line k="Groups" v={d.groups.length} />
          <Line k="Directory users" v={d.identities.filter((i) => i.source === 'ad').length} />
        </Factor>
        <Factor name="RADIUS" state={healthTone[radiusState]} stateLabel={healthLabel[radiusState]}>
          <Line k="Controllers healthy" v={d.radiusClients.length ? `${healthyCtrls} of ${d.radiusClients.length}` : 'None'} tone={healthyCtrls < d.radiusClients.length ? 'text-[var(--f-warn-ink)]' : undefined} />
          <Line k="Active RADIUS clients" v={m.activeRadiusClients} />
          <Line k="Snapshot age" v={formatSeconds(snap)} />
          <Line k="Server" v={<span className="truncate">{d.radiusSettings ? `${d.radiusSettings.authPort}/${d.radiusSettings.acctPort}` : '—'}</span>} />
        </Factor>
      </Panel>

      <div className="mt-9 grid gap-x-10 gap-y-10 xl:grid-cols-12">
        <section className="min-w-0 xl:col-span-8" aria-labelledby="f-auth-h">
          <SectionHeader
            id="f-auth-h"
            title="Authentication, last 24 hours"
            meta={m.auth.total ? <><span className="f-num text-[var(--f-ink)] font-semibold">{formatPercent(m.auth.successRate)}</span> success · <span className="f-num">{m.auth.rejects}</span> failures</> : undefined}
          />
          {m.auth.total === 0 ? (
            <Empty icon={<CircleDashed />} title="No authentication requests yet" action={<Btn onClick={() => navigate('radius')}>Add a controller<ArrowRight aria-hidden /></Btn>}>
              RADIUS has received nothing because no wireless controller is registered for {current.name}.
            </Empty>
          ) : (
            <>
              <AuthChart hourly={m.auth.hourly} marker={marker} />
              <div className="mt-7 grid gap-x-10 gap-y-6 md:grid-cols-2">
                <div>
                  <h3 className="f-h3 mb-3">Why requests were rejected</h3>
                  {m.failures.length ? <FailureBars failures={m.failures} total={m.auth.rejects} /> : <p className="f-small f-ink-2">No rejections in the last 24 hours.</p>}
                </div>
                <div>
                  <h3 className="f-h3 mb-3">Where accepted users landed</h3>
                  <ul className="space-y-2.5">
                    {m.vlanUsage.map(([vid, n]) => {
                      const v = d.vlans.find((x) => x.id === vid)
                      const max = m.vlanUsage[0][1]
                      return (
                        <li key={vid}>
                          <Tip content={<span><span className="f-num font-semibold">{n}</span> of {m.auth.accepts} accepted requests · {Math.round((n / Math.max(1, m.auth.accepts)) * 100)}%</span>}>
                            <div tabIndex={0} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 rounded-[6px] outline-offset-4">
                              <VlanTag vlan={v} />
                              <span className="f-num text-[13px] font-semibold">{n}</span>
                              <span className="col-span-2 block h-[6px] rounded-[3px] bg-[rgba(237,234,227,0.06)]">
                                <span className="block h-full rounded-[3px]" style={{ width: `${(n / max) * 100}%`, background: `var(--f-vlan-${v?.color ?? 'slate'})` }} />
                              </span>
                            </div>
                          </Tip>
                        </li>
                      )
                    })}
                  </ul>
                </div>
              </div>
            </>
          )}
        </section>

        <section className="min-w-0 xl:col-span-4" aria-labelledby="f-risk-h">
          <SectionHeader id="f-risk-h" title="Next decisions" meta={risks.length > queue.length ? `${queue.length} of ${risks.length} open` : risks.length ? `${risks.length} open` : undefined} />
          {queue.length === 0 ? (
            <Empty icon={<CircleCheck />} title="Nothing needs a decision">Controllers, directory sync and certificates are all healthy.</Empty>
          ) : (
            <ol className="f-divide border-y border-[var(--f-line)]">
              {queue.map((r) => (
                <li key={r.id} className="py-3">
                  <div className="flex gap-3">
                    <span className={cn('mt-0.5 [&_svg]:size-[18px]', toneText[r.tone])}>{toneIcon[r.tone]}</span>
                    <div className="min-w-0 flex-1">
                      <p className="text-[13.5px] font-semibold leading-snug">{r.title}</p>
                      <p className="f-small f-ink-2 mt-0.5">{r.detail}</p>
                      {openRisk === r.id && r.extra}
                      <Btn size="sm" className="mt-2" onClick={r.action.run} aria-expanded={r.extra ? openRisk === r.id : undefined}>
                        {r.action.label}
                        {!r.extra && <ArrowRight aria-hidden />}
                      </Btn>
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="min-w-0 xl:col-span-7" aria-labelledby="f-recent-h">
          <SectionHeader id="f-recent-h" title="Recent authentications" actions={m.auth.total > 0 && <Btn size="sm" variant="ghost" onClick={() => navigate('users')}>All users<ArrowRight aria-hidden /></Btn>} />
          {recent.length === 0 ? (
            <Empty title="No requests recorded">Authentications appear here as soon as a controller forwards them.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="f-table">
                <caption className="sr-only">Most recent authentication decisions</caption>
                <thead>
                  <tr><th>Time</th><th>Result</th><th>User and device</th><th>Outcome</th></tr>
                </thead>
                <tbody>
                  {recent.map((e) => {
                    const who = person(e.identityId)
                    const dev = device(e.deviceId)
                    return (
                      <tr key={e.id} data-clickable={!!who} onClick={() => who && navigate('user', who.id)}>
                        <td className="f-num f-ink-3 whitespace-nowrap">{formatTime(e.at).slice(0, 5)}</td>
                        <td>{e.result === 'accept' ? <Chip tone="valid" icon={<Check aria-hidden />}>Accept</Chip> : <Chip tone="crit" icon={<X aria-hidden />}>Reject</Chip>}</td>
                        <td className="min-w-0">
                          {who ? <button type="button" className="f-rowlink font-medium hover:underline" onClick={(ev) => { ev.stopPropagation(); navigate('user', who.id) }}>{who.displayName}</button> : <span>{e.username ?? 'Unknown'}</span>}
                          <span className="f-small f-ink-3 block truncate">{dev ? dev.name : 'Unenrolled device'} · {e.ssid}</span>
                        </td>
                        <td className="min-w-[180px]">
                          {e.result === 'accept' ? <VlanTag vlan={d.vlans.find((v) => v.id === e.vlanId)} /> : <span className="f-small text-[var(--f-crit-ink)]">{e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'}</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="min-w-0 xl:col-span-5" aria-labelledby="f-life-h">
          <SectionHeader id="f-life-h" title="Credentials expiring soonest" actions={lifelines.length > 0 && <Btn size="sm" variant="ghost" onClick={() => navigate('certificates')}>All certificates<ArrowRight aria-hidden /></Btn>} />
          {lifelines.length === 0 ? (
            <Empty icon={<FilePlus />} title="No certificates issued yet" action={<Btn variant="primary" onClick={() => onIssue()}>Issue the first certificate</Btn>}>Each device gets its own certificate; issue one from a user’s record.</Empty>
          ) : (
            <ul className="f-divide border-y border-[var(--f-line)]">
              {lifelines.map((c) => {
                const dev = device(c.deviceId)
                return (
                  <li key={c.id}>
                    <button type="button" className="grid w-full grid-cols-[minmax(0,1fr)_minmax(56px,120px)_3.5rem] items-center gap-4 rounded-[4px] py-2.5 text-left hover:bg-[var(--f-hover)]" onClick={() => navigate('certificates', c.id)}>
                      <span className="flex min-w-0 items-center gap-2.5">
                        <PlatformIcon platform={dev?.platform ?? null} />
                        <span className="min-w-0">
                          <span className="block truncate text-[13.5px] font-medium">{dev?.name}</span>
                          <span className="block truncate text-[12px] f-ink-3">{person(c.identityId)?.displayName} · to {formatDate(c.notAfter)}</span>
                        </span>
                      </span>
                      <Lifeline cert={c} />
                      <Remaining cert={c} />
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        <section className="min-w-0 xl:col-span-12" aria-labelledby="f-audit-h">
          <SectionHeader id="f-audit-h" title="Certificate and audit activity" />
          {activity.length === 0 ? (
            <Empty title="No activity yet">Issuing, revoking and configuration changes are recorded here.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="f-table">
                <caption className="sr-only">Recent audit entries</caption>
                <thead><tr><th>Event</th><th>Target</th><th>Detail</th><th>By</th><th className="f-right">When</th></tr></thead>
                <tbody>
                  {activity.map((a) => (
                    <tr key={a.id}>
                      <td className="whitespace-nowrap font-medium">
                        <span className="inline-flex items-center gap-2">
                          {a.action === 'certificate.revoke' ? <Ban className="size-4 text-[var(--f-crit-ink)]" aria-hidden /> : a.action.endsWith('failed') ? <TriangleExclamationPoint className="size-4 text-[var(--f-warn)]" aria-hidden /> : <Check className="size-4 f-ink-3" aria-hidden />}
                          {auditLabels[a.action] ?? a.action}
                        </span>
                      </td>
                      <td className="whitespace-nowrap">{a.target}</td>
                      <td className="f-ink-2 min-w-[260px]">{a.detail}</td>
                      <td className="f-ink-3 whitespace-nowrap">{a.actor}</td>
                      <td className="f-num f-ink-3 f-right whitespace-nowrap">{ago(a.at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
