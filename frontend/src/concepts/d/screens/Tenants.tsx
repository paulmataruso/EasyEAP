import { CircleCheck, CircleDashed, SearchX } from 'lucide-react'
import { Fragment } from 'react'
import type { Tenant } from '@/domain/types'
import { useTenants } from '@/prototype/store'
import { formatPercent } from '@/ui/lib'
import type { ScreenId } from '../../contract'
import { siteCode } from '../model/codes'
import { relTime, setupSteps, type TenantSnapshot } from '../model/derive'
import { portfolioSnapshot, useLiveSnapshot } from '../model/portfolio'
import { useViewState } from '../model/state'
import { EmptyState, MetaSep, PageHeader, Section } from '../ui/Section'
import { HealthMark, StatusMark } from '../ui/Status'
import { Tape } from '../ui/Tape'

type Nav = (s: ScreenId, id?: string) => void

const needsAttention = (t: Tenant, s: TenantSnapshot) =>
  t.status === 'setup' || [t.health.radius, t.health.pki, t.health.directory].some((h) => h === 'degraded' || h === 'down') || s.controllersOk < s.controllers

export function Tenants({ navigate }: { navigate: Nav }) {
  const { tenants, current, switchTenant } = useTenants()
  const vs = useViewState()
  const liveSnap = useLiveSnapshot()
  const rows = tenants.map((t) => ({ t, s: t.id === current.id ? liveSnap : portfolioSnapshot(t.id)! }))
  const view = vs.tenantsView
  const shown = rows.filter(({ t, s }) => (view === 'all' ? true : view === 'setup' ? t.status === 'setup' : needsAttention(t, s)))
  const open = (t: Tenant) => {
    if (t.id !== current.id) { vs.resetForTenant(); switchTenant(t.id) }
    navigate('dashboard')
  }
  const totals = rows.reduce((a, { s }) => ({ users: a.users + s.users, expiring: a.expiring + s.expiring, auth: a.auth + s.authTotal, acc: a.acc + s.authAccepts }), { users: 0, expiring: 0, auth: 0, acc: 0 })
  const attention = rows.filter(({ t, s }) => needsAttention(t, s)).length

  return (
    <>
      <PageHeader
        title="Tenants"
        meta={<><span>Brightline IT managed portfolio</span><MetaSep /><span className="tnum">{tenants.length} tenants</span><MetaSep /><span>Selecting a tenant switches to it and opens its overview</span></>}
      />
      <div className="d-strip">
        <div><p className="d-label">Tenants</p><p className="d-fig">{tenants.length}</p><p className="d-fig-sub">{tenants.filter((t) => t.status === 'active').length} live · {tenants.filter((t) => t.status === 'setup').length} in setup</p></div>
        <div><p className="d-label">Wi-Fi users</p><p className="d-fig">{totals.users}</p><p className="d-fig-sub">Across all directories</p></div>
        <div><p className="d-label">Expiring certificates</p><p className="d-fig">{totals.expiring}</p><p className="d-fig-sub">Within 30 days, all tenants</p></div>
        <div><p className="d-label">Needs attention</p><p className="d-fig">{attention}</p><p className="d-fig-sub">Degraded service or unfinished setup</p></div>
      </div>

      <Section title={view === 'all' ? 'All tenants' : view === 'setup' ? 'In setup' : 'Needs attention'} description={`Portfolio auth success, 24 h: ${formatPercent(totals.auth ? totals.acc / totals.auth : null)} of ${totals.auth} attempts.`}>
        <div className="d-table-wrap">
          <table className="d-table">
            <caption className="sr-only">Tenant portfolio</caption>
            <thead>
              <tr className="d-th-groups">
                <th colSpan={2} data-group="" />
                <th colSpan={3} data-group="Health" scope="colgroup">Health</th>
                <th colSpan={4} data-group="Operations" scope="colgroup" className="d-hide-sm">Operations</th>
                <th colSpan={2} data-group="" />
              </tr>
              <tr className="d-th-cols">
                <th scope="col">Site</th>
                <th scope="col">Tenant</th>
                <th scope="col">RADIUS</th>
                <th scope="col">PKI</th>
                <th scope="col">Directory</th>
                <th scope="col" data-align="right" className="d-hide-sm">Users</th>
                <th scope="col" data-align="right" className="d-hide-sm">Expiring</th>
                <th scope="col" data-align="right" className="d-hide-sm">Auth 24 h</th>
                <th scope="col" className="d-hide-sm">Last sync</th>
                <th scope="col">Setup</th>
                <th scope="col"><span className="sr-only">Open</span></th>
              </tr>
            </thead>
            <tbody>
              {shown.map(({ t, s }) => {
                const steps = setupSteps(t, s)
                const done = steps.filter((x) => x.done).length
                const isCurrent = t.id === current.id
                return (
                  <Fragment key={t.id}>
                    <tr data-clickable="true" aria-selected={isCurrent} onClick={(e) => { if (!(e.target as HTMLElement).closest('button')) open(t) }}>
                      <td><Tape code={siteCode(t)} /></td>
                      <td>
                        <button type="button" className="d-rowlink" onClick={() => open(t)}>{t.name}</button>
                        <span className="d-sub mono">{t.domain}</span>
                        {isCurrent && <span className="mt-0.5 block text-[12px] text-[var(--d-signal)]">Current tenant</span>}
                      </td>
                      <td><HealthMark state={t.health.radius} /></td>
                      <td><HealthMark state={t.health.pki} /></td>
                      <td><HealthMark state={t.health.directory} /></td>
                      <td data-align="right" className="tnum d-hide-sm">{s.users}</td>
                      <td data-align="right" className="tnum d-hide-sm">{s.certCount ? s.expiring : <span className="ink-3">—</span>}</td>
                      <td data-align="right" className="tnum d-hide-sm">{s.authTotal ? <>{formatPercent(s.authAccepts / s.authTotal)}<span className="d-sub nowrap">{s.authTotal} attempts</span></> : <span className="ink-3">No traffic</span>}</td>
                      <td className="d-hide-sm"><span className={t.health.directory === 'degraded' ? 'nowrap' : 'ink-2 nowrap'}>{relTime(t.health.lastDirectorySync)}</span></td>
                      <td>{t.status === 'setup' ? <StatusMark tone="off" icon={<CircleDashed aria-hidden="true" />}>{done} of {steps.length} done</StatusMark> : <StatusMark tone="ok">Live</StatusMark>}</td>
                      <td data-align="right"><button type="button" className="d-btn d-btn--sm" onClick={() => open(t)}>Open</button></td>
                    </tr>
                    {t.status === 'setup' && (
                      <tr>
                        <td />
                        <td colSpan={10} className="!pt-1 !pb-4">
                          <p className="mb-2 text-[13px] text-[var(--d-ink-2)]">What remains before {t.name.split(' ')[0]} devices can authenticate:</p>
                          <ol className="grid gap-x-8 gap-y-1.5 sm:grid-cols-2 xl:grid-cols-3">
                            {steps.map((st) => (
                              <li key={st.key} className="flex items-start gap-2 text-[13px]">
                                {st.done ? <CircleCheck aria-label="Done" className="mt-0.5 size-4 shrink-0 text-[var(--d-signal)]" /> : <CircleDashed aria-label="Remaining" className="mt-0.5 size-4 shrink-0 text-[var(--d-ink-3)]" />}
                                <span><span className={st.done ? 'text-[var(--d-ink-2)]' : 'font-medium'}>{st.label}</span><span className="block text-[12px] text-[var(--d-ink-2)]">{st.detail}</span></span>
                              </li>
                            ))}
                          </ol>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
          {shown.length === 0 && (
            <EmptyState icon={<SearchX className="d-empty-icon" aria-hidden="true" />} title="No tenants in this view" action={<button type="button" className="d-btn d-btn--sm" onClick={() => vs.setTenantsView('all')}>Show all tenants</button>} />
          )}
        </div>
      </Section>
    </>
  )
}
