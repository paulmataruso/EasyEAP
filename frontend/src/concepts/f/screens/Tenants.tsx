import { ArrowRight, Check, CircleDashed } from 'lucide-react'
import { cn, formatPercent } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import type { Tenant } from '@/domain/types'
import { ago, healthTone, monogram, worstTone } from '../lib'
import { computeStats, statsFor, type TenantStats } from '../portfolio'
import type { Navigate } from '../shell'
import { TenantStateChip } from '../shell'
import { Btn, Chip, HealthChip, PageHeader, Panel, SectionHeader } from '../ui'

function SetupChecklist({ tenant, stats, onOpen }: { tenant: Tenant; stats: TenantStats; onOpen: () => void }) {
  const done = stats.setup.filter((s) => s.done).length
  return (
    <Panel risk="gold" className="px-5 py-5" aria-labelledby={`f-setup-${tenant.id}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id={`f-setup-${tenant.id}`} className="f-h2">{tenant.name} setup</h3>
          <p className="f-small f-ink-2 mt-0.5">{done} of {stats.setup.length} steps done · created {ago(tenant.createdAt)}</p>
        </div>
        <Btn onClick={onOpen}>Open {tenant.name.split(' ')[0]}<ArrowRight aria-hidden /></Btn>
      </div>
      <div className="mt-4 flex h-1.5 gap-[2px]" aria-hidden>
        {stats.setup.map((s) => <span key={s.key} className={cn('h-full flex-1 first:rounded-l-full last:rounded-r-full', s.done ? 'bg-[var(--f-gold)]' : 'bg-[rgba(237,234,227,0.1)]')} />)}
      </div>
      <ol className="mt-4 grid gap-x-8 gap-y-3 md:grid-cols-2 xl:grid-cols-5">
        {stats.setup.map((s) => (
          <li key={s.key} className="flex gap-2.5">
            {s.done ? <Check className="mt-0.5 size-4 shrink-0 text-[var(--f-valid)]" aria-label="Done" /> : <CircleDashed className="mt-0.5 size-4 shrink-0 f-ink-3" aria-label="Remaining" />}
            <span>
              <span className={cn('block text-[13px] font-medium', s.done && 'f-ink-2')}>{s.label}</span>
              {!s.done && <span className="f-small f-ink-3 block">{s.hint}</span>}
            </span>
          </li>
        ))}
      </ol>
    </Panel>
  )
}

export function TenantsScreen({ navigate }: { navigate: Navigate }) {
  const { tenants, current, switchTenant } = useTenants()
  const d = useTenantData()
  const liveCurrent = computeStats(d, current.health.directory !== 'unconfigured')
  const rows = tenants.map((t) => ({ t, s: t.id === current.id ? liveCurrent : statsFor(t.id, t.health.directory !== 'unconfigured') }))
  const open = (id: string) => { switchTenant(id); navigate('dashboard') }
  const attention = rows.filter(({ t, s }) => t.status !== 'setup' && (worstTone([healthTone[t.health.radius], healthTone[t.health.pki], healthTone[t.health.directory]]) !== 'valid' || s.controllersDegraded > 0))
  const inSetup = rows.filter(({ t }) => t.status === 'setup')
  const totalUsers = rows.reduce((n, r) => n + r.s.users, 0)

  return (
    <div>
      <PageHeader
        title="Tenants"
        lede={<>{tenants.length} customer organisations · {totalUsers} Wi-Fi users · {attention.length} {attention.length === 1 ? 'needs' : 'need'} attention · {inSetup.length} in setup</>}
      />

      <div className="overflow-x-auto">
        <table className="f-table">
          <caption className="sr-only">All tenants. Select one to switch to it and open its dashboard.</caption>
          <thead>
            <tr>
              <th>Tenant</th>
              <th>State</th>
              <th>RADIUS</th>
              <th>PKI</th>
              <th>Directory</th>
              <th className="f-right">Users</th>
              <th className="f-right">Expiring</th>
              <th className="f-right">Success, 24 h</th>
              <th><span className="sr-only">Open</span></th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ t, s }) => {
              const isCurrent = t.id === current.id
              return (
                <tr key={t.id} data-clickable="true" aria-selected={isCurrent} onClick={() => open(t.id)}>
                  <td className="min-w-[220px]">
                    <span className="flex items-center gap-3">
                      <span className="f-monogram size-7 text-[11.5px]" aria-hidden>{monogram(t)}</span>
                      <span className="min-w-0">
                        <button type="button" className="f-rowlink block whitespace-nowrap font-semibold hover:underline" onClick={(e) => { e.stopPropagation(); open(t.id) }}>{t.name}</button>
                        <span className="f-small f-ink-3 block whitespace-nowrap">{t.domain}{isCurrent && <span className="text-[var(--f-gold)]"> · current tenant</span>}</span>
                      </span>
                    </span>
                  </td>
                  <td>{t.status === 'setup' ? <Chip tone="gold">Setup · {s.setup.filter((x) => x.done).length} of {s.setup.length}</Chip> : <TenantStateChip status={t.status} />}</td>
                  <td className="whitespace-nowrap">
                    <HealthChip state={t.health.radius === 'ok' && s.controllersDegraded > 0 ? 'degraded' : t.health.radius} />
                    {s.controllersDegraded > 0 && <span className="f-small f-ink-3 block">{s.controllersDegraded} of {s.controllers} controllers</span>}
                  </td>
                  <td><HealthChip state={t.health.pki} /></td>
                  <td className="whitespace-nowrap">
                    <HealthChip state={t.health.directory} />
                    {t.health.directory !== 'unconfigured' && <span className={cn('f-small block', t.health.directory === 'degraded' ? 'text-[var(--f-warn-ink)]' : 'f-ink-3')}>synced {t.health.lastDirectorySync ? ago(t.health.lastDirectorySync) : 'never'}</span>}
                  </td>
                  <td className="f-num f-right">{s.users}</td>
                  <td className={cn('f-num f-right', s.expiring > 0 && 'text-[var(--f-warn-ink)]')}>{s.expiring}</td>
                  <td className="f-num f-right">{formatPercent(s.successRate)}</td>
                  <td className="f-right"><ArrowRight className="ml-auto size-4 f-ink-3" aria-hidden /></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {inSetup.length > 0 && (
        <section className="mt-10" aria-label="Tenants in setup">
          <SectionHeader title="What remains" meta="Steps are checked against the tenant’s live configuration" />
          <div className="space-y-4">
            {inSetup.map(({ t, s }) => <SetupChecklist key={t.id} tenant={t} stats={s} onOpen={() => open(t.id)} />)}
          </div>
        </section>
      )}

      {attention.length > 0 && (
        <section className="mt-10" aria-labelledby="f-attn-h">
          <SectionHeader id="f-attn-h" title="Needs attention" />
          <ul className="f-divide border-y border-[var(--f-line)]">
            {attention.map(({ t, s }) => (
              <li key={t.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <span className="min-w-0">
                  <span className="block text-[13.5px] font-semibold">{t.name}</span>
                  <span className="f-small f-ink-2 block">
                    {[
                      t.health.directory !== 'ok' && `Directory ${t.health.directory} · last sync ${ago(t.health.lastDirectorySync)}`,
                      s.controllersDegraded > 0 && `${s.controllersDegraded} wireless ${s.controllersDegraded === 1 ? 'controller' : 'controllers'} degraded`,
                      t.health.radius !== 'ok' && `RADIUS ${t.health.radius}`,
                    ].filter(Boolean).join(' · ')}
                  </span>
                </span>
                <Btn size="sm" onClick={() => open(t.id)}>Open dashboard<ArrowRight aria-hidden /></Btn>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
