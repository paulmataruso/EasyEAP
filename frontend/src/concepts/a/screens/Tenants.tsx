import { useMemo } from 'react'
import { ArrowRight, CircleCheck, CircleDashed, Network } from 'lucide-react'
import type { HealthState } from '@/domain/types'
import { cn, formatPercent } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { HealthPill, healthLabels } from '../ui/badges'
import { DataTable, useDataTable, type TableColumn } from '../ui/DataTable'
import { Button, IconButton, Mono, PageHeader, Panel } from '../ui/primitives'
import { ScopeChip } from '../ui/scope'
import { AuditTimeline } from '../features/activity'
import { tenantHealth, worstHealth } from '../lib/model'
import { usePortfolio, type TenantSummary } from '../lib/portfolio'
import { ago } from '../lib/time'
import { useNav } from '../shell/nav'

function ServicePill({ name, state, detail }: { name: string; state: HealthState; detail?: string }) {
  return (
    <span title={`${name}: ${detail ?? healthLabels[state]}`}>
      <HealthPill state={state} label={name} />
      <span className="sr-only"> {detail ?? healthLabels[state]}</span>
    </span>
  )
}

export function Tenants() {
  const portfolio = usePortfolio()
  const { current, switchTenant } = useTenants()
  const d = useTenantData()
  const { navigate } = useNav()

  const open = (id: string) => {
    if (id !== current.id) switchTenant(id)
    navigate('dashboard')
  }

  const columns = useMemo<TableColumn<TenantSummary>[]>(
    () => [
      {
        key: 'name',
        header: 'Tenant',
        sortValue: (p) => p.tenant.name,
        cell: (p) => (
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <button type="button" onClick={() => open(p.tenant.id)} className="truncate text-left text-[14px] font-semibold text-[var(--a-text)] underline-offset-[3px] hover:underline">
                {p.tenant.name}
              </button>
              {p.tenant.id === current.id && <ScopeChip depth="tenant" className="!h-5 shrink-0 !rounded-md !px-1.5 !text-[11px]">Current</ScopeChip>}
            </div>
            <Mono className="text-[12px] text-[var(--a-text-3)]">{p.tenant.domain}</Mono>
          </div>
        ),
      },
      {
        key: 'state',
        header: 'Setup',
        sortValue: (p) => p.steps.filter((s) => s.done).length,
        cell: (p) => {
          const done = p.steps.filter((s) => s.done).length
          return p.tenant.status === 'setup' ? (
            <div className="min-w-[120px]">
              <span className="text-[13px] font-medium text-[var(--a-text)]">
                {done} of {p.steps.length} steps
              </span>
              <div className="mt-1 h-1 rounded-full bg-white/[0.08]">
                <div className="h-full rounded-full bg-[var(--a-info)]" style={{ width: `${(done / p.steps.length) * 100}%` }} />
              </div>
            </div>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-[13px] text-[var(--a-text-2)]">
              <CircleCheck className="size-3.5 text-[var(--a-ok-text)]" aria-hidden /> Live
            </span>
          )
        },
      },
      {
        key: 'health',
        header: 'Health',
        sortValue: (p) => ['ok', 'unconfigured', 'degraded', 'down'].indexOf(tenantHealth(p.tenant, p.controllers).state),
        cell: (p) => {
          const nasBad = p.controllers.filter((c) => c.status === 'degraded' || c.status === 'down')
          const radius = worstHealth([p.tenant.health.radius, ...nasBad.map((c) => c.status)])
          return (
            <div className="flex flex-nowrap gap-1.5">
              <ServicePill name="RADIUS" state={radius} detail={nasBad.length ? `${nasBad.length} controller degraded` : undefined} />
              <ServicePill name="PKI" state={p.tenant.health.pki} />
              <ServicePill name="Directory" state={p.tenant.health.directory} />
            </div>
          )
        },
      },
      { key: 'users', header: 'Users', align: 'right', sortValue: (p) => p.users, cell: (p) => <span className="a-num text-[var(--a-text)]">{p.users}</span> },
      {
        key: 'expiring',
        header: 'Expiring certs',
        align: 'right',
        sortValue: (p) => p.expiring,
        cell: (p) => <span className={cn('a-num', p.expiring ? 'text-[var(--a-warn-text)]' : 'text-[var(--a-text-3)]')}>{p.expiring}</span>,
      },
      {
        key: 'success',
        header: 'Auth success 24h',
        align: 'right',
        sortValue: (p) => p.successRate,
        cell: (p) =>
          p.successRate === null ? (
            <span className="text-[var(--a-text-3)]">No traffic</span>
          ) : (
            <span className="a-num text-[var(--a-text)]">
              {formatPercent(p.successRate)} <span className="text-[12px] text-[var(--a-text-3)]">of {p.events24h}</span>
            </span>
          ),
      },
      {
        key: 'sync',
        header: 'Directory sync',
        className: 'hidden lg:table-cell',
        sortValue: (p) => p.tenant.health.lastDirectorySync,
        cell: (p) => <span className={cn('a-num whitespace-nowrap', p.tenant.health.directory === 'degraded' && 'text-[var(--a-warn-text)]')}>{p.tenant.health.lastDirectorySync ? ago(p.tenant.health.lastDirectorySync) : 'Never'}</span>,
      },
      {
        key: 'open',
        header: 'Open',
        srHeader: true,
        align: 'right',
        cell: (p) => <IconButton icon={ArrowRight} label={`Open ${p.tenant.name} dashboard`} onClick={() => open(p.tenant.id)} />,
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [current.id],
  )
  const table = useDataTable(portfolio, columns, { initialSort: { key: 'name', dir: 'asc' } })

  const totals = {
    users: portfolio.reduce((s, p) => s + p.users, 0),
    expiring: portfolio.reduce((s, p) => s + p.expiring, 0),
    events: portfolio.reduce((s, p) => s + p.events24h, 0),
    accepts: portfolio.reduce((s, p) => s + p.accepts24h, 0),
  }
  const inSetup = portfolio.filter((p) => p.tenant.status === 'setup')
  const needAttention = portfolio.filter((p) => p.tenant.status !== 'setup' && ['degraded', 'down'].includes(tenantHealth(p.tenant, p.controllers).state))
  const platformAudit = d.audit.filter((a) => a.tenantId === null)

  return (
    <>
      <PageHeader
        leading={
          <span className="grid size-10 place-items-center rounded-[10px] border border-[var(--a-d0-border)] bg-[var(--a-d0-fill)] text-[#a5b4fc]">
            <Network className="size-5" aria-hidden />
          </span>
        }
        title="Tenants"
        description={`${portfolio.length} organisations managed from this console. Selecting one switches every screen to it.`}
      />

      {/* Platform scope: everything on this screen sits on the platform glass. */}
      <section aria-label="Portfolio totals" className="a-panel a-depth-platform mb-4 grid grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Wi-Fi users', value: totals.users.toLocaleString(), hint: 'across all tenants' },
          {
            label: 'Need attention',
            value: String(needAttention.length),
            hint: [needAttention.length ? needAttention.map((p) => p.tenant.name.split(' ')[0]).join(', ') : 'all live tenants healthy', inSetup.length ? `${inSetup.length} in setup` : ''].filter(Boolean).join(' · '),
          },
          { label: 'Certificates expiring', value: String(totals.expiring), hint: 'within 30 days' },
          { label: 'Auth success 24h', value: formatPercent(totals.events ? totals.accepts / totals.events : null), hint: `${totals.events.toLocaleString()} attempts` },
        ].map((t, i) => (
          <div key={t.label} className={cn('px-[18px] py-3.5', i > 0 && 'lg:border-l lg:border-[var(--a-d0-border)]', i % 2 === 1 && 'border-l border-[var(--a-d0-border)]', i >= 2 && 'border-t border-[var(--a-d0-border)] lg:border-t-0')}>
            <p className="text-[13px] text-[var(--a-d0-ink)]">{t.label}</p>
            <p className="mt-1 text-[24px] leading-none font-semibold text-[var(--a-text)]">{t.value}</p>
            <p className="mt-1 truncate text-[12px] text-[var(--a-text-3)]">{t.hint}</p>
          </div>
        ))}
      </section>

      <div className="grid items-start gap-4 2xl:grid-cols-12">
        <section aria-label="Tenant portfolio" className="a-panel a-depth-platform 2xl:col-span-8">
          <header className="a-panel-head">
            <div>
              <h2 className="a-panel-title">Portfolio</h2>
              <p className="a-panel-desc">Health, adoption and setup for every tenant. Select a row to open its dashboard.</p>
            </div>
          </header>
          <DataTable caption="Tenants" columns={columns} table={table} rowKey={(p) => p.tenant.id} selectedKey={current.id} onRowClick={(p) => open(p.tenant.id)} />
          <p className="border-t border-[var(--a-d0-border)] px-[18px] py-2.5 text-[12px] text-[var(--a-text-3)]">
            {portfolio.find((p) => p.live)?.tenant.name} shows live figures from this session; other tenants show their last loaded snapshot.
          </p>
        </section>

        <div className="flex flex-col gap-4 2xl:col-span-4">
          {inSetup.map((p) => {
            const done = p.steps.filter((s) => s.done).length
            return (
              <Panel
                key={p.tenant.id}
                depth="platform"
                title={`${p.tenant.name} is mid-setup`}
                description={`${done} of ${p.steps.length} steps done. Wi-Fi authentication is not live yet.`}
                actions={
                  <Button size="sm" variant="primary" onClick={() => open(p.tenant.id)}>
                    Continue setup
                  </Button>
                }
              >
                <ol className="border-t border-[var(--a-d0-border)] px-[18px] py-2">
                  {p.steps.map((s) => (
                    <li key={s.id} className="flex items-start gap-3 py-2">
                      {s.done ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-[var(--a-ok-text)]" aria-hidden /> : <CircleDashed className="mt-0.5 size-4 shrink-0 text-[var(--a-text-3)]" aria-hidden />}
                      <div className="min-w-0">
                        <p className={cn('text-[14px]', s.done ? 'text-[var(--a-text-2)]' : 'font-medium text-[var(--a-text)]')}>
                          {s.label}
                          <span className="sr-only">{s.done ? ' (done)' : ' (remaining)'}</span>
                        </p>
                        <p className="text-[12px] text-[var(--a-text-3)]">{s.detail}</p>
                      </div>
                    </li>
                  ))}
                </ol>
              </Panel>
            )
          })}
          <Panel depth="platform" title="Platform activity" description="Changes that apply across tenants.">
            <div className="border-t border-[var(--a-d0-border)] px-[18px] py-4">
              {platformAudit.length ? <AuditTimeline events={platformAudit} limit={5} /> : <p className="text-[13px] text-[var(--a-text-3)]">No platform-level changes recorded.</p>}
            </div>
          </Panel>
        </div>
      </div>
    </>
  )
}
