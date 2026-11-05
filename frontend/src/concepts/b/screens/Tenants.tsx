import { useMemo } from 'react'
import { ArrowRight, CircleCheck, CircleDashed, LayoutDashboard } from 'lucide-react'
import { useTenants } from '@/prototype/store'
import type { Tenant } from '@/domain/types'
import { cn, formatPercent } from '@/ui/lib'
import { PageHeader } from '../ui/PageHeader'
import { Panel, PanelHead } from '../ui/Panel'
import { Button } from '../ui/Button'
import { StatusText } from '../ui/Badge'
import { DataTable, useDataTable, type ColumnDef } from '../ui/DataTable'
import { usePortfolio } from '../shell/portfolio'
import { useIntent, useShell } from '../shell/context'
import { setupSteps, type TenantSummary } from '../lib/portfolio'
import { classify, DIRECTORY_BUDGET } from '../lib/freshness'
import { formatAge, pluralize, secondsSince } from '../lib/format'
import { healthLabel, healthTone, type Tone } from '../lib/status'

interface Row {
  tenant: Tenant
  s: TenantSummary
  steps: ReturnType<typeof setupSteps>
}

interface Issue {
  tenant: Tenant
  tone: Tone
  title: string
  detail: string
  screen: 'dashboard' | 'users' | 'certificates' | 'radius' | 'tenants'
}

export function TenantsScreen() {
  const { tenants, current, switchTenant } = useTenants()
  const portfolio = usePortfolio()
  const { go } = useShell()
  useIntent('tenants')

  const rows = useMemo<Row[]>(() => tenants.flatMap((t) => (portfolio.get(t.id) ? [{ tenant: t, s: portfolio.get(t.id)!, steps: setupSteps(t, portfolio.get(t.id)!) }] : [])), [tenants, portfolio])
  const open = (t: Tenant, screen: Issue['screen'] = 'dashboard', section?: string) => {
    if (t.id !== current.id) switchTenant(t.id)
    go(screen, section ? { section } : undefined)
  }

  const columns = useMemo<ColumnDef<Row>[]>(
    () => [
      {
        id: 'tenant',
        header: 'Tenant',
        sticky: true,
        sort: (r) => r.tenant.name,
        search: (r) => `${r.tenant.name} ${r.tenant.domain}`,
        cell: (r) => (
          <span className="flex min-w-0 items-baseline gap-2">
            <span className="shrink-0 font-medium text-[var(--b-text)]">{r.tenant.name}</span>
            <span className="b-mono hidden truncate text-[11px] text-[var(--b-text-3)] 2xl:inline">{r.tenant.domain}</span>
            {r.tenant.id === current.id && <span className="b-chip h-[18px] shrink-0 self-center text-[11px]">Current</span>}
          </span>
        ),
      },
      {
        id: 'radius',
        header: 'RADIUS',
        sort: (r) => r.tenant.health.radius,
        cell: (r) =>
          r.s.controllers.unhealthy.length ? (
            <StatusText tone="warn">{r.s.controllers.unhealthy.length} of {r.s.controllers.total} controllers degraded</StatusText>
          ) : (
            <StatusText tone={healthTone[r.tenant.health.radius]}>{r.tenant.health.radius === 'unconfigured' ? 'Not set up' : `${healthLabel[r.tenant.health.radius]} · ${r.s.controllers.total} ${r.s.controllers.total === 1 ? 'controller' : 'controllers'}`}</StatusText>
          ),
      },
      { id: 'pki', header: 'PKI', sort: (r) => r.tenant.health.pki, cell: (r) => <StatusText tone={healthTone[r.tenant.health.pki]}>{healthLabel[r.tenant.health.pki]}</StatusText> },
      {
        id: 'directory',
        header: 'Directory',
        sort: (r) => secondsSince(r.tenant.health.lastDirectorySync) ?? Infinity,
        cell: (r) => {
          const age = secondsSince(r.tenant.health.lastDirectorySync)
          const fresh = classify(age, DIRECTORY_BUDGET)
          if (r.tenant.health.directory === 'unconfigured') return <StatusText tone="neutral">Not connected</StatusText>
          return (
            <StatusText tone={fresh === 'stale' ? 'crit' : r.tenant.health.directory === 'ok' ? 'ok' : healthTone[r.tenant.health.directory]}>
              {fresh === 'stale' ? 'Stale' : 'Synced'} <span className="b-num text-[var(--b-text-2)]">{formatAge(age)} ago</span>
            </StatusText>
          )
        },
      },
      { id: 'users', header: 'Users', align: 'end', sort: (r) => r.s.users, cell: (r) => <span className="b-num">{r.s.users}</span> },
      {
        id: 'expiring',
        header: 'Expiring certs',
        align: 'end',
        sort: (r) => r.s.certificates.expiring,
        cell: (r) => <span className={cn('b-num', r.s.certificates.expiring ? 'b-ink-warn' : 'text-[var(--b-text-3)]')}>{r.s.certificates.expiring}</span>,
      },
      {
        id: 'success',
        header: 'Auth success 24 h',
        align: 'end',
        sort: (r) => r.s.auth.successRate,
        cell: (r) =>
          r.s.auth.total ? (
            <span className="b-num">
              {formatPercent(r.s.auth.successRate)} <span className="text-[12px] text-[var(--b-text-3)]">of {r.s.auth.total}</span>
            </span>
          ) : (
            <span className="text-[var(--b-text-3)]">No traffic</span>
          ),
      },
      {
        id: 'setup',
        header: 'Setup',
        sort: (r) => r.steps.filter((x) => x.done).length,
        cell: (r) => {
          const done = r.steps.filter((x) => x.done).length
          if (done === r.steps.length) return <StatusText tone="ok">Complete</StatusText>
          return (
            <span className="flex items-center gap-2">
              <span className="flex gap-[2px]" aria-hidden>
                {r.steps.map((x) => (
                  <i key={x.id} className={cn('h-2 w-2.5 rounded-[2px]', x.done ? 'bg-[var(--b-cyan-deep)]' : 'bg-[#2b3949]')} />
                ))}
              </span>
              <span className="b-num text-[12.5px] text-[var(--b-text-2)]">
                {done} of {r.steps.length}
              </span>
            </span>
          )
        },
      },
      {
        id: 'open',
        header: '',
        cell: (r) => (
          <span className="flex justify-end">
            <Button
              size="sm"
              variant="ghost"
              iconEnd={ArrowRight}
              onClick={(e) => {
                e.stopPropagation()
                open(r.tenant)
              }}
              onKeyDown={(e) => e.stopPropagation()}
            >
              Open dashboard
            </Button>
          </span>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `open` closes over current tenant, which is already a dependency
    [current.id],
  )
  const table = useDataTable(rows, columns, { initialSort: { key: 'tenant', dir: 'asc' } })

  const issues: Issue[] = rows
    .flatMap(({ tenant: t, s, steps }) => {
      const out: Issue[] = []
      const syncAge = secondsSince(t.health.lastDirectorySync)
      if (t.health.directory !== 'ok' && t.health.directory !== 'unconfigured')
        out.push({ tenant: t, tone: classify(syncAge, DIRECTORY_BUDGET) === 'stale' ? 'crit' : 'warn', title: `Directory sync failing for ${formatAge(syncAge)}`, detail: s.lastDirectoryError ?? 'The last sync did not complete.', screen: 'users' })
      for (const c of s.controllers.unhealthy)
        out.push({ tenant: t, tone: 'warn', title: `${c.name} silent for ${formatAge(secondsSince(c.lastRequestAt))}`, detail: `No RADIUS requests from ${c.site} since ${c.lastRequestAt?.slice(11, 16) ?? 'registration'} UTC.`, screen: 'radius' })
      if (s.certificates.expiring) out.push({ tenant: t, tone: 'warn', title: `${pluralize(s.certificates.expiring, 'certificate')} expire${s.certificates.expiring === 1 ? 's' : ''} within 30 days`, detail: `${s.certificates.expired ? `${s.certificates.expired} already expired. ` : ''}Issue replacements before users lose Wi-Fi.`, screen: 'certificates' })
      const left = steps.filter((x) => !x.done)
      if (left.length) out.push({ tenant: t, tone: 'neutral', title: `Setup: ${left.length} steps remaining`, detail: left.map((x) => x.label).join(' · '), screen: 'tenants' })
      return out
    })
    .sort((a, b) => ['crit', 'warn', 'neutral', 'info', 'ok'].indexOf(a.tone) - ['crit', 'warn', 'neutral', 'info', 'ok'].indexOf(b.tone))

  const inSetup = rows.filter((r) => r.steps.some((x) => !x.done))

  return (
    <>
      <PageHeader title="Tenants" context={`${tenants.length} customer organisations managed by Brightline · select a tenant to open its dashboard`} />
      <Panel id="b-sec-portfolio" aria-label="Tenant portfolio" className="mb-3">
        <DataTable
          table={table}
          label="Tenant portfolio"
          noun="tenants"
          showFilters={false}
          rowKey={(r) => r.tenant.id}
          rowLabel={(r) => r.tenant.name}
          isActive={(r) => r.tenant.id === current.id}
          onActivate={(r) => open(r.tenant)}
        />
      </Panel>
      <div className="grid gap-3 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <Panel aria-labelledby="attn-title">
          <PanelHead id="attn-title" title="Needs attention" meta={attentionMeta(issues)} />
          <ul className="b-divide-y">
            {issues.map((i, n) => (
              <li key={n}>
                <button type="button" className="grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-[var(--b-hover)]" onClick={() => open(i.tenant, i.screen, i.screen === 'tenants' ? 'setup' : undefined)}>
                  <span className="min-w-0">
                    <StatusText tone={i.tone} className="text-[13px] font-medium">
                      {i.title}
                    </StatusText>
                    <span className="mt-0.5 block truncate pl-5 text-[12.5px] text-[var(--b-text-2)]">
                      <span className="text-[var(--b-text)]">{i.tenant.name}</span> · {i.detail}
                    </span>
                  </span>
                  <ArrowRight className="size-4 text-[var(--b-text-3)]" aria-hidden />
                </button>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel id="b-sec-setup" aria-labelledby="setup-title">
          <PanelHead id="setup-title" title="Setup in progress" />
          {inSetup.length === 0 ? (
            <p className="b-t2 px-3 py-4 text-[12.5px]">Every tenant is fully set up.</p>
          ) : (
            inSetup.map(({ tenant: t, steps }) => (
              <div key={t.id} className="px-3 py-3">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <p className="text-[13.5px] font-semibold text-[var(--b-text)]">{t.name}</p>
                  <span className="b-num text-[12.5px] text-[var(--b-text-2)]">
                    {steps.filter((x) => x.done).length} of {steps.length} done
                  </span>
                  <Button size="sm" variant="ghost" icon={LayoutDashboard} className="ml-auto" onClick={() => open(t)}>
                    Open
                  </Button>
                </div>
                <ol className="space-y-0.5">
                  {steps.map((x) => (
                    <li key={x.id} className="flex items-start gap-2.5 rounded px-1 py-1">
                      {x.done ? <CircleCheck className="b-ink-ok mt-0.5 size-4 shrink-0" aria-hidden /> : <CircleDashed className="mt-0.5 size-4 shrink-0 text-[var(--b-text-3)]" aria-hidden />}
                      <span className="min-w-0 flex-1">
                        <span className={cn('block text-[13px]', x.done ? 'text-[var(--b-text-2)]' : 'font-medium text-[var(--b-text)]')}>
                          {x.label}
                          <span className="sr-only">{x.done ? ' (done)' : ' (remaining)'}</span>
                        </span>
                        {!x.done && <span className="block text-[12px] text-[var(--b-text-2)]">{x.hint}</span>}
                      </span>
                      {!x.done && x.screen !== 'tenants' && (
                        <Button size="sm" variant="secondary" onClick={() => open(t, x.screen as Issue['screen'])}>
                          {x.screen === 'radius' ? 'Open RADIUS' : x.screen === 'users' ? 'Open Users' : 'Open'}
                        </Button>
                      )}
                    </li>
                  ))}
                </ol>
              </div>
            ))
          )}
        </Panel>
      </div>
    </>
  )
}

function attentionMeta(issues: { tenant: Tenant; tone: Tone }[]) {
  const problems = issues.filter((i) => i.tone !== 'neutral')
  const tenants = new Set(problems.map((i) => i.tenant.id)).size
  const setups = issues.length - problems.length
  const parts = [`${pluralize(problems.length, 'issue')} across ${pluralize(tenants, 'tenant')}`]
  if (setups) parts.push(`${setups} in setup`)
  return parts.join(' · ')
}
