import { useMemo } from 'react'
import { ArrowRight, CircleCheck, CircleDashed } from 'lucide-react'
import { useTenants } from '@/prototype/store'
import type { Tenant } from '@/domain/types'
import { formatPercent } from '@/ui/lib'
import { DataTable } from '../DataTable'
import { tenantStats, type TenantStats } from '../bits'
import { INK, STATUS, ago, healthWorst } from '../theme'
import { Button, HealthBullets, PageHeader, Panel, RampLegend, StatusIcon, VolumeGlyph, useE } from '../ui'

interface Row { t: Tenant; s: TenantStats; steps: Array<{ label: string; done: boolean; detail: string }> }

function setupSteps(t: Tenant, s: TenantStats) {
  return [
    { label: 'Tenant created', done: true, detail: `Created ${ago(t.createdAt)}` },
    { label: 'PKI initialised', done: s.issuingCa, detail: 'Offline root CA and an issuing CA' },
    { label: 'Access policy', done: s.rules > 0, detail: s.rules ? `${s.rules} rules, default deny` : 'Add at least one allow rule' },
    { label: 'Connect Active Directory', done: t.health.directory !== 'unconfigured', detail: t.health.directory === 'unconfigured' ? `LDAPS bind to ${t.domain} not configured` : 'Syncing users and groups' },
    { label: 'Issue the RADIUS server certificate', done: s.serverCert, detail: s.serverCert ? 'Issued' : `For radius.${t.domain}` },
    { label: 'Register a wireless controller', done: s.controllers > 0, detail: s.controllers ? `${s.controllers} registered` : 'Catalyst 9800, AireOS or UniFi' },
  ]
}

export function Tenants() {
  const { tenants, current, switchTenant } = useTenants()
  const { go } = useE()
  const rows = useMemo<Row[]>(() => tenants.map((t) => { const s = tenantStats(t.id); return { t, s, steps: setupSteps(t, s) } }), [tenants])
  const open = (t: Tenant) => { switchTenant(t.id); go('dashboard') }
  const setup = rows.filter((r) => r.t.status === 'setup')
  const totals = rows.reduce((a, r) => ({ users: a.users + r.s.users, events: a.events + r.s.events, expiring: a.expiring + r.s.expiring }), { users: 0, events: 0, expiring: 0 })

  return (
    <>
      <PageHeader title="Tenants" meta={<><span className="num">{tenants.length} networks managed by Brightline MSP</span><span aria-hidden className="t3">·</span><span className="num">{totals.users} users</span><span aria-hidden className="t3">·</span><span className="num">{totals.events} authentications in 24 hours</span><span aria-hidden className="t3">·</span><span className="num">{totals.expiring} certificates expiring</span></>} />

      <Panel title="Portfolio" desc="Select a tenant to switch to it and open its dashboard." actions={<RampLegend className="max-lg:hidden" />}>
        <DataTable
          caption="Tenants"
          rows={rows}
          rowKey={(r) => r.t.id}
          selectedKey={current.id}
          onActivate={(r) => open(r.t)}
          columns={[
            { key: 'name', header: 'Network', cell: ({ t }) => (
              <div className="min-w-0 py-2">
                <button type="button" data-row-primary className="e-rowlink block max-w-full truncate" onClick={() => open(t)}>{t.name}</button>
                <span className="t2 block truncate text-[12px]">{t.domain}{t.id === current.id ? ' · current' : ''}</span>
              </div>
            ) },
            { key: 'health', header: 'Health', cell: ({ t, s }) => {
              const w = s.degradedControllers > 0 && t.status !== 'setup' ? healthWorst([t.health.radius, t.health.pki, t.health.directory, 'degraded']) : healthWorst([t.health.radius, t.health.pki, t.health.directory])
              const label = t.status === 'setup' ? 'Setup in progress' : t.health.directory !== 'ok' ? 'Directory sync failing' : t.health.radius !== 'ok' ? 'RADIUS degraded' : s.degradedControllers > 0 ? `${s.degradedControllers} controller degraded` : 'Operational'
              return (
                <div className="flex items-center gap-2.5">
                  <HealthBullets radius={t.health.radius} pki={t.health.pki} directory={t.health.directory} />
                  <span className="e-state max-md:hidden"><StatusIcon state={t.status === 'setup' ? 'unconfigured' : w} /><span>{label}</span></span>
                </div>
              )
            } },
            { key: 'users', header: 'Users', align: 'right', hideBelow: 'sm', cell: ({ s }) => <span className="num">{s.users}</span> },
            { key: 'exp', header: 'Expiring certs', align: 'right', hideBelow: 'md', cell: ({ s }) => <span className="num">{s.expiring}</span> },
            { key: 'rate', header: '24h success', align: 'right', cell: ({ s }) => s.events ? <span className="num">{formatPercent(s.accepts / s.events)}<span className="t2 block text-[12px]">{s.accepts} of {s.events}</span></span> : <span className="t3">No traffic</span> },
            { key: 'vol', header: '24h volume', hideBelow: 'lg', cell: ({ s }) => <span className="inline-flex items-center gap-2"><VolumeGlyph count={s.events} color={INK.station} form={s.events ? 'live' : 'idle'} length={48} /><span className="t2 num text-[12px]">{s.controllers} {s.controllers === 1 ? 'controller' : 'controllers'}</span></span> },
            { key: 'sync', header: 'Directory sync', hideBelow: 'lg', cell: ({ t }) => <span className={t.health.directory === 'degraded' ? 'e-state' : 't2'}>{t.health.directory === 'degraded' && <StatusIcon state="degraded" />}{t.health.lastDirectorySync ? ago(t.health.lastDirectorySync) : 'Never'}</span> },
            { key: 'setup', header: 'Setup', cell: ({ steps }) => {
              const done = steps.filter((x) => x.done).length
              return done === steps.length ? <span className="t2">Complete</span> : (
                <span className="inline-flex items-center gap-2">
                  <span className="flex gap-[3px]" aria-hidden>{steps.map((x, i) => <span key={i} className="h-[6px] w-3 rounded-full" style={x.done ? { background: INK.station } : { border: `1px dashed ${INK.text3}` }} />)}</span>
                  <span className="num">{done} of {steps.length}</span>
                </span>
              )
            } },
          ]}
        />
      </Panel>

      {setup.map(({ t, steps }) => {
        const remaining = steps.filter((x) => !x.done)
        return (
          <Panel key={t.id} className="mt-4" title={`${t.name}: ${remaining.length} setup ${remaining.length === 1 ? 'step remains' : 'steps remain'}`} desc="Nobody can authenticate on this network until every step is complete."
            actions={<Button variant="primary" onClick={() => open(t)}>Open {t.name}<ArrowRight /></Button>}>
            <ol className="grid grid-cols-1 gap-x-6 px-4 pb-4 md:grid-cols-2 xl:grid-cols-3">
              {steps.map((x, i) => (
                <li key={x.label} className="flex items-start gap-3 border-t border-[var(--e-hair)] py-3">
                  <span className="mt-0.5">{x.done ? <CircleCheck size={18} color={STATUS.ok.hex} aria-hidden /> : <CircleDashed size={18} color={STATUS.unconfigured.hex} aria-hidden />}</span>
                  <span className="min-w-0">
                    <span className="block text-[13.5px] font-semibold"><span className="t3 num mr-1.5">{i + 1}</span>{x.label}<span className="sr-only">{x.done ? ', done' : ', remaining'}</span></span>
                    <span className="t2 block text-[12.5px]">{x.detail}</span>
                  </span>
                </li>
              ))}
            </ol>
          </Panel>
        )
      })}
    </>
  )
}
