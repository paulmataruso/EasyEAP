import { ArrowRight, CircleCheck, CircleDashed } from 'lucide-react'
import { useTenantData, useTenants } from '@/prototype/store'
import type { HealthState } from '@/domain/types'
import { formatPercent } from '@/ui/lib'
import { useConcept } from '../app/context'
import { Button } from '../ui/Button'
import { Cell, DataTable, type ColumnDef } from '../ui/DataTable'
import { Lede, Section } from '../ui/Layout'
import { HealthMark } from '../ui/Status'
import { list, plural, since } from '../lib/format'
import { summarize, type TenantSummary } from '../lib/portfolio'

/** "Initialise the PKI" -> "initialise the PKI"; acronyms keep their case. */
const lowerFirst = (s: string) => (/^[A-Z][a-z]/.test(s) ? s[0].toLowerCase() + s.slice(1) : s)

const serviceLabel = (s: HealthState) => ({ ok: 'Healthy', degraded: 'Degraded', down: 'Down', unconfigured: 'Not set up' })[s]

export function TenantsScreen() {
  const { tenants, current, switchTenant } = useTenants()
  const live = useTenantData()
  const { go } = useConcept()
  const rows = tenants.map((t) => summarize(t, live))

  const open = (s: TenantSummary, screen: 'dashboard' | 'radius' | 'users' | 'policies' = 'dashboard', intent?: Parameters<typeof go>[1]) => {
    if (s.tenant.id !== current.id) switchTenant(s.tenant.id)
    go(screen, intent)
  }

  const degraded = rows.filter((r) => r.tenant.status !== 'setup' && [r.tenant.health.radius, r.tenant.health.pki, r.tenant.health.directory].some((h) => h === 'degraded' || h === 'down'))
  const inSetup = rows.filter((r) => r.tenant.status === 'setup')
  const healthy = rows.length - degraded.length - inSetup.length
  const restParts = [
    ...degraded.map((r) => `${r.tenant.name} needs attention`),
    ...inSetup.map((r) => `${r.tenant.name} is mid-setup`),
  ]

  const columns: ColumnDef<TenantSummary>[] = [
    {
      key: 'tenant',
      header: 'Tenant',
      cell: (s) => (
        <Cell
          primary={
            <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: '4px 8px', alignItems: 'center' }}>
              <button type="button" className="c-rowlink" onClick={() => open(s)}>
                {s.tenant.name}
              </button>
              {s.tenant.id === current.id ? <span className="c-tag is-strong">Current</span> : null}
            </span>
          }
          secondary={
            s.tenant.status === 'setup'
              ? `${s.tenant.domain} · setup ${s.setup.done} of ${s.setup.total}`
              : `${s.tenant.domain} · ${s.attention ? plural(s.attention, 'item needs', 'items need') + ' attention' : 'nothing needs attention'}`
          }
        />
      ),
    },
    { key: 'radius', header: 'RADIUS', hide: 'md', cell: (s) => <Cell primary={<HealthMark state={s.tenant.health.radius} label={serviceLabel(s.tenant.health.radius)} />} secondary={s.controllers ? (s.controllersQuiet ? `${s.controllersQuiet} of ${s.controllers} controllers quiet` : `${plural(s.controllers, 'controller')} reporting`) : 'No controllers'} /> },
    { key: 'pki', header: 'PKI', hide: 'lg', cell: (s) => <HealthMark state={s.tenant.health.pki} label={serviceLabel(s.tenant.health.pki)} /> },
    { key: 'dir', header: 'Directory', hide: 'md', cell: (s) => <Cell primary={<HealthMark state={s.tenant.health.directory} label={serviceLabel(s.tenant.health.directory)} />} secondary={s.tenant.health.lastDirectorySync ? `Synced ${since(s.tenant.health.lastDirectorySync)}` : 'Never synced'} /> },
    { key: 'users', header: 'Users', align: 'end', hide: 'sm', cell: (s) => <Cell primary={<span className="tnum">{s.users}</span>} secondary={`${s.allowed} allowed`} /> },
    { key: 'expiring', header: 'Expiring', align: 'end', hide: 'lg', cell: (s) => <Cell primary={<span className="tnum">{s.expiring}</span>} secondary={s.validCerts ? `of ${s.validCerts} valid` : 'None issued'} /> },
    { key: 'auth', header: 'Success, 24h', align: 'end', cell: (s) => <Cell primary={<span className="tnum">{s.successRate === null ? '—' : formatPercent(s.successRate)}</span>} secondary={s.authTotal ? `${s.authTotal} attempts` : 'No traffic'} /> },
  ]

  return (
    <>
      <Lede
        page="Tenants"
        state={
          <>
            <strong>
              {healthy} of {rows.length}
            </strong>{' '}
            tenants are healthy.
          </>
        }
        rest={restParts.length ? `${list(restParts)}.` : 'Everything is running.'}
        detail="Every customer you manage, with its own CA, directory, policies and controllers. Choose one to switch to it and open its overview."
      />
      <Section title="Portfolio" flush>
        <DataTable
          caption="Tenants"
          columns={columns}
          rows={rows}
          rowKey={(s) => s.tenant.id}
          onRowClick={(s) => open(s)}
          renderAfter={(s) =>
            s.tenant.status === 'setup' ? (
              <div style={{ display: 'grid', gap: 12 }}>
                <p className="c-muted c-small" style={{ margin: 0 }}>
                  {plural(s.setup.remaining.length, 'step remains', 'steps remain')} before {s.tenant.name} can authenticate anyone:
                </p>
                <ol className="c-list" style={{ maxWidth: 820 }}>
                  {s.setup.remaining.map((step) => (
                    <li key={step.id}>
                      <div className="c-listrow" style={{ minHeight: 48, padding: '8px 0' }}>
                        <CircleDashed size={17} aria-hidden="true" style={{ color: 'var(--c-text-3)', flex: 'none' }} />
                        <span className="c-listrow-main">
                          <span style={{ fontWeight: 500 }}>{step.title}</span>
                          <span className="c-cell-secondary">{step.detail}</span>
                        </span>
                        {step.action ? (
                          <Button size="sm" variant="ghost" iconEnd={<ArrowRight size={15} aria-hidden="true" />} onClick={() => open(s, step.action!.screen as 'radius' | 'users' | 'policies', { intent: step.action!.intent })}>
                            {step.action.label}
                          </Button>
                        ) : (
                          <span className="c-faint c-small">Needs the LDAPS bind account</span>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
                <p className="c-faint c-small" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <CircleCheck size={15} aria-hidden="true" style={{ color: 'var(--c-ok)' }} />
                  Done: {list(s.setup.completed.map((c) => lowerFirst(c.title)))}.
                </p>
              </div>
            ) : null
          }
        />
      </Section>
    </>
  )
}

