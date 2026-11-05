import { Check, ChevronsUpDown } from 'lucide-react'
import { Popover } from 'radix-ui'
import { useState } from 'react'
import { useTenants } from '@/prototype/store'
import type { HealthState } from '@/domain/types'
import { siteCode } from '../model/codes'
import { usePortal } from '../model/state'
import { Tape } from '../ui/Tape'
import { healthLabel, healthTone } from '../ui/Status'
import { StatusMark } from '../ui/Status'

function worst(...s: HealthState[]): HealthState {
  if (s.includes('down')) return 'down'
  if (s.includes('degraded')) return 'degraded'
  if (s.includes('unconfigured')) return 'unconfigured'
  return 'ok'
}

/** The site label: tenant code on tape atop the rail, opening the tenant list. */
export function TenantSwitcher({ onSwitch, onAllTenants, variant = 'rail' }: { onSwitch: (id: string) => void; onAllTenants: () => void; variant?: 'rail' | 'bar' }) {
  const { tenants, current } = useTenants()
  const [open, setOpen] = useState(false)
  const portal = usePortal()
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger
        className={variant === 'rail' ? 'd-site' : 'd-btn d-btn--ghost !h-9 !px-1.5'}
        aria-label={`Tenant: ${current.name}. Switch tenant`}
      >
        <Tape code={siteCode(current)} size="lg" />
        {variant === 'rail' ? (
          <span className="inline-flex items-center gap-0.5">Site<ChevronsUpDown aria-hidden="true" className="size-3" /></span>
        ) : (
          <ChevronsUpDown aria-hidden="true" className="size-4 text-[var(--d-rail-ink-2)]" />
        )}
      </Popover.Trigger>
      <Popover.Portal container={portal}>
        <Popover.Content className="d-popover" side={variant === 'rail' ? 'right' : 'bottom'} align="start" sideOffset={10} collisionPadding={12}>
          <p className="px-2.5 pt-2 pb-2 text-[13px] font-semibold">Switch tenant</p>
          <ul className="grid gap-0.5" role="list">
            {tenants.map((t) => {
              const h = worst(t.health.radius, t.health.pki, t.health.directory)
              const isCurrent = t.id === current.id
              return (
                <li key={t.id}>
                  <button
                    type="button"
                    className="d-tenant-opt"
                    aria-current={isCurrent ? 'true' : undefined}
                    onClick={() => { setOpen(false); if (!isCurrent) onSwitch(t.id) }}
                  >
                    <Tape code={siteCode(t)} />
                    <span className="min-w-0">
                      <span className="block truncate text-[13.5px] font-medium">{t.name}</span>
                      <span className="mt-0.5 block">
                        <StatusMark tone={healthTone(h)}>
                          <span className="text-[12px] text-[var(--d-ink-2)]">{t.status === 'setup' ? 'Setup in progress' : h === 'ok' ? 'All systems healthy' : `Directory ${healthLabel(t.health.directory).toLowerCase()}`}</span>
                        </StatusMark>
                      </span>
                    </span>
                    {isCurrent ? <Check aria-label="Current tenant" className="size-4 text-[var(--d-signal)]" /> : <span className="size-4" />}
                  </button>
                </li>
              )
            })}
          </ul>
          <div className="mt-1 border-t border-[var(--d-line)] p-1.5 pt-2">
            <button type="button" className="d-btn d-btn--sm w-full" onClick={() => { setOpen(false); onAllTenants() }}>
              Open tenant portfolio
            </button>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
