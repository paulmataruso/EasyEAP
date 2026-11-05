import { DropdownMenu } from 'radix-ui'
import { Check, ChevronDown, LayoutGrid, Pin, PinOff } from 'lucide-react'
import { useTenants } from '@/prototype/store'
import type { Tenant } from '@/domain/types'
import { cn } from '@/ui/lib'
import { healthLabel, healthTone, toneIcon, worstTone, type Tone } from '../lib/status'
import { useStoredState } from '../lib/hooks'
import type { TenantSummary } from '../lib/portfolio'
import { usePortal } from '../ui/portal'
import { Tip } from '../ui/Tip'
import { useShell } from './context'
import { usePortfolio } from './portfolio'

const DEFAULT_PINNED = ['t-harborview', 't-cedar', 't-northgate']

export function tenantTone(t: Tenant, s: TenantSummary | undefined): Tone {
  if (t.status === 'setup') return 'neutral'
  const tones: Tone[] = [healthTone[t.health.radius], healthTone[t.health.pki], healthTone[t.health.directory]]
  if (s?.controllers.degraded || s?.controllers.down) tones.push(s.controllers.down ? 'crit' : 'warn')
  return worstTone(tones)
}

export function tenantHealthSummary(t: Tenant, s: TenantSummary | undefined): string {
  if (t.status === 'setup') return 'Setup in progress'
  const parts = [`RADIUS ${healthLabel[t.health.radius].toLowerCase()}`, `PKI ${healthLabel[t.health.pki].toLowerCase()}`, `directory ${healthLabel[t.health.directory].toLowerCase()}`]
  if (s?.controllers.degraded) parts.push(`${s.controllers.degraded} controller degraded`)
  return parts.join(' · ')
}

/** Pinned-tenant tab strip: operators keep the tenants they watch one click away; every tenant is in the menu. */
export function TenantTabs() {
  const { tenants, current, switchTenant } = useTenants()
  const { screen, go } = useShell()
  const portfolio = usePortfolio()
  const container = usePortal()
  const [pinned, setPinned] = useStoredState<string[]>('easyeap.b.pinnedTenants', DEFAULT_PINNED)
  const shown = tenants.filter((t) => pinned.includes(t.id) || t.id === current.id)
  const select = (id: string) => {
    if (id === current.id) return
    switchTenant(id)
    // A user belongs to one tenant: fall back to the list rather than show a foreign record.
    if (screen === 'user') go('users')
  }
  const togglePin = (id: string) => setPinned(pinned.includes(id) ? pinned.filter((x) => x !== id) : [...pinned, id])

  return (
    <div className="b-tabs">
      <nav aria-label="Pinned tenants" className="flex min-w-0 overflow-x-auto [scrollbar-width:none]">
        {shown.map((t) => {
          const tone = tenantTone(t, portfolio.get(t.id))
          const Icon = toneIcon[tone]
          const isPinned = pinned.includes(t.id)
          return (
            <Tip key={t.id} label={`${t.name}: ${tenantHealthSummary(t, portfolio.get(t.id))}`} side="bottom" align="start">
              <button type="button" className="b-tenant-tab" aria-current={t.id === current.id ? 'true' : undefined} onClick={() => select(t.id)}>
                <Icon className={`b-ink-${tone}`} aria-hidden />
                <span>{t.name}</span>
                {!isPinned && <span className="b-t3 text-[11.5px]">not pinned</span>}
              </button>
            </Tip>
          )
        })}
      </nav>
      <DropdownMenu.Root>
        <DropdownMenu.Trigger className="b-tenant-tab shrink-0 gap-1.5" aria-label="All tenants">
          <LayoutGrid aria-hidden />
          <span className="hidden sm:inline">All tenants</span>
          <span className="b-cond b-num font-semibold text-[var(--b-text-3)]">{tenants.length}</span>
          <ChevronDown aria-hidden />
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal container={container}>
          <DropdownMenu.Content align="start" sideOffset={4} className="b-pop w-[340px] p-1">
            <DropdownMenu.Label className="px-2 pb-1 pt-1.5 text-[12px] text-[var(--b-text-2)]">Switch tenant</DropdownMenu.Label>
            {tenants.map((t) => {
              const tone = tenantTone(t, portfolio.get(t.id))
              const Icon = toneIcon[tone]
              return (
                <DropdownMenu.Item key={t.id} className="b-menu-item" onSelect={() => select(t.id)}>
                  <Icon className={`b-ink-${tone}`} aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate">{t.name}</span>
                    <span className="b-t3 block truncate text-[11.5px]">{t.status === 'setup' ? 'Setup in progress' : t.domain}</span>
                  </span>
                  {t.id === current.id && <Check className="text-[var(--b-cyan)]" aria-label="Current tenant" />}
                </DropdownMenu.Item>
              )
            })}
            <DropdownMenu.Separator className="b-menu-sep" />
            <DropdownMenu.Label className="px-2 pb-1 pt-1 text-[12px] text-[var(--b-text-2)]">Pinned to the tab strip</DropdownMenu.Label>
            {tenants.map((t) => (
              <DropdownMenu.CheckboxItem
                key={t.id}
                className="b-menu-item"
                checked={pinned.includes(t.id)}
                onCheckedChange={() => togglePin(t.id)}
                onSelect={(e) => e.preventDefault()}
              >
                {pinned.includes(t.id) ? <Pin className="text-[var(--b-cyan)]" aria-hidden /> : <PinOff className="text-[var(--b-text-3)]" aria-hidden />}
                <span className={cn('flex-1 truncate', !pinned.includes(t.id) && 'text-[var(--b-text-2)]')}>{t.name}</span>
              </DropdownMenu.CheckboxItem>
            ))}
            <DropdownMenu.Separator className="b-menu-sep" />
            <DropdownMenu.Item className="b-menu-item" onSelect={() => go('tenants')}>
              <LayoutGrid aria-hidden />
              Open tenant portfolio
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
      <div className="ml-auto hidden items-center gap-3 pr-3 pl-4 text-[12px] lg:flex">
        <span className="b-chip" title="Every organisation, person and serial on these screens is fictional">
          Synthetic data
        </span>
        <span className="flex items-center gap-2 text-[var(--b-text-2)]">
          <span className="b-cond grid size-6 place-items-center rounded bg-[var(--b-raised)] text-[12px] font-semibold text-[var(--b-text)]" aria-hidden>
            MO
          </span>
          m.okafor@brightline.example
        </span>
      </div>
    </div>
  )
}
