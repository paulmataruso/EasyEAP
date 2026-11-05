import { useState, type ReactNode } from 'react'
import { Dialog, DropdownMenu } from 'radix-ui'
import { Check, ChevronDown, LayoutGrid, LogOut, Menu, Search, X } from 'lucide-react'
import { useTenants } from '@/prototype/store'
import { LogoMark, Wordmark } from '@/ui/Logo'
import { cn } from '@/ui/lib'
import type { ScreenId } from '../contract'
import { STATUS, healthWorst } from './theme'
import { Button, HealthBullets, useE, type Intent } from './ui'
import { PALETTE_KEY } from './CommandPalette'
import { tenantStats } from './bits'

interface NavItem { label: string; screen: ScreenId; entityId?: string; intent?: Intent; hint?: string }
interface NavSection { id: string; label: string; screens: ScreenId[]; screen?: ScreenId; items?: NavItem[] }

export const NAV: NavSection[] = [
  { id: 'overview', label: 'Overview', screens: ['dashboard'], screen: 'dashboard' },
  {
    id: 'identity', label: 'Identity', screens: ['users', 'user'], items: [
      { label: 'All users', screen: 'users', hint: 'Directory and local accounts' },
      { label: 'Denied users', screen: 'users', intent: { kind: 'users.filter', access: 'deny' }, hint: 'No Wi-Fi access under current policy' },
      { label: 'Local accounts', screen: 'users', intent: { kind: 'users.filter', source: 'local' }, hint: 'Not synced from Active Directory' },
    ],
  },
  {
    id: 'pki', label: 'Certificates', screens: ['certificates'], items: [
      { label: 'All certificates', screen: 'certificates' },
      { label: 'Expiring soon', screen: 'certificates', intent: { kind: 'certs.filter', status: 'expiring' }, hint: 'Within the renewal window' },
      { label: 'Revoked', screen: 'certificates', intent: { kind: 'certs.filter', status: 'revoked' } },
      { label: 'Certificate authorities', screen: 'certificates', intent: { kind: 'scroll', target: 'ca-status' }, hint: 'Offline root, issuing CA, CRL, OCSP' },
    ],
  },
  {
    id: 'network', label: 'Network', screens: ['radius', 'policies'], items: [
      { label: 'RADIUS server', screen: 'radius', hint: 'Ports, TLS and server certificate' },
      { label: 'Wireless controllers', screen: 'radius', intent: { kind: 'scroll', target: 'controllers' } },
      { label: 'Register a controller', screen: 'radius', entityId: 'new' },
      { label: 'VLAN policies', screen: 'policies', hint: 'VLANs and access rules' },
      { label: 'Test a user', screen: 'policies', intent: { kind: 'policies.test' } },
    ],
  },
  { id: 'tenants', label: 'Tenants', screens: ['tenants'], screen: 'tenants' },
]

export function Shell({ screen, children }: { screen: ScreenId; children: ReactNode }) {
  const { go, openPalette, container } = useE()
  const [sheet, setSheet] = useState(false)
  return (
    <>
      <a href="#e-main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[90] focus:rounded-md focus:bg-[var(--e-station)] focus:px-3 focus:py-2 focus:text-[var(--e-ground)]">Skip to content</a>
      <header className="e-topbar">
        <div className="flex min-w-0 items-center gap-1">
          <Button variant="ghost" icon className="min-[1280px]:hidden" aria-label="Open navigation" onClick={() => setSheet(true)}><Menu /></Button>
          <button type="button" className="mr-3 inline-flex items-center rounded-md text-[17px] text-[var(--e-text)] max-sm:hidden" onClick={() => go('dashboard')} aria-label="EasyEAP overview">
            <Wordmark markClassName="size-6" />
          </button>
          <button type="button" className="mr-1 inline-flex items-center rounded-md text-[var(--e-text)] sm:hidden" onClick={() => go('dashboard')} aria-label="EasyEAP overview"><LogoMark className="size-6" /></button>
          <nav aria-label="Sections" className="flex items-center gap-0.5 max-[1279px]:hidden">
            {NAV.map((s) => {
              const active = s.screens.includes(screen)
              if (!s.items) return <button key={s.id} type="button" className="e-navlink" data-active={active} aria-current={active ? 'page' : undefined} onClick={() => go(s.screen!)}>{s.label}</button>
              return (
                <DropdownMenu.Root key={s.id} modal={false}>
                  <DropdownMenu.Trigger className="e-navlink" data-active={active} aria-current={active ? 'page' : undefined}>
                    {s.label}<ChevronDown size={14} aria-hidden className="opacity-70" />
                  </DropdownMenu.Trigger>
                  <DropdownMenu.Portal container={container}>
                    <DropdownMenu.Content className="e-menu w-[300px]" sideOffset={10} align="start">
                      {s.items.map((it) => (
                        <DropdownMenu.Item key={it.label} className="e-menu-item !items-start" onSelect={() => go(it.screen, { entityId: it.entityId, intent: it.intent })}>
                          <span className="min-w-0">
                            <span className="block font-semibold">{it.label}</span>
                            {it.hint && <span className="t2 block text-[12px]">{it.hint}</span>}
                          </span>
                        </DropdownMenu.Item>
                      ))}
                    </DropdownMenu.Content>
                  </DropdownMenu.Portal>
                </DropdownMenu.Root>
              )
            })}
          </nav>
        </div>

        <div className="flex min-w-0 justify-center">
          <button type="button" className="e-palette-trigger max-w-[460px] max-sm:hidden" onClick={openPalette} aria-label="Search and run commands" aria-keyshortcuts="Control+K Meta+K">
            <Search size={16} aria-hidden />
            <span className="min-w-0 flex-1 truncate">Search users, certificates, controllers…</span>
            <span className="e-kbd" aria-hidden>{PALETTE_KEY}</span>
          </button>
          <Button variant="ghost" icon className="sm:hidden" aria-label="Search and run commands" onClick={openPalette}><Search /></Button>
        </div>

        <div className="flex min-w-0 items-center justify-end gap-2">
          <NetworkSelector screen={screen} />
          <AccountMenu />
        </div>
      </header>

      <MobileSheet open={sheet} onOpenChange={setSheet} screen={screen} />

      <main id="e-main" className="mx-auto w-full max-w-[1680px] px-4 pb-16 sm:px-6" tabIndex={-1}>
        {children}
      </main>
      <footer className="mx-auto flex w-full max-w-[1680px] flex-wrap justify-between gap-2 border-t border-[var(--e-hair)] px-4 py-5 text-[12px] t3 sm:px-6">
        <span>EasyEAP · Enterprise Wi-Fi Authentication, Simplified.</span>
        <span>Design prototype · all organisations, people and serials are synthetic</span>
      </footer>
    </>
  )
}

/** Tenant switcher, framed as the network selector: each tenant is a network with health bullets. */
function NetworkSelector({ screen }: { screen: ScreenId }) {
  const { tenants, current, switchTenant } = useTenants()
  const { go, container } = useE()
  const h = current.health
  const worst = healthWorst([h.radius, h.pki, h.directory])
  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger className="e-btn e-btn-secondary !h-[38px] min-w-0 max-w-[290px] !gap-2.5 !px-2.5" aria-label={`Network: ${current.name}. ${STATUS[worst].label}. Switch network`}>
        <HealthBullets radius={h.radius} pki={h.pki} directory={h.directory} />
        <span className="min-w-0 truncate text-left text-[13.5px] max-sm:max-w-[84px]">{current.name}</span>
        <ChevronDown size={15} aria-hidden className="t2 shrink-0" />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <DropdownMenu.Content className="e-menu w-[360px] max-w-[calc(100vw-16px)]" sideOffset={8} align="end">
          <DropdownMenu.Label className="e-menu-label">Switch network</DropdownMenu.Label>
          <DropdownMenu.RadioGroup value={current.id} onValueChange={(id) => { switchTenant(id); if (screen === 'user') go('users'); else if (screen === 'certificates' || screen === 'radius') go(screen) }}>
            {tenants.map((t) => {
              const th = t.health
              const degraded = t.status === 'setup' ? 0 : tenantStats(t.id).degradedControllers
              const issue = t.status === 'setup' ? 'Setup in progress' : th.directory !== 'ok' ? `Directory ${STATUS[th.directory].label.toLowerCase()}` : th.radius !== 'ok' ? `RADIUS ${STATUS[th.radius].label.toLowerCase()}` : degraded > 0 ? `${degraded} controller degraded` : 'All services operational'
              return (
                <DropdownMenu.RadioItem key={t.id} value={t.id} className="e-menu-item !items-start !py-2">
                  <span className="mt-0.5"><HealthBullets radius={th.radius} pki={th.pki} directory={th.directory} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-semibold">{t.name}</span>
                    <span className="t2 block truncate text-[12px]">{t.domain} · {issue}</span>
                  </span>
                  <DropdownMenu.ItemIndicator className="mt-0.5"><Check size={16} /></DropdownMenu.ItemIndicator>
                </DropdownMenu.RadioItem>
              )
            })}
          </DropdownMenu.RadioGroup>
          <DropdownMenu.Separator className="e-menu-sep" />
          <DropdownMenu.Item className="e-menu-item" onSelect={() => go('tenants')}><LayoutGrid />View all tenants</DropdownMenu.Item>
          <p className="t2 px-2.5 pb-1.5 pt-1 text-[11.5px]">R RADIUS · P PKI · D Directory</p>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

function AccountMenu() {
  const { container, toast, openPalette } = useE()
  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger className="inline-grid size-[34px] shrink-0 place-items-center rounded-full border border-[var(--e-hair-strong)] bg-[var(--e-raised)] text-[12px] font-bold text-[var(--e-text)] hover:bg-[var(--e-raised-2)]" aria-label="Account: m.okafor@brightline.example">
        MO
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <DropdownMenu.Content className="e-menu w-[270px]" sideOffset={8} align="end">
          <div className="px-2.5 py-2">
            <p className="text-[13.5px] font-semibold">m.okafor@brightline.example</p>
            <p className="t2 text-[12px]">Brightline MSP · MSP technician</p>
          </div>
          <DropdownMenu.Separator className="e-menu-sep" />
          <DropdownMenu.Item className="e-menu-item" onSelect={openPalette}><Search />Command palette<span className="e-kbd ml-auto">{PALETTE_KEY}</span></DropdownMenu.Item>
          <DropdownMenu.Item className="e-menu-item" onSelect={() => toast({ title: 'Sign-out is disabled in the prototype', tone: 'warn' })}><LogOut />Sign out</DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

function MobileSheet({ open, onOpenChange, screen }: { open: boolean; onOpenChange: (o: boolean) => void; screen: ScreenId }) {
  const { go, container } = useE()
  const nav = (s: ScreenId, opts?: { entityId?: string; intent?: Intent }) => { onOpenChange(false); go(s, opts) }
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="e-overlay" />
        <Dialog.Content className="e-sheet" aria-describedby={undefined}>
          <div className="mb-4 flex items-center justify-between">
            <Dialog.Title className="text-[16px]"><Wordmark markClassName="size-6" /></Dialog.Title>
            <Dialog.Close asChild><Button variant="ghost" icon aria-label="Close navigation"><X /></Button></Dialog.Close>
          </div>
          <nav aria-label="Sections" className="space-y-4">
            {NAV.map((s) => (
              <div key={s.id}>
                {s.items ? (
                  <>
                    <p className={cn('px-2 pb-1 text-[12px] font-semibold', s.screens.includes(screen) ? 'text-[var(--e-text)]' : 't2')}>{s.label}</p>
                    {s.items.map((it) => (
                      <button key={it.label} type="button" className="e-menu-item w-full text-left" onClick={() => nav(it.screen, { entityId: it.entityId, intent: it.intent })}>{it.label}</button>
                    ))}
                  </>
                ) : (
                  <button type="button" className="e-menu-item w-full text-left font-semibold" aria-current={s.screens.includes(screen) ? 'page' : undefined} onClick={() => nav(s.screen!)}>{s.label}</button>
                )}
              </div>
            ))}
          </nav>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
