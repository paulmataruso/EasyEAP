import { useState } from 'react'
import { Dialog, DropdownMenu } from 'radix-ui'
import { Building2, ChevronDown, ChevronRight, Menu, X } from 'lucide-react'
import { useTenants } from '@/prototype/store'
import type { HealthState, Tenant } from '@/domain/types'
import { LogoMark } from '@/ui/Logo'
import type { ScreenId } from '../../contract'
import { ConceptPortal } from '../ui/Portal'
import { healthMeta } from '../ui/Status'
import { useConcept } from './context'
import { PAGE_LABEL, SECTIONS, sectionOf, type NavItem } from './nav'

const worst = (t: Tenant): HealthState => {
  const order: HealthState[] = ['down', 'degraded', 'unconfigured', 'ok']
  const states = [t.health.radius, t.health.pki, t.health.directory]
  return order.find((s) => states.includes(s)) ?? 'ok'
}

const tenantSummary = (t: Tenant) => {
  if (t.status === 'setup') return 'Setup in progress'
  const w = worst(t)
  if (w === 'ok') return 'All services healthy'
  const which = (['radius', 'pki', 'directory'] as const).filter((k) => t.health[k] === w).map((k) => ({ radius: 'RADIUS', pki: 'PKI', directory: 'Directory' })[k])
  return `${which.join(', ')} ${healthMeta[w].label.toLowerCase()}`
}

/** Glass top bar: brand, breadcrumb rooted at the tenant switcher, five section menus. */
export function TopBar({ screen, entityLabel }: { screen: ScreenId; entityLabel?: string }) {
  const { go } = useConcept()
  const active = sectionOf(screen)
  return (
    <header className="c-topbar">
      <div className="c-container c-topbar-inner">
        <button type="button" className="c-home" onClick={() => go('dashboard')} aria-label="EasyEAP overview">
          <LogoMark className="size-[22px]" title="EasyEAP" />
        </button>
        <nav aria-label="Breadcrumb" className="c-crumbs">
          <ol>
            <li>
              <TenantSwitcher screen={screen} />
            </li>
            <li className="c-crumb-page">
              <ChevronRight size={14} className="c-crumb-sep" aria-hidden="true" />
              {entityLabel ? (
                <button type="button" className="c-crumb" onClick={() => go(screen === 'user' ? 'users' : screen)}>
                  {PAGE_LABEL[screen]}
                </button>
              ) : (
                <span className="c-crumb" aria-current="page">
                  {PAGE_LABEL[screen]}
                </span>
              )}
            </li>
            {entityLabel ? (
              <li className="c-crumb-page">
                <ChevronRight size={14} className="c-crumb-sep" aria-hidden="true" />
                <span className="c-crumb" aria-current="page">
                  {entityLabel}
                </span>
              </li>
            ) : null}
          </ol>
        </nav>
        <nav aria-label="Sections" className="c-sections">
          {SECTIONS.map((s) =>
            s.items.length === 1 ? (
              <button key={s.id} type="button" className="c-navitem" data-active={active?.id === s.id} aria-current={active?.id === s.id ? 'page' : undefined} onClick={() => go(s.items[0].screen, { intent: s.items[0].intent })}>
                {s.label}
              </button>
            ) : (
              <DropdownMenu.Root key={s.id} modal={false}>
                <DropdownMenu.Trigger className="c-navitem" data-active={active?.id === s.id}>
                  {s.label}
                  <ChevronDown size={14} aria-hidden="true" />
                </DropdownMenu.Trigger>
                <DropdownMenu.Portal>
                  <ConceptPortal>
                    <DropdownMenu.Content className="c-pop" align="start" sideOffset={12} style={{ width: 320 }}>
                      {s.items.map((it) => (
                        <MenuLink key={it.label} item={it} onSelect={() => go(it.screen, { intent: it.intent })} />
                      ))}
                    </DropdownMenu.Content>
                  </ConceptPortal>
                </DropdownMenu.Portal>
              </DropdownMenu.Root>
            ),
          )}
        </nav>
        <AccountMenu />
        <MobileMenu screen={screen} />
      </div>
    </header>
  )
}

function MenuLink({ item, onSelect }: { item: NavItem; onSelect: () => void }) {
  const Icon = item.icon
  return (
    <DropdownMenu.Item className="c-menuitem" onSelect={onSelect}>
      <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
      <span className="c-menuitem-title">{item.label}</span>
      <span />
      <span className="c-menuitem-desc">{item.description}</span>
    </DropdownMenu.Item>
  )
}

function TenantSwitcher({ screen }: { screen: ScreenId }) {
  const { tenants, current, switchTenant } = useTenants()
  const { go } = useConcept()
  const onSwitch = (id: string) => {
    if (id === current.id) return
    switchTenant(id)
    go(screen === 'user' ? 'users' : screen)
  }
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="c-tenant-trigger" aria-label={`Tenant: ${current.name}. Switch tenant`}>
        <span className="c-tenant-name">{current.name}</span>
        <ChevronDown size={15} aria-hidden="true" style={{ color: 'var(--c-text-3)', flex: 'none' }} />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <ConceptPortal>
          <DropdownMenu.Content className="c-pop" align="start" sideOffset={10} style={{ width: 'min(400px, calc(100vw - 32px))' }}>
            <DropdownMenu.Label className="c-pop-label">Switch tenant</DropdownMenu.Label>
            <DropdownMenu.RadioGroup value={current.id} onValueChange={onSwitch}>
              {tenants.map((t) => {
                const m = healthMeta[t.status === 'setup' ? 'unconfigured' : worst(t)]
                const Icon = m.icon
                return (
                  <DropdownMenu.RadioItem key={t.id} value={t.id} className="c-menuitem" data-current={t.id === current.id}>
                    <Icon size={17} strokeWidth={1.9} aria-hidden="true" style={{ color: `var(--c-${m.tone === 'neutral' ? 'neutral' : m.tone})` }} />
                    <span className="c-menuitem-title">{t.name}</span>
                    <span />
                    <span className="c-menuitem-desc">
                      {t.domain} · {tenantSummary(t)}
                    </span>
                  </DropdownMenu.RadioItem>
                )
              })}
            </DropdownMenu.RadioGroup>
            <DropdownMenu.Separator className="c-pop-sep" />
            <DropdownMenu.Item className="c-menuitem" onSelect={() => go('tenants')}>
              <Building2 size={17} strokeWidth={1.8} aria-hidden="true" />
              <span className="c-menuitem-title">All tenants</span>
              <span />
              <span className="c-menuitem-desc">Compare health and setup across customers</span>
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </ConceptPortal>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

function AccountMenu() {
  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger className="c-account c-hide-sm" aria-label="Signed in as M. Okafor">
        MO
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <ConceptPortal>
          <DropdownMenu.Content className="c-pop" align="end" sideOffset={12} style={{ width: 300 }}>
            <div style={{ padding: '10px 12px 8px' }}>
              <div style={{ fontWeight: 600 }}>M. Okafor</div>
              <div className="c-faint c-small">m.okafor@brightline.example · MSP technician</div>
            </div>
            <DropdownMenu.Separator className="c-pop-sep" />
            <p className="c-faint c-small" style={{ margin: 0, padding: '6px 12px 10px' }}>
              Design prototype. Every organisation, person and serial number shown is synthetic.
            </p>
          </DropdownMenu.Content>
        </ConceptPortal>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

/** Below 900px the section menus collapse into one glass sheet. */
function MobileMenu({ screen }: { screen: ScreenId }) {
  const [open, setOpen] = useState(false)
  const { go } = useConcept()
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger className="c-iconbtn c-menu-button" aria-label="Open navigation">
        <Menu size={20} aria-hidden="true" />
      </Dialog.Trigger>
      <Dialog.Portal>
        <ConceptPortal>
          <Dialog.Overlay className="c-overlay" />
          <Dialog.Content className="c-drawer" aria-describedby={undefined}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '2px 4px 6px 12px' }}>
              <Dialog.Title style={{ margin: 0, fontSize: 15, fontWeight: 600 }}>Navigate</Dialog.Title>
              <Dialog.Close className="c-iconbtn" aria-label="Close navigation">
                <X size={18} aria-hidden="true" />
              </Dialog.Close>
            </div>
            {SECTIONS.map((s) => (
              <div key={s.id}>
                <h2>{s.label}</h2>
                {s.items.map((it) => {
                  const Icon = it.icon
                  const current = it.screen === screen && !it.intent
                  return (
                    <button
                      key={it.label}
                      type="button"
                      className="c-drawer-item"
                      aria-current={current ? 'page' : undefined}
                      onClick={() => {
                        setOpen(false)
                        go(it.screen, { intent: it.intent })
                      }}
                    >
                      <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
                      {it.label}
                    </button>
                  )
                })}
              </div>
            ))}
          </Dialog.Content>
        </ConceptPortal>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
