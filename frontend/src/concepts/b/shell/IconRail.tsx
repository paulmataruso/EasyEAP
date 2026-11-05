import { useRef, useState, type KeyboardEvent } from 'react'
import { BadgeCheck, Building2, LayoutDashboard, Network, RadioTower, Users, type LucideIcon } from 'lucide-react'
import type { ScreenId } from '@/concepts/contract'
import { LogoMark } from '@/ui/Logo'
import { useShell, type GoOptions } from './context'

interface NavLink {
  label: string
  opts: GoOptions
}
interface NavItem {
  screen: ScreenId
  label: string
  short: string
  icon: LucideIcon
  links: NavLink[]
}

const NAV: NavItem[] = [
  {
    screen: 'dashboard',
    label: 'Dashboard',
    short: 'Board',
    icon: LayoutDashboard,
    links: [
      { label: 'Live authentications', opts: { section: 'stream' } },
      { label: 'Controllers', opts: { section: 'controllers' } },
      { label: 'Failure reasons', opts: { section: 'failures' } },
      { label: 'Service health', opts: { section: 'health' } },
    ],
  },
  {
    screen: 'users',
    label: 'Users',
    short: 'Users',
    icon: Users,
    links: [
      { label: 'All users', opts: { filters: {} } },
      { label: 'Denied Wi-Fi access', opts: { filters: { access: 'deny' } } },
      { label: 'Certificates expiring', opts: { filters: { cert: 'expiring' } } },
      { label: 'Local accounts', opts: { filters: { source: 'local' } } },
    ],
  },
  {
    screen: 'certificates',
    label: 'Certificates',
    short: 'Certs',
    icon: BadgeCheck,
    links: [
      { label: 'Certificate authorities', opts: { section: 'authorities' } },
      { label: 'All certificates', opts: { section: 'inventory', filters: {} } },
      { label: 'Expiring soon', opts: { section: 'inventory', filters: { status: 'expiring' } } },
      { label: 'Revoked', opts: { section: 'inventory', filters: { status: 'revoked' } } },
    ],
  },
  {
    screen: 'radius',
    label: 'RADIUS',
    short: 'RADIUS',
    icon: RadioTower,
    links: [
      { label: 'Server settings', opts: { section: 'server' } },
      { label: 'Wireless controllers', opts: { section: 'controllers' } },
      { label: 'Configuration snippets', opts: { section: 'snippet' } },
    ],
  },
  {
    screen: 'policies',
    label: 'VLAN policies',
    short: 'Policies',
    icon: Network,
    links: [
      { label: 'Access rules', opts: { section: 'rules' } },
      { label: 'VLANs', opts: { section: 'vlans' } },
      { label: 'Test a user', opts: { section: 'test' } },
    ],
  },
]

const MSP: NavItem = {
  screen: 'tenants',
  label: 'Tenants',
  short: 'Tenants',
  icon: Building2,
  links: [
    { label: 'Portfolio', opts: { section: 'portfolio' } },
    { label: 'Setup in progress', opts: { section: 'setup' } },
  ],
}

/** 56px icon rail with tooltip-style flyouts that also list each section. Becomes a bottom bar on phones. */
export function IconRail() {
  return (
    <aside className="b-rail" aria-label="Primary">
      <div className="b-rail-brand flex h-[var(--b-tabs-h)] w-full shrink-0 items-center justify-center border-b border-[var(--b-line)] text-[var(--b-cyan)]">
        <LogoMark className="size-6" title="EasyEAP" />
      </div>
      <nav aria-label="Console" className="mt-3 flex w-full flex-col items-center">
        <ul className="flex flex-col items-center gap-1.5">
          {NAV.map((item) => (
            <RailItem key={item.screen} item={item} />
          ))}
        </ul>
      </nav>
      <nav aria-label="MSP" className="b-rail-foot mt-auto mb-3 flex w-full flex-col items-center border-t border-[var(--b-line)] pt-3">
        <ul>
          <RailItem item={MSP} />
        </ul>
      </nav>
    </aside>
  )
}

function RailItem({ item }: { item: NavItem }) {
  const { screen, go } = useShell()
  const [open, setOpen] = useState(false)
  const timer = useRef<number | undefined>(undefined)
  const linkRef = useRef<HTMLAnchorElement>(null)
  const active = screen === item.screen || (item.screen === 'users' && screen === 'user')
  const Icon = item.icon
  const show = () => {
    window.clearTimeout(timer.current)
    setOpen(true)
  }
  const hide = () => {
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setOpen(false), 120)
  }
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape' && open) {
      setOpen(false)
      linkRef.current?.focus()
    }
  }
  const flyoutId = `b-flyout-${item.screen}`
  return (
    <li
      className="relative"
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) hide()
      }}
      onKeyDown={onKey}
    >
      <a
        ref={linkRef}
        href={`#/c/b/${item.screen}`}
        className="b-rail-link"
        aria-current={active ? 'page' : undefined}
        aria-label={item.label}
        onClick={(e) => {
          e.preventDefault()
          setOpen(false)
          go(item.screen)
        }}
      >
        <Icon className="size-[19px]" strokeWidth={1.75} aria-hidden />
        <span className="b-rail-mobile-label hidden">{item.short}</span>
      </a>
      {open && (
        <div id={flyoutId} className="b-flyout b-pop hidden md:block" role="group" aria-label={`${item.label} sections`}>
          <p className="px-2 pt-1 pb-1.5 text-[13px] font-semibold text-[var(--b-text)]">{item.label}</p>
          <ul>
            {item.links.map((l) => (
              <li key={l.label}>
                <a
                  href={`#/c/b/${item.screen}`}
                  className="b-menu-item text-[var(--b-text-2)] hover:text-[var(--b-text)]"
                  onClick={(e) => {
                    e.preventDefault()
                    setOpen(false)
                    go(item.screen, l.opts)
                  }}
                >
                  {l.label}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  )
}
