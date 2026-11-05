import { useMemo } from 'react'
import { FlaskConical } from 'lucide-react'
import { Wordmark } from '@/ui/Logo'
import { cn } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { HealthDot } from '../ui/badges'
import { worstHealth } from '../lib/model'
import { NAV, useNav, type NavItem } from './nav'

function useNavMeta() {
  const d = useTenantData()
  const { tenants } = useTenants()
  return useMemo(() => {
    const expiring = d.certificates.filter((c) => c.identityId && c.status === 'expiring').length
    const radiusState = d.radiusClients.length ? worstHealth(d.radiusClients.map((c) => (c.status === 'unconfigured' ? 'ok' : c.status))) : 'unconfigured'
    return {
      users: d.identities.length,
      expiring,
      radiusState,
      degradedNas: d.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down').length,
      rules: d.rules.filter((r) => r.enabled).length,
      tenants: tenants.length,
    }
  }, [d, tenants.length])
}

export function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const { screen, navigate } = useNav()
  const meta = useNavMeta()
  const trailing = (item: NavItem) => {
    switch (item.screen) {
      case 'users':
        return <span className="a-nav-count">{meta.users}</span>
      case 'certificates':
        return meta.expiring ? (
          <span className="a-nav-count !text-[var(--a-warn-text)]" title={`${meta.expiring} certificates expiring within 30 days`}>
            {meta.expiring} expiring
          </span>
        ) : null
      case 'radius':
        return (
          <span className="ml-auto inline-flex items-center gap-1.5 text-[12px] text-[var(--a-text-3)]">
            {meta.degradedNas > 0 && <span className="text-[var(--a-warn-text)]">{meta.degradedNas} degraded</span>}
            {meta.radiusState === 'unconfigured' && <span>Not set up</span>}
            <HealthDot state={meta.radiusState} label={meta.radiusState === 'unconfigured' ? 'No controllers' : meta.degradedNas ? `${meta.degradedNas} controller degraded` : 'All controllers operational'} />
          </span>
        )
      case 'policies':
        return <span className="a-nav-count">{meta.rules} rules</span>
      case 'tenants':
        return <span className="a-nav-count">{meta.tenants}</span>
      default:
        return null
    }
  }
  return (
    <nav aria-label="Main" className="flex flex-col gap-5">
      {NAV.map((g) => (
        <div key={g.group}>
          <p className="a-nav-group">{g.group}</p>
          <ul className="flex flex-col gap-0.5">
            {g.items.map((item) => {
              const current = screen === item.screen || item.also?.includes(screen)
              const Icon = item.icon
              return (
                <li key={item.screen}>
                  <a
                    href={`#/c/a/${item.screen}`}
                    aria-current={current ? 'page' : undefined}
                    className={cn('a-nav-item', item.platform && !current && 'hover:!bg-[rgba(129,140,248,0.08)]')}
                    onClick={(e) => {
                      e.preventDefault()
                      navigate(item.screen)
                      onNavigate?.()
                    }}
                  >
                    <Icon aria-hidden className={cn(item.platform && !current && '!text-[#a5b4fc]')} />
                    {item.label}
                    {trailing(item)}
                  </a>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )
}

export function SyntheticNote() {
  return (
    <p className="flex items-start gap-2 rounded-lg border border-white/[0.07] px-3 py-2.5 text-[12px] leading-snug text-[var(--a-text-3)]">
      <FlaskConical className="mt-px size-3.5 shrink-0" aria-hidden />
      Design prototype. All organisations and records are synthetic.
    </p>
  )
}

export function Sidebar() {
  const { navigate } = useNav()
  return (
    <aside className="a-frame hidden w-[248px] shrink-0 border-r border-[var(--a-d0-border)] lg:block">
      <div className="sticky top-0 flex h-screen flex-col">
      <div className="flex h-[var(--a-topbar-h)] items-center px-5">
        <a
          href="#/c/a/dashboard"
          onClick={(e) => {
            e.preventDefault()
            navigate('dashboard')
          }}
          className="rounded-md text-[19px] text-[var(--a-text)]"
          aria-label="EasyEAP dashboard"
        >
          <Wordmark markClassName="size-7 text-[var(--a-accent)]" />
        </a>
      </div>
      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-3 pt-4 pb-4">
        <SidebarNav />
        <div className="mt-auto pt-6">
          <SyntheticNote />
        </div>
      </div>
      </div>
    </aside>
  )
}
