import { Menu } from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { now, useDecisions, useTenantData, useTenants } from '@/prototype/store'
import { LogoMark } from '@/ui/Logo'
import { cn, formatDuration } from '@/ui/lib'
import type { ScreenId } from '../../contract'
import { siteCode } from '../model/codes'
import { userCertState } from '../model/derive'
import { EMPTY_CERTS, EMPTY_USERS, useViewState, type CertsFilter, type TenantsView, type UsersFilter } from '../model/state'
import { Sheet } from '../ui/Dialog'
import { HealthMark } from '../ui/Status'
import { Tape } from '../ui/Tape'
import { ANCHORS, SECTIONS, sectionOf, type SectionId } from './nav'
import { TenantSwitcher } from './TenantSwitcher'

interface ShellProps {
  screen: ScreenId
  entityId?: string
  navigate: (screen: ScreenId, entityId?: string) => void
  children: ReactNode
}

const usersEqual = (a: UsersFilter, b: UsersFilter) => a.source === b.source && a.access === b.access && a.cert === b.cert && a.group === b.group
const certsEqual = (a: CertsFilter, b: CertsFilter) => a.status === b.status && a.purpose === b.purpose

function scrollToAnchor(id: string) {
  const el = document.getElementById(id)
  if (!el) return
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' })
  const h = el.querySelector<HTMLElement>('h2')
  if (h) { h.tabIndex = -1; h.focus({ preventScroll: true }) }
}

function useActiveAnchor(ids: string[]) {
  const [active, setActive] = useState<string | null>(ids[0] ?? null)
  const key = ids.join(',')
  useEffect(() => {
    const list = key ? key.split(',') : []
    if (!list.length) return
    const onScroll = () => {
      let cur = list[0]
      for (const id of list) {
        const el = document.getElementById(id)
        if (el && el.getBoundingClientRect().top < 160) cur = id
      }
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) cur = list[list.length - 1]
      setActive(cur)
    }
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [key])
  return active
}

const NO_ANCHORS: Array<{ id: string; label: string }> = []

interface PanelItem { key: string; label: string; count?: number; current: boolean; onSelect: () => void }

function useSecondaryItems(section: SectionId, screen: ScreenId, navigate: ShellProps['navigate'], entityId?: string): { title: string; items: PanelItem[]; record?: PanelItem } {
  const d = useTenantData()
  const decisions = useDecisions()
  const vs = useViewState()
  const anchors = ANCHORS[section] ?? NO_ANCHORS
  const activeAnchor = useActiveAnchor(anchors.map((a) => a.id))

  return useMemo(() => {
    const go = (s: ScreenId) => { if (screen !== s) navigate(s) }
    if (section === 'users') {
      const certsBy = new Map<string, number>()
      for (const c of d.certificates) if (c.identityId) certsBy.set(c.identityId, (certsBy.get(c.identityId) ?? 0) + 1)
      const presets: Array<[string, string, UsersFilter, number]> = [
        ['all', 'All users', EMPTY_USERS, d.identities.length],
        ['ad', 'Directory (AD)', { ...EMPTY_USERS, source: 'ad' }, d.identities.filter((i) => i.source === 'ad').length],
        ['local', 'Local accounts', { ...EMPTY_USERS, source: 'local' }, d.identities.filter((i) => i.source === 'local').length],
        ['deny', 'Denied access', { ...EMPTY_USERS, access: 'deny' }, d.identities.filter((i) => decisions.get(i.id)?.outcome === 'deny').length],
        ['nocert', 'No certificate', { ...EMPTY_USERS, cert: 'none' }, d.identities.filter((i) => userCertState(d.certificates.filter((c) => c.identityId === i.id)) === 'none').length],
      ]
      const identity = screen === 'user' ? d.identities.find((i) => i.id === entityId) : undefined
      return {
        title: 'Users',
        items: presets.map(([key, label, f, count]) => ({
          key, label, count,
          current: screen === 'users' && usersEqual(vs.users, f),
          onSelect: () => { vs.setUsers({ ...f, query: vs.users.query }); go('users') },
        })),
        record: identity ? { key: 'record', label: identity.displayName, current: true, onSelect: () => {} } : undefined,
      }
    }
    if (section === 'certificates') {
      const user = d.certificates.filter((c) => c.identityId)
      const presets: Array<[string, string, CertsFilter, number]> = [
        ['all', 'All certificates', EMPTY_CERTS, d.certificates.length],
        ['expiring', 'Expiring soon', { ...EMPTY_CERTS, status: 'expiring' }, user.filter((c) => c.status === 'expiring').length],
        ['expired', 'Expired', { ...EMPTY_CERTS, status: 'expired' }, user.filter((c) => c.status === 'expired').length],
        ['revoked', 'Revoked', { ...EMPTY_CERTS, status: 'revoked' }, user.filter((c) => c.status === 'revoked').length],
      ]
      return {
        title: 'Certificates',
        items: [
          ...presets.map(([key, label, f, count]) => ({ key, label, count, current: certsEqual(vs.certs, f), onSelect: () => vs.setCerts({ ...f, query: vs.certs.query }) })),
          { key: 'cas', label: 'Certificate authorities', current: false, onSelect: () => scrollToAnchor('cas') },
        ],
      }
    }
    if (section === 'tenants') {
      const views: Array<[TenantsView, string]> = [['all', 'All tenants'], ['attention', 'Needs attention'], ['setup', 'In setup']]
      return { title: 'Portfolio', items: views.map(([key, label]) => ({ key, label, current: vs.tenantsView === key, onSelect: () => vs.setTenantsView(key) })) }
    }
    const title = section === 'overview' ? 'Overview' : section === 'radius' ? 'RADIUS' : 'VLAN policies'
    return { title, items: anchors.map((a) => ({ key: a.id, label: a.label, current: activeAnchor === a.id, onSelect: () => scrollToAnchor(a.id) })) }
  }, [section, screen, navigate, d, decisions, vs, anchors, activeAnchor, entityId])
}

function SecondaryPanel({ section, screen, navigate, entityId, onPick }: { section: SectionId; screen: ScreenId; navigate: ShellProps['navigate']; entityId?: string; onPick?: () => void }) {
  const { current } = useTenants()
  const { title, items, record } = useSecondaryItems(section, screen, navigate, entityId)
  const h = current.health
  return (
    <>
      <div className="d-panel-head">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="d-panel-name">{current.name}</p>
            <p className="d-panel-domain">{current.domain}</p>
          </div>
          <Tape code={siteCode(current)} size="sm" />
        </div>
        <div className="d-panel-health">
          <div><span>RADIUS</span><HealthMark state={h.radius} /></div>
          <div><span>PKI</span><HealthMark state={h.pki} /></div>
          <div><span>Directory</span><HealthMark state={h.directory} label={h.directory === 'ok' && h.lastDirectorySync ? `Synced ${formatDuration(Math.max(60, Math.round((now().getTime() - new Date(h.lastDirectorySync).getTime()) / 1000)))} ago` : undefined} /></div>
        </div>
      </div>
      <nav className="d-panel-section" aria-label={`${title} pages`}>
        <p className="d-panel-title">{title}</p>
        <ul className="grid gap-0.5">
          {items.map((it) => (
            <li key={it.key}>
              <button type="button" className="d-panel-link" aria-current={it.current ? 'true' : undefined} onClick={() => { it.onSelect(); onPick?.() }}>
                <span className="truncate">{it.label}</span>
                {it.count !== undefined && <span className="d-count">{it.count}</span>}
              </button>
            </li>
          ))}
        </ul>
        {record && (
          <>
            <p className="d-panel-title mt-4">Open record</p>
            <p className="d-panel-link" aria-current="true"><span className="truncate">{record.label}</span></p>
          </>
        )}
      </nav>
      <div className="d-panel-foot">
        <span className="font-medium text-[var(--d-rail-ink)]">m.okafor@brightline.example</span>
        <span>MSP administrator · Brightline IT</span>
        <span className="mt-1.5">Synthetic demonstration data</span>
      </div>
    </>
  )
}

function RailNav({ section, navigate, onPick }: { section: SectionId; navigate: ShellProps['navigate']; onPick?: () => void }) {
  return (
    <nav aria-label="Sections">
      <ul className="grid gap-1">
        {SECTIONS.map((s) => (
          <li key={s.id}>
            <a
              href={`#/c/d/${s.screen}`}
              className="d-rail-item"
              aria-current={section === s.id ? 'page' : undefined}
              onClick={(e) => { e.preventDefault(); navigate(s.screen); onPick?.() }}
            >
              <s.icon aria-hidden="true" />
              <span>{s.short}</span>
            </a>
          </li>
        ))}
      </ul>
    </nav>
  )
}

export function Shell({ screen, entityId, navigate, children }: ShellProps) {
  const section = sectionOf(screen)
  const { switchTenant } = useTenants()
  const vs = useViewState()
  const [menuOpen, setMenuOpen] = useState(false)
  const onSwitch = (id: string) => {
    vs.resetForTenant()
    switchTenant(id)
    if (screen === 'user') navigate('users')
  }
  useEffect(() => { window.scrollTo(0, 0) }, [screen, entityId])
  const sectionLabel = SECTIONS.find((s) => s.id === section)!.label

  return (
    <div className="d-shell">
      <a href="#d-main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-[90] d-btn">Skip to content</a>
      <aside className="d-rail" aria-label="Primary">
        <div className="d-rail-inner">
        <div className="flex justify-center pb-1 pt-0.5 text-[var(--d-rail-ink)]" title="EasyEAP">
          <LogoMark className="size-7" />
        </div>
        <div className="d-rail-sep" />
        <TenantSwitcher onSwitch={onSwitch} onAllTenants={() => navigate('tenants')} />
        <div className="d-rail-sep" />
        <RailNav section={section} navigate={navigate} />
        </div>
      </aside>
      <aside className="d-panel" aria-label="Tenant and section">
        <div className="d-panel-inner">
          <SecondaryPanel section={section} screen={screen} navigate={navigate} entityId={entityId} />
        </div>
      </aside>

      <div className="d-mobilebar">
        <div className="flex min-w-0 items-center gap-2 text-[var(--d-rail-ink)]">
          <LogoMark className="size-6" />
          <TenantSwitcher variant="bar" onSwitch={onSwitch} onAllTenants={() => navigate('tenants')} />
          <span className="truncate text-[14px] font-semibold">{sectionLabel}</span>
        </div>
        <button type="button" className="d-btn d-btn--ghost d-btn--icon text-[var(--d-rail-ink)]" aria-label="Open navigation" onClick={() => setMenuOpen(true)}>
          <Menu aria-hidden="true" />
        </button>
      </div>
      <Sheet open={menuOpen} onOpenChange={setMenuOpen} side="left" title="Navigate" className="!p-0">
        <div className={cn('-mx-5 -my-[18px]')}>
          <div className="bg-[var(--d-rail)] px-3 py-3"><RailNav section={section} navigate={navigate} onPick={() => setMenuOpen(false)} /></div>
          <SecondaryPanel section={section} screen={screen} navigate={navigate} entityId={entityId} onPick={() => setMenuOpen(false)} />
        </div>
      </Sheet>

      <main id="d-main" className="d-main" tabIndex={-1}>
        <div className="d-main-inner">{children}</div>
      </main>
    </div>
  )
}
