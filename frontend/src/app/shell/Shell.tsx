// Search-first shell (direction F). The sidebar's scope block names the tenant and searches inside it; `/` focuses
// the search, ⌘K / Ctrl+K opens the command palette. MSP-level destinations appear for platform roles.
import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Dialog, DropdownMenu, Popover } from 'radix-ui'
import { NavLink, useLocation, useNavigate } from 'react-router'
import {
  Building, Cable, Check, ChevronsUpDown, Clock, Command, FileBadge, FileKey, FilePlus, KeyRound, LayoutDashboard, ListOrdered, LogOut, Menu, Router,
  ScrollText, Search, ServerCog, Settings, ShieldCheck, SquareTerminal, UserCog, Users, X, BookUser, History,
} from 'lucide-react'
import { LogoMark, Wordmark } from '@/ui/Logo'
import { cn } from '@/ui/lib'
import { useSession } from '../api/session'
import { useOptionalTenant, useTenantList } from '../api/tenant'
import type { TenantListItem } from '../api/types'
import { plural } from '../lib/format'
import { useRecent, type RecentItem } from '../lib/recent'
import { paths } from '../routes'
import { Btn } from '../ui'
import { CommandPalette } from './CommandPalette'
import { useEntitySearch, type Hit } from './search'

export const monogram = (name: string) => name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]?.toUpperCase()).join('')

/** The switcher's one line per tenant: the same status and top item as its dashboard. */
function tenantLine(t: TenantListItem): { text: string; crit: boolean } {
  if (t.status === 'setup') return { text: 'Setup in progress', crit: false }
  if (t.status === 'suspended') return { text: 'Suspended: nobody can connect', crit: false }
  const p = t.posture
  if (!p) return { text: t.domain || t.slug, crit: false }
  if (p.top?.severity === 'critical') return { text: p.top.title, crit: true }
  if (p.status.tone === 'crit') return { text: p.status.label, crit: true }
  if (p.status.tone === 'warn') return { text: p.status.label, crit: false }
  if (p.top?.severity === 'warning') return { text: p.top.title, crit: false }
  return { text: p.status.state === 'enforcing' ? `Enforcing${t.domain ? ` · ${t.domain}` : ''}` : p.status.label, crit: false }
}

function TenantSwitcher({ onNavigated }: { onNavigated?: () => void }) {
  const tctx = useOptionalTenant()
  const tenants = useTenantList()
  const { isPlatform } = useSession()
  const navigate = useNavigate()
  const location = useLocation()
  const current = tctx?.tenant
  const switchTo = (id: string) => {
    if (id === current?.id) return
    // Keep the same section when switching; entity pages belong to the previous tenant, so land on the list.
    const section = location.pathname.split('/')[3] ?? 'dashboard'
    const keep = ['dashboard', 'users', 'certificates', 'radius', 'mac', 'device-admin', 'policy', 'directory', 'pki', 'events', 'audit', 'settings']
    navigate(`/t/${id}/${keep.includes(section) ? section : 'dashboard'}`)
    onNavigated?.()
  }
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="flex w-full items-center gap-2.5 rounded-t-[8px] px-2.5 py-2 text-left hover:bg-[var(--ee-hover)]" aria-label={current ? `Tenant: ${current.name}. Switch tenant` : 'Choose a tenant'}>
        <span className="ee-monogram" aria-hidden>{current ? monogram(current.name) : <Building className="size-3.5" />}</span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13.5px] font-semibold">{current?.name ?? (isPlatform ? 'All tenants' : 'Choose a tenant')}</span>
          <span className="block truncate text-[12px] ee-ink-3">{current ? (current.domain || current.slug) : (tenants.data ? plural(tenants.data.length, 'tenant') : 'Loading tenants…')}</span>
        </span>
        <ChevronsUpDown className="size-4 ee-ink-3" aria-hidden />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="ee-menu w-[300px] max-h-[70vh] overflow-y-auto" sideOffset={6} align="start">
          <DropdownMenu.Label className="ee-menu-label">Switch tenant</DropdownMenu.Label>
          <DropdownMenu.RadioGroup value={current?.id ?? ''} onValueChange={switchTo}>
            {(tenants.data ?? []).map((t) => (
              <DropdownMenu.RadioItem key={t.id} value={t.id} className="ee-menu-item">
                <span className="ee-monogram" aria-hidden>{monogram(t.name)}</span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{t.name}</span>
                  {(() => { const l = tenantLine(t); return <span className={l.crit ? 'block truncate text-[12px] text-[var(--ee-crit-ink)]' : 'block truncate text-[12px] ee-ink-3'}>{l.text}</span> })()}
                </span>
                <DropdownMenu.ItemIndicator><Check className="size-4 text-[var(--ee-gold)]" aria-hidden /></DropdownMenu.ItemIndicator>
              </DropdownMenu.RadioItem>
            ))}
          </DropdownMenu.RadioGroup>
          {tenants.data?.length === 0 && <p className="px-2.5 py-2 ee-small ee-ink-3">No tenants yet.</p>}
          {isPlatform && (
            <>
              <DropdownMenu.Separator className="ee-menu-sep" />
              <DropdownMenu.Item className="ee-menu-item" onSelect={() => { navigate(paths.tenants()); onNavigated?.() }}>
                <Building className="size-4 ee-ink-3" aria-hidden />
                All tenants
              </DropdownMenu.Item>
            </>
          )}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

function hitPath(tid: string, h: Hit) {
  if (h.kind === 'user') return paths.user(tid, h.id)
  if (h.kind === 'certificate') return paths.certificate(tid, h.id)
  if (h.kind === 'controller') return paths.radius(tid, { client: h.id })
  if (h.kind === 'mac') return paths.mac(tid, { device: h.id })
  if (h.kind === 'admin') return paths.deviceAdmin(tid, { account: h.id })
  return paths.policy(tid)
}

function ScopeSearch({ inputRef, onNavigated }: { inputRef: React.RefObject<HTMLInputElement | null>; onNavigated?: () => void }) {
  const tctx = useOptionalTenant()
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const { hits, loading } = useEntitySearch(tctx?.tid ?? null, query, undefined, { mac: tctx?.can('mac:read') ?? false, admin: tctx?.can('admin:read') ?? false })
  const listId = 'ee-search-results'
  const go = (h: Hit) => { if (!tctx) return; navigate(hitPath(tctx.tid, h)); setQuery(''); setOpen(false); onNavigated?.() }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setOpen(true); setActive((i) => Math.min(hits.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(0, i - 1)) }
    else if (e.key === 'Enter') { const h = hits[active]; if (h) { e.preventDefault(); go(h) } }
    else if (e.key === 'Escape') { if (query) setQuery(''); setOpen(false) }
  }
  return (
    <Popover.Root open={open && query.trim().length > 0 && !!tctx} onOpenChange={setOpen}>
      <Popover.Anchor asChild>
        <div className="ee-scope">
          <TenantSwitcher onNavigated={onNavigated} />
          {tctx && (
            <div className="flex items-center gap-2 border-t border-[var(--ee-line)] px-2.5 py-2">
              <Search className="size-4 ee-ink-3 shrink-0" aria-hidden />
              <input
                ref={inputRef}
                role="combobox"
                aria-expanded={open && hits.length > 0}
                aria-controls={listId}
                aria-autocomplete="list"
                aria-activedescendant={hits[active] ? `ee-hit-${active}` : undefined}
                aria-label={`Search ${tctx.tenant.name}`}
                placeholder="Search users, serials, controllers…"
                value={query}
                onChange={(e) => { setQuery(e.target.value); setActive(0); setOpen(true) }}
                onFocus={() => setOpen(true)}
                onKeyDown={onKey}
              />
              {query ? (
                <button type="button" className="rounded ee-ink-3 hover:text-[var(--ee-ink)]" aria-label="Clear search" onClick={() => { setQuery(''); inputRef.current?.focus() }}><X className="size-4" aria-hidden /></button>
              ) : <kbd className="ee-kbd" aria-hidden>/</kbd>}
            </div>
          )}
        </div>
      </Popover.Anchor>
      <Popover.Portal>
        <Popover.Content
          className="ee-menu w-[min(380px,calc(100vw-24px))] p-1.5"
          side="bottom"
          align="start"
          sideOffset={6}
          onOpenAutoFocus={(e) => e.preventDefault()}
          onInteractOutside={(e) => { if (e.target instanceof Node && inputRef.current?.closest('.ee-scope')?.contains(e.target)) e.preventDefault() }}
        >
          <div id={listId} role="listbox" aria-label="Search results">
            {hits.length === 0 ? (
              <p className="px-3 py-3 ee-small ee-ink-2">{loading ? 'Searching…' : `No matches in ${tctx?.tenant.name}. Search by name, username, email, serial, device, controller, rule or VLAN.`}</p>
            ) : hits.map((h, i) => (
              <div key={h.key}>
                {(i === 0 || hits[i - 1].group !== h.group) && <p className="ee-menu-label" aria-hidden>{h.group}</p>}
                <div id={`ee-hit-${i}`} role="option" aria-selected={i === active} className="ee-menu-item flex-col items-start gap-0" onMouseEnter={() => setActive(i)} onMouseDown={(e) => e.preventDefault()} onClick={() => go(h)}>
                  <span className="block w-full truncate font-medium">{h.label}</span>
                  {h.sub && <span className="block w-full truncate text-[12px] ee-ink-3">{h.sub}</span>}
                </div>
              </div>
            ))}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}

function RecentList({ onNavigated }: { onNavigated?: () => void }) {
  const tctx = useOptionalTenant()
  const recent = useRecent(tctx?.tid ?? '')
  const navigate = useNavigate()
  // Nothing to show until something has been opened: no placeholder hint taking sidebar space.
  if (!tctx || recent.length === 0) return null
  const open = (r: RecentItem) => {
    navigate(r.kind === 'identity' ? paths.user(tctx.tid, r.id) : r.kind === 'certificate' ? paths.certificate(tctx.tid, r.id) : paths.radius(tctx.tid, { client: r.id }))
    onNavigated?.()
  }
  return (
    <div className="mt-5">
      <p className="ee-nav-group mt-0 flex items-center gap-1.5"><Clock className="size-3.5" aria-hidden />Recently viewed</p>
      <ul>
        {recent.slice(0, 4).map((r) => (
          <li key={`${r.kind}:${r.id}`}>
            <button type="button" className="ee-nav-item h-auto py-1.5" onClick={() => open(r)}>
              <span className="min-w-0">
                <span className="block truncate text-[13px]">{r.label}</span>
                <span className="block truncate text-[12px] ee-ink-3">{r.sub}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}

interface NavEntry { to: string; label: string; icon: ReactNode; perm?: string }

function NavGroup({ title, items, onNavigated }: { title: string; items: NavEntry[]; onNavigated?: () => void }) {
  const tctx = useOptionalTenant()
  const visible = items.filter((i) => !i.perm || tctx?.can(i.perm))
  if (!visible.length) return null
  return (
    <div>
      <p className="ee-nav-group">{title}</p>
      <ul className="space-y-0.5">
        {visible.map((it) => (
          <li key={it.to}>
            <NavLink to={it.to} className="ee-nav-item" onClick={onNavigated}>{it.icon}{it.label}</NavLink>
          </li>
        ))}
      </ul>
    </div>
  )
}

function SidebarContent({ inputRef, onNavigated, onPalette }: { inputRef: React.RefObject<HTMLInputElement | null>; onNavigated?: () => void; onPalette: (start?: 'issue') => void }) {
  const tctx = useOptionalTenant()
  const { me, isPlatform, canManageAdmins, signOut } = useSession()
  const navigate = useNavigate()
  const tid = tctx?.tid
  return (
    <div className="flex h-full flex-col px-3 pb-4 pt-4">
      <div className="mb-4 flex items-center justify-between px-1.5">
        <Wordmark className="text-[17px] text-[var(--ee-ink)]" markClassName="size-7" />
        <Btn variant="ghost" size="sm" onClick={() => onPalette()} aria-label="Open command palette" aria-keyshortcuts="Control+K Meta+K">
          <Command aria-hidden /><span className="text-[12px] ee-ink-3">K</span>
        </Btn>
      </div>
      <ScopeSearch inputRef={inputRef} onNavigated={onNavigated} />
      {/* Only the lists scroll: the wordmark, search and account footer stay put on short screens. */}
      <div className="-mx-1 min-h-0 flex-1 overflow-y-auto px-1 pb-2">
      <RecentList onNavigated={onNavigated} />
      <nav aria-label="Main" className="mt-1">
        {tid && (
          <>
            <NavGroup title="Investigate" onNavigated={onNavigated} items={[
              { to: paths.dashboard(tid), label: 'Dashboard', icon: <LayoutDashboard aria-hidden /> },
              { to: paths.users(tid), label: 'Users', icon: <Users aria-hidden />, perm: 'identities:read' },
              { to: paths.events(tid), label: 'Authentication log', icon: <ScrollText aria-hidden />, perm: 'events:read' },
            ]} />
            <div>
              <p className="ee-nav-group">Enroll</p>
              <ul className="space-y-0.5">
                {tctx.can('certificates:issue') && (
                  <li>
                    <button type="button" className="ee-nav-item" aria-haspopup="dialog" onClick={() => { onPalette('issue'); onNavigated?.() }}>
                      <FilePlus aria-hidden />Issue certificate
                    </button>
                  </li>
                )}
                {tctx.can('certificates:read') && <li><NavLink to={paths.certificates(tid)} className="ee-nav-item" onClick={onNavigated}><FileKey aria-hidden />Certificates</NavLink></li>}
              </ul>
            </div>
            <NavGroup title="Configure" onNavigated={onNavigated} items={[
              { to: paths.policy(tid), label: 'Access policy', icon: <ListOrdered aria-hidden />, perm: 'policy:read' },
              { to: paths.radius(tid), label: 'RADIUS', icon: <Router aria-hidden />, perm: 'radius:read' },
              { to: paths.mac(tid), label: 'MAC allow list', icon: <Cable aria-hidden />, perm: 'mac:read' },
              { to: paths.deviceAdmin(tid), label: 'Device administration', icon: <SquareTerminal aria-hidden />, perm: 'admin:read' },
              { to: paths.directory(tid), label: 'Directory', icon: <BookUser aria-hidden />, perm: 'directory:read' },
              { to: paths.autoenroll(tid), label: 'GPO autoenrollment', icon: <FileBadge aria-hidden />, perm: 'directory:read' },
              { to: paths.pki(tid), label: 'Certificate authority', icon: <KeyRound aria-hidden />, perm: 'certificates:read' },
            ]} />
            <NavGroup title="Govern" onNavigated={onNavigated} items={[
              ...(tctx.tenant.status === 'setup' ? [{ to: paths.setup(tid), label: 'Finish setup', icon: <ShieldCheck aria-hidden /> }] : []),
              { to: paths.tenantAudit(tid), label: 'Audit log', icon: <History aria-hidden />, perm: 'audit:read' },
              { to: paths.settings(tid), label: 'Tenant settings', icon: <Settings aria-hidden />, perm: 'tenant:read' },
            ]} />
          </>
        )}
        {isPlatform && (
          <div>
            <p className="ee-nav-group">MSP</p>
            <ul className="space-y-0.5">
              <li><NavLink end to={paths.tenants()} className="ee-nav-item" onClick={onNavigated}><Building aria-hidden />Tenants</NavLink></li>
              {canManageAdmins && <li><NavLink to={paths.admins()} className="ee-nav-item" onClick={onNavigated}><UserCog aria-hidden />Administrators</NavLink></li>}
              <li><NavLink to={paths.platformAudit()} className="ee-nav-item" onClick={onNavigated}><History aria-hidden />Platform audit</NavLink></li>
              <li><NavLink to={paths.system()} className="ee-nav-item" onClick={onNavigated}><ServerCog aria-hidden />System health</NavLink></li>
            </ul>
          </div>
        )}
      </nav>
      </div>
      <div className="pt-3">
        <div className="flex items-center gap-1 rounded-[8px] border border-[var(--ee-line)] py-1.5 pl-3 pr-1.5">
          <NavLink to={paths.account()} className="min-w-0 flex-1 rounded" onClick={onNavigated}>
            <span className="block truncate text-[12.5px] font-medium">{me?.email}</span>
            <span className="block truncate text-[12px] ee-ink-3">{me?.platform_role_label ?? me?.grants.find((g) => g.tenant_id === tid)?.role_label ?? 'Administrator'}</span>
          </NavLink>
          <Btn variant="ghost" size="sm" icon aria-label="Sign out" onClick={async () => { await signOut(); navigate(paths.login()) }}><LogOut aria-hidden /></Btn>
        </div>
      </div>
    </div>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const [drawer, setDrawer] = useState(false)
  const [palette, setPalette] = useState(false)
  const [paletteStart, setPaletteStart] = useState<'issue' | undefined>()
  const openPalette = (start?: 'issue') => { setPaletteStart(start); setPalette(true) }
  const inputRef = useRef<HTMLInputElement>(null)
  const drawerInputRef = useRef<HTMLInputElement>(null)
  const tctx = useOptionalTenant()
  const location = useLocation()

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteStart(undefined); setPalette((p) => !p); return }
      if (e.key === '/' && !typing) {
        e.preventDefault()
        if (window.matchMedia('(min-width: 1024px)').matches) inputRef.current?.focus()
        else { setDrawer(true); setTimeout(() => drawerInputRef.current?.focus(), 30) }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Route change: move focus to <main> so the page heading (PageHeader) can take it.
  useEffect(() => { document.getElementById('ee-main')?.focus({ preventScroll: true }); window.scrollTo(0, 0) }, [location.pathname])

  return (
    <div className="flex min-h-screen">
      <a href="#ee-main" onClick={(e) => { e.preventDefault(); document.getElementById('ee-main')?.focus() }} className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[90] focus:rounded-md focus:bg-[var(--ee-gold)] focus:px-3 focus:py-2 focus:text-[var(--ee-gold-ink)]">Skip to content</a>
      <div className="ee-sidebar hidden w-[264px] shrink-0 lg:block">
        <aside className="sticky top-0 h-dvh" aria-label="Sidebar">
          <SidebarContent inputRef={inputRef} onPalette={openPalette} />
        </aside>
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="ee-sidebar sticky top-0 z-30 flex items-center gap-3 border-b border-[var(--ee-line)] px-4 py-2.5 lg:hidden" style={{ borderRight: 0 }}>
          <Dialog.Root open={drawer} onOpenChange={setDrawer}>
            <Dialog.Trigger asChild>
              <Btn variant="ghost" icon aria-label="Open navigation"><Menu aria-hidden /></Btn>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="ee-backdrop" />
              <Dialog.Content className="ee-drawer ee-sidebar" aria-describedby={undefined}>
                <Dialog.Title className="sr-only">Navigation</Dialog.Title>
                <SidebarContent inputRef={drawerInputRef} onNavigated={() => setDrawer(false)} onPalette={(st) => { setDrawer(false); openPalette(st) }} />
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
          <LogoMark decorative className="size-7" />
          <span className="min-w-0 flex-1 truncate text-[14px] font-semibold">{tctx?.tenant.name ?? 'EasyEAP'}</span>
          <Btn variant="ghost" icon aria-label="Open command palette" onClick={() => openPalette()}><Search aria-hidden /></Btn>
        </div>
        <main id="ee-main" tabIndex={-1} className={cn('mx-auto w-full min-w-0 max-w-[1680px] flex-1 px-4 pb-16 pt-6 outline-none sm:px-6 lg:px-8 lg:pt-8')}>
          {children}
        </main>
      </div>
      <CommandPalette open={palette} onOpenChange={setPalette} start={paletteStart} />
    </div>
  )
}
