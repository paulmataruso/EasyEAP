import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Dialog, DropdownMenu, Popover } from 'radix-ui'
import {
  Building, Check, ChevronsUpDown, Clock, FileKey, FilePlus, LayoutDashboard, ListOrdered, Menu, Router, Search, Users, X,
} from 'lucide-react'
import { LogoMark, Wordmark } from '@/ui/Logo'
import { formatSerial } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import type { ScreenId } from '../contract'
import { healthLabel, monogram, tenantShort, usePortal, useRecent, worstTone, healthTone, type RecentItem } from './lib'
import { Btn, Chip } from './ui'

export type Navigate = (screen: ScreenId, entityId?: string) => void

interface NavEntry { id: ScreenId; label: string; icon: ReactNode; match: ScreenId[] }
const NAV: Array<{ group: string; items: Array<NavEntry | 'issue'> }> = [
  { group: 'Investigate', items: [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard aria-hidden />, match: ['dashboard'] },
    { id: 'users', label: 'Users', icon: <Users aria-hidden />, match: ['users', 'user'] },
  ] },
  { group: 'Enroll', items: ['issue', { id: 'certificates', label: 'Certificates', icon: <FileKey aria-hidden />, match: ['certificates'] }] },
  { group: 'Configure', items: [
    { id: 'radius', label: 'RADIUS', icon: <Router aria-hidden />, match: ['radius'] },
    { id: 'policies', label: 'VLAN policies', icon: <ListOrdered aria-hidden />, match: ['policies'] },
  ] },
  { group: 'Govern', items: [{ id: 'tenants', label: 'Tenants', icon: <Building aria-hidden />, match: ['tenants'] }] },
]

// ── Search index ─────────────────────────────────────────────────────────
interface Hit { key: string; group: string; label: string; sub: string; go: () => void; score: number }

function useSearch(query: string, navigate: Navigate) {
  const d = useTenantData()
  return useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return [] as Hit[]
    const score = (...fields: Array<string | null | undefined>) => {
      let best = 0
      for (const f of fields) {
        if (!f) continue
        const s = f.toLowerCase()
        if (s === q) best = Math.max(best, 4)
        else if (s.startsWith(q)) best = Math.max(best, 3)
        else if (s.split(/[\s.@:_-]+/).some((w) => w.startsWith(q))) best = Math.max(best, 2)
        else if (s.includes(q)) best = Math.max(best, 1)
      }
      return best
    }
    const hits: Hit[] = []
    d.identities.forEach((i, idx) => {
      const s = score(i.displayName, i.username, i.upn, i.email, i.department)
      if (s) hits.push({ key: `${i.id}#${idx}`, group: 'Users', label: i.displayName, sub: i.upn ?? i.username, go: () => navigate('user', i.id), score: s })
    })
    d.devices.forEach((dev, idx) => {
      const s = score(dev.name, dev.lastSeenMac)
      if (s) hits.push({ key: `${dev.id}#${idx}`, group: 'Devices', label: dev.name, sub: dev.lastSeenMac ?? '', go: () => navigate('user', dev.identityId), score: s - 0.5 })
    })
    for (const c of d.certificates) {
      const s = score(c.serial, formatSerial(c.serial), c.commonName)
      if (s) hits.push({ key: c.id, group: 'Certificates', label: formatSerial(c.serial).slice(0, 19) + '…', sub: c.commonName, go: () => navigate('certificates', c.id), score: s - 0.25 })
    }
    for (const n of d.radiusClients) {
      const s = score(n.name, n.address, n.site)
      if (s) hits.push({ key: n.id, group: 'Controllers', label: n.name, sub: `${n.address} · ${n.site}`, go: () => navigate('radius', n.id), score: s })
    }
    for (const r of d.rules) {
      const s = score(r.name)
      if (s) hits.push({ key: r.id, group: 'Access rules', label: r.name, sub: r.action === 'deny' ? 'Deny rule' : 'Allow rule', go: () => navigate('policies'), score: s })
    }
    for (const v of d.vlans) {
      const s = score(String(v.vlanId), v.name)
      if (s) hits.push({ key: v.id, group: 'VLANs', label: `VLAN ${v.vlanId} · ${v.name}`, sub: v.description, go: () => navigate('policies'), score: s })
    }
    const order = ['Users', 'Devices', 'Certificates', 'Controllers', 'Access rules', 'VLANs']
    const grouped = order.flatMap((g) => hits.filter((h) => h.group === g).sort((a, b) => b.score - a.score).slice(0, 4))
    return grouped.sort((a, b) => (b.score >= 3 ? 1 : 0) - (a.score >= 3 ? 1 : 0) || order.indexOf(a.group) - order.indexOf(b.group))
  }, [query, d, navigate])
}

// ── Tenant scope + search ────────────────────────────────────────────────
function ScopeSearch({ navigate, screen, inputRef, onNavigated }: { navigate: Navigate; screen: ScreenId; inputRef: React.RefObject<HTMLInputElement | null>; onNavigated?: () => void }) {
  const { tenants, current, switchTenant } = useTenants()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [activeIdx, setActiveIdx] = useState(0)
  const container = usePortal()
  const go: Navigate = (s, id) => { navigate(s, id); setQuery(''); setOpen(false); onNavigated?.() }
  const hits = useSearch(query, go)
  const listId = 'f-search-results'

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setOpen(true); setActiveIdx((i) => Math.min(hits.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx((i) => Math.max(0, i - 1)) }
    else if (e.key === 'Enter') { const h = hits[activeIdx]; if (h) { e.preventDefault(); h.go() } }
    else if (e.key === 'Escape') { if (query) setQuery(''); setOpen(false) }
  }

  const tenantTone = (t: (typeof tenants)[number]) => worstTone([healthTone[t.health.radius], healthTone[t.health.pki], healthTone[t.health.directory]])
  const switchTo = (id: string) => {
    if (id === current.id) return
    switchTenant(id)
    // Entity routes belong to the previous tenant; land on the list instead.
    navigate(screen === 'user' ? 'users' : screen)
  }

  return (
    <Popover.Root open={open && query.trim().length > 0} onOpenChange={setOpen}>
      <Popover.Anchor asChild>
        <div className="f-scope">
          <DropdownMenu.Root>
            <DropdownMenu.Trigger className="flex w-full items-center gap-2.5 rounded-t-[8px] px-2.5 py-2 text-left hover:bg-[var(--f-hover)]" aria-label={`Tenant: ${current.name}. Switch tenant`}>
              <span className="f-monogram" aria-hidden>{monogram(current)}</span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13.5px] font-semibold">{current.name}</span>
                <span className="block truncate text-[12px] f-ink-3">{current.domain}</span>
              </span>
              <ChevronsUpDown className="size-4 f-ink-3" aria-hidden />
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal container={container}>
              <DropdownMenu.Content className="f-menu w-[300px]" sideOffset={6} align="start">
                <DropdownMenu.Label className="f-menu-label">Switch tenant</DropdownMenu.Label>
                <DropdownMenu.RadioGroup value={current.id} onValueChange={switchTo}>
                  {tenants.map((t) => {
                    const tone = tenantTone(t)
                    return (
                      <DropdownMenu.RadioItem key={t.id} value={t.id} className="f-menu-item">
                        <span className="f-monogram" aria-hidden>{monogram(t)}</span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-medium">{t.name}</span>
                          <span className="block truncate text-[12px] f-ink-3">{t.status === 'setup' ? 'Setup in progress' : tone === 'valid' ? 'All systems healthy' : `Directory ${healthLabel[t.health.directory].toLowerCase()}`}</span>
                        </span>
                        <DropdownMenu.ItemIndicator><Check className="size-4 text-[var(--f-gold)]" aria-hidden /></DropdownMenu.ItemIndicator>
                      </DropdownMenu.RadioItem>
                    )
                  })}
                </DropdownMenu.RadioGroup>
                <DropdownMenu.Separator className="f-menu-sep" />
                <DropdownMenu.Item className="f-menu-item" onSelect={() => navigate('tenants')}>
                  <Building className="size-4 f-ink-3" aria-hidden />
                  All tenants
                </DropdownMenu.Item>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
          <div className="flex items-center gap-2 border-t border-[var(--f-line)] px-2.5 py-2">
            <Search className="size-4 f-ink-3 shrink-0" aria-hidden />
            <input
              ref={inputRef}
              role="combobox"
              aria-expanded={open && hits.length > 0}
              aria-controls={listId}
              aria-autocomplete="list"
              aria-activedescendant={hits[activeIdx] ? `f-hit-${activeIdx}` : undefined}
              aria-label={`Search ${current.name}`}
              placeholder={`Search ${tenantShort(current)}…`}
              value={query}
              onChange={(e) => { setQuery(e.target.value); setActiveIdx(0); setOpen(true) }}
              onFocus={() => setOpen(true)}
              onKeyDown={onKey}
            />
            {query ? (
              <button type="button" className="rounded f-ink-3 hover:text-[var(--f-ink)]" aria-label="Clear search" onClick={() => { setQuery(''); inputRef.current?.focus() }}><X className="size-4" aria-hidden /></button>
            ) : (
              <kbd className="f-kbd" aria-hidden>/</kbd>
            )}
          </div>
        </div>
      </Popover.Anchor>
      <Popover.Portal container={container}>
        <Popover.Content
          className="f-menu w-[min(380px,calc(100vw-24px))] p-1.5"
          side="bottom"
          align="start"
          sideOffset={6}
          onOpenAutoFocus={(e) => e.preventDefault()}
          onInteractOutside={(e) => { if (e.target instanceof Node && inputRef.current?.closest('.f-scope')?.contains(e.target)) e.preventDefault() }}
        >
          <div id={listId} role="listbox" aria-label="Search results">
            {hits.length === 0 ? (
              <p className="px-3 py-3 f-small f-ink-2">No matches in {current.name}. Search by name, UPN, serial, MAC, controller or VLAN.</p>
            ) : (
              hits.map((h, i) => (
                <div key={h.key}>
                  {(i === 0 || hits[i - 1].group !== h.group) && <p className="f-menu-label" aria-hidden>{h.group}</p>}
                  <div
                    id={`f-hit-${i}`}
                    role="option"
                    aria-selected={i === activeIdx}
                    className="f-menu-item flex-col items-start gap-0"
                    onMouseEnter={() => setActiveIdx(i)}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => h.go()}
                  >
                    <span className="block w-full truncate font-medium">{h.label}</span>
                    <span className="block w-full truncate text-[12px] f-ink-3">{h.sub}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}

function RecentList({ navigate, onNavigated }: { navigate: Navigate; onNavigated?: () => void }) {
  const { current } = useTenants()
  const recent = useRecent(current.id)
  const open = (r: RecentItem) => {
    if (r.kind === 'identity') navigate('user', r.id)
    else if (r.kind === 'certificate') navigate('certificates', r.id)
    else navigate('radius', r.id)
    onNavigated?.()
  }
  return (
    <div className="mt-5">
      <p className="f-nav-group mt-0 flex items-center gap-1.5"><Clock className="size-3.5" aria-hidden />Recently viewed</p>
      {recent.length === 0 ? (
        <p className="px-2.5 text-[12.5px] f-ink-3">Users, certificates and controllers you open appear here.</p>
      ) : (
        <ul>
          {recent.slice(0, 4).map((r) => (
            <li key={r.id}>
              <button type="button" className="f-nav-item h-auto py-1.5" onClick={() => open(r)}>
                <span className="min-w-0">
                  <span className="block truncate text-[13px]">{r.label}</span>
                  <span className="block truncate text-[11.5px] f-ink-3">{r.sub}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function SidebarContent({ screen, navigate, onIssue, inputRef, onNavigated }: { screen: ScreenId; navigate: Navigate; onIssue: () => void; inputRef: React.RefObject<HTMLInputElement | null>; onNavigated?: () => void }) {
  const go = (s: ScreenId) => { navigate(s); onNavigated?.() }
  return (
    <div className="flex h-full flex-col px-3 pb-4 pt-4">
      <div className="mb-4 flex items-center justify-between px-1.5">
        <Wordmark className="text-[17px] text-[var(--f-ink)]" markClassName="size-6 text-[var(--f-gold)]" />
      </div>
      <ScopeSearch navigate={navigate} screen={screen} inputRef={inputRef} onNavigated={onNavigated} />
      <RecentList navigate={navigate} onNavigated={onNavigated} />
      <nav aria-label="Main" className="mt-1">
        {NAV.map((sec) => (
          <div key={sec.group}>
            <p className="f-nav-group">{sec.group}</p>
            <ul className="space-y-0.5">
              {sec.items.map((it) =>
                it === 'issue' ? (
                  <li key="issue">
                    <button type="button" className="f-nav-item" aria-haspopup="dialog" onClick={() => { onIssue(); onNavigated?.() }}>
                      <FilePlus aria-hidden />
                      Issue certificate
                    </button>
                  </li>
                ) : (
                  <li key={it.id}>
                    <button type="button" className="f-nav-item" aria-current={it.match.includes(screen) ? 'page' : undefined} onClick={() => go(it.id)}>
                      {it.icon}
                      {it.label}
                    </button>
                  </li>
                ),
              )}
            </ul>
          </div>
        ))}
      </nav>
      <div className="mt-auto pt-6">
        <div className="rounded-[8px] border border-[var(--f-line)] px-3 py-2.5">
          <p className="truncate text-[12.5px] font-medium">m.okafor@brightline.example</p>
          <p className="text-[12px] f-ink-3">MSP administrator · Brightline</p>
        </div>
        <p className="mt-2.5 px-1 text-[11.5px] f-ink-3">Synthetic demonstration data</p>
      </div>
    </div>
  )
}

export function Shell({ screen, navigate, onIssue, children }: { screen: ScreenId; navigate: Navigate; onIssue: () => void; children: ReactNode }) {
  const [drawer, setDrawer] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const drawerInputRef = useRef<HTMLInputElement>(null)
  const container = usePortal()
  const { current } = useTenants()

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)
      if ((e.key === '/' && !typing) || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) {
        e.preventDefault()
        if (window.matchMedia('(min-width: 1024px)').matches) inputRef.current?.focus()
        else { setDrawer(true); setTimeout(() => drawerInputRef.current?.focus(), 30) }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="flex min-h-screen">
      <a href="#f-main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[90] focus:rounded-md focus:bg-[var(--f-gold)] focus:px-3 focus:py-2 focus:text-[var(--f-gold-ink)]">Skip to content</a>
      <div className="f-sidebar hidden w-[264px] shrink-0 lg:block">
        <aside className="sticky top-0 h-screen overflow-y-auto" aria-label="Sidebar">
          <SidebarContent screen={screen} navigate={navigate} onIssue={onIssue} inputRef={inputRef} />
        </aside>
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="f-sidebar sticky top-0 z-30 flex items-center gap-3 border-b border-[var(--f-line)] px-4 py-2.5 lg:hidden" style={{ borderRight: 0 }}>
          <Dialog.Root open={drawer} onOpenChange={setDrawer}>
            <Dialog.Trigger asChild>
              <Btn variant="ghost" icon aria-label="Open navigation"><Menu aria-hidden /></Btn>
            </Dialog.Trigger>
            <Dialog.Portal container={container}>
              <Dialog.Overlay className="f-backdrop" />
              <Dialog.Content className="f-drawer f-sidebar">
                <Dialog.Title className="sr-only">Navigation</Dialog.Title>
                <Dialog.Description className="sr-only">Search, switch tenant and move between sections</Dialog.Description>
                <SidebarContent screen={screen} navigate={navigate} onIssue={onIssue} inputRef={drawerInputRef} onNavigated={() => setDrawer(false)} />
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
          <LogoMark className="size-6 text-[var(--f-gold)]" />
          <span className="min-w-0 flex-1 truncate text-[14px] font-semibold">{current.name}</span>
          <Btn variant="ghost" icon aria-label={`Search ${current.name}`} onClick={() => { setDrawer(true); setTimeout(() => drawerInputRef.current?.focus(), 30) }}><Search aria-hidden /></Btn>
        </div>
        <main id="f-main" tabIndex={-1} className="mx-auto w-full min-w-0 max-w-[1680px] flex-1 px-4 pb-16 pt-6 outline-none sm:px-6 lg:px-8 lg:pt-8">
          {children}
        </main>
      </div>
    </div>
  )
}

export function TenantStateChip({ status }: { status: 'active' | 'setup' | 'suspended' }) {
  return status === 'setup' ? <Chip tone="gold">Setup in progress</Chip> : status === 'suspended' ? <Chip tone="neutral">Suspended</Chip> : <Chip tone="valid" icon={<Check aria-hidden />}>Active</Chip>
}

