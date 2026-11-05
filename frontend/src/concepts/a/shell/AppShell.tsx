import { useCallback, useState, type ReactNode } from 'react'
import { Dialog, DropdownMenu } from 'radix-ui'
import { Copy, FileBadge, Keyboard, LogOut, Menu, Network, Router, Search, UserRound, X } from 'lucide-react'
import { Wordmark } from '@/ui/Logo'
import { cn, copyText } from '@/ui/lib'
import { useTenantData } from '@/prototype/store'
import { Avatar, IconButton } from '../ui/primitives'
import { GlassDialog } from '../ui/dialog'
import { usePortalContainer } from '../ui/portal'
import { ScopeChip, ScopeSeparator } from '../ui/scope'
import { useToast } from '../ui/toast'
import { CommandSearch, useSearchShortcut } from './CommandSearch'
import { Sidebar, SidebarNav, SyntheticNote } from './Sidebar'
import { TenantSwitcher } from './TenantSwitcher'
import { useNav } from './nav'

const ADMIN = { name: 'Michael Okafor', email: 'm.okafor@brightline.example', role: 'MSP administrator' }

function useRecordScope(): { label: string; icon: typeof UserRound } | null {
  const { screen, entityId } = useNav()
  const d = useTenantData()
  if (!entityId) return null
  if (screen === 'user' || screen === 'policies') {
    const u = d.identities.find((i) => i.id === entityId)
    return u ? { label: screen === 'policies' ? `Testing ${u.displayName}` : u.displayName, icon: UserRound } : null
  }
  if (screen === 'certificates') {
    const c = d.certificates.find((x) => x.id === entityId)
    return c ? { label: c.commonName, icon: FileBadge } : null
  }
  if (screen === 'radius') {
    const n = d.radiusClients.find((x) => x.id === entityId)
    return n ? { label: n.name, icon: Router } : null
  }
  return null
}

function AdminMenu({ onShortcuts }: { onShortcuts: () => void }) {
  const container = usePortalContainer()
  const toast = useToast()
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="flex items-center gap-2 rounded-full p-0.5 transition-colors hover:bg-white/[0.06]" aria-label={`Account: ${ADMIN.name}`}>
        <Avatar name={ADMIN.name} size={32} />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <DropdownMenu.Content align="end" sideOffset={8} className="a-menu a-overlay-glass w-[280px]">
          <div className="px-3 pt-2 pb-2.5">
            <p className="text-[14px] font-semibold text-[var(--a-text)]">{ADMIN.name}</p>
            <p className="a-mono truncate text-[12px] text-[var(--a-text-3)]">{ADMIN.email}</p>
            <ScopeChip depth="platform" icon={Network} className="mt-2 !h-7 !text-[12px]">
              {ADMIN.role} · all tenants
            </ScopeChip>
          </div>
          <DropdownMenu.Separator className="a-menu-sep" />
          <DropdownMenu.Item className="a-menu-item" onSelect={onShortcuts}>
            <Keyboard aria-hidden /> Keyboard shortcuts
          </DropdownMenu.Item>
          <DropdownMenu.Item
            className="a-menu-item"
            onSelect={async () => {
              await copyText(ADMIN.email)
              toast({ title: 'Email copied', description: ADMIN.email, tone: 'info' })
            }}
          >
            <Copy aria-hidden /> Copy my email
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="a-menu-sep" />
          <DropdownMenu.Item className="a-menu-item" disabled>
            <LogOut aria-hidden /> Sign out
            <span className="ml-auto text-[11px]">Prototype</span>
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

function ShortcutsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const rows: Array<[string[], string]> = [
    [['Ctrl', 'K'], 'Search this tenant'],
    [['/'], 'Search this tenant'],
    [['Esc'], 'Close a dialog, drawer or menu'],
    [['Arrow keys'], 'Read values on a focused chart'],
    [['Tab'], 'Move between controls'],
  ]
  return (
    <GlassDialog open={open} onOpenChange={onOpenChange} title="Keyboard shortcuts" width={440}>
      <dl className="divide-y divide-white/[0.07]">
        {rows.map(([keys, what]) => (
          <div key={what + keys.join()} className="flex items-center justify-between gap-4 py-2.5">
            <dt className="text-[14px] text-[var(--a-text-2)]">{what}</dt>
            <dd className="flex gap-1">
              {keys.map((k) => (
                <kbd key={k} className="a-kbd">
                  {k}
                </kbd>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </GlassDialog>
  )
}

function MobileNav({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const container = usePortalContainer()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="a-scrim" />
        <Dialog.Content className="a-drawer a-drawer-left a-overlay-glass">
          <div className="flex h-14 items-center justify-between border-b border-white/10 px-4">
            <Dialog.Title className="text-[18px] text-[var(--a-text)]">
              <Wordmark markClassName="size-6 text-[var(--a-accent)]" />
            </Dialog.Title>
            <Dialog.Description className="sr-only">Main navigation</Dialog.Description>
            <Dialog.Close className="a-icon-btn" aria-label="Close navigation">
              <X aria-hidden />
            </Dialog.Close>
          </div>
          <div className="flex min-h-0 flex-1 flex-col overflow-y-auto p-3">
            <SidebarNav onNavigate={() => onOpenChange(false)} />
            <div className="mt-auto pt-6">
              <SyntheticNote />
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

function TopBar({ onSearch, onMenu, onShortcuts }: { onSearch: () => void; onMenu: () => void; onShortcuts: () => void }) {
  const { screen, navigate } = useNav()
  const record = useRecordScope()
  const platformCurrent = screen === 'tenants'
  return (
    <header className="a-frame sticky top-0 z-40 h-[var(--a-topbar-h)] border-b border-[var(--a-d0-border)]">
      <div className="flex h-full items-center gap-2 px-3 sm:px-5 lg:px-7">
        <IconButton label="Open navigation" icon={Menu} className="lg:hidden" onClick={onMenu} tooltip={false} />
        <nav aria-label="Scope" className="flex min-w-0 flex-1 items-center gap-1.5">
          <button
            type="button"
            onClick={() => navigate('tenants')}
            aria-current={platformCurrent ? 'page' : undefined}
            className={cn('a-scope a-scope-platform hidden md:inline-flex', platformCurrent && '!border-[rgba(165,180,252,0.38)] !text-[#e0e7ff]')}
          >
            <Network className="size-4" aria-hidden />
            All tenants
          </button>
          <span className="hidden md:inline-flex">
            <ScopeSeparator />
          </span>
          <TenantSwitcher />
          {record && (
            <span className="hidden min-w-0 items-center gap-1.5 xl:inline-flex">
              <ScopeSeparator />
              <ScopeChip depth="record" icon={record.icon} className="max-w-[280px]">
                {record.label}
              </ScopeChip>
            </span>
          )}
        </nav>
        <div className="flex shrink-0 items-center gap-1.5 sm:gap-2">
          <button type="button" onClick={onSearch} className="a-btn a-btn-secondary hidden w-[240px] !justify-start !font-normal !text-[var(--a-text-3)] md:inline-flex xl:w-[280px]">
            <Search aria-hidden />
            Search
            <span className="ml-auto flex gap-1">
              <kbd className="a-kbd">Ctrl</kbd>
              <kbd className="a-kbd">K</kbd>
            </span>
          </button>
          <IconButton label="Search" icon={Search} className="md:hidden" onClick={onSearch} tooltip={false} />
          <AdminMenu onShortcuts={onShortcuts} />
        </div>
      </div>
    </header>
  )
}

export function AppShell({ children }: { children: ReactNode }) {
  const [searchOpen, setSearchOpen] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)
  const openSearch = useCallback(() => setSearchOpen(true), [])
  useSearchShortcut(openSearch)
  return (
    <div className="flex min-h-screen">
      <a href="#a-main" className="a-btn a-btn-primary sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[90]">
        Skip to content
      </a>
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onSearch={openSearch} onMenu={() => setMenuOpen(true)} onShortcuts={() => setShortcutsOpen(true)} />
        <main id="a-main" tabIndex={-1} className="mx-auto w-full max-w-[1640px] flex-1 px-4 pt-6 pb-12 outline-none sm:px-6 lg:px-7">
          {children}
        </main>
      </div>
      <CommandSearch open={searchOpen} onOpenChange={setSearchOpen} />
      <MobileNav open={menuOpen} onOpenChange={setMenuOpen} />
      <ShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
    </div>
  )
}
