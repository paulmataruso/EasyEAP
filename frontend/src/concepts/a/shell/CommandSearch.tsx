import { useEffect, useId, useMemo, useRef, useState, type ComponentType, type KeyboardEvent } from 'react'
import { Dialog } from 'radix-ui'
import { ArrowDown, ArrowUp, FileBadge, Router, Search, UserRound } from 'lucide-react'
import { cn, formatSerial } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import type { ScreenId } from '../../contract'
import { usePortalContainer } from '../ui/portal'
import { NAV, useNav } from './nav'

interface Result {
  id: string
  group: 'Go to' | 'Users' | 'Certificates' | 'Wireless controllers'
  title: string
  detail: string
  icon: ComponentType<{ className?: string; 'aria-hidden'?: boolean }>
  go: () => void
}

export function useSearchShortcut(open: () => void) {
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      const typing = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)
      if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typing)) {
        e.preventDefault()
        open()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])
}

export function CommandSearch({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const d = useTenantData()
  const { current } = useTenants()
  const { navigate } = useNav()
  const container = usePortalContainer()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const listId = useId()
  const listRef = useRef<HTMLUListElement>(null)

  const results = useMemo<Result[]>(() => {
    const q = query.trim().toLowerCase()
    const go = (screen: ScreenId, id?: string) => () => {
      onOpenChange(false)
      setQuery('')
      navigate(screen, id)
    }
    const pages: Result[] = NAV.flatMap((g) => g.items).map((i) => ({ id: `p-${i.screen}`, group: 'Go to' as const, title: i.label, detail: g(i.screen), icon: i.icon, go: go(i.screen) }))
    function g(s: ScreenId) {
      return NAV.find((x) => x.items.some((i) => i.screen === s))?.group ?? ''
    }
    if (!q) return pages
    const users: Result[] = d.identities
      .filter((u) => `${u.displayName} ${u.upn ?? ''} ${u.username} ${u.department ?? ''}`.toLowerCase().includes(q))
      .slice(0, 6)
      .map((u, i) => ({ id: `u-${u.id}-${i}`, group: 'Users', title: u.displayName, detail: u.upn ?? u.username, icon: UserRound, go: go('user', u.id) }))
    const certs: Result[] = d.certificates
      .filter((c) => `${c.serial} ${c.commonName} ${c.subject}`.toLowerCase().includes(q.replace(/\s/g, '')) || c.commonName.toLowerCase().includes(q))
      .slice(0, 5)
      .map((c) => ({ id: `c-${c.id}`, group: 'Certificates', title: c.commonName, detail: formatSerial(c.serial), icon: FileBadge, go: go('certificates', c.id) }))
    const nas: Result[] = d.radiusClients
      .filter((n) => `${n.name} ${n.address} ${n.site}`.toLowerCase().includes(q))
      .slice(0, 4)
      .map((n) => ({ id: `n-${n.id}`, group: 'Wireless controllers', title: n.name, detail: `${n.address} · ${n.site}`, icon: Router, go: go('radius', n.id) }))
    return [...pages.filter((p) => p.title.toLowerCase().includes(q)), ...users, ...certs, ...nas]
  }, [query, d, navigate, onOpenChange])

  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [active])

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((a) => Math.min(results.length - 1, a + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => Math.max(0, a - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      results[active]?.go()
    }
  }

  let lastGroup = ''
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o)
        if (!o) setQuery('')
      }}
    >
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="a-scrim" />
        <Dialog.Content className="a-dialog a-overlay-glass" style={{ ['--a-dialog-w' as string]: '600px', top: '14vh', transform: 'translate(-50%, 0)', animation: 'none' }}>
          <Dialog.Title className="sr-only">Search {current.name}</Dialog.Title>
          <Dialog.Description className="sr-only">Find users, certificates, controllers and pages in this tenant.</Dialog.Description>
          <div className="relative border-b border-white/10">
            <Search className="pointer-events-none absolute top-1/2 left-5 size-[18px] -translate-y-1/2 text-[var(--a-text-3)]" aria-hidden />
            <input
              autoFocus
              role="combobox"
              aria-expanded="true"
              aria-controls={listId}
              aria-activedescendant={results[active] ? `${listId}-${active}` : undefined}
              aria-label={`Search ${current.name}`}
              placeholder={`Search users, serials, controllers in ${current.name}`}
              className="h-14 w-full bg-transparent pr-5 pl-12 text-[15px] text-[var(--a-text)] outline-none placeholder:text-[#8b9ab0]"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value)
                setActive(0)
              }}
              onKeyDown={onKeyDown}
            />
          </div>
          <ul ref={listRef} id={listId} role="listbox" aria-label="Results" className="max-h-[min(440px,60vh)] overflow-y-auto p-2">
            {results.length === 0 && <li className="px-3 py-8 text-center text-[13px] text-[var(--a-text-3)]">Nothing in {current.name} matches “{query}”. Try a UPN, a serial or a controller IP.</li>}
            {results.map((r, i) => {
              const header = r.group !== lastGroup
              lastGroup = r.group
              const Icon = r.icon
              return (
                <li key={r.id} role="presentation">
                  {header && <div className="px-3 pt-2.5 pb-1 text-[12px] font-medium text-[var(--a-text-3)]">{r.group}</div>}
                  <div
                    id={`${listId}-${i}`}
                    role="option"
                    aria-selected={i === active}
                    data-active={i === active}
                    onPointerMove={() => setActive(i)}
                    onClick={r.go}
                    className={cn('flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2', i === active && 'bg-white/[0.08]')}
                  >
                    <Icon className="size-4 shrink-0 text-[var(--a-text-3)]" aria-hidden />
                    <span className="min-w-0 flex-1 truncate text-[14px] text-[var(--a-text)]">{r.title}</span>
                    <span className={cn('truncate text-[12px] text-[var(--a-text-3)]', r.group !== 'Go to' && 'a-mono')}>{r.detail}</span>
                  </div>
                </li>
              )
            })}
          </ul>
          <div className="flex items-center gap-4 border-t border-white/10 px-4 py-2.5 text-[12px] text-[var(--a-text-3)]">
            <span className="flex items-center gap-1.5">
              <kbd className="a-kbd" aria-label="Up arrow">
                <ArrowUp className="size-3" aria-hidden />
              </kbd>
              <kbd className="a-kbd" aria-label="Down arrow">
                <ArrowDown className="size-3" aria-hidden />
              </kbd>{' '}
              to move
            </span>
            <span className="flex items-center gap-1.5">
              <kbd className="a-kbd">Enter</kbd> to open
            </span>
            <span className="ml-auto">Scoped to {current.name}</span>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
