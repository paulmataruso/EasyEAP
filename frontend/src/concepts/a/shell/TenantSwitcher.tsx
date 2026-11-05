import { useId, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { Popover } from 'radix-ui'
import { Check, ChevronsUpDown, Search } from 'lucide-react'
import { cn, formatPercent } from '@/ui/lib'
import { useTenants } from '@/prototype/store'
import { HealthDot } from '../ui/badges'
import { usePortalContainer } from '../ui/portal'
import { tenantHealth } from '../lib/model'
import { usePortfolio } from '../lib/portfolio'
import { useNav } from './nav'

/** Tenant switcher combobox — lives in the platform frame, renders as a tenant-depth chip. */
export function TenantSwitcher({ compact = false }: { compact?: boolean }) {
  const { tenants, current, switchTenant } = useTenants()
  const { screen, navigate } = useNav()
  const portfolio = usePortfolio()
  const container = usePortalContainer()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)
  const listId = useId()
  const inputRef = useRef<HTMLInputElement>(null)

  const healthById = useMemo(() => new Map(portfolio.map((p) => [p.tenant.id, { ...tenantHealth(p.tenant, p.controllers), summary: p }])), [portfolio])
  const filtered = tenants.filter((t) => `${t.name} ${t.domain}`.toLowerCase().includes(query.trim().toLowerCase()))
  const currentHealth = healthById.get(current.id)

  const choose = (id: string) => {
    setOpen(false)
    setQuery('')
    if (id !== current.id) switchTenant(id)
    // Records belong to a tenant: drop the record and stay on the same screen.
    const next = screen === 'user' ? 'users' : screen === 'tenants' ? 'dashboard' : screen
    navigate(next)
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIdx((i) => Math.min(filtered.length - 1, i + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIdx((i) => Math.max(0, i - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const t = filtered[activeIdx]
      if (t) choose(t.id)
    }
  }

  return (
    <Popover.Root
      open={open}
      onOpenChange={(o) => {
        setOpen(o)
        if (o) setActiveIdx(Math.max(0, tenants.findIndex((t) => t.id === current.id)))
        else setQuery('')
      }}
    >
      <Popover.Trigger asChild>
        <button type="button" className={cn('a-scope a-scope-tenant !h-10 min-w-0 gap-2.5 !pr-2 text-left', compact ? 'max-w-[200px]' : 'max-w-[340px]')} aria-haspopup="listbox" aria-label={`Tenant: ${current.name}. ${currentHealth?.label ?? ''}. Switch tenant`}>
          <HealthDot state={currentHealth?.state ?? 'ok'} label={currentHealth?.label} />
          <span className="flex min-w-0 flex-col leading-tight">
            <span className="truncate text-[13px] font-semibold text-[var(--a-text)]">{current.name}</span>
            {!compact && <span className="a-mono truncate text-[11px] font-normal text-[var(--a-text-3)]">{current.domain}</span>}
          </span>
          <ChevronsUpDown className="size-4 shrink-0 text-[var(--a-text-3)]" aria-hidden />
        </button>
      </Popover.Trigger>
      <Popover.Portal container={container}>
        <Popover.Content
          align="start"
          sideOffset={8}
          className="a-popover a-overlay-glass w-[min(calc(100vw-24px),400px)] p-0"
          onOpenAutoFocus={(e) => {
            e.preventDefault()
            inputRef.current?.focus()
          }}
        >
          <div className="relative border-b border-white/10 p-2">
            <Search className="pointer-events-none absolute top-1/2 left-5 size-4 -translate-y-1/2 text-[var(--a-text-3)]" aria-hidden />
            <input
              ref={inputRef}
              role="combobox"
              aria-expanded="true"
              aria-controls={listId}
              aria-activedescendant={filtered[activeIdx] ? `${listId}-${filtered[activeIdx].id}` : undefined}
              aria-autocomplete="list"
              aria-label="Find a tenant"
              placeholder="Find a tenant"
              className="a-input !border-transparent !bg-transparent pl-9 !shadow-none"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value)
                setActiveIdx(0)
              }}
              onKeyDown={onKeyDown}
            />
          </div>
          <ul id={listId} role="listbox" aria-label="Tenants" className="max-h-[340px] overflow-y-auto p-1.5">
            {filtered.length === 0 && <li className="px-3 py-6 text-center text-[13px] text-[var(--a-text-3)]">No tenant matches “{query}”.</li>}
            {filtered.map((t, i) => {
              const h = healthById.get(t.id)
              const selected = t.id === current.id
              return (
                <li
                  key={t.id}
                  id={`${listId}-${t.id}`}
                  role="option"
                  aria-selected={selected}
                  onPointerMove={() => setActiveIdx(i)}
                  onClick={() => choose(t.id)}
                  className={cn('flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2.5', i === activeIdx && 'bg-white/[0.07]')}
                >
                  <HealthDot state={h?.state ?? 'ok'} label={h?.label} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[14px] font-medium text-[var(--a-text)]">{t.name}</span>
                    <span className="flex flex-wrap gap-x-2 text-[12px] text-[var(--a-text-3)]">
                      <span className="a-mono">{t.domain}</span>
                    </span>
                    <span className="mt-0.5 flex flex-wrap gap-x-2 text-[12px] text-[var(--a-text-3)]">
                      <span className={cn(h?.state === 'degraded' && 'text-[var(--a-warn-text)]', h?.state === 'down' && 'text-[var(--a-danger-text)]')}>{h?.label}</span>
                      {h?.summary && (
                        <span className="a-num">
                          · {h.summary.users} users{h.summary.successRate !== null ? ` · ${formatPercent(h.summary.successRate, 0)} success` : ''}
                        </span>
                      )}
                    </span>
                  </span>
                  {selected && <Check className="size-4 shrink-0 text-[var(--a-accent-hover)]" aria-hidden />}
                </li>
              )
            })}
          </ul>
          <div className="border-t border-white/10 p-1.5">
            <button
              type="button"
              className="a-menu-item w-full !text-[13px] !text-[#c7d2fe] hover:bg-[rgba(129,140,248,0.1)]"
              onClick={() => {
                setOpen(false)
                navigate('tenants')
              }}
            >
              View all tenants
            </button>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
