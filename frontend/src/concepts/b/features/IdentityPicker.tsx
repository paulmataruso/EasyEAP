import { useId, useMemo, useState, type KeyboardEvent } from 'react'
import { Popover } from 'radix-ui'
import { ChevronsUpDown, Search } from 'lucide-react'
import type { Decision, Identity } from '@/domain/types'
import { cn } from '@/ui/lib'
import { usePortal } from '../ui/portal'

/** Searchable identity combobox (popover + listbox, arrow keys + Enter). */
export function IdentityPicker({ identities, value, onChange, decisions }: { identities: Identity[]; value: Identity | undefined; onChange: (id: string) => void; decisions: Map<string, Decision> }) {
  const container = usePortal()
  const listId = useId()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [hi, setHi] = useState(0)
  const results = useMemo(() => {
    const s = q.trim().toLowerCase()
    return identities
      .map((i, idx) => ({ i, idx }))
      .filter(({ i }) => !s || [i.displayName, i.username, i.upn, i.department].some((v) => v?.toLowerCase().includes(s)))
      .slice(0, 60)
  }, [identities, q])
  const choose = (id: string) => {
    onChange(id)
    setOpen(false)
    setQ('')
  }
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') setHi((h) => Math.min(results.length - 1, h + 1))
    else if (e.key === 'ArrowUp') setHi((h) => Math.max(0, h - 1))
    else if (e.key === 'Enter' && results[hi]) choose(results[hi].i.id)
    else return
    e.preventDefault()
  }
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger className="b-input b-select-trigger !h-auto min-h-[36px] !py-1" aria-label="Choose a user to test">
        {value ? (
          <span className="min-w-0 text-left">
            <span className="block truncate text-[13px] text-[var(--b-text)]">{value.displayName}</span>
            <span className="b-mono block truncate text-[11px] text-[var(--b-text-3)]">{value.upn ?? value.username}</span>
          </span>
        ) : (
          <span className="text-[var(--b-text-3)]">Choose a user…</span>
        )}
        <ChevronsUpDown aria-hidden />
      </Popover.Trigger>
      <Popover.Portal container={container}>
        <Popover.Content align="start" sideOffset={4} className="b-pop w-[var(--radix-popover-trigger-width)] min-w-[280px] p-1">
          <div className="relative mb-1">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-[var(--b-text-3)]" aria-hidden />
            <input
              autoFocus
              role="combobox"
              aria-expanded="true"
              aria-controls={listId}
              aria-activedescendant={results[hi] ? `${listId}-${results[hi].idx}` : undefined}
              aria-label="Search users"
              className="b-input pl-8"
              placeholder="Name, username or department"
              value={q}
              onChange={(e) => {
                setQ(e.target.value)
                setHi(0)
              }}
              onKeyDown={onKey}
            />
          </div>
          <ul id={listId} role="listbox" aria-label="Users" className="max-h-[300px] overflow-y-auto">
            {results.length === 0 && <li className="b-t2 px-2 py-3 text-[12.5px]">No user matches “{q}”.</li>}
            {results.map(({ i, idx }, n) => {
              const dec = decisions.get(i.id)
              return (
                <li
                  key={`${i.id}-${idx}`}
                  id={`${listId}-${idx}`}
                  role="option"
                  aria-selected={value?.id === i.id}
                  className={cn('b-menu-item', n === hi && 'bg-[rgba(229,237,245,0.07)]')}
                  onPointerMove={() => setHi(n)}
                  onClick={() => choose(i.id)}
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate">{i.displayName}</span>
                    <span className="b-t3 block truncate text-[11.5px]">{[i.department, i.title].filter(Boolean).join(' · ')}</span>
                  </span>
                  <span className={cn('text-[12px]', dec?.outcome === 'allow' ? 'b-ink-ok' : 'b-ink-crit')}>{dec?.outcome === 'allow' ? 'Allowed' : 'Denied'}</span>
                </li>
              )
            })}
          </ul>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
