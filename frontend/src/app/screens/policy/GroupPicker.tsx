// Multi-select over the tenant's directory groups (GET /directory/groups) with search. AD and local groups can share
// a name, so each option carries its source and DN. Groups deleted from the directory stay visible on the rule,
// marked, because they now match nobody.
import { useEffect, useId, useMemo, useState, type KeyboardEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Check, Search, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import { directoryApi, GROUP_LIST_LIMIT, useDirectoryGroups, type DirectoryGroup } from '../../api/directory'
import { qk } from '../../api/keys'
import type { RuleGroup } from '../../api/policy'
import { ErrorState, LoadingBlock, SourceTag } from '../../ui'
import { plural } from '../../lib/format'

function useDebounced<T>(value: T, ms = 200): T {
  const [v, setV] = useState(value)
  useEffect(() => { const id = setTimeout(() => setV(value), ms); return () => clearTimeout(id) }, [value, ms])
  return v
}

export function GroupPicker({ tid, value, onChange, invalid, describedBy }: { tid: string; value: RuleGroup[]; onChange: (v: RuleGroup[]) => void; invalid?: boolean; describedBy?: string }) {
  const all = useDirectoryGroups(tid)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const q = useDebounced(query.trim())
  const listId = useId()
  // More groups than one page: search server-side.
  const capped = (all.data?.groups.length ?? 0) >= GROUP_LIST_LIMIT
  const remote = useQuery({
    queryKey: [...qk.directoryGroups(tid), { q }],
    queryFn: ({ signal }) => directoryApi.searchGroups(tid, q, signal),
    enabled: capped && q.length > 0,
  })
  const options: DirectoryGroup[] = useMemo(() => {
    const src = capped && q ? remote.data?.groups ?? [] : all.data?.groups ?? []
    if (!q || capped) return src
    const ql = q.toLowerCase()
    return src.filter((g) => g.name.toLowerCase().includes(ql) || g.dn.toLowerCase().includes(ql))
  }, [all.data, remote.data, q, capped])
  const selected = new Set(value.map((g) => g.id))

  const toggle = (g: DirectoryGroup) => {
    if (selected.has(g.id)) onChange(value.filter((x) => x.id !== g.id))
    else onChange([...value, { id: g.id, name: g.name, deleted: false }])
  }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(options.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(0, i - 1)) }
    else if (e.key === 'Enter') { e.preventDefault(); const g = options[active]; if (g) toggle(g) }
    else if (e.key === 'Escape' && query) { e.preventDefault(); e.stopPropagation(); setQuery('') }
  }
  const sourceOf = (id: string) => all.data?.groups.find((g) => g.id === id)?.source

  return (
    <div className="space-y-2">
      {value.length > 0 ? (
        <ul className="flex flex-wrap gap-1.5" aria-label="Selected groups">
          {value.map((g) => (
            <li key={g.id} className={cn('inline-flex h-7 items-center gap-1.5 rounded-[6px] border pl-2 pr-1 text-[12.5px]', g.deleted ? 'border-[rgba(244,63,94,0.45)] text-[var(--ee-crit-ink)]' : 'border-[var(--ee-line-2)]')}>
              <span className="max-w-[220px] truncate">{g.name}</span>
              {g.deleted ? <span className="text-[12px]">· deleted in directory</span> : sourceOf(g.id) === 'local' ? <span className="ee-ink-3 text-[12px]">· local</span> : null}
              <button type="button" className="grid size-5 place-items-center rounded ee-ink-3 hover:text-[var(--ee-ink)]" aria-label={`Remove ${g.name}`} onClick={() => onChange(value.filter((x) => x.id !== g.id))}>
                <X className="size-3.5" aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="ee-small ee-ink-3">No groups chosen yet.</p>
      )}
      <div className="rounded-[8px] border border-[var(--ee-line-2)] bg-[rgba(6,9,17,0.35)]" data-invalid={invalid || undefined}>
        <div className="flex items-center gap-2 border-b border-[var(--ee-line)] px-2.5">
          <Search className="size-4 shrink-0 ee-ink-3" aria-hidden />
          <input
            role="combobox"
            aria-expanded
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={options[active] ? `${listId}-${active}` : undefined}
            aria-label="Search groups"
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            className="h-9 min-w-0 flex-1 bg-transparent text-[13.5px] outline-none placeholder:text-[var(--ee-ink-3)]"
            placeholder="Search groups by name or DN"
            value={query}
            onChange={(e) => { setQuery(e.target.value); setActive(0) }}
            onKeyDown={onKey}
          />
        </div>
        {all.isLoading ? (
          <div className="px-3 py-2"><LoadingBlock rows={3} label="Loading groups" /></div>
        ) : all.error ? (
          <div className="p-2"><ErrorState error={all.error} onRetry={() => all.refetch()} title="Groups couldn’t be loaded" /></div>
        ) : (
          <div id={listId} role="listbox" aria-multiselectable aria-label="Directory groups" className="max-h-[232px] overflow-y-auto p-1">
            {options.length === 0 ? (
              <p className="px-2.5 py-3 ee-small ee-ink-2">{q ? `No group matches “${q}”.` : 'This tenant has no directory groups yet. Connect the directory or create a local group in Directory.'}</p>
            ) : options.map((g, i) => {
              const on = selected.has(g.id)
              return (
                <div
                  key={g.id}
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={on}
                  className={cn('flex cursor-pointer items-start gap-2.5 rounded-[6px] px-2.5 py-1.5', i === active && 'bg-[rgba(237,234,227,0.07)]')}
                  onMouseEnter={() => setActive(i)}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => toggle(g)}
                >
                  <span className={cn('mt-0.5 grid size-4 shrink-0 place-items-center rounded-[4px] border', on ? 'border-[var(--ee-gold)] bg-[var(--ee-gold)] text-[var(--ee-gold-ink)]' : 'border-[var(--ee-line-3)]')} aria-hidden>
                    {on && <Check className="size-3" />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2">
                      <span className="truncate text-[13px] font-medium">{g.name}</span>
                      <SourceTag source={g.source} />
                    </span>
                    <span className="block truncate text-[12px] ee-ink-3" title={g.dn}>{g.source === 'local' ? 'Local group in EasyEAP' : g.dn}</span>
                  </span>
                  <span className="ee-num shrink-0 pt-0.5 text-[12px] ee-ink-3">{plural(g.members, 'member')}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>
      {capped && !q && <p className="ee-small ee-ink-3">Showing the first {GROUP_LIST_LIMIT} groups. Type to search all of them.</p>}
    </div>
  )
}
