import { useCallback, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { ArrowDown, ArrowUp, ChevronsUpDown, SearchX } from 'lucide-react'
import { useTable, type Column, type SortDir } from '@/ui/useTable'
import { cn } from '@/ui/lib'
import { SelectBox, type Option } from './Field'
import { Button } from './Button'
import { useOverflowX } from '../lib/hooks'

export const ALL = '__all'

export type FilterDef<T> =
  | { kind: 'select'; options: Option[]; test: (row: T, value: string) => boolean; allLabel?: string }
  | { kind: 'text'; placeholder?: string; test: (row: T, query: string) => boolean }

export interface ColumnDef<T> {
  id: string
  header: string
  cell: (row: T) => ReactNode
  /** Sort key; omit to make the column unsortable */
  sort?: (row: T) => string | number | null
  /** Text included in the toolbar search */
  search?: (row: T) => string | null
  /** Inline column filter rendered under the header */
  filter?: FilterDef<T>
  width?: number | string
  align?: 'start' | 'end'
  /** Sticky first column (stays put while the table scrolls sideways on narrow screens) */
  sticky?: boolean
  className?: string
}

export interface TableOptions<T> {
  initialSort?: { key: string; dir: SortDir }
  initialFilters?: Record<string, string>
  /** Filters applied outside the column filters (e.g. a segmented source switch) */
  extraFilter?: (row: T) => boolean
}

/** Search + inline column filters + sort, built on the shared useTable helper. Memoise `columns`. */
export function useDataTable<T>(rows: T[], columns: ColumnDef<T>[], opts: TableOptions<T> = {}) {
  const [filters, setFilters] = useState<Record<string, string>>(opts.initialFilters ?? {})
  const { extraFilter } = opts
  const filter = useCallback(
    (row: T) => {
      if (extraFilter && !extraFilter(row)) return false
      for (const c of columns) {
        const v = filters[c.id]
        if (!c.filter || !v || v === ALL) continue
        if (!c.filter.test(row, c.filter.kind === 'text' ? v.trim().toLowerCase() : v)) return false
      }
      return true
    },
    [columns, filters, extraFilter],
  )
  const tableColumns = useMemo<Column<T>[]>(
    () =>
      columns.flatMap((c) => {
        const out: Column<T>[] = []
        if (c.sort) out.push({ key: c.id, value: c.sort, searchable: false })
        if (c.search) out.push({ key: `${c.id}__q`, value: c.search, searchable: true })
        return out
      }),
    [columns],
  )
  const t = useTable(rows, tableColumns, { initialSort: opts.initialSort, filter })
  const activeFilters = Object.values(filters).filter((v) => v && v !== ALL).length + (t.query.trim() ? 1 : 0)
  return {
    ...t,
    columns,
    filters,
    total: rows.length,
    activeFilters,
    setFilter: (id: string, v: string) => setFilters((f) => ({ ...f, [id]: v })),
    setFilters,
    clearFilters: () => {
      setFilters({})
      t.setQuery('')
    },
  }
}

export type DataTableState<T> = ReturnType<typeof useDataTable<T>>

/**
 * Dense ops table: 32px rows, inline column filters, sticky header and first column,
 * keyboard row navigation (j/k or arrows, Home/End, Enter to open).
 */
export function DataTable<T>({
  table,
  rowKey,
  onActivate,
  rowLabel,
  label,
  isActive,
  empty,
  noun = 'rows',
  showFilters = true,
}: {
  table: DataTableState<T>
  rowKey: (row: T, index: number) => string
  onActivate?: (row: T) => void
  /** Accessible name for a row, e.g. the user's name */
  rowLabel?: (row: T) => string
  label: string
  isActive?: (row: T) => boolean
  empty?: ReactNode
  noun?: string
  showFilters?: boolean
}) {
  const [cursor, setCursor] = useState(0)
  const bodyRef = useRef<HTMLTableSectionElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const tableRef = useRef<HTMLTableElement>(null)
  const overflow = useOverflowX(wrapRef, tableRef)
  const { rows, columns } = table
  const current = Math.min(cursor, Math.max(0, rows.length - 1))
  const hasFilters = showFilters && columns.some((c) => c.filter)

  const focusRow = (i: number) => {
    const next = Math.max(0, Math.min(rows.length - 1, i))
    setCursor(next)
    const el = bodyRef.current?.querySelectorAll<HTMLTableRowElement>('tr[data-row]')[next]
    el?.focus()
  }

  const onKey = (e: KeyboardEvent<HTMLTableRowElement>, i: number, row: T) => {
    if (e.altKey || e.metaKey || e.ctrlKey) return
    switch (e.key) {
      case 'j':
      case 'ArrowDown':
        e.preventDefault()
        focusRow(i + 1)
        break
      case 'k':
      case 'ArrowUp':
        e.preventDefault()
        focusRow(i - 1)
        break
      case 'Home':
        e.preventDefault()
        focusRow(0)
        break
      case 'End':
        e.preventDefault()
        focusRow(rows.length - 1)
        break
      case 'Enter':
      case 'o':
        if (onActivate) {
          e.preventDefault()
          onActivate(row)
        }
        break
    }
  }

  return (
    <div>
      <div className="b-table-wrap" ref={wrapRef} data-overflow={overflow}>
        <table className="b-table" ref={tableRef} aria-label={label} aria-rowcount={rows.length}>
          <thead>
            <tr>
              {columns.map((c) => (
                <th
                  key={c.id}
                  scope="col"
                  data-align={c.align}
                  aria-sort={c.sort ? table.ariaSort(c.id) : undefined}
                  className={cn(c.sticky && 'is-sticky', c.className)}
                  style={{ width: c.width }}
                >
                  {c.sort ? (
                    <button type="button" className="b-sort" onClick={() => table.toggleSort(c.id)}>
                      {c.header}
                      {table.sort?.key === c.id ? table.sort.dir === 'asc' ? <ArrowUp aria-hidden /> : <ArrowDown aria-hidden /> : <ChevronsUpDown aria-hidden />}
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              ))}
            </tr>
            {hasFilters && (
              <tr className="b-filter-row">
                {columns.map((c) => (
                  <td key={c.id} className={cn(c.sticky && 'is-sticky', c.className)}>
                    {c.filter?.kind === 'select' ? (
                      <SelectBox
                        size="sm"
                        ariaLabel={`Filter by ${c.header.toLowerCase()}`}
                        value={table.filters[c.id] ?? ALL}
                        onChange={(v) => table.setFilter(c.id, v)}
                        options={[{ value: ALL, label: c.filter.allLabel ?? 'All' }, ...c.filter.options]}
                      />
                    ) : c.filter?.kind === 'text' ? (
                      <input
                        className="b-input b-input-sm"
                        aria-label={`Filter by ${c.header.toLowerCase()}`}
                        placeholder={c.filter.placeholder ?? 'Filter…'}
                        value={table.filters[c.id] ?? ''}
                        onChange={(e) => table.setFilter(c.id, e.target.value)}
                      />
                    ) : null}
                  </td>
                ))}
              </tr>
            )}
          </thead>
          <tbody ref={bodyRef}>
            {rows.map((row, i) => (
              <tr
                key={rowKey(row, i)}
                data-row
                data-interactive={onActivate ? 'true' : undefined}
                data-active={isActive?.(row) ? 'true' : undefined}
                tabIndex={i === current ? 0 : -1}
                aria-label={rowLabel?.(row)}
                onFocus={() => setCursor(i)}
                onClick={onActivate ? () => onActivate(row) : undefined}
                onKeyDown={(e) => onKey(e, i, row)}
              >
                {columns.map((c) => (
                  <td key={c.id} data-align={c.align} className={cn(c.sticky && 'is-sticky', c.className)}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={columns.length} style={{ height: 'auto', whiteSpace: 'normal' }}>
                  {empty ?? (
                    <div className="flex flex-wrap items-center gap-3 px-1 py-6">
                      <SearchX className="size-4 text-[var(--b-text-3)]" aria-hidden />
                      <span className="b-t2">No {noun} match these filters.</span>
                      {table.activeFilters > 0 && (
                        <Button size="sm" variant="secondary" onClick={table.clearFilters}>
                          Clear filters
                        </Button>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-[var(--b-line)] px-3 py-2 text-[12px] text-[var(--b-text-3)]">
        <span className="b-num">
          Showing <span className="text-[var(--b-text-2)]">{rows.length}</span> of {table.total} {noun}
        </span>
        {table.activeFilters > 0 && (
          <button type="button" className="b-link text-[12px]" onClick={table.clearFilters}>
            Clear {table.activeFilters === 1 ? 'filter' : `${table.activeFilters} filters`}
          </button>
        )}
        {onActivate && rows.length > 0 && (
          <span className="ml-auto hidden items-center gap-1.5 md:inline-flex">
            <kbd>j</kbd>
            <kbd>k</kbd> move <span className="mx-1 text-[var(--b-line-strong)]">·</span>
            <kbd>Enter</kbd> open
          </span>
        )}
      </div>
    </div>
  )
}
