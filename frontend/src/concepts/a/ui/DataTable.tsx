import { useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import { cn } from '@/ui/lib'
import { useTable, type Column, type SortDir } from '@/ui/useTable'

export interface TableColumn<T> {
  key: string
  header: ReactNode
  cell: (row: T) => ReactNode
  /** Enables sorting on this column */
  sortValue?: (row: T) => string | number | null
  align?: 'left' | 'right'
  /** Applied to both th and td (e.g. responsive hiding) */
  className?: string
  /** Screen-reader-only header (for action columns) */
  srHeader?: boolean
}

/** Search + sort state for a table; search runs over `searchText`, sort over column sortValues. */
export function useDataTable<T>(rows: T[], columns: TableColumn<T>[], opts: { searchText?: (row: T) => string; filter?: (row: T) => boolean; initialSort?: { key: string; dir: SortDir } } = {}) {
  const { searchText, filter, initialSort } = opts
  const tableColumns = useMemo<Column<T>[]>(() => {
    const cols: Column<T>[] = columns.filter((c) => c.sortValue).map((c) => ({ key: c.key, value: c.sortValue!, searchable: false }))
    if (searchText) cols.push({ key: '__search', value: searchText, searchable: true })
    return cols
  }, [columns, searchText])
  return useTable(rows, tableColumns, { filter, initialSort })
}

export type DataTableState<T> = ReturnType<typeof useDataTable<T>>

/**
 * True while the table fits its wrapper. A table that fits gets the sticky glass header (the page
 * scrolls); one that doesn't scrolls sideways inside its wrapper and keeps the header in flow,
 * because a sticky header inside a horizontal scroller would pin to the wrong edge.
 */
function useFits() {
  const wrapRef = useRef<HTMLDivElement>(null)
  const tableRef = useRef<HTMLTableElement>(null)
  const [fits, setFits] = useState(true)
  useLayoutEffect(() => {
    const wrap = wrapRef.current
    const table = tableRef.current
    if (!wrap || !table) return
    const check = () => setFits(table.offsetWidth <= wrap.clientWidth + 1)
    check()
    const ro = new ResizeObserver(check)
    ro.observe(wrap)
    ro.observe(table)
    return () => ro.disconnect()
  }, [])
  return { wrapRef, tableRef, fits }
}

export function DataTable<T>({
  columns,
  table,
  rowKey,
  onRowClick,
  selectedKey,
  empty,
  caption,
  className,
}: {
  columns: TableColumn<T>[]
  table: Pick<DataTableState<T>, 'rows' | 'sort' | 'toggleSort' | 'ariaSort'>
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
  selectedKey?: string | null
  empty?: ReactNode
  caption: string
  className?: string
}) {
  const { wrapRef, tableRef, fits } = useFits()
  return (
    <div ref={wrapRef} className={cn('a-table-wrap', className)} data-fits={fits}>
      <table ref={tableRef} className="a-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => {
              const sortable = !!c.sortValue
              const active = table.sort?.key === c.key
              const Icon = active ? (table.sort?.dir === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown
              return (
                <th key={c.key} scope="col" aria-sort={sortable ? table.ariaSort(c.key) : undefined} className={cn(c.align === 'right' && 'text-right', c.className)}>
                  {c.srHeader ? (
                    <span className="sr-only">{c.header}</span>
                  ) : sortable ? (
                    <button type="button" className={cn('a-th-sort', active && 'text-[var(--a-text)]', c.align === 'right' && 'flex-row-reverse')} onClick={() => table.toggleSort(c.key)}>
                      {c.header}
                      <Icon aria-hidden className={cn(!active && 'opacity-50')} />
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((row) => {
            const key = rowKey(row)
            return (
              <tr
                key={key}
                data-clickable={onRowClick ? 'true' : undefined}
                data-selected={selectedKey === key ? 'true' : undefined}
                onClick={
                  onRowClick
                    ? (e) => {
                        if ((e.target as HTMLElement).closest('button, a, input, [role="menuitem"], [role="switch"]')) return
                        onRowClick(row)
                      }
                    : undefined
                }
              >
                {columns.map((c) => (
                  <td key={c.key} className={cn(c.align === 'right' && 'text-right', c.className)}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
      {table.rows.length === 0 && empty}
    </div>
  )
}
