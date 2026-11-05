import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/ui/lib'

export interface TableColumn<T> {
  key: string
  header: ReactNode
  /** Grouped column header shown above consecutive columns that share it. */
  group?: string
  align?: 'left' | 'right'
  sortable?: boolean
  width?: number | string
  className?: string
  hideSm?: boolean
  cell: (row: T, index: number) => ReactNode
}

interface SortProps {
  sortKey?: string | null
  sortDir?: 'asc' | 'desc'
  onSort?: (key: string) => void
  ariaSort?: (key: string) => 'ascending' | 'descending' | 'none'
}

/** Ruled hairline table with optional grouped headers and sortable columns. */
export function DataTable<T>({ columns, rows, rowKey, onRowClick, selectedKey, dimRow, caption, empty, sort, className }: {
  columns: TableColumn<T>[]
  rows: T[]
  rowKey: (row: T, index: number) => string
  onRowClick?: (row: T, index: number) => void
  selectedKey?: string | null
  dimRow?: (row: T) => boolean
  caption: string
  empty?: ReactNode
  sort?: SortProps
  className?: string
}) {
  const hasGroups = columns.some((c) => c.group)
  const groupRuns: Array<{ group: string; span: number; hideSm: boolean }> = []
  if (hasGroups) {
    for (const c of columns) {
      const g = c.group ?? ''
      const last = groupRuns[groupRuns.length - 1]
      if (last && last.group === g) { last.span++; last.hideSm = last.hideSm && !!c.hideSm }
      else groupRuns.push({ group: g, span: 1, hideSm: !!c.hideSm })
    }
  }
  return (
    <div className={cn('d-table-wrap', className)}>
      <table className="d-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          {hasGroups && (
            <tr className="d-th-groups">
              {groupRuns.map((g, i) => (
                <th key={i} colSpan={g.span} data-group={g.group} scope="colgroup" className={cn(g.hideSm && 'd-hide-sm')}>
                  {g.group}
                </th>
              ))}
            </tr>
          )}
          <tr className="d-th-cols">
            {columns.map((c) => {
              const active = sort?.sortKey === c.key
              return (
                <th
                  key={c.key}
                  scope="col"
                  data-align={c.align}
                  style={c.width ? { width: c.width } : undefined}
                  aria-sort={c.sortable && sort?.ariaSort ? sort.ariaSort(c.key) : undefined}
                  className={cn(c.hideSm && 'd-hide-sm', c.className)}
                >
                  {c.sortable && sort?.onSort ? (
                    <button type="button" className="d-sort" data-active={active || undefined} onClick={() => sort.onSort!(c.key)}>
                      {c.header}
                      {active ? sort.sortDir === 'asc' ? <ArrowUp aria-hidden="true" /> : <ArrowDown aria-hidden="true" /> : <ArrowUpDown aria-hidden="true" />}
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
          {rows.map((r, i) => {
            const key = rowKey(r, i)
            return (
              <tr
                key={key}
                data-clickable={onRowClick ? true : undefined}
                aria-selected={selectedKey != null ? selectedKey === key : undefined}
                data-dim={dimRow?.(r) || undefined}
                onClick={onRowClick ? (e) => {
                  if ((e.target as HTMLElement).closest('button, a, input, [role="switch"], [role="combobox"]')) return
                  onRowClick(r, i)
                } : undefined}
              >
                {columns.map((c) => (
                  <td key={c.key} data-align={c.align} className={cn(c.hideSm && 'd-hide-sm', c.className)}>
                    {c.cell(r, i)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
      {rows.length === 0 && empty}
    </div>
  )
}
