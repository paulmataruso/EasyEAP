import type { KeyboardEvent, ReactNode } from 'react'
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import { cn } from '@/ui/lib'

export interface ColumnDef<T> {
  key: string
  header: ReactNode
  cell: (row: T) => ReactNode
  sortable?: boolean
  align?: 'left' | 'right'
  width?: string
  className?: string
  /** Hide below a breakpoint to keep the table usable on narrow screens */
  hideBelow?: 'sm' | 'md' | 'lg' | 'xl'
}

const HIDE: Record<NonNullable<ColumnDef<unknown>['hideBelow']>, string> = {
  sm: 'max-sm:hidden',
  md: 'max-md:hidden',
  lg: 'max-lg:hidden',
  xl: 'max-xl:hidden',
}

export function DataTable<T>({ rows, columns, rowKey, caption, onActivate, selectedKey, sort, onSort, ariaSort, empty, maxHeight, dense }: {
  rows: T[]
  columns: ColumnDef<T>[]
  rowKey: (row: T) => string
  caption: string
  onActivate?: (row: T) => void
  selectedKey?: string | null
  sort?: { key: string; dir: 'asc' | 'desc' } | null
  onSort?: (key: string) => void
  ariaSort?: (key: string) => 'ascending' | 'descending' | 'none'
  empty?: ReactNode
  maxHeight?: number
  dense?: boolean
}) {
  const onKey = (e: KeyboardEvent<HTMLTableRowElement>, row: T) => {
    if (!onActivate) return
    if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
      e.preventDefault()
      onActivate(row)
    }
  }
  return (
    <div className="e-table-wrap" style={maxHeight ? { maxHeight, overflowY: 'auto' } : undefined}>
      <table className="e-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col" data-align={c.align} style={{ width: c.width }} aria-sort={c.sortable && ariaSort ? ariaSort(c.key) : undefined} className={cn(c.hideBelow && HIDE[c.hideBelow])}>
                {c.sortable && onSort ? (
                  <button type="button" className="e-th-sort" data-sorted={sort?.key === c.key} onClick={() => onSort(c.key)}>
                    {c.header}
                    {sort?.key === c.key ? sort.dir === 'asc' ? <ArrowUp aria-hidden /> : <ArrowDown aria-hidden /> : <ArrowUpDown aria-hidden />}
                  </button>
                ) : (
                  c.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="!h-auto">{empty}</td>
            </tr>
          ) : (
            rows.map((r) => {
              const k = rowKey(r)
              return (
                <tr
                  key={k}
                  data-clickable={!!onActivate}
                  data-selected={selectedKey === k}
                  onClick={onActivate ? (e) => { if ((e.target as HTMLElement).closest('button:not([data-row-primary]),a,input,[role="switch"],[role="combobox"]')) return; onActivate(r) } : undefined}
                  onKeyDown={(e) => onKey(e, r)}
                >
                  {columns.map((c) => (
                    <td key={c.key} data-align={c.align} className={cn(dense && '!h-10', c.className, c.hideBelow && HIDE[c.hideBelow])}>
                      {c.cell(r)}
                    </td>
                  ))}
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}
