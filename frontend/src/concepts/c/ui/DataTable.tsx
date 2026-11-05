import { Fragment, useId, useState, type MouseEvent, type ReactNode } from 'react'
import { ArrowDown, ArrowUp, ChevronRight, ChevronsUpDown } from 'lucide-react'
import { cn } from '@/ui/lib'

export interface ColumnDef<T> {
  key: string
  header: ReactNode
  cell: (row: T) => ReactNode
  /** Makes the header a sort button (the screen owns sort state via useTable). */
  sortable?: boolean
  align?: 'start' | 'end'
  /** 'lg' hides below 1024px, 'md' below 768px, 'sm' below 520px */
  hide?: 'lg' | 'md' | 'sm'
  tight?: boolean
  width?: string
}

export interface TableSort {
  toggleSort: (key: string) => void
  ariaSort: (key: string) => 'ascending' | 'descending' | 'none'
}

interface DataTableProps<T> {
  caption: string
  columns: ColumnDef<T>[]
  rows: T[]
  rowKey: (row: T) => string
  sort?: TableSort
  /** Whole-row navigation. Keyboard users reach it through a link/button rendered in a cell. */
  onRowClick?: (row: T) => void
  /** Inline row expansion (detail lives inside the list, not in a modal). */
  renderExpanded?: (row: T) => ReactNode
  expanded?: Set<string>
  onToggle?: (key: string) => void
  expandLabel?: (row: T) => string
  empty?: ReactNode
  rowProps?: (row: T) => Record<string, string | undefined>
  /** Always-visible detail under a row (e.g. remaining setup steps). Return null for none. */
  renderAfter?: (row: T) => ReactNode | null
  /** Render this many rows, then offer "Show more" (long lists stay scannable). */
  pageSize?: number
  /** Noun for the "Show more" footer, e.g. "certificates". */
  noun?: string
}

const hideClass = { lg: 'c-hide-lg', md: 'c-hide-md', sm: 'c-hide-sm' } as const

/** Ignore row clicks that started on an interactive control inside the row. */
const fromControl = (e: MouseEvent) => Boolean((e.target as HTMLElement).closest('button, a, input, [role="switch"], [role="combobox"], [data-row-stop]'))

/** Borderless 56px list rows, hairlines only, no vertical rules. */
export function DataTable<T>({ caption, columns, rows, rowKey, sort, onRowClick, renderExpanded, expanded, onToggle, expandLabel, empty, rowProps, renderAfter, pageSize, noun = 'rows' }: DataTableProps<T>) {
  const baseId = useId()
  const [limit, setLimit] = useState(pageSize ?? Infinity)
  const visible = rows.length > limit ? rows.slice(0, limit) : rows
  const expandable = Boolean(renderExpanded && onToggle)
  const colCount = columns.length + (expandable ? 1 : 0)
  return (
    <div className="c-table-wrap">
      <table className="c-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                scope="col"
                data-align={c.align}
                aria-sort={c.sortable && sort ? sort.ariaSort(c.key) : undefined}
                className={cn(c.hide && hideClass[c.hide])}
                style={c.width ? { width: c.width } : undefined}
              >
                {c.sortable && sort ? (
                  <button type="button" className="c-sort" onClick={() => sort.toggleSort(c.key)}>
                    {c.header}
                    <SortIcon state={sort.ariaSort(c.key)} />
                  </button>
                ) : (
                  c.header
                )}
              </th>
            ))}
            {expandable ? (
              <th scope="col" style={{ width: 48 }}>
                <span className="sr-only">Details</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && empty ? (
            <tr>
              <td colSpan={colCount} style={{ height: 'auto', borderBottom: 0 }}>
                {empty}
              </td>
            </tr>
          ) : null}
          {visible.map((row) => {
            const key = rowKey(row)
            const isOpen = expanded?.has(key) ?? false
            const detailId = `${baseId}-${key.replace(/[^a-zA-Z0-9_-]/g, '')}`
            const clickable = Boolean(onRowClick || expandable)
            const after = renderAfter?.(row) ?? null
            return (
              <Fragment key={key}>
                <tr
                  className={cn('c-tr', clickable && 'is-clickable')}
                  data-expanded={isOpen || after ? 'true' : undefined}
                  onClick={(e) => {
                    if (fromControl(e)) return
                    if (onRowClick) onRowClick(row)
                    else if (expandable) onToggle!(key)
                  }}
                  {...rowProps?.(row)}
                >
                  {columns.map((c) => (
                    <td key={c.key} data-align={c.align} className={cn(c.hide && hideClass[c.hide], c.tight && 'is-tight')}>
                      {c.cell(row)}
                    </td>
                  ))}
                  {expandable ? (
                    <td className="is-tight" data-align="end">
                      <button
                        type="button"
                        className="c-iconbtn"
                        aria-expanded={isOpen}
                        aria-controls={isOpen ? detailId : undefined}
                        aria-label={`${isOpen ? 'Hide' : 'Show'} details${expandLabel ? ` for ${expandLabel(row)}` : ''}`}
                        onClick={() => onToggle!(key)}
                      >
                        <ChevronRight size={17} className="c-expander" aria-hidden="true" />
                      </button>
                    </td>
                  ) : null}
                </tr>
                {expandable && isOpen ? (
                  <tr className="c-tr-detail">
                    <td colSpan={colCount} id={detailId}>
                      <div className="c-expand">{renderExpanded!(row)}</div>
                    </td>
                  </tr>
                ) : null}
                {after ? (
                  <tr className="c-tr-detail">
                    <td colSpan={colCount}>
                      <div className="c-expand">{after}</div>
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            )
          })}
        </tbody>
      </table>
      {rows.length > visible.length && pageSize ? (
        <div className="c-table-more" style={{ paddingLeft: 12 }}>
          <span>
            Showing {visible.length} of {rows.length} {noun}
          </span>
          <button type="button" className="c-btn is-secondary is-sm" onClick={() => setLimit((l) => l + pageSize)}>
            Show {Math.min(pageSize, rows.length - visible.length)} more
          </button>
          <button type="button" className="c-btn is-ghost is-sm" onClick={() => setLimit(Infinity)}>
            Show all
          </button>
        </div>
      ) : null}
    </div>
  )
}

function SortIcon({ state }: { state: 'ascending' | 'descending' | 'none' }) {
  if (state === 'ascending') return <ArrowUp size={13} aria-hidden="true" />
  if (state === 'descending') return <ArrowDown size={13} aria-hidden="true" />
  return <ChevronsUpDown size={13} aria-hidden="true" />
}

/** Two-line cell: primary text and a quieter second line. */
export function Cell({ primary, secondary }: { primary: ReactNode; secondary?: ReactNode }) {
  return (
    <span style={{ display: 'block', minWidth: 0 }}>
      <span className="c-cell-primary">{primary}</span>
      {secondary ? <span className="c-cell-secondary">{secondary}</span> : null}
    </span>
  )
}

/** Small helper for Set-based expansion state. */
export function toggleInSet(set: Set<string>, key: string, single = false): Set<string> {
  const next = new Set(single ? [] : set)
  if (set.has(key)) next.delete(key)
  else next.add(key)
  return next
}
