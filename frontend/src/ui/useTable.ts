import { useMemo, useState } from 'react'

export type SortDir = 'asc' | 'desc'
export interface Column<T> {
  key: string
  /** Value used for sorting & text search */
  value: (row: T) => string | number | null
  searchable?: boolean
}

/** Minimal client-side search + filter + sort for tables (prototypes and small server pages). */
export function useTable<T>(rows: T[], columns: Column<T>[], opts: { initialSort?: { key: string; dir: SortDir }; filter?: (row: T) => boolean } = {}) {
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<{ key: string; dir: SortDir } | null>(opts.initialSort ?? null)
  const { filter } = opts
  const result = useMemo(() => {
    const q = query.trim().toLowerCase()
    let out = filter ? rows.filter(filter) : rows
    if (q) {
      const searchCols = columns.filter((c) => c.searchable !== false)
      out = out.filter((r) => searchCols.some((c) => String(c.value(r) ?? '').toLowerCase().includes(q)))
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key)
      if (col) {
        out = [...out].sort((a, b) => {
          const av = col.value(a), bv = col.value(b)
          if (av === bv) return 0
          if (av === null) return 1
          if (bv === null) return -1
          const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv))
          return sort.dir === 'asc' ? cmp : -cmp
        })
      }
    }
    return out
  }, [rows, columns, query, sort, filter])
  const toggleSort = (key: string) => setSort((s) => (s?.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }))
  const ariaSort = (key: string): 'ascending' | 'descending' | 'none' => (sort?.key === key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none')
  return { rows: result, query, setQuery, sort, toggleSort, ariaSort }
}
