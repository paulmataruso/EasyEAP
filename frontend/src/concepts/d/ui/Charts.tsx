import { useEffect, useRef, useState, type KeyboardEvent } from 'react'
import { hourlyGeometry, barScale, type HourPoint } from '@/ui/charts'
import { cn } from '@/ui/lib'
import { utcClock } from '../model/derive'

function useWidth<T extends HTMLElement>(initial: number) {
  const ref = useRef<T>(null)
  const [w, setW] = useState(initial)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setW(Math.max(200, Math.round(e.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, w] as const
}

/** Column with a 4px rounded data end and a square baseline. */
function columnPath(x: number, y: number, w: number, h: number, r: number) {
  if (h <= 0) return ''
  const rr = Math.min(r, h, w / 2)
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`
}

/**
 * Hourly authentication volume, accepted (de-emphasised steel) stacked under rejected (critical red).
 * One y-axis, hairline grid, crosshair-free per-column hover and arrow-key focus, plus a table twin.
 */
export function HourlyChart({ points, height = 196 }: { points: HourPoint[]; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>(640)
  const [active, setActive] = useState<number | null>(null)
  const [showTable, setShowTable] = useState(false)
  const g = hourlyGeometry(points, width, height, { top: 12, right: 4, bottom: 24, left: 30 })
  const bw = Math.min(24, g.band.bandwidth())
  const gap = 2
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault()
      setActive((a) => Math.max(0, Math.min(points.length - 1, (a ?? points.length - 1) + (e.key === 'ArrowRight' ? 1 : -1))))
    } else if (e.key === 'Escape') setActive(null)
  }
  const total = points.reduce((s, p) => s + p.accept + p.reject, 0)
  const a = active !== null ? points[active] : null
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 pb-2">
        <div className="flex items-center gap-4" aria-hidden="true">
          <span className="d-key"><i className="bg-steel" />Accepted</span>
          <span className="d-key"><i className="bg-crit" />Rejected</span>
        </div>
        <button type="button" className="d-btn d-btn--ghost d-btn--sm" onClick={() => setShowTable((s) => !s)} aria-expanded={showTable}>
          {showTable ? 'Hide table' : 'Show as table'}
        </button>
      </div>
      <div ref={ref} className="d-chart">
        <svg
          width={width}
          height={height}
          role="img"
          tabIndex={0}
          aria-label={`Authentications per hour, last 24 hours: ${total} attempts. Use left and right arrow keys to read each hour.`}
          onKeyDown={onKey}
          onBlur={() => setActive(null)}
          onPointerLeave={() => setActive(null)}
          className="block overflow-visible"
        >
          {g.yTicks.map((t) => (
            <g key={t}>
              <line x1={g.pad.left} x2={width - g.pad.right} y1={g.y(t)} y2={g.y(t)} stroke="#222b36" strokeWidth={1} />
              <text x={g.pad.left - 8} y={g.y(t)} dy="0.32em" textAnchor="end">{t}</text>
            </g>
          ))}
          {points.map((p, i) => {
            const x = (g.band(i) ?? 0) + (g.band.bandwidth() - bw) / 2
            const base = g.y(0)
            const ha = base - g.y(p.accept)
            const hr = base - g.y(p.reject)
            const topAccept = base - ha
            const rejectBottom = topAccept - (ha > 0 && hr > 0 ? gap : 0)
            const dim = active !== null && active !== i
            return (
              <g key={i} opacity={dim ? 0.45 : 1}>
                <path d={columnPath(x, topAccept, bw, ha, hr > 0 ? 0 : 4)} fill="#5c7890" />
                {hr > 0 && <path d={columnPath(x, rejectBottom - hr, bw, hr, 4)} fill="#f75d59" />}
                <rect x={g.band(i)! - 1} y={g.pad.top} width={g.band.step()} height={base - g.pad.top} fill="transparent" onPointerEnter={() => setActive(i)} />
              </g>
            )
          })}
          <line x1={g.pad.left} x2={width - g.pad.right} y1={g.y(0)} y2={g.y(0)} stroke="#33404f" strokeWidth={1} />
          {points.map((p, i) =>
            i % 6 === 5 || i === points.length - 1 ? (
              <text key={i} x={(g.band(i) ?? 0) + g.band.bandwidth() / 2} y={height - 6} textAnchor="middle">
                {i === points.length - 1 ? 'Now' : utcClock(p.hourEnd.toISOString())}
              </text>
            ) : null,
          )}
        </svg>
        {a && active !== null && (
          <div className="d-chart-tip" style={{ left: Math.min(width - 70, Math.max(70, (g.band(active) ?? 0) + g.band.bandwidth() / 2)), top: g.y(a.accept + a.reject) }} role="status">
            <div className="ink-2 mb-1">{utcClock(new Date(a.hourEnd.getTime() - 3600_000).toISOString())}–{utcClock(a.hourEnd.toISOString())} UTC</div>
            <div className="flex items-center gap-2"><i className="inline-block h-0.5 w-3 rounded-sm bg-steel" /><span className="v">{a.accept}</span><span className="ink-2">accepted</span></div>
            <div className="flex items-center gap-2"><i className="inline-block h-0.5 w-3 rounded-sm bg-crit" /><span className="v">{a.reject}</span><span className="ink-2">rejected</span></div>
          </div>
        )}
      </div>
      {showTable && (
        <div className="mt-3 max-h-64 overflow-y-auto">
          <table className="d-table">
            <caption className="sr-only">Authentications per hour</caption>
            <thead><tr className="d-th-cols"><th scope="col">Hour ending (UTC)</th><th scope="col" data-align="right">Accepted</th><th scope="col" data-align="right">Rejected</th></tr></thead>
            <tbody>
              {points.map((p, i) => (
                <tr key={i}><td className="tnum">{utcClock(p.hourEnd.toISOString())}</td><td data-align="right" className="tnum">{p.accept}</td><td data-align="right" className="tnum">{p.reject}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/** Ranked horizontal bars, one series (single colour, no legend), value at the tip. */
export function RankedBars({ items, onSelect }: { items: Array<{ key: string; label: string; value: number; hint?: string }>; onSelect?: (key: string) => void }) {
  const [ref, width] = useWidth<HTMLDivElement>(320)
  const max = Math.max(1, ...items.map((i) => i.value))
  const s = barScale(max, Math.max(60, width - 44))
  return (
    <div ref={ref}>
      <ul className="grid gap-2.5">
        {items.map((it) => (
          <li key={it.key}>
            <div className="mb-1 flex items-baseline justify-between gap-3 text-[13px]">
              {onSelect ? <button type="button" className="d-rowlink truncate font-normal" onClick={() => onSelect(it.key)} title={it.hint}>{it.label}</button> : <span className="truncate">{it.label}</span>}
            </div>
            <div className="flex items-center gap-2" title={`${it.label}: ${it.value}`}>
              <span className="block h-2 rounded-r-[4px] bg-steel" style={{ width: Math.max(3, s(it.value)) }} />
              <span className="tnum text-[12.5px] text-[var(--d-ink)]">{it.value}</span>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Thin segmented bar — one whole split into categorical parts (VLAN field colours, fixed order). */
export function SegmentBar({ parts, label, className }: { parts: Array<{ key: string; label: string; value: number; colorClass: string }>; label: string; className?: string }) {
  const total = parts.reduce((s, p) => s + p.value, 0)
  const [hover, setHover] = useState<string | null>(null)
  const h = parts.find((p) => p.key === hover)
  if (!total) return null
  return (
    <div className={cn('relative', className)}>
      <div className="d-segbar" role="img" aria-label={`${label}: ${parts.filter((p) => p.value).map((p) => `${p.label} ${p.value}`).join(', ')}`}>
        {parts.filter((p) => p.value > 0).map((p) => (
          <span
            key={p.key}
            className={p.colorClass}
            style={{ flexGrow: p.value, flexBasis: 0 }}
            onPointerEnter={() => setHover(p.key)}
            onPointerLeave={() => setHover(null)}
          />
        ))}
      </div>
      {h && (
        <div className="d-chart-tip" style={{ left: '50%', top: -2 }} role="status">
          <span className="v">{h.value}</span> <span className="ink-2">{h.label} · {Math.round((h.value / total) * 100)}%</span>
        </div>
      )}
    </div>
  )
}
