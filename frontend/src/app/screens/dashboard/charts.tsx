// Dashboard charts. Forms (dataviz procedure): hourly accept/reject = stacked columns over time (2 series, legend +
// tooltip + table view); failure reasons and VLAN usage = ranked horizontal bars. Failure reasons are nominal, so one hue
// with identity carried by the label. VLANs have a stored identity colour shown everywhere in EasyEAP, so each bar wears
// its VLAN's colour (colour follows the entity, never its rank) and the label still names it. Series colours --ee-series-accept / --ee-series-reject
// were validated against the panel surface #141b30 (dark): lightness, chroma, CVD ΔE 10.7, normal ΔE 31.9, contrast ≥ 3:1.
import { useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { BarChart3, Table2 } from 'lucide-react'
import { hourlyGeometry } from '@/ui/charts'
import { cn } from '@/ui/lib'
import { fmtDate, fmtPercent, fmtTime, plural, timeZoneName } from '../../lib/format'
import { Seg, Tip } from '../../ui'
import type { HourBucket } from '../../api/dashboard'

export type ChartView = 'chart' | 'table'

export function ViewToggle({ value, onChange, what }: { value: ChartView; onChange: (v: ChartView) => void; what: string }) {
  return (
    <Seg
      label={`Show ${what} as`}
      value={value}
      onChange={onChange}
      options={[
        { value: 'chart', label: <><BarChart3 className="size-3.5" aria-hidden />Chart</> },
        { value: 'table', label: <><Table2 className="size-3.5" aria-hidden />Table</> },
      ]}
    />
  )
}

function useWidth<T extends HTMLElement>(fallback: number) {
  const ref = useRef<T>(null)
  const [w, setW] = useState(fallback)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setW(Math.max(260, Math.round(el.getBoundingClientRect().width)))
    const ro = new ResizeObserver(([e]) => setW(Math.max(260, Math.round(e.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, w] as const
}

/** Rect with only the data-end (top) corners rounded; square at the baseline. */
function topRounded(x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.max(0, Math.min(r, h, w / 2))
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`
}

const hourEnd = (b: HourBucket) => new Date(new Date(b.hour).getTime() + 3_600_000)
const hourRange = (b: HourBucket) => `${fmtDate(b.hour)}, ${fmtTime(b.hour)}–${fmtTime(hourEnd(b).toISOString())}`

function SeriesKey({ color, label, value }: { color: string; label: string; value: number }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className="inline-block size-2.5 rounded-[2px]" style={{ background: color }} aria-hidden />
      <span className="ee-ink-2">{label}</span>
      <span className="ee-num font-semibold">{value.toLocaleString('en-GB')}</span>
    </span>
  )
}

/** Authentications per hour, accepted and rejected stacked, last 24 hours (local time). */
export function HourlyChart({ hourly, view, height = 200 }: { hourly: HourBucket[]; view: ChartView; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>(640)
  const [active, setActive] = useState<number | null>(null)
  const totalAccept = hourly.reduce((s, p) => s + p.accept, 0)
  const totalReject = hourly.reduce((s, p) => s + p.reject, 0)
  const n = hourly.length

  const legend = (
    <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[12.5px]">
      <SeriesKey color="var(--ee-series-accept)" label="Accepted" value={totalAccept} />
      <SeriesKey color="var(--ee-series-reject)" label="Rejected" value={totalReject} />
      <span className="ee-ink-3">Hourly, {timeZoneName}</span>
    </div>
  )

  if (view === 'table') {
    return (
      <div>
        {legend}
        <div className="max-h-[320px] overflow-auto rounded-[8px] border border-[var(--ee-line)]">
          <table className="ee-table">
            <caption className="sr-only">Authentications per hour, last 24 hours</caption>
            <thead className="sticky top-0 bg-[var(--ee-panel-solid)]"><tr><th className="pt-2.5">Hour</th><th className="pt-2.5 text-right">Accepted</th><th className="pt-2.5 text-right">Rejected</th><th className="pt-2.5 text-right">Success</th></tr></thead>
            <tbody>
              {[...hourly].reverse().map((b) => {
                const t = b.accept + b.reject
                return (
                  <tr key={b.hour}>
                    <td className="ee-num whitespace-nowrap">{hourRange(b)}</td>
                    <td className="ee-num text-right">{b.accept}</td>
                    <td className="ee-num text-right">{b.reject}</td>
                    <td className="ee-num text-right ee-ink-2">{t ? fmtPercent(b.accept / t, 0) : '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  const pts = hourly.map((b) => ({ hourEnd: hourEnd(b), accept: b.accept, reject: b.reject }))
  const g = hourlyGeometry(pts, width, height, { top: 12, right: 4, bottom: 26, left: 30 })
  const bw = Math.min(20, g.band.bandwidth())
  const base = g.y(0)
  const ticks = g.yTicks.filter((t) => Number.isInteger(t))
  const labelEvery = width < 420 ? 8 : 6
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowRight') { e.preventDefault(); setActive((a) => Math.min(n - 1, (a ?? -1) + 1)) }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); setActive((a) => Math.max(0, (a ?? n) - 1)) }
    else if (e.key === 'Home') { e.preventDefault(); setActive(0) }
    else if (e.key === 'End') { e.preventDefault(); setActive(n - 1) }
    else if (e.key === 'Escape') setActive(null)
  }
  const p = active !== null ? hourly[active] : null
  const tipX = active !== null ? (g.band(active) ?? 0) + g.band.bandwidth() / 2 : 0
  const tipYTop = p ? g.y(p.accept + p.reject) : 0

  return (
    <div>
      {legend}
      <div ref={ref} className="relative" onPointerLeave={() => setActive(null)}>
        <svg
          width={width}
          height={height}
          className="ee-chart block"
          role="img"
          tabIndex={0}
          aria-label={`Authentications per hour over the last 24 hours: ${totalAccept} accepted, ${totalReject} rejected. Use the arrow keys to read each hour, or switch to the table.`}
          onKeyDown={onKey}
          onBlur={() => setActive(null)}
        >
          {ticks.map((t) => (
            <g key={t}>
              <line className="ee-grid" x1={g.pad.left} x2={width - g.pad.right} y1={g.y(t)} y2={g.y(t)} />
              <text x={g.pad.left - 8} y={g.y(t)} dy="0.32em" textAnchor="end">{t}</text>
            </g>
          ))}
          {hourly.map((b, i) => {
            const x = (g.band(i) ?? 0) + (g.band.bandwidth() - bw) / 2
            const yA = g.y(b.accept)
            const yT = g.y(b.accept + b.reject)
            const hA = base - yA
            const gap = b.accept > 0 && b.reject > 0 ? 2 : 0
            const hR = Math.max(1.5, yA - yT - gap)
            const dim = active !== null && active !== i ? 0.4 : 1
            return (
              <g key={b.hour} opacity={dim}>
                {b.accept > 0 && (b.reject > 0
                  ? <rect x={x} y={yA} width={bw} height={hA} fill="var(--ee-series-accept)" />
                  : <path d={topRounded(x, yA, bw, hA, 4)} fill="var(--ee-series-accept)" />)}
                {b.reject > 0 && <path d={topRounded(x, yA - gap - hR, bw, hR, 4)} fill="var(--ee-series-reject)" />}
              </g>
            )
          })}
          <line x1={g.pad.left} x2={width - g.pad.right} y1={base} y2={base} stroke="rgba(237,234,227,0.22)" />
          {hourly.map((b, i) => {
            const last = i === n - 1
            if (!last && (i % labelEvery !== 0 || n - 1 - i < labelEvery / 2)) return null
            return (
              <text key={`t${b.hour}`} x={(g.band(i) ?? 0) + g.band.bandwidth() / 2} y={height - 8} textAnchor={last ? 'end' : 'middle'}>
                {last ? 'This hour' : fmtTime(b.hour)}
              </text>
            )
          })}
          {active !== null && (
            <rect x={(g.band(active) ?? 0) - 1} y={g.pad.top} width={g.band.bandwidth() + 2} height={base - g.pad.top} fill="rgba(237,234,227,0.05)" rx={3} pointerEvents="none" />
          )}
          {hourly.map((b, i) => (
            <rect
              key={`hit${b.hour}`}
              x={(g.band(i) ?? 0) - (g.band.step() - g.band.bandwidth()) / 2}
              y={g.pad.top}
              width={g.band.step()}
              height={base - g.pad.top + 20}
              fill="transparent"
              onPointerEnter={() => setActive(i)}
              onPointerMove={() => setActive(i)}
            />
          ))}
        </svg>
        {p && (
          <div className="ee-chart-tip" style={{ left: Math.min(Math.max(tipX, 96), width - 96), top: Math.max(0, tipYTop - 8), transform: 'translate(-50%, -100%)' }} role="status">
            <p className="ee-ink-3 text-[12px]">{hourRange(p)}{active === n - 1 && ' (so far)'}</p>
            <p className="mt-1 flex items-center gap-2"><span className="inline-block h-[2px] w-3" style={{ background: 'var(--ee-series-accept)' }} aria-hidden /><span className="ee-num font-semibold">{p.accept}</span><span className="ee-ink-2">accepted</span></p>
            <p className="flex items-center gap-2"><span className="inline-block h-[2px] w-3" style={{ background: 'var(--ee-series-reject)' }} aria-hidden /><span className="ee-num font-semibold">{p.reject}</span><span className="ee-ink-2">rejected</span></p>
            {p.accept + p.reject > 0 && <p className="ee-ink-3 mt-1 text-[12px]">{fmtPercent(p.accept / (p.accept + p.reject), 0)} success</p>}
          </div>
        )}
      </div>
    </div>
  )
}

export interface RankedItem { key: string; label: ReactNode; text: string; value: number; to?: string; hint?: string; /** Entity colour (VLANs); else the chart's hue. */ color?: string }

/** Ranked horizontal bars: one hue unless an item carries its entity's colour. Value at the bar tip; tooltip adds the share; table view lists the same rows. */
export function RankedBars({ items, color, unit, view, caption, nameHeader }: {
  items: RankedItem[]
  color: string
  unit: [string, string]
  view: ChartView
  caption: string
  nameHeader: string
}) {
  const total = items.reduce((s, i) => s + i.value, 0)
  const max = Math.max(1, ...items.map((i) => i.value))
  if (view === 'table') {
    return (
      <div className="overflow-x-auto">
        <table className="ee-table">
          <caption className="sr-only">{caption}</caption>
          <thead><tr><th>{nameHeader}</th><th className="text-right">{unit[1][0].toUpperCase() + unit[1].slice(1)}</th><th className="text-right">Share</th></tr></thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.key}>
                <td className="min-w-0">{i.to ? <Link to={i.to} className="underline-offset-2 hover:underline">{i.label}</Link> : i.label}</td>
                <td className="ee-num text-right">{i.value}</td>
                <td className="ee-num text-right ee-ink-2">{fmtPercent(i.value / Math.max(1, total), 0)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }
  return (
    <ul className="space-y-1" aria-label={caption}>
      {items.map((i) => {
        const share = fmtPercent(i.value / Math.max(1, total), 0)
        const body = (
          <>
            <span className="min-w-0 truncate text-[13px]">{i.label}</span>
            <span className="ee-num text-[13px] font-semibold">{i.value}</span>
            <span className="col-span-2 block h-[6px] rounded-[1px] bg-[rgba(237,234,227,0.06)]" aria-hidden>
              <span className="block h-full rounded-r-[3px] rounded-l-[1px] transition-[width] duration-300" style={{ width: `${Math.max(2, (i.value / max) * 100)}%`, background: i.color ?? color }} />
            </span>
          </>
        )
        const cls = 'grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 rounded-[7px] px-2 py-2 -mx-2'
        const label = `${i.text}: ${plural(i.value, unit[0], unit[1])}, ${share} of ${plural(total, unit[0], unit[1])}${i.to ? `. ${i.hint ?? 'Open'}` : ''}`
        return (
          <li key={i.key}>
            <Tip content={<span className="block"><span className="ee-num font-semibold">{plural(i.value, unit[0], unit[1])}</span><span className="ee-ink-2"> · {share} of {total}</span>{i.hint && <span className="mt-0.5 block ee-ink-3">{i.hint}</span>}</span>}>
              {i.to
                ? <Link to={i.to} className={cn(cls, 'hover:bg-[var(--ee-hover)]')} aria-label={label}>{body}</Link>
                : <div tabIndex={0} className={cls} aria-label={label}>{body}</div>}
            </Tip>
          </li>
        )
      })}
    </ul>
  )
}
