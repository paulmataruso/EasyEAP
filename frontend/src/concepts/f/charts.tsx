import { useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react'
import { hourlyGeometry, type HourPoint } from '@/ui/charts'
import { formatTime } from '@/ui/lib'
import { failureExplanations } from '@/domain/explain'
import type { FailureCode } from '@/domain/types'
import { Tip } from './ui'

function useWidth<T extends HTMLElement>(fallback: number) {
  const ref = useRef<T>(null)
  const [w, setW] = useState(fallback)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.round(e.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, w] as const
}

/** Rect with only the data-end (top) corners rounded; square at the baseline. */
function topRounded(x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.min(r, h, w / 2)
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`
}

export interface ChartMarker { hoursAgo: number; label: string }

/** Authentications per hour, accepted and rejected stacked, last 24 h. */
export function AuthChart({ hourly, marker, height = 210 }: { hourly: HourPoint[]; marker?: ChartMarker | null; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>(720)
  const [active, setActive] = useState<number | null>(null)
  const g = hourlyGeometry(hourly, width, height, { top: 14, right: 6, bottom: 26, left: 30 })
  const bw = Math.min(20, g.band.bandwidth())
  const base = g.y(0)
  const totalAccept = hourly.reduce((s, p) => s + p.accept, 0)
  const totalReject = hourly.reduce((s, p) => s + p.reject, 0)
  const markerIndex = marker ? Math.max(0, Math.min(23, 23 - Math.floor(marker.hoursAgo))) : null

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowRight') { e.preventDefault(); setActive((a) => Math.min(23, (a ?? -1) + 1)) }
    if (e.key === 'ArrowLeft') { e.preventDefault(); setActive((a) => Math.max(0, (a ?? 24) - 1)) }
    if (e.key === 'Home') setActive(0)
    if (e.key === 'End') setActive(23)
    if (e.key === 'Escape') setActive(null)
  }
  const p = active !== null ? hourly[active] : null
  const tipX = active !== null ? (g.band(active) ?? 0) + g.band.bandwidth() / 2 : 0

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-[12.5px]" aria-hidden>
        <span className="inline-flex items-center gap-2"><span className="inline-block h-2.5 w-2.5 rounded-[2px]" style={{ background: 'var(--f-series-accept)' }} />Accepted <span className="f-num f-ink-2">{totalAccept}</span></span>
        <span className="inline-flex items-center gap-2"><span className="inline-block h-2.5 w-2.5 rounded-[2px]" style={{ background: 'var(--f-series-reject)' }} />Rejected <span className="f-num f-ink-2">{totalReject}</span></span>
      </div>
      <div ref={ref} className="relative" onPointerLeave={() => setActive(null)}>
        <svg
          width={width}
          height={height}
          className="f-chart block"
          role="img"
          tabIndex={0}
          aria-label={`Authentications per hour over the last 24 hours: ${totalAccept} accepted, ${totalReject} rejected. Use the arrow keys to read each hour.`}
          onKeyDown={onKey}
          onBlur={() => setActive(null)}
        >
          {g.yTicks.map((t) => (
            <g key={t}>
              <line className="f-grid" x1={g.pad.left} x2={width - g.pad.right} y1={g.y(t)} y2={g.y(t)} />
              <text x={g.pad.left - 8} y={g.y(t)} dy="0.32em" textAnchor="end">{t}</text>
            </g>
          ))}
          {markerIndex !== null && marker && (
            <g>
              <line x1={(g.band(markerIndex) ?? 0) - 1} x2={(g.band(markerIndex) ?? 0) - 1} y1={g.pad.top - 6} y2={base} stroke="var(--f-warn)" strokeWidth={1} opacity={0.8} />
              <text x={(g.band(markerIndex) ?? 0) - 6} y={g.pad.top} textAnchor="end" style={{ fill: 'var(--f-ink-2)' }}>{marker.label}</text>
            </g>
          )}
          {hourly.map((pt, i) => {
            const x = (g.band(i) ?? 0) + (g.band.bandwidth() - bw) / 2
            const yA = g.y(pt.accept)
            const yT = g.y(pt.accept + pt.reject)
            const hA = base - yA
            const gap = pt.accept > 0 && pt.reject > 0 ? 2 : 0
            const hR = Math.max(0, yA - yT - gap)
            const dim = active !== null && active !== i ? 0.45 : 1
            return (
              <g key={i} opacity={dim}>
                {pt.accept > 0 && (pt.reject > 0 ? <rect x={x} y={yA} width={bw} height={hA} fill="var(--f-series-accept)" /> : <path d={topRounded(x, yA, bw, hA, 4)} fill="var(--f-series-accept)" />)}
                {pt.reject > 0 && <path d={topRounded(x, yT, bw, Math.max(hR, 1.5), 4)} fill="var(--f-series-reject)" />}
              </g>
            )
          })}
          <line x1={g.pad.left} x2={width - g.pad.right} y1={base} y2={base} stroke="rgba(237,234,227,0.22)" />
          {[0, 6, 12, 18, 23].map((i) => (
            <text key={i} x={(g.band(i) ?? 0) + g.band.bandwidth() / 2} y={height - 8} textAnchor={i === 23 ? 'end' : 'middle'}>
              {i === 23 ? 'now' : `−${24 - i} h`}
            </text>
          ))}
          {hourly.map((_, i) => (
            <rect key={`hit${i}`} x={g.band(i)! - (g.band.step() - g.band.bandwidth()) / 2} y={g.pad.top} width={g.band.step()} height={base - g.pad.top} fill="transparent" onPointerEnter={() => setActive(i)} onPointerMove={() => setActive(i)} />
          ))}
        </svg>
        {p && (
          <div className="f-chart-tip" style={{ left: Math.min(Math.max(tipX, 90), width - 90), top: 0, transform: 'translate(-50%, -100%)' }} role="status">
            <p className="f-ink-3 text-[11.5px]">{formatTime(new Date(p.hourEnd.getTime() - 3600_000).toISOString()).slice(0, 5)}–{formatTime(p.hourEnd.toISOString()).slice(0, 5)} UTC</p>
            <p className="mt-1 flex items-center gap-2"><span className="inline-block h-[2px] w-3" style={{ background: 'var(--f-series-accept)' }} /><span className="f-num font-semibold">{p.accept}</span><span className="f-ink-2">accepted</span></p>
            <p className="flex items-center gap-2"><span className="inline-block h-[2px] w-3" style={{ background: 'var(--f-series-reject)' }} /><span className="f-num font-semibold">{p.reject}</span><span className="f-ink-2">rejected</span></p>
            {p.accept + p.reject > 0 && <p className="f-ink-3 mt-1 text-[11.5px]">{Math.round((p.accept / (p.accept + p.reject)) * 100)}% success</p>}
          </div>
        )}
      </div>
      <table className="sr-only">
        <caption>Authentications per hour, last 24 hours</caption>
        <thead><tr><th>Hour ending (UTC)</th><th>Accepted</th><th>Rejected</th></tr></thead>
        <tbody>{hourly.map((pt, i) => <tr key={i}><td>{formatTime(pt.hourEnd.toISOString()).slice(0, 5)}</td><td>{pt.accept}</td><td>{pt.reject}</td></tr>)}</tbody>
      </table>
    </div>
  )
}

/** Rejections by plain-language cause. One series, value at the bar tip. */
export function FailureBars({ failures, total }: { failures: Array<[string, number]>; total: number }) {
  const max = Math.max(1, ...failures.map(([, n]) => n))
  return (
    <ul className="space-y-2.5">
      {failures.map(([code, n]) => {
        const f = failureExplanations[code as FailureCode]
        return (
          <li key={code}>
            <Tip
              content={
                <span className="block max-w-[280px]">
                  <span className="block font-semibold">{n} of {total} rejections · {Math.round((n / Math.max(1, total)) * 100)}%</span>
                  <span className="f-ink-2 mt-1 block">{f.fix}</span>
                </span>
              }
            >
              <div tabIndex={0} className="grid cursor-default grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 rounded-[6px] outline-offset-4">
                <span className="truncate text-[13px]">{f.title}</span>
                <span className="f-num text-[13px] font-semibold">{n}</span>
                <span className="col-span-2 block h-[6px] rounded-[3px] bg-[rgba(237,234,227,0.06)]">
                  <span className="block h-full rounded-[3px]" style={{ width: `${(n / max) * 100}%`, background: 'var(--f-series-reject)', opacity: 0.85 }} />
                </span>
              </div>
            </Tip>
          </li>
        )
      })}
    </ul>
  )
}

/** Thin segmented bar: one whole split into parts (8px, rounded ends, no text). */
export function SegBar({ parts, label }: { parts: Array<{ value: number; color: string; name: string }>; label: string }) {
  const total = parts.reduce((s, p) => s + p.value, 0)
  return (
    <div className="flex h-2 w-full gap-[2px]" role="img" aria-label={`${label}: ${parts.map((p) => `${p.value} ${p.name}`).join(', ')}`}>
      {parts.filter((p) => p.value > 0).map((p) => (
        <span key={p.name} className="h-full first:rounded-l-full last:rounded-r-full" style={{ width: `${(p.value / Math.max(1, total)) * 100}%`, background: p.color }} title={`${p.value} ${p.name}`} />
      ))}
      {total === 0 && <span className="h-full w-full rounded-full bg-[rgba(237,234,227,0.08)]" />}
    </div>
  )
}
