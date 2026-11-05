import { useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react'
import { hourlyGeometry, type HourPoint } from '@/ui/charts'
import { formatTime } from '@/ui/lib'

const HEIGHT = 248
const PAD = { top: 22, right: 2, bottom: 30, left: 36 }
const GAP = 2

/** Path for a column with 4px rounded data-end and a square baseline. */
function columnPath(x: number, y: number, w: number, h: number, rounded: boolean) {
  if (h <= 0) return ''
  const r = rounded ? Math.min(4, h, w / 2) : 0
  return `M${x},${y + h}V${y + r}${r ? `A${r},${r} 0 0 1 ${x + r},${y}` : ''}H${x + w - r}${r ? `A${r},${r} 0 0 1 ${x + w},${y + r}` : ''}V${y + h}Z`
}

const rangeLabel = (p: HourPoint) => `${formatTime(new Date(p.hourEnd.getTime() - 3_600_000).toISOString()).slice(0, 5)}–${formatTime(p.hourEnd.toISOString()).slice(0, 5)} UTC`

/**
 * Authentications per hour, stacked: accepted volume recedes in warm grey, rejections carry the
 * critical colour. Crosshair band + tooltip on hover; arrow keys walk the hours.
 */
export function HourlyChart({ points }: { points: HourPoint[] }) {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(1120)
  const [active, setActive] = useState<number | null>(null)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([entry]) => setWidth(Math.max(280, Math.round(entry.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const g = hourlyGeometry(points, width, HEIGHT, PAD)
  const step = g.band.step()
  const bw = Math.min(24, g.band.bandwidth())
  const base = g.y(0)
  const peak = points.reduce((best, p, i) => (p.reject > points[best].reject ? i : best), 0)
  // Direct label for the worst hour. It sits above every column it spans (not just the peak's),
  // so it never collides with a taller neighbour on narrow charts.
  const peakLabel = (() => {
    const p = points[peak]
    if (!p || p.reject <= 0) return null
    const text = `${p.reject} rejected`
    const half = (text.length * 6.6) / 2 + 2
    const center = (g.band(peak) ?? 0) + g.band.bandwidth() / 2
    const x = Math.min(width - PAD.right - half, Math.max(PAD.left + half, center))
    const tallest = points.reduce((m, q, i) => {
      const qc = (g.band(i) ?? 0) + g.band.bandwidth() / 2
      return Math.abs(qc - x) <= half + bw / 2 ? Math.max(m, q.accept + q.reject) : m
    }, 0)
    const y = g.y(tallest) - GAP - 10
    return y < 12 ? null : { text, x, y }
  })()
  const boundary = (i: number) => (g.band(i) ?? 0) - (g.band.paddingInner() * step) / 2
  const xLabels: Array<{ x: number; text: string; anchor: 'start' | 'middle' | 'end' }> = [
    { x: PAD.left, text: '24h ago', anchor: 'start' },
    { x: boundary(6), text: '18h', anchor: 'middle' },
    { x: boundary(12), text: '12h', anchor: 'middle' },
    { x: boundary(18), text: '6h', anchor: 'middle' },
    { x: width - PAD.right, text: 'Now', anchor: 'end' },
  ]

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault()
      setActive((a) => Math.max(0, Math.min(points.length - 1, (a ?? points.length) + (e.key === 'ArrowRight' ? 1 : -1))))
    } else if (e.key === 'Home') setActive(0)
    else if (e.key === 'End') setActive(points.length - 1)
    else if (e.key === 'Escape') setActive(null)
  }

  const a = active !== null ? points[active] : null
  const ax = active !== null ? (g.band(active) ?? 0) + g.band.bandwidth() / 2 : 0
  const tipLeft = ax > width - 200 ? ax - 186 : ax + 14

  return (
    <div
      ref={ref}
      className="c-chart"
      tabIndex={0}
      role="group"
      aria-label="Authentications per hour over the last 24 hours. Use the left and right arrow keys to read each hour."
      onKeyDown={onKey}
      onFocus={() => setActive((x) => x ?? points.length - 1)}
      onBlur={() => setActive(null)}
      onPointerLeave={() => setActive(null)}
    >
      <svg height={HEIGHT} viewBox={`0 0 ${width} ${HEIGHT}`} aria-hidden="true">
        {g.yTicks.map((t) => (
          <g key={t}>
            <line x1={PAD.left} x2={width - PAD.right} y1={g.y(t)} y2={g.y(t)} stroke={t === 0 ? 'rgba(255,255,255,0.16)' : 'rgba(255,255,255,0.06)'} strokeWidth={1} shapeRendering="crispEdges" />
            <text x={PAD.left - 10} y={g.y(t)} textAnchor="end" dominantBaseline="middle">
              {t}
            </text>
          </g>
        ))}
        {active !== null ? <rect x={(g.band(active) ?? 0) - (step - g.band.bandwidth()) / 2} y={PAD.top - 8} width={step} height={base - PAD.top + 8} fill="rgba(255,255,255,0.045)" rx={6} /> : null}
        {points.map((p, i) => {
          const cx = (g.band(i) ?? 0) + g.band.bandwidth() / 2
          const x = cx - bw / 2
          const hA = base - g.y(p.accept)
          const hR = base - g.y(p.reject)
          const rejectBottom = hA > 0 ? base - hA - GAP : base
          const dim = active !== null && active !== i
          return (
            <g key={i} opacity={dim ? 0.55 : 1} style={{ transition: 'opacity 200ms' }}>
              <path d={columnPath(x, base - hA, bw, hA, hR <= 0)} fill="var(--c-series-accept)" />
              {hR > 0 ? <path d={columnPath(x, rejectBottom - hR, bw, hR, true)} fill="var(--c-series-reject)" /> : null}
            </g>
          )
        })}
        {peakLabel && active === null ? (
          <text x={peakLabel.x} y={peakLabel.y} textAnchor="middle" style={{ fill: 'var(--c-text-2)' }}>
            {peakLabel.text}
          </text>
        ) : null}
        {xLabels.map((l) => (
          <text key={l.text} x={l.x} y={HEIGHT - 8} textAnchor={l.anchor}>
            {l.text}
          </text>
        ))}
        {points.map((_, i) => (
          <rect key={i} x={(g.band(i) ?? 0) - (step - g.band.bandwidth()) / 2} y={0} width={step} height={base} fill="transparent" onPointerEnter={() => setActive(i)} onPointerMove={() => active !== i && setActive(i)} />
        ))}
      </svg>
      {a ? (
        <div className="c-tip c-chart-tip" style={{ left: tipLeft, top: 8 }} aria-hidden="true">
          <div className="c-faint" style={{ marginBottom: 6 }}>
            {rangeLabel(a)}
          </div>
          <div className="c-tip-row">
            <span className="c-line-key" style={{ background: 'var(--c-series-accept)', height: 3 }} />
            <b>{a.accept}</b>
            <span className="c-muted">accepted</span>
          </div>
          <div className="c-tip-row">
            <span className="c-line-key" style={{ background: 'var(--c-series-reject)', height: 3 }} />
            <b>{a.reject}</b>
            <span className="c-muted">rejected</span>
          </div>
        </div>
      ) : null}
      <p className="sr-only" aria-live="polite">
        {a ? `${rangeLabel(a)}: ${a.accept} accepted, ${a.reject} rejected.` : ''}
      </p>
    </div>
  )
}

/** Same data as a table: the chart's accessible twin. */
export function HourlyTable({ points }: { points: HourPoint[] }) {
  return (
    <div className="c-table-wrap" style={{ maxHeight: 320, overflowY: 'auto' }}>
      <table className="c-table">
        <caption className="sr-only">Authentications per hour, last 24 hours</caption>
        <thead>
          <tr>
            <th scope="col">Hour (UTC)</th>
            <th scope="col" data-align="end">Accepted</th>
            <th scope="col" data-align="end">Rejected</th>
            <th scope="col" data-align="end">Success</th>
          </tr>
        </thead>
        <tbody>
          {[...points].reverse().map((p) => {
            const total = p.accept + p.reject
            return (
              <tr key={p.hourEnd.toISOString()}>
                <td style={{ height: 40 }}>{rangeLabel(p)}</td>
                <td style={{ height: 40 }} data-align="end">{p.accept}</td>
                <td style={{ height: 40 }} data-align="end">{p.reject}</td>
                <td style={{ height: 40 }} data-align="end" className="c-muted">{total ? `${Math.round((p.accept / total) * 100)}%` : '—'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
