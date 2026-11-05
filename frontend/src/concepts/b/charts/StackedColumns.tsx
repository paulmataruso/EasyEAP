import { useRef, useState, type KeyboardEvent } from 'react'
import { createPortal } from 'react-dom'
import { scaleBand } from 'd3-scale'
import { barScale, hourlyGeometry, type HourPoint } from '@/ui/charts'
import { formatPercent } from '@/ui/lib'
import { useElementWidth } from '../lib/hooks'
import { hhmm } from '../lib/format'
import { usePortal } from '../ui/portal'

const GAP = 2
const RADIUS = 4

/** Rect with rounded top corners only (data-end rounded, baseline square). */
function topRounded(x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.max(0, Math.min(r, h, w / 2))
  return `M${x},${y + h}V${y + rr}A${rr},${rr} 0 0 1 ${x + rr},${y}H${x + w - rr}A${rr},${rr} 0 0 1 ${x + w},${y + rr}V${y + h}Z`
}

export interface Marker {
  at: Date
  label: string
}

/**
 * Hourly accept/reject columns, stacked (accepted at the baseline, rejected on top), 2px surface gap.
 * Crosshair + tooltip on hover; arrow keys move it when the chart has focus.
 * Pass `yMax` to share one scale across small multiples.
 */
export function StackedColumns({ points, height = 170, yMax, compact = false, label, marker }: { points: HourPoint[]; height?: number; yMax?: number; compact?: boolean; label: string; marker?: Marker }) {
  const ref = useRef<HTMLDivElement>(null)
  const measured = useElementWidth(ref, 520)
  const [hover, setHoverState] = useState<number | null>(null)
  const [box, setBox] = useState<DOMRect | null>(null)
  const portal = usePortal()
  const setHover = (next: number | null | ((h: number | null) => number | null)) => {
    setBox(ref.current?.getBoundingClientRect() ?? null)
    setHoverState(next)
  }
  const pad = compact ? { top: 6, right: 2, bottom: 16, left: 2 } : { top: 10, right: 4, bottom: 22, left: 30 }
  // A collapsed container (0px while hidden) must not produce an inverted range.
  const width = Math.max(measured, pad.left + pad.right + points.length * 3)
  const plotBottom = height - pad.bottom

  let y: (v: number) => number
  let ticks: number[]
  let band: (i: number) => number
  let bandwidth: number
  if (yMax === undefined) {
    const g = hourlyGeometry(points, width, height, pad)
    y = (v) => g.y(v)
    ticks = g.yTicks
    band = (i) => g.band(i) ?? 0
    bandwidth = g.band.bandwidth()
  } else {
    const s = barScale(yMax, plotBottom - pad.top)
    y = (v) => plotBottom - s(v)
    ticks = [0, yMax]
    const b = scaleBand<number>().domain(points.map((_, i) => i)).range([pad.left, width - pad.right]).padding(0.22)
    band = (i) => b(i) ?? 0
    bandwidth = b.bandwidth()
  }
  const bw = Math.max(1, Math.min(24, bandwidth))
  const slot = (i: number) => band(i) + (bandwidth - bw) / 2
  const step = points.length > 1 ? band(1) - band(0) : bandwidth

  const markerX = (() => {
    if (!marker || points.length < 2) return null
    const t = marker.at.getTime()
    const firstEnd = points[0].hourEnd.getTime()
    const idx = (t - (firstEnd - 3600_000)) / 3600_000 // fractional bucket position
    if (idx < 0 || idx > points.length) return null
    return band(0) + idx * step - (step - bandwidth) / 2
  })()

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowRight') setHover((h) => Math.min(points.length - 1, (h ?? points.length - 2) + 1))
    else if (e.key === 'ArrowLeft') setHover((h) => Math.max(0, (h ?? points.length) - 1))
    else if (e.key === 'Home') setHover(0)
    else if (e.key === 'End') setHover(points.length - 1)
    else if (e.key === 'Escape') setHover(null)
    else return
    e.preventDefault()
  }

  const p = hover !== null ? points[hover] : null
  const start = p ? new Date(p.hourEnd.getTime() - 3600_000).toISOString() : ''
  const tipX = hover !== null ? slot(hover) + bw / 2 : 0
  const tipLeft = box ? (tipX + 14 + 170 < width ? box.left + tipX + 14 : box.left + tipX - 14 - 170) : 0
  const tipTop = box ? box.top + pad.top : 0
  const xLabels = compact ? [0, points.length - 1] : [0, 6, 12, 18, points.length - 1]

  return (
    <div
      ref={ref}
      className="b-chart select-none"
      role="group"
      aria-label={`${label}. Use arrow keys to read each hour.`}
      tabIndex={0}
      onKeyDown={onKey}
      onBlur={() => setHover(null)}
      onPointerLeave={() => setHover(null)}
    >
      <svg width={width} height={height} aria-hidden className="block overflow-visible">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} stroke={t === 0 ? '#2b3949' : '#1a2430'} strokeWidth={1} shapeRendering="crispEdges" />
            {!compact && (
              <text x={pad.left - 6} y={y(t)} dy="0.32em" textAnchor="end">
                {t}
              </text>
            )}
          </g>
        ))}
        {compact && yMax !== undefined && (
          <text x={width - pad.right} y={pad.top - 1} textAnchor="end" style={{ fontSize: 10.5 }}>
            {yMax}/h
          </text>
        )}
        {hover !== null && <line x1={slot(hover) + bw / 2} x2={slot(hover) + bw / 2} y1={pad.top} y2={plotBottom} stroke="#3a4a5c" strokeWidth={1} />}
        {points.map((pt, i) => {
          const x = slot(i)
          const base = y(0)
          const aTop = y(pt.accept)
          const rTop = y(pt.accept + pt.reject)
          const aH = base - aTop
          const rH = aTop - rTop - (pt.accept > 0 && pt.reject > 0 ? GAP : 0)
          const dim = hover !== null && hover !== i ? 0.55 : 1
          return (
            <g key={i} opacity={dim}>
              {pt.accept > 0 && <path d={pt.reject > 0 ? `M${x},${aTop}h${bw}v${aH}h${-bw}Z` : topRounded(x, aTop, bw, aH, RADIUS)} fill="var(--b-accept)" />}
              {pt.reject > 0 && rH > 0 && <path d={topRounded(x, rTop, bw, rH, RADIUS)} fill="var(--b-reject)" />}
            </g>
          )
        })}
        {markerX !== null && marker && (
          <g>
            <line x1={markerX} x2={markerX} y1={pad.top - 2} y2={plotBottom} stroke="var(--b-warn)" strokeWidth={1} />
            <text x={markerX - 4} y={pad.top + 8} textAnchor="end" style={{ fill: 'var(--b-text-2)' }}>
              {marker.label}
            </text>
          </g>
        )}
        {xLabels.map((i) =>
          points[i] ? (
            <text key={i} x={slot(i) + bw / 2} y={height - 4} textAnchor={i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle'}>
              {i === points.length - 1 ? 'Now' : hhmm(points[i].hourEnd.toISOString())}
            </text>
          ) : null,
        )}
        {points.map((_, i) => (
          <rect key={i} x={band(i) - (step - bandwidth) / 2} y={pad.top} width={step} height={plotBottom - pad.top} fill="transparent" onPointerEnter={() => setHover(i)} />
        ))}
      </svg>
      {p &&
        box &&
        portal &&
        createPortal(
        <div className="b-chart-tip" style={{ position: 'fixed', zIndex: 90, left: tipLeft, top: tipTop, width: 170 }}>
          <p className="b-num mb-1 text-[11.5px] text-[var(--b-text-2)]">
            {hhmm(start)}–{hhmm(p.hourEnd.toISOString())} UTC
          </p>
          <p className="b-tip-row">
            <b>{p.accept}</b>
            <i className="b-tip-key" style={{ background: 'var(--b-accept)' }} />
            <span className="b-t2">Accepted</span>
          </p>
          <p className="b-tip-row">
            <b>{p.reject}</b>
            <i className="b-tip-key" style={{ background: 'var(--b-reject)' }} />
            <span className="b-t2">Rejected</span>
          </p>
          <p className="b-num mt-0.5 border-t border-[var(--b-line)] pt-1 text-[11.5px] text-[var(--b-text-2)]">
            {p.accept + p.reject ? `${formatPercent(p.accept / (p.accept + p.reject), 0)} success` : 'No requests'}
          </p>
        </div>,
          portal,
        )}
      <span className="sr-only" aria-live="polite">
        {p ? `${hhmm(start)} to ${hhmm(p.hourEnd.toISOString())} UTC: ${p.accept} accepted, ${p.reject} rejected.` : ''}
      </span>
    </div>
  )
}

export function AcceptRejectLegend() {
  return (
    <span className="b-legend">
      <span>
        <i style={{ background: 'var(--b-accept)' }} aria-hidden />
        Accepted
      </span>
      <span>
        <i style={{ background: 'var(--b-reject)' }} aria-hidden />
        Rejected
      </span>
    </span>
  )
}
