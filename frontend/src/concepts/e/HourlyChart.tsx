import { useState, type KeyboardEvent } from 'react'
import { hourlyGeometry, type HourPoint } from '@/ui/charts'
import { INK, REJECT } from './theme'
import { useWidth } from './RouteMap'

const ACCEPT = '#7F8CA3' // neutral accepted ink: 5.4:1 on the panel; rejects carry the status red
const hh = (d: Date) => `${String(d.getUTCHours()).padStart(2, '0')}:00`

/** 24 hourly columns, accepted below rejected with a 2px surface gap; per-column hover + arrow-key readout. */
export function HourlyChart({ points, height = 150 }: { points: HourPoint[]; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [active, setActive] = useState<number | null>(null)
  const w = Math.max(240, width)
  const g = hourlyGeometry(points, w, height, { top: 10, right: 4, bottom: 22, left: 30 })
  const bw = Math.min(24, g.band.bandwidth())
  const total = points.reduce((a, p) => a + p.accept + p.reject, 0)
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowRight') { e.preventDefault(); setActive((a) => Math.min(points.length - 1, (a ?? -1) + 1)) }
    if (e.key === 'ArrowLeft') { e.preventDefault(); setActive((a) => Math.max(0, (a ?? points.length) - 1)) }
    if (e.key === 'Escape') setActive(null)
  }
  const ap = active !== null ? points[active] : null
  const start = (p: HourPoint) => new Date(p.hourEnd.getTime() - 3600_000)
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] t2">
        <span className="inline-flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-[2px]" style={{ background: ACCEPT }} />Accepted</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-[2px]" style={{ background: REJECT.hex }} />Rejected</span>
        <span className="ml-auto">UTC, hourly</span>
      </div>
      <div ref={ref} className="relative">
        {total === 0 ? (
          <div className="grid place-items-center rounded-lg border border-dashed border-[var(--e-hair-strong)] text-[13px] t2" style={{ height }}>No authentications in the last 24 hours</div>
        ) : (
          <svg
            width={w}
            height={height}
            role="img"
            aria-label={`Authentications per hour, last 24 hours. ${total} total. Use the left and right arrow keys to read each hour.`}
            tabIndex={0}
            onKeyDown={onKey}
            onBlur={() => setActive(null)}
            className="block rounded-md"
          >
            {g.yTicks.map((t) => (
              <g key={t}>
                <line x1={g.pad.left} x2={w - g.pad.right} y1={g.y(t)} y2={g.y(t)} stroke={INK.hair} strokeWidth={1} />
                <text x={g.pad.left - 8} y={g.y(t) + 4} textAnchor="end" fontSize={11} fill={INK.text3} className="num">{t}</text>
              </g>
            ))}
            {points.map((p, i) => {
              const x = (g.band(i) ?? 0) + (g.band.bandwidth() - bw) / 2
              const yA = g.y(p.accept)
              const base = g.y(0)
              const yR = g.y(p.accept + p.reject)
              const isA = active === i
              return (
                <g key={i} opacity={active === null || isA ? 1 : 0.55}>
                  {p.accept > 0 && <path d={colPath(x, yA, bw, base - yA, p.reject === 0)} fill={ACCEPT} />}
                  {p.reject > 0 && <path d={colPath(x, yR, bw, Math.max(1.5, yA - yR - (p.accept > 0 ? 2 : 0)), true)} fill={REJECT.hex} />}
                  <rect x={g.band(i)! - 1} y={g.pad.top} width={g.band.step()} height={height - g.pad.top - g.pad.bottom} fill="transparent" onPointerEnter={() => setActive(i)} onPointerLeave={() => setActive(null)} />
                </g>
              )
            })}
            {[0, 6, 12, 18, 23].map((i) => (
              <text key={i} x={(g.band(i) ?? 0) + g.band.bandwidth() / 2} y={height - 6} textAnchor="middle" fontSize={11} fill={INK.text3} className="num">{hh(start(points[i]))}</text>
            ))}
          </svg>
        )}
        {ap && (
          <div className="e-tip" style={{ left: Math.min(Math.max(0, (g.band(active!) ?? 0) - 60), w - 170), top: -8, transform: 'translateY(-100%)' }}>
            <p className="t2 num">{hh(start(ap))}–{hh(ap.hourEnd)} UTC</p>
            <p className="num mt-0.5 flex items-center gap-2"><span className="inline-block h-[2px] w-3" style={{ background: ACCEPT }} /><strong>{ap.accept}</strong> <span className="t2">accepted</span></p>
            <p className="num flex items-center gap-2"><span className="inline-block h-[2px] w-3" style={{ background: REJECT.hex }} /><strong>{ap.reject}</strong> <span className="t2">rejected</span></p>
          </div>
        )}
      </div>
    </div>
  )
}

/** Column with a 4px rounded data end, square at the baseline. */
function colPath(x: number, y: number, w: number, h: number, roundTop: boolean) {
  if (h <= 0) return ''
  const r = roundTop ? Math.min(4, w / 2, h) : 0
  return `M${x} ${y + h}V${y + r}${r ? `Q${x} ${y} ${x + r} ${y}` : ''}H${x + w - r}${r ? `Q${x + w} ${y} ${x + w} ${y + r}` : ''}V${y + h}Z`
}
