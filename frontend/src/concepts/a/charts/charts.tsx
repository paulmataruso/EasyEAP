// Concept A charts. Thin marks, 2px lines, 4px rounded data-ends, hairline solid grid, one y-axis,
// hover + keyboard tooltip on every chart, text in text tokens (never series colours).
import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from 'react'
import { scaleBand, scaleLinear } from 'd3-scale'
import { line } from 'd3-shape'
import { cn } from '@/ui/lib'

export const SERIES = {
  accept: '#22c55e',
  reject: '#ef4444',
  neutral: '#7c8aa5',
  neutralHi: '#cbd5e1',
  expiring: '#f59e0b',
  grid: 'rgba(148,163,184,0.13)',
  axis: 'rgba(148,163,184,0.28)',
  surface: '#1b2336',
}

export function useMeasure<T extends HTMLElement>() {
  const ref = useRef<T | null>(null)
  const [width, setWidth] = useState(0)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)))
    ro.observe(el)
    setWidth(Math.floor(el.getBoundingClientRect().width))
    return () => ro.disconnect()
  }, [])
  return { ref, width }
}

/** Shared hover/focus cursor over N positions. */
function useCursor(n: number, indexAt: (x: number) => number) {
  const [active, setActive] = useState<number | null>(null)
  const onPointerMove = useCallback(
    (e: PointerEvent<HTMLElement>) => {
      const rect = e.currentTarget.getBoundingClientRect()
      const i = indexAt(e.clientX - rect.left)
      setActive(i < 0 || i >= n ? null : i)
    },
    [indexAt, n],
  )
  const onKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    if (!n) return
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') setActive((a) => Math.min(n - 1, (a ?? -1) + 1))
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') setActive((a) => Math.max(0, (a ?? n) - 1))
    else if (e.key === 'Home') setActive(0)
    else if (e.key === 'End') setActive(n - 1)
    else if (e.key === 'Escape') setActive(null)
    else return
    e.preventDefault()
  }
  return {
    active,
    bind: {
      onPointerMove,
      onPointerLeave: () => setActive(null),
      onKeyDown,
      onFocus: () => setActive((a) => a ?? n - 1),
      onBlur: () => setActive(null),
      tabIndex: 0,
    },
  }
}

function Tip({ x, width, children, top = 0 }: { x: number; width: number; children: ReactNode; top?: number }) {
  const tipW = 160
  const left = Math.max(0, Math.min(width - tipW, x - tipW / 2))
  return (
    <div className="a-chart-tip" style={{ left, top, width: tipW }} aria-hidden>
      {children}
    </div>
  )
}

function TipRow({ color, value, label, line: isLine }: { color: string; value: ReactNode; label: ReactNode; line?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span aria-hidden style={{ width: 12, height: isLine ? 2 : 8, borderRadius: isLine ? 1 : 2, background: color }} />
      <span className="a-num font-semibold text-[var(--a-text)]">{value}</span>
      <span className="text-[var(--a-text-3)]">{label}</span>
    </div>
  )
}

const hourLabel = (d: Date) => `${String(d.getUTCHours()).padStart(2, '0')}:00`

// ── Diverging hourly accept/reject ─────────────────────────────────────────

export interface HourPoint {
  hourEnd: Date
  accept: number
  reject: number
}

export function AuthDivergingChart({ points, height = 220, label }: { points: HourPoint[]; height?: number; label: string }) {
  const { ref, width } = useMeasure<HTMLDivElement>()
  const pad = { top: 10, right: 6, bottom: 24, left: 34 }
  const innerW = Math.max(0, width - pad.left - pad.right)
  const maxA = Math.max(1, ...points.map((p) => p.accept))
  const maxR = Math.max(1, ...points.map((p) => p.reject))
  const plotH = height - pad.top - pad.bottom
  // Accepts above the baseline, rejects below it, on ONE count scale.
  const y = scaleLinear()
    .domain([-maxR, maxA])
    .range([pad.top + plotH, pad.top])
  const zeroY = y(0)
  const band = scaleBand<number>()
    .domain(points.map((_, i) => i))
    .range([pad.left, pad.left + innerW])
    .paddingInner(0.28)
    .paddingOuter(0.1)
  const bw = Math.min(18, band.bandwidth())
  const step = band.step()
  const offset = pad.left + band.paddingOuter() * step
  const indexAt = useCallback((x: number) => Math.floor((x - offset) / Math.max(1, step)), [offset, step])
  const { active, bind } = useCursor(points.length, indexAt)
  const ticksUp = y.ticks(4).filter((t) => t > 0)
  const ticksDown = y.ticks(4).filter((t) => t < 0)
  const desc = useId()
  const a = active !== null ? points[active] : null
  return (
    <div ref={ref} className="relative w-full min-w-0">
      <div {...bind} role="img" aria-label={label} aria-describedby={desc} className="a-chart-focus relative rounded-md outline-none">
        {width > 0 && (
          <svg width={width} height={height} className="block overflow-visible">
            {[...ticksUp, ...ticksDown].map((t) => (
              <g key={t}>
                <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} stroke={SERIES.grid} />
                <text x={pad.left - 8} y={y(t)} dy="0.32em" textAnchor="end" className="a-num fill-[var(--a-text-3)] text-[11px]">
                  {Math.abs(t)}
                </text>
              </g>
            ))}
            {active !== null && <rect x={(band(active) ?? 0) - (step - band.bandwidth()) / 2} y={pad.top} width={step} height={plotH} fill="rgba(255,255,255,0.05)" rx={4} />}
            {points.map((p, i) => {
              const x = (band(i) ?? 0) + (band.bandwidth() - bw) / 2
              const ah = zeroY - y(p.accept)
              const rh = y(-p.reject) - zeroY
              return (
                <g key={i} opacity={active === null || active === i ? 1 : 0.55}>
                  {p.accept > 0 && <path d={roundedTop(x, zeroY - 1, bw, Math.max(1, ah - 1))} fill={SERIES.accept} />}
                  {p.reject > 0 && <path d={roundedBottom(x, zeroY + 1, bw, Math.max(1, rh - 1))} fill={SERIES.reject} />}
                </g>
              )
            })}
            <line x1={pad.left} x2={width - pad.right} y1={zeroY} y2={zeroY} stroke={SERIES.axis} />
            {points.map((p, i) =>
              i % 4 === 3 || i === points.length - 1 ? (
                <text key={i} x={(band(i) ?? 0) + band.bandwidth() / 2} y={height - 6} textAnchor="middle" className="a-num fill-[var(--a-text-3)] text-[11px]">
                  {i === points.length - 1 ? 'Now' : hourLabel(p.hourEnd)}
                </text>
              ) : null,
            )}
          </svg>
        )}
        {a && active !== null && (
          <Tip x={(band(active) ?? 0) + band.bandwidth() / 2} width={width} top={-8}>
            <div className="mb-1 text-[var(--a-text-3)]">
              {hourLabel(new Date(a.hourEnd.getTime() - 3600_000))}–{hourLabel(a.hourEnd)} UTC
            </div>
            <TipRow color={SERIES.accept} value={a.accept} label="accepted" />
            <TipRow color={SERIES.reject} value={a.reject} label="rejected" />
          </Tip>
        )}
      </div>
      <p id={desc} className="sr-only">
        {a ? `${hourLabel(a.hourEnd)}: ${a.accept} accepted, ${a.reject} rejected.` : 'Use arrow keys to read each hour.'}
      </p>
    </div>
  )
}

function roundedTop(x: number, baseY: number, w: number, h: number, r = 3) {
  const rr = Math.min(r, h, w / 2)
  return `M${x},${baseY} V${baseY - h + rr} Q${x},${baseY - h} ${x + rr},${baseY - h} H${x + w - rr} Q${x + w},${baseY - h} ${x + w},${baseY - h + rr} V${baseY} Z`
}
function roundedBottom(x: number, baseY: number, w: number, h: number, r = 3) {
  const rr = Math.min(r, h, w / 2)
  return `M${x},${baseY} V${baseY + h - rr} Q${x},${baseY + h} ${x + rr},${baseY + h} H${x + w - rr} Q${x + w},${baseY + h} ${x + w},${baseY + h - rr} V${baseY} Z`
}

// ── Mini columns (single series) ───────────────────────────────────────────

export interface ColumnDatum {
  label: string
  value: number
}

export function MiniColumns({ data, color = SERIES.neutral, highlightLast = false, height = 64, label, unit, emptyLabel }: { data: ColumnDatum[]; color?: string; highlightLast?: boolean; height?: number; label: string; unit: (n: number) => string; emptyLabel?: string }) {
  const { ref, width } = useMeasure<HTMLDivElement>()
  const max = Math.max(1, ...data.map((d) => d.value))
  const band = scaleBand<number>()
    .domain(data.map((_, i) => i))
    .range([0, width])
    .paddingInner(0.3)
  const step = band.step()
  const bw = Math.min(10, band.bandwidth())
  const y = scaleLinear().domain([0, max]).range([height - 1, 4])
  const indexAt = useCallback((x: number) => Math.floor(x / Math.max(1, step)), [step])
  const { active, bind } = useCursor(data.length, indexAt)
  const desc = useId()
  const a = active !== null ? data[active] : null
  const allZero = data.every((d) => d.value === 0)
  return (
    <div ref={ref} className="relative w-full min-w-0">
      <div {...bind} role="img" aria-label={label} aria-describedby={desc} className="a-chart-focus relative outline-none">
        {width > 0 && (
          <svg width={width} height={height} className="block overflow-visible">
            <line x1={0} x2={width} y1={height - 0.5} y2={height - 0.5} stroke={SERIES.axis} />
            {data.map((d, i) => {
              const x = (band(i) ?? 0) + (band.bandwidth() - bw) / 2
              const h = height - 1 - y(d.value)
              const fill = highlightLast && i === data.length - 1 ? SERIES.neutralHi : color
              return (
                <g key={i}>
                  {active === i && <rect x={(band(i) ?? 0) - (step - band.bandwidth()) / 2} y={0} width={step} height={height} fill="rgba(255,255,255,0.06)" rx={3} />}
                  {d.value > 0 && <path d={roundedTop(x, height - 1, bw, Math.max(2, h), 2)} fill={fill} opacity={active === null || active === i ? 1 : 0.6} />}
                </g>
              )
            })}
          </svg>
        )}
        {allZero && emptyLabel && <span className="absolute inset-x-0 bottom-2 text-center text-[12px] text-[var(--a-text-3)]">{emptyLabel}</span>}
        {a && active !== null && (
          <Tip x={(band(active) ?? 0) + band.bandwidth() / 2} width={width} top={-46}>
            <div className="text-[var(--a-text-3)]">{a.label}</div>
            <div className="a-num font-semibold text-[var(--a-text)]">{unit(a.value)}</div>
          </Tip>
        )}
      </div>
      <p id={desc} className="sr-only">
        {a ? `${a.label}: ${unit(a.value)}` : 'Use arrow keys to read each value.'}
      </p>
    </div>
  )
}

// ── Mini line (rate over 24h) with crosshair ───────────────────────────────

export function MiniRateLine({ data, color = SERIES.accept, height = 64, label, emptyLabel }: { data: Array<{ label: string; rate: number | null; total: number }>; color?: string; height?: number; label: string; emptyLabel?: string }) {
  const { ref, width } = useMeasure<HTMLDivElement>()
  const n = data.length
  const xAt = (i: number) => (n <= 1 ? 0 : 4 + (i * (width - 8)) / (n - 1))
  const rates = data.map((d) => d.rate).filter((r): r is number => r !== null)
  const lo = rates.length ? Math.max(0, Math.floor((Math.min(...rates) - 0.05) * 10) / 10) : 0
  const y = scaleLinear().domain([lo, 1]).range([height - 4, 6])
  const path =
    line<{ rate: number | null }>()
      .defined((d) => d.rate !== null)
      .x((_, i) => xAt(i))
      .y((d) => y(d.rate ?? 0))(data) ?? ''
  const indexAt = useCallback((x: number) => (n <= 1 ? 0 : Math.round(((x - 4) / Math.max(1, width - 8)) * (n - 1))), [n, width])
  const { active, bind } = useCursor(n, indexAt)
  const desc = useId()
  const a = active !== null ? data[active] : null
  const last = [...data].reverse().find((d) => d.rate !== null)
  const lastIdx = last ? data.lastIndexOf(last) : -1
  return (
    <div ref={ref} className="relative w-full min-w-0">
      <div {...bind} role="img" aria-label={label} aria-describedby={desc} className="a-chart-focus relative outline-none">
        {width > 0 && (
          <svg width={width} height={height} className="block overflow-visible">
            <line x1={0} x2={width} y1={y(1)} y2={y(1)} stroke={SERIES.grid} />
            <line x1={0} x2={width} y1={height - 0.5} y2={height - 0.5} stroke={SERIES.axis} />
            {active !== null && <line x1={xAt(active)} x2={xAt(active)} y1={0} y2={height} stroke="rgba(203,213,225,0.45)" />}
            <path d={path} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
            {lastIdx >= 0 && last?.rate !== null && last && <circle cx={xAt(lastIdx)} cy={y(last.rate ?? 0)} r={4} fill={color} stroke={SERIES.surface} strokeWidth={2} />}
            {active !== null && data[active].rate !== null && <circle cx={xAt(active)} cy={y(data[active].rate ?? 0)} r={4} fill={color} stroke={SERIES.surface} strokeWidth={2} />}
          </svg>
        )}
        {!rates.length && emptyLabel && <span className="absolute inset-x-0 bottom-2 text-center text-[12px] text-[var(--a-text-3)]">{emptyLabel}</span>}
        {a && active !== null && (
          <Tip x={xAt(active)} width={width} top={-46}>
            <div className="text-[var(--a-text-3)]">{a.label}</div>
            <div className="a-num font-semibold text-[var(--a-text)]">{a.rate === null ? 'No attempts' : `${(a.rate * 100).toFixed(0)}% of ${a.total}`}</div>
          </Tip>
        )}
      </div>
      <p id={desc} className="sr-only">
        {a ? `${a.label}: ${a.rate === null ? 'no attempts' : `${Math.round(a.rate * 100)} percent of ${a.total}`}` : 'Use arrow keys to read each hour.'}
      </p>
    </div>
  )
}

// ── Horizontal bar list (labelled, single series) ──────────────────────────

export interface BarItem {
  key: string
  label: ReactNode
  value: number
  color?: string
  /** Tooltip / sr text */
  detail: string
  trailing?: ReactNode
}

export function BarList({ items, label, max: maxIn, valueFormat = (n) => String(n), className }: { items: BarItem[]; label: string; max?: number; valueFormat?: (n: number) => string; className?: string }) {
  const max = Math.max(1, maxIn ?? Math.max(0, ...items.map((i) => i.value)))
  const [active, setActive] = useState<string | null>(null)
  return (
    <ul className={cn('flex flex-col gap-2.5', className)} aria-label={label}>
      {items.map((it) => (
        <li
          key={it.key}
          className="group relative"
          tabIndex={0}
          aria-label={it.detail}
          onPointerEnter={() => setActive(it.key)}
          onPointerLeave={() => setActive(null)}
          onFocus={() => setActive(it.key)}
          onBlur={() => setActive(null)}
        >
          <div className="mb-1 flex items-baseline justify-between gap-3 text-[13px]">
            <span className="min-w-0 truncate text-[var(--a-text-2)]">{it.label}</span>
            <span className="flex shrink-0 items-center gap-2">
              {it.trailing}
              <span className="a-num font-semibold text-[var(--a-text)]">{valueFormat(it.value)}</span>
            </span>
          </div>
          <div className="h-1.5 rounded-full bg-white/[0.06]">
            <div className="h-full rounded-full transition-[width] duration-300" style={{ width: `${(it.value / max) * 100}%`, background: it.color ?? SERIES.neutral, opacity: active === null || active === it.key ? 1 : 0.6 }} />
          </div>
          {active === it.key && (
            <div className="a-chart-tip right-0 -top-9" aria-hidden>
              {it.detail}
            </div>
          )}
        </li>
      ))}
    </ul>
  )
}

// ── Thin segmented bar (part-to-whole) ─────────────────────────────────────

export interface Segment {
  key: string
  label: string
  value: number
  color: string
}

export function SegmentBar({ segments, label, legend = true, unit = '' }: { segments: Segment[]; label: string; legend?: boolean; unit?: string }) {
  const total = segments.reduce((s, x) => s + x.value, 0)
  const [active, setActive] = useState<string | null>(null)
  const act = segments.find((s) => s.key === active)
  const before = act ? segments.slice(0, segments.indexOf(act)).reduce((s, x) => s + x.value, 0) : 0
  const tipLeft = act ? Math.max(16, Math.min(78, ((before + act.value / 2) / Math.max(1, total)) * 100)) : 0
  return (
    <div className="relative">
      <div className="flex h-2.5 gap-[2px]" role="img" aria-label={`${label}: ${segments.map((s) => `${s.label} ${s.value}`).join(', ')}`}>
        {total === 0 ? (
          <div className="h-full flex-1 rounded-full bg-white/[0.07]" />
        ) : (
          segments
            .filter((s) => s.value > 0)
            .map((s, i, arr) => (
              <div
                key={s.key}
                tabIndex={0}
                aria-label={`${s.label}: ${s.value} of ${total}`}
                onPointerEnter={() => setActive(s.key)}
                onPointerLeave={() => setActive(null)}
                onFocus={() => setActive(s.key)}
                onBlur={() => setActive(null)}
                className={cn('h-full outline-none focus-visible:ring-2 focus-visible:ring-[var(--a-accent-hover)]', i === 0 && 'rounded-l-full', i === arr.length - 1 && 'rounded-r-full')}
                style={{ width: `${(s.value / total) * 100}%`, background: s.color, opacity: active === null || active === s.key ? 1 : 0.55 }}
              />
            ))
        )}
      </div>
      {act && (
        <div className="a-chart-tip -top-11 whitespace-nowrap" style={{ left: `${tipLeft}%`, transform: 'translateX(-50%)' }} aria-hidden>
          <span className="text-[var(--a-text)]">{act.label}</span> · <span className="a-num font-semibold text-[var(--a-text)]">{act.value}</span>
          {unit && ` ${unit}`} · <span className="a-num">{Math.round((act.value / Math.max(1, total)) * 100)}%</span>
        </div>
      )}
      {legend && (
        <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[12px] text-[var(--a-text-3)]">
          {segments.map((s) => (
            <li key={s.key} className="flex items-center gap-1.5">
              <span className="size-2 rounded-[2px]" style={{ background: s.color }} aria-hidden />
              {s.label} <span className="a-num text-[var(--a-text-2)]">{s.value}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function Legend({ items }: { items: Array<{ label: string; color: string; shape?: 'rect' | 'line' }> }) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-[var(--a-text-2)]">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-1.5">
          <span aria-hidden style={{ width: i.shape === 'line' ? 12 : 8, height: i.shape === 'line' ? 2 : 8, borderRadius: 2, background: i.color }} />
          {i.label}
        </li>
      ))}
    </ul>
  )
}
