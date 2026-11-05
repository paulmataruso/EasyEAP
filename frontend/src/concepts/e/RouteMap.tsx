import { useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore, type KeyboardEvent, type PointerEvent as RPointerEvent, type ReactNode } from 'react'
import { Map as MapIcon, MoveHorizontal, Pause, Play, Plus, Table2 } from 'lucide-react'
import { vendorLabels } from '@/domain/explain'
import { formatPercent, formatTime } from '@/ui/lib'
import { INK, STATUS, dotRadius, formStyle, plural, type LineForm } from './theme'
import { REJECTED, layoutMap, outcomeKeyOf, type MapLayout, type Outcome, type RouteData, type Station } from './routes'
import { Button, FormLegend, LineBullet, RampLegend, RejectBullet, Segmented, StatusMark } from './ui'
import { DataTable } from './DataTable'

export type MapSelection = { type: 'station'; id: string } | { type: 'outcome'; key: string } | { type: 'interchange' } | null

const reducedQuery = typeof window !== 'undefined' ? window.matchMedia('(prefers-reduced-motion: reduce)') : null
export function useReducedMotion() {
  return useSyncExternalStore(
    (cb) => { reducedQuery?.addEventListener('change', cb); return () => reducedQuery?.removeEventListener('change', cb) },
    () => reducedQuery?.matches ?? false,
    () => false,
  )
}

export function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [w, setW] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setW(el.clientWidth)
    const ro = new ResizeObserver(([e]) => setW(Math.round(e.contentRect.width)))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, w] as const
}

const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)
const share = (n: number, d: number) => (d ? formatPercent(n / d, 0) : '0%')

interface Tip { x: number; y: number; body: ReactNode }

export function RouteMap({ data, selection, onSelect, policySummary, snapshotLabel, onAddController }: {
  data: RouteData
  selection: MapSelection
  onSelect: (s: MapSelection) => void
  policySummary: string
  snapshotLabel: string
  onAddController: () => void
}) {
  const reduced = useReducedMotion()
  const [paused, setPaused] = useState(false)
  const [view, setView] = useState<'map' | 'table'>('map')
  const live = !reduced && !paused && data.events.length > 0
  const [wrapRef, width] = useWidth<HTMLDivElement>()
  const layout = useMemo(() => layoutMap(data, width || 900), [data, width])
  const [hover, setHover] = useState<MapSelection>(null)
  const [tip, setTip] = useState<Tip | null>(null)
  const active = hover ?? selection
  const tickerRef = useRef<HTMLSpanElement>(null)
  const empty = data.stations.length === 0

  return (
    <section className="e-panel overflow-hidden" aria-labelledby="route-map-title">
      <header className="e-panel-head flex-wrap">
        <div className="min-w-0">
          <h2 className="e-panel-title" id="route-map-title">Authentication routes</h2>
          <p className="e-panel-desc">
            Last 24 hours: {plural(data.total, 'authentication')} from {plural(data.stations.length, 'controller')}, through policy, to {plural(data.outcomes.filter((o) => !o.reject).length, 'VLAN')}.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {!empty && view === 'map' && (
            reduced ? (
              <span className="t2 text-[12.5px]">Reduced motion: showing static counts</span>
            ) : (
              <Button size="sm" variant="secondary" onClick={() => setPaused((p) => !p)} aria-pressed={paused}>
                {paused ? <Play /> : <Pause />}
                {paused ? 'Resume live events' : 'Pause live events'}
              </Button>
            )
          )}
          <Segmented
            label="Route view"
            value={view}
            onValueChange={setView}
            options={[
              { value: 'map', label: <><MapIcon aria-hidden />Map</> },
              { value: 'table', label: <><Table2 aria-hidden />Table</> },
            ]}
          />
        </div>
      </header>

      {view === 'table' ? (
        <RouteTable data={data} />
      ) : (
        <>
          <div ref={wrapRef} className="e-map-scroll relative" role="region" aria-label="Authentication route map. Use Tab or arrow keys to move between stations; Enter opens the inspector." tabIndex={-1}>
            <MapSvg
              layout={layout}
              data={data}
              active={active}
              selection={selection}
              live={live}
              showCounts={!live}
              onSelect={onSelect}
              onHover={setHover}
              setTip={setTip}
              policySummary={policySummary}
              snapshotLabel={snapshotLabel}
              tickerRef={tickerRef}
            />
            {tip && (
              <div className="e-tip" style={{ left: Math.min(tip.x + 14, layout.width - 290), top: tip.y + 14 }} role="status">
                {tip.body}
              </div>
            )}
            {empty && (
              <div className="absolute left-4 top-1/2 w-[200px] -translate-y-1/2 sm:left-6">
                <p className="text-[13.5px] font-bold">No controllers yet</p>
                <p className="t2 mt-1 text-[12.5px]">Register a wireless controller to start routing authentications through policy.</p>
                <Button size="sm" variant="primary" className="mt-3" onClick={onAddController}><Plus />Register controller</Button>
              </div>
            )}
          </div>
          {width > 0 && width < layout.width && (
            <p className="t2 flex items-center gap-1.5 border-t border-[var(--e-hair)] px-4 py-2 text-[12px]"><MoveHorizontal size={14} aria-hidden />Scroll sideways to follow each route to its VLAN, or switch to Table.</p>
          )}
          <footer className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3 border-t border-[var(--e-hair)] px-4 py-3">
            <div className="space-y-2">
              <RampLegend />
              <FormLegend forms={['live', 'idle', 'degraded']} />
            </div>
            <p className="t2 min-h-[18px] text-[12px]" aria-live="off">
              {empty ? 'Waiting for the first controller' : live ? <>Replaying recent events · <span ref={tickerRef} className="mono num" /></> : 'Counts are totals for the last 24 hours'}
            </p>
          </footer>
        </>
      )}
    </section>
  )
}

function MapSvg({ layout, data, active, selection, live, showCounts, onSelect, onHover, setTip, policySummary, snapshotLabel, tickerRef }: {
  layout: MapLayout
  data: RouteData
  active: MapSelection
  selection: MapSelection
  live: boolean
  showCounts: boolean
  onSelect: (s: MapSelection) => void
  onHover: (s: MapSelection) => void
  setTip: (t: Tip | null) => void
  policySummary: string
  snapshotLabel: string
  tickerRef: React.RefObject<HTMLSpanElement | null>
}) {
  const svgRef = useRef<SVGSVGElement>(null)
  const dotsRef = useRef<SVGGElement>(null)
  const routeRefs = useRef(new Map<string, SVGPathElement>())
  const { stations, outcomes, interchange: ix, width: W, height: H } = layout

  // ── Emphasis: the active station or terminus keeps full strength, the rest recede ──
  const strandAlpha = (stationId: string, outcomeKey: string) => {
    if (!active) return 1
    if (active.type === 'station') return active.id === stationId ? 1 : 0.14
    if (active.type === 'outcome') return active.key === outcomeKey ? 1 : 0.14
    return 1
  }
  const exitAlpha = (o: Outcome) => {
    if (!active) return 1
    if (active.type === 'station') return (data.stations.find((s) => s.id === active.id)?.byOutcome.get(o.key) ?? 0) > 0 ? 1 : 0.14
    if (active.type === 'outcome') return active.key === o.key ? 1 : 0.14
    return 1
  }

  // ── Tooltip helpers ──
  const tipAt = (clientX: number, clientY: number, body: ReactNode) => {
    const box = svgRef.current?.getBoundingClientRect()
    if (!box) return
    setTip({ x: clientX - box.left, y: clientY - box.top, body })
  }
  const tipAtEl = (el: Element, body: ReactNode) => {
    const box = svgRef.current?.getBoundingClientRect()
    const r = el.getBoundingClientRect()
    if (!box) return
    setTip({ x: r.left - box.left + Math.min(r.width, 200) * 0.5, y: r.bottom - box.top - 6, body })
  }

  const stationTip = (s: Station) => (
    <>
      <p className="font-bold">{s.client.name}</p>
      <p className="t2">{s.client.site} · {vendorLabels[s.client.vendor]}</p>
      <p className="mt-1 num"><strong>{s.total}</strong> authentications · {share(s.accepts, s.total)} accepted</p>
      <p className="mt-1"><StatusMark state={s.client.status} /></p>
    </>
  )
  const outcomeTip = (o: Outcome) => (
    <>
      <p className="font-bold">{o.reject ? 'Rejected' : `VLAN ${o.vlan?.vlanId ?? ''} · ${o.label}`}</p>
      <p className="mt-1 num"><strong>{o.total}</strong> authentications · {share(o.total, data.total)} of all traffic</p>
      {o.total === 0 && <p className="t2 mt-1">Configured, no traffic in 24 hours</p>}
    </>
  )
  const strandTip = (s: Station, o: Outcome, n: number) => (
    <>
      <p className="font-bold">{s.client.name}</p>
      <p className="t2">to {o.reject ? 'Rejected' : `VLAN ${o.vlan?.vlanId} ${o.label}`}</p>
      <p className="mt-1 num"><strong>{n}</strong> authentications · {share(n, s.total)} of this controller</p>
    </>
  )

  // ── Live replay: real recent events travel their route as dots ──
  useEffect(() => {
    if (!live) return
    const g = dotsRef.current
    if (!g) return
    const queue = [...data.events].filter((e) => e.nasClientId).sort((a, b) => a.at.localeCompare(b.at)).slice(-60)
    if (!queue.length) return
    let i = 0
    let nextEmit = 0
    let raf = 0
    const speed = 0.24 // px per ms
    const dots: Array<{ el: SVGCircleElement; path: SVGPathElement; len: number; start: number }> = []
    const tick = (t: number) => {
      if (t >= nextEmit) {
        const e = queue[i % queue.length]
        i++
        nextEmit = t + 560
        const key = `${e.nasClientId}|${outcomeKeyOf(e)}`
        const path = routeRefs.current.get(key)
        const meta = layout.routes.get(key)
        if (path && meta) {
          const el = document.createElementNS('http://www.w3.org/2000/svg', 'circle')
          el.setAttribute('r', String(dotRadius(1) + meta.width / 4))
          el.setAttribute('fill', INK.station)
          el.setAttribute('stroke', INK.ground)
          el.setAttribute('stroke-width', '1.5')
          g.appendChild(el)
          dots.push({ el, path, len: path.getTotalLength(), start: t })
          if (tickerRef.current) {
            const o = data.outcomes.find((x) => x.key === outcomeKeyOf(e))
            tickerRef.current.textContent = `${formatTime(e.at)} ${e.username?.split('@')[0] ?? 'unknown'} → ${o?.reject ? 'Rejected' : `VLAN ${o?.vlan?.vlanId ?? ''}`}`
          }
        }
      }
      for (let k = dots.length - 1; k >= 0; k--) {
        const d = dots[k]
        const dist = (t - d.start) * speed
        if (dist >= d.len) { d.el.remove(); dots.splice(k, 1); continue }
        const p = d.path.getPointAtLength(dist)
        d.el.setAttribute('cx', p.x.toFixed(1))
        d.el.setAttribute('cy', p.y.toFixed(1))
      }
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => { cancelAnimationFrame(raf); dots.forEach((d) => d.el.remove()) }
  }, [live, data, layout, tickerRef])

  // ── Keyboard: arrows move between stations (left), interchange (centre) and termini (right) ──
  const nodeOrder = useMemo(() => [
    stations.map((s) => `s:${s.station.id}`),
    ['i'],
    outcomes.map((o) => `o:${o.outcome.key}`),
  ], [stations, outcomes])
  const focusNode = (id: string) => svgRef.current?.querySelector<SVGGElement>(`[data-node="${CSS.escape(id)}"]`)?.focus()
  const onKeyDown = (e: KeyboardEvent<SVGSVGElement>) => {
    const cur = (e.target as Element).getAttribute?.('data-node')
    if (!cur) return
    const col = nodeOrder.findIndex((c) => c.includes(cur))
    const row = nodeOrder[col].indexOf(cur)
    const move = (c: number, r: number) => { const list = nodeOrder[c]; if (list?.length) { e.preventDefault(); focusNode(list[Math.max(0, Math.min(list.length - 1, r))]) } }
    if (e.key === 'ArrowDown') move(col, row + 1)
    else if (e.key === 'ArrowUp') move(col, row - 1)
    else if (e.key === 'ArrowRight' && col < 2) move(col + 1, Math.round((row / Math.max(1, nodeOrder[col].length - 1)) * (nodeOrder[col + 1].length - 1)))
    else if (e.key === 'ArrowLeft' && col > 0) move(col - 1, Math.round((row / Math.max(1, nodeOrder[col].length - 1)) * (nodeOrder[col - 1].length - 1)))
  }
  const nodeHandlers = (sel: NonNullable<MapSelection>, body: () => ReactNode) => ({
    tabIndex: 0,
    role: 'button' as const,
    onClick: () => onSelect(isSame(selection, sel) ? null : sel),
    onKeyDown: (e: KeyboardEvent<SVGGElement>) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(isSame(selection, sel) ? null : sel) } },
    onPointerEnter: () => onHover(sel),
    onPointerMove: (e: RPointerEvent<SVGGElement>) => tipAt(e.clientX, e.clientY, body()),
    onPointerLeave: () => { onHover(null); setTip(null) },
    onFocus: (e: React.FocusEvent<SVGGElement>) => { onHover(sel); tipAtEl(e.currentTarget, body()) },
    onBlur: () => { onHover(null); setTip(null) },
    'aria-pressed': isSame(selection, sel),
  })

  const idleDash = (w: number) => formStyle('idle', w).strokeDasharray
  const strandStyle = (form: LineForm, w: number) => formStyle(form, w)

  return (
    <svg ref={svgRef} className="e-map" width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="group" aria-label="Route map" onKeyDown={onKeyDown}>
      {/* Exit lines: interchange → termini */}
      <g>
        {outcomes.map((g) => {
          const st = g.form === 'idle' ? { strokeDasharray: idleDash(g.width), opacity: 0.9 } : { strokeDasharray: undefined, opacity: 1 }
          return (
            <g key={g.outcome.key} className="trunk" opacity={exitAlpha(g.outcome) * st.opacity}>
              <path d={g.d} fill="none" stroke={g.outcome.color} strokeWidth={g.width} strokeLinecap="butt" strokeLinejoin="round" strokeDasharray={st.strokeDasharray} />
              <path
                d={g.d}
                fill="none"
                stroke="transparent"
                strokeWidth={g.width + 12}
                onPointerMove={(e) => { onHover({ type: 'outcome', key: g.outcome.key }); tipAt(e.clientX, e.clientY, outcomeTip(g.outcome)) }}
                onPointerLeave={() => { onHover(null); setTip(null) }}
                onClick={() => onSelect({ type: 'outcome', key: g.outcome.key })}
              />
            </g>
          )
        })}
      </g>

      {/* Strands: station → interchange, one per outcome, weight from the fixed ramp */}
      <g>
        {stations.map((sg) => (
          <g key={sg.station.id}>
            {sg.idleD && <path d={sg.idleD} fill="none" stroke={INK.neutralLine} strokeWidth={2} strokeDasharray={idleDash(2)} className="strand" opacity={strandAlpha(sg.station.id, '') * 0.9} />}
            {sg.strands.map((s) => {
              const o = data.outcomes.find((x) => x.key === s.outcomeKey)!
              const st = strandStyle(s.form, s.width)
              return (
                <g key={s.key} className="strand" opacity={strandAlpha(s.stationId, s.outcomeKey) * st.opacity}>
                  <path d={s.d} fill="none" stroke={s.color} strokeWidth={s.width} strokeLinejoin="round" strokeDasharray={st.strokeDasharray} />
                  <path
                    d={s.d}
                    fill="none"
                    stroke="transparent"
                    strokeWidth={s.width + 4}
                    onPointerMove={(e) => { onHover({ type: 'station', id: s.stationId }); tipAt(e.clientX, e.clientY, strandTip(sg.station, o, s.count)) }}
                    onPointerLeave={() => { onHover(null); setTip(null) }}
                    onClick={() => onSelect({ type: 'station', id: s.stationId })}
                  />
                </g>
              )
            })}
          </g>
        ))}
      </g>

      {/* Hidden full routes for travelling dots */}
      <g aria-hidden style={{ visibility: 'hidden' }}>
        {[...layout.routes.entries()].map(([k, r]) => (
          <path key={k} d={r.d} fill="none" stroke="none" ref={(el) => { if (el) routeRefs.current.set(k, el); else routeRefs.current.delete(k) }} />
        ))}
      </g>
      <g ref={dotsRef} aria-hidden pointerEvents="none" />

      {/* Policy interchange: label block sits above every line, joined by a leader */}
      <g className="node" data-node="i" aria-label={`EasyEAP policy interchange. ${policySummary}. ${snapshotLabel}.`} {...nodeHandlers({ type: 'interchange' }, () => (<><p className="font-bold">EasyEAP policy</p><p className="t2">{policySummary}</p><p className="t2">{snapshotLabel}</p></>))}>
        <rect className="hit" x={ix.x - 120} y={layout.label.y1 - 18} width={240} height={layout.label.y3 - layout.label.y1 + 26} rx={8} />
        <rect className="ring" x={ix.x - 120} y={layout.label.y1 - 18} width={240} height={layout.label.y3 - layout.label.y1 + 26} rx={8} fill="none" stroke={INK.station} strokeWidth={2} />
        <line x1={ix.x} x2={ix.x} y1={layout.label.y3 + 8} y2={ix.y - ix.h / 2 - 2} stroke="rgba(167,177,194,0.45)" strokeWidth={1} strokeDasharray="2 3" />
        <rect className="hit" x={ix.x - 20} y={ix.y - ix.h / 2 - 6} width={40} height={ix.h + 12} rx={12} />
        <rect x={ix.x - ix.w / 2} y={ix.y - ix.h / 2} width={ix.w} height={ix.h} rx={ix.w / 2} fill={INK.station} stroke={INK.ground} strokeWidth={4} />
        <text x={ix.x} y={layout.label.y1} textAnchor="middle" fontSize={13.5} fontWeight={800}>EasyEAP policy</text>
        <text x={ix.x} y={layout.label.y2} textAnchor="middle" fontSize={11.5} className="lbl-2">{policySummary}</text>
        <text x={ix.x} y={layout.label.y3} textAnchor="middle" fontSize={11.5} className="lbl-2">{snapshotLabel}</text>
      </g>

      {/* Origin stations */}
      {stations.map((sg) => {
        const s = sg.station
        const h = Math.max(18, sg.thickness + 8)
        const warn = s.client.status !== 'ok'
        const label = `${s.client.name}, ${s.client.site}. ${s.total} authentications in 24 hours, ${share(s.accepts, s.total)} accepted. Status ${STATUS[s.client.status].label}.`
        return (
          <g key={s.id} className="node" data-node={`s:${s.id}`} aria-label={label} {...nodeHandlers({ type: 'station', id: s.id }, () => stationTip(s))}>
            <rect className="hit" x={8} y={sg.y - Math.max(30, h / 2 + 6)} width={sg.x + 18 - 8} height={Math.max(60, h + 12) + (warn ? 14 : 0)} rx={8} />
            <rect className="ring" x={8} y={sg.y - Math.max(30, h / 2 + 6)} width={sg.x + 18 - 8} height={Math.max(60, h + 12) + (warn ? 14 : 0)} rx={8} fill="none" stroke={INK.station} strokeWidth={2} />
            <rect x={sg.x - 8} y={sg.y - h / 2} width={16} height={h} rx={8} fill={INK.station} stroke={INK.ground} strokeWidth={3} />
            <text x={sg.x - 20} y={sg.y - 4} textAnchor="end" fontSize={13} fontWeight={750}>{trunc(s.client.name, 27)}</text>
            <text x={sg.x - 20} y={sg.y + 12} textAnchor="end" fontSize={11.5} className="lbl-2">
              {trunc(s.client.site, 24)} · <tspan className="num">{s.total}</tspan> auths
            </text>
            {warn && (
              <g>
                <text x={sg.x - 20} y={sg.y + 28} textAnchor="end" fontSize={11.5} fontWeight={700}>{STATUS[s.client.status].label}</text>
                <StatusGlyph x={sg.x - 20 - (STATUS[s.client.status].label.length * 6.6) - 16} y={sg.y + 18} state={s.client.status} />
              </g>
            )}
          </g>
        )
      })}

      {/* Termini */}
      {outcomes.map((g) => {
        const o = g.outcome
        const th = g.width + 12
        const label = `${o.reject ? 'Rejected terminus' : `VLAN ${o.vlan?.vlanId} ${o.label}`}. ${o.total} authentications, ${share(o.total, data.total)} of traffic.`
        return (
          <g key={o.key} className="node" data-node={`o:${o.key}`} aria-label={label} {...nodeHandlers({ type: 'outcome', key: o.key }, () => outcomeTip(o))}>
            <rect className="hit" x={g.x - 10} y={g.y - 21} width={W - g.x + 2} height={42} rx={8} />
            <rect className="ring" x={g.x - 10} y={g.y - 21} width={W - g.x + 2} height={42} rx={8} fill="none" stroke={INK.station} strokeWidth={2} />
            <rect x={g.x - 5} y={g.y - th / 2} width={10} height={th} rx={5} fill={INK.station} stroke={INK.ground} strokeWidth={3} />
            <g transform={`translate(${g.labelX}, ${g.y - 11})`}>
              <circle cx={11} cy={11} r={11} fill={o.color} />
              {o.reject ? (
                <path d="M7 7 L15 15 M15 7 L7 15" stroke={o.ink} strokeWidth={2.6} strokeLinecap="round" />
              ) : (
                <text x={11} y={15} textAnchor="middle" fontSize={o.vlan && String(o.vlan.vlanId).length > 2 ? 9.5 : 11} fontWeight={850} style={{ fill: o.ink }} className="num">{o.vlan?.vlanId ?? '—'}</text>
              )}
            </g>
            <text x={g.labelX + 30} y={g.y - 2} fontSize={13} fontWeight={750}>{trunc(o.label, 20)}</text>
            <text x={g.labelX + 30} y={g.y + 13} fontSize={11.5} className="lbl-2">
              <tspan className="num">{o.total}</tspan> · {share(o.total, data.total)}{o.total === 0 ? ' · idle' : ''}
            </text>
          </g>
        )
      })}

      {/* Static counts (reduced motion or paused): per-strand totals at the station side */}
      {showCounts && stations.map((sg) => sg.strands.length > 0 && (
        <g key={`c-${sg.station.id}`} pointerEvents="none" opacity={active && active.type === 'station' && active.id !== sg.station.id ? 0.25 : 1}>
          <CountPill x={sg.x + 30} y={sg.y - sg.thickness / 2 - 13} text={`${sg.station.total}`} />
        </g>
      ))}
      {showCounts && outcomes.map((g) => g.outcome.total > 0 && (
        <g key={`co-${g.outcome.key}`} pointerEvents="none" opacity={exitAlpha(g.outcome) < 1 ? 0.25 : 1}>
          <CountPill x={g.x - 44} y={g.y - g.width / 2 - 12} text={`${g.outcome.total}`} />
        </g>
      ))}
    </svg>
  )
}

function CountPill({ x, y, text }: { x: number; y: number; text: string }) {
  const w = text.length * 7 + 12
  return (
    <g transform={`translate(${x}, ${y})`}>
      <rect x={-w / 2} y={-9} width={w} height={18} rx={9} fill={INK.ground} stroke="rgba(167,177,194,0.35)" />
      <text x={0} y={4} textAnchor="middle" fontSize={11} fontWeight={700} className="num">{text}</text>
    </g>
  )
}

function StatusGlyph({ x, y, state }: { x: number; y: number; state: Station['client']['status'] }) {
  const c = STATUS[state].hex
  if (state === 'degraded') return <path transform={`translate(${x}, ${y})`} d="M7 1 L13.5 12.5 H0.5 Z M7 5 V8.5 M7 10.4 V10.6" fill="none" stroke={c} strokeWidth={1.7} strokeLinejoin="round" strokeLinecap="round" aria-hidden />
  if (state === 'down') return <g transform={`translate(${x}, ${y})`} aria-hidden><circle cx={7} cy={7} r={6} fill="none" stroke={c} strokeWidth={1.7} /><path d="M4.5 4.5 L9.5 9.5 M9.5 4.5 L4.5 9.5" stroke={c} strokeWidth={1.7} strokeLinecap="round" /></g>
  return <circle cx={x + 7} cy={y + 7} r={6} fill="none" stroke={c} strokeWidth={1.5} strokeDasharray="2.5 2" aria-hidden />
}

const isSame = (a: MapSelection, b: MapSelection) => {
  if (!a || !b || a.type !== b.type) return false
  if (a.type === 'station' && b.type === 'station') return a.id === b.id
  if (a.type === 'outcome' && b.type === 'outcome') return a.key === b.key
  return a.type === 'interchange'
}

/** The same routes as a table: the accessible, exact view of the map. */
function RouteTable({ data }: { data: RouteData }) {
  const rows = data.stations.flatMap((s) => data.outcomes.filter((o) => (s.byOutcome.get(o.key) ?? 0) > 0).map((o) => ({ s, o, n: s.byOutcome.get(o.key)! })))
  return (
    <DataTable
      caption="Authentications by controller and destination, last 24 hours"
      rows={rows}
      rowKey={(r) => `${r.s.id}|${r.o.key}`}
      dense
      maxHeight={420}
      empty={<p className="t2 py-8 text-center">No authentications in the last 24 hours.</p>}
      columns={[
        { key: 'c', header: 'Controller', cell: (r) => <span className="font-semibold">{r.s.client.name}</span> },
        { key: 'site', header: 'Site', cell: (r) => <span className="t2">{r.s.client.site}</span>, hideBelow: 'md' },
        { key: 'st', header: 'Status', cell: (r) => <StatusMark state={r.s.client.status} />, hideBelow: 'lg' },
        { key: 'o', header: 'Destination', cell: (r) => <span className="inline-flex items-center gap-2">{r.o.reject ? <RejectBullet size={20} /> : r.o.vlan ? <LineBullet vlan={r.o.vlan} size={20} /> : null}{r.o.reject ? 'Rejected' : r.o.label}</span> },
        { key: 'n', header: 'Authentications', align: 'right', cell: (r) => <span className="num">{r.n}</span> },
        { key: 'p', header: 'Share of controller', align: 'right', cell: (r) => <span className="num t2">{share(r.n, r.s.total)}</span>, hideBelow: 'sm' },
      ]}
    />
  )
}

export { REJECTED }
