// Route-map model: controllers (origin stations) → EasyEAP policy interchange → VLAN termini + Rejected.
// Pure functions: aggregation from tenant data, and an octilinear (0°/45°) schematic layout.
import type { AuthEvent, RadiusClient, Vlan } from '@/domain/types'
import { now } from '@/prototype/store'
import { INK, LINE, REJECT, lineWidth, type LineForm } from './theme'

export const REJECTED = 'rejected'

export interface Outcome { key: string; vlan: Vlan | null; label: string; color: string; ink: string; total: number; reject: boolean }
export interface Station { id: string; client: RadiusClient; total: number; accepts: number; byOutcome: Map<string, number>; form: LineForm }
export interface RouteData { stations: Station[]; outcomes: Outcome[]; events: AuthEvent[]; total: number }

export const outcomeKeyOf = (e: AuthEvent) => (e.result === 'accept' ? e.vlanId ?? 'none' : REJECTED)

export function buildRouteData(clients: RadiusClient[], vlans: Vlan[], events: AuthEvent[]): RouteData {
  const since = now().getTime() - 24 * 3600_000
  const ev = events.filter((e) => new Date(e.at).getTime() > since)
  const byStation = new Map<string, Map<string, number>>()
  const outcomeTotals = new Map<string, number>()
  for (const e of ev) {
    const k = outcomeKeyOf(e)
    outcomeTotals.set(k, (outcomeTotals.get(k) ?? 0) + 1)
    if (!e.nasClientId) continue
    const m = byStation.get(e.nasClientId) ?? new Map<string, number>()
    m.set(k, (m.get(k) ?? 0) + 1)
    byStation.set(e.nasClientId, m)
  }
  const outcomes: Outcome[] = vlans.map((v) => ({ key: v.id, vlan: v, label: v.name, color: LINE[v.color].hex, ink: LINE[v.color].ink, total: outcomeTotals.get(v.id) ?? 0, reject: false }))
  if ((outcomeTotals.get('none') ?? 0) > 0) outcomes.push({ key: 'none', vlan: null, label: 'No VLAN (default)', color: INK.neutralLine, ink: '#FFFFFF', total: outcomeTotals.get('none') ?? 0, reject: false })
  outcomes.push({ key: REJECTED, vlan: null, label: 'Rejected', color: REJECT.hex, ink: REJECT.ink, total: outcomeTotals.get(REJECTED) ?? 0, reject: true })
  const stations: Station[] = clients.map((c) => {
    const m = byStation.get(c.id) ?? new Map<string, number>()
    const total = [...m.values()].reduce((a, b) => a + b, 0)
    const accepts = total - (m.get(REJECTED) ?? 0)
    const form: LineForm = c.status === 'degraded' || c.status === 'down' ? 'degraded' : total === 0 ? 'idle' : 'live'
    return { id: c.id, client: c, total, accepts, byOutcome: m, form }
  })
  return { stations, outcomes, events: ev, total: ev.length }
}

// ── Geometry ─────────────────────────────────────────────────────────────
type P = [number, number]
const f = (n: number) => Math.round(n * 10) / 10
const dist = (a: P, b: P) => Math.hypot(b[0] - a[0], b[1] - a[1])

function dedupe(pts: P[]): P[] {
  const out: P[] = []
  for (const p of pts) if (!out.length || dist(out[out.length - 1], p) > 0.5) out.push(p)
  // drop collinear middle points
  return out.filter((p, i) => {
    if (i === 0 || i === out.length - 1) return true
    const a = out[i - 1], c = out[i + 1]
    return Math.abs((p[0] - a[0]) * (c[1] - a[1]) - (p[1] - a[1]) * (c[0] - a[0])) > 0.5
  })
}

/** Perpendicular offset of a polyline with mitred joints, so parallel strands keep their gap on diagonals. */
export function offsetPolyline(pts: P[], off: number): P[] {
  if (off === 0) return pts
  const n = pts.length
  const normal = (a: P, b: P): P => { const dx = b[0] - a[0], dy = b[1] - a[1]; const L = Math.hypot(dx, dy) || 1; return [-dy / L, dx / L] }
  return pts.map((p, i) => {
    if (i === 0) { const nn = normal(pts[0], pts[1]); return [p[0] + nn[0] * off, p[1] + nn[1] * off] }
    if (i === n - 1) { const nn = normal(pts[n - 2], pts[n - 1]); return [p[0] + nn[0] * off, p[1] + nn[1] * off] }
    const n1 = normal(pts[i - 1], p), n2 = normal(p, pts[i + 1])
    const m: P = [n1[0] + n2[0], n1[1] + n2[1]]
    const mL = Math.hypot(m[0], m[1]) || 1
    const mu: P = [m[0] / mL, m[1] / mL]
    const k = off / (mu[0] * n1[0] + mu[1] * n1[1])
    return [p[0] + mu[0] * k, p[1] + mu[1] * k]
  })
}

/** Polyline → path with quadratic rounded bends (transit-map curves). */
export function roundedPath(raw: P[], r = 18): string {
  const pts = dedupe(raw)
  if (pts.length < 2) return ''
  let d = `M${f(pts[0][0])} ${f(pts[0][1])}`
  for (let i = 1; i < pts.length - 1; i++) {
    const a = pts[i - 1], b = pts[i], c = pts[i + 1]
    const l1 = dist(a, b), l2 = dist(b, c)
    const rr = Math.min(r, l1 / 2, l2 / 2)
    const p1: P = [b[0] + ((a[0] - b[0]) * rr) / l1, b[1] + ((a[1] - b[1]) * rr) / l1]
    const p2: P = [b[0] + ((c[0] - b[0]) * rr) / l2, b[1] + ((c[1] - b[1]) * rr) / l2]
    d += `L${f(p1[0])} ${f(p1[1])}Q${f(b[0])} ${f(b[1])} ${f(p2[0])} ${f(p2[1])}`
  }
  const last = pts[pts.length - 1]
  return d + `L${f(last[0])} ${f(last[1])}`
}

export interface StrandGeo { key: string; stationId: string; outcomeKey: string; count: number; width: number; d: string; pts: P[]; color: string; form: LineForm; mid: P }
export interface StationGeo { station: Station; x: number; y: number; thickness: number; strands: StrandGeo[]; idleD: string | null }
export interface OutcomeGeo { outcome: Outcome; x: number; y: number; exitY: number; width: number; d: string; pts: P[]; form: LineForm; labelX: number }
export interface MapLayout {
  width: number; height: number
  stations: StationGeo[]
  outcomes: OutcomeGeo[]
  interchange: { x: number; y: number; w: number; h: number }
  label: { x: number; y1: number; y2: number; y3: number }
  routes: Map<string, { d: string; width: number; color: string }>
  x0: number; xt: number
}

const STRAND_GAP = 2
const BUNDLE_GAP = 14
const EXIT_GAP = 6

export function layoutMap(data: RouteData, width: number): MapLayout {
  const W = Math.max(760, Math.round(width))
  const x0 = 236
  const xt = W - 206
  const xi = Math.round(x0 + (xt - x0) * 0.48)

  // Bundles: one strand per outcome with traffic, in terminus order.
  const bundles = data.stations.map((s) => {
    const strands = data.outcomes.filter((o) => (s.byOutcome.get(o.key) ?? 0) > 0).map((o) => ({ o, count: s.byOutcome.get(o.key)!, w: lineWidth(s.byOutcome.get(o.key)!) }))
    const thickness = strands.length ? strands.reduce((a, b) => a + b.w, 0) + STRAND_GAP * (strands.length - 1) : lineWidth(0)
    return { s, strands, thickness }
  })
  const exits = data.outcomes.map((o) => ({ o, w: lineWidth(o.total) }))

  const leftStack = bundles.reduce((a, b) => a + b.thickness, 0) + BUNDLE_GAP * Math.max(0, bundles.length - 1)
  const rightStack = exits.reduce((a, b) => a + b.w, 0) + EXIT_GAP * Math.max(0, exits.length - 1)
  const ih = Math.max(leftStack, rightStack) + 22

  const stationGap = Math.max(104, ...bundles.map((b) => b.thickness + 64))
  const terminusGap = 50
  const rejectExtra = 16
  const stationSpan = (bundles.length - 1) * stationGap
  const terminusSpan = (exits.length - 1) * terminusGap + rejectExtra

  const place = (cy: number) => {
    // Termini
    const terminiTop = cy - terminusSpan / 2
    let exitCursor = cy - rightStack / 2
    const outcomes: OutcomeGeo[] = exits.map(({ o, w }, i) => {
      const y = terminiTop + i * terminusGap + (o.reject ? rejectExtra : 0)
      const exitY = exitCursor + w / 2
      exitCursor += w + EXIT_GAP
      const xc = xi + 46
      let xd = xc + Math.abs(y - exitY)
      if (xd > xt - 30) xd = xt - 30
      const pts: P[] = [[xi, exitY], [xc, exitY], [xd, y], [xt, y]]
      const form: LineForm = o.total === 0 ? 'idle' : 'live'
      return { outcome: o, x: xt, y, exitY, width: w, d: roundedPath(pts, 22), pts, form, labelX: xt + 18 }
    })

    // Stations + strands
    const stationTop = cy - stationSpan / 2
    let entryCursor = cy - leftStack / 2
    const routes = new Map<string, { d: string; width: number; color: string }>()
    const stations: StationGeo[] = bundles.map(({ s, strands, thickness }, i) => {
      const y = bundles.length === 1 ? cy : stationTop + i * stationGap
      const entryY = entryCursor + thickness / 2
      entryCursor += thickness + BUNDLE_GAP
      const xb = xi - 46
      let xa = xb - Math.abs(entryY - y)
      if (xa < x0 + 30) xa = x0 + 30
      const centre: P[] = [[x0, y], [xa, y], [xb, entryY], [xi, entryY]]
      let cursor = -thickness / 2
      const geos: StrandGeo[] = strands.map(({ o, count, w }) => {
        const off = cursor + w / 2
        cursor += w + STRAND_GAP
        const pts = offsetPolyline(centre, off)
        const og = outcomes.find((g) => g.outcome.key === o.key)!
        const key = `${s.id}|${o.key}`
        const routePts: P[] = [...pts.slice(0, -1), [xi, pts[pts.length - 1][1]], [xi, og.exitY], ...og.pts.slice(1)]
        routes.set(key, { d: roundedPath(routePts, 16), width: w, color: o.color })
        return { key, stationId: s.id, outcomeKey: o.key, count, width: w, d: roundedPath(pts, 18), pts, color: o.color, form: s.form === 'idle' ? 'live' : s.form, mid: [(pts[1][0] + pts[2][0]) / 2, (pts[1][1] + pts[2][1]) / 2] }
      })
      const idleD = strands.length ? null : roundedPath(centre, 18)
      return { station: s, x: x0, y, thickness, strands: geos, idleD }
    })
    return { outcomes, stations, routes }
  }

  // Pass 1 at cy = 0 to measure; the interchange label sits above every line, joined by a leader.
  const probe = place(0)
  const lineTop = Math.min(-ih / 2, ...probe.stations.map((g) => g.y - g.thickness / 2 - 24), ...probe.outcomes.map((g) => g.y - g.width / 2 - 24))
  const lineBottom = Math.max(ih / 2 + 8, ...probe.stations.map((g) => g.y + Math.max(g.thickness / 2, 34)), ...probe.outcomes.map((g) => g.y + 22))
  const label3 = lineTop - 14
  const labelTop = label3 - 31 - 14
  const offset = 16 - labelTop
  const cy = offset
  const { outcomes, stations, routes } = place(cy)
  const H = Math.round(lineBottom + offset + 26)

  return { width: W, height: H, stations, outcomes, interchange: { x: xi, y: cy, w: 24, h: ih }, label: { x: xi, y1: label3 - 31 + offset, y2: label3 - 15 + offset, y3: label3 + offset }, routes, x0, xt }
}
