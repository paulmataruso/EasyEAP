// Concept E: night-map tokens shared by TS (SVG fills) and CSS (custom properties in concept.css).
import type { HealthState, Vlan } from '@/domain/types'
import { now } from '@/prototype/store'
import { relativeTime } from '@/ui/lib'

/**
 * Transit line colours for VLANs. Validated as a categorical set on the map ground #0A0E17
 * (dataviz validate_palette.js --mode dark): on-map order 100,110,120,130,150 + Rejected
 * passes every check (worst adjacent CVD ΔE 8.9, normal-vision 16.8, all ≥ 3:1).
 * `ink` is the label colour inside the line bullet, picked for ≥ 4.5:1 (WCAG 2).
 */
export const LINE: Record<Vlan['color'], { hex: string; ink: string; name: string }> = {
  blue: { hex: '#0C84FA', ink: '#0A0E17', name: 'Blue line' },
  violet: { hex: '#8038D1', ink: '#FFFFFF', name: 'Violet line' },
  teal: { hex: '#0BAA92', ink: '#0A0E17', name: 'Teal line' },
  orange: { hex: '#A74A04', ink: '#FFFFFF', name: 'Orange line' },
  amber: { hex: '#AF8E2A', ink: '#0A0E17', name: 'Gold line' },
  green: { hex: '#097F23', ink: '#FFFFFF', name: 'Green line' },
  rose: { hex: '#C20D80', ink: '#FFFFFF', name: 'Rose line' },
  slate: { hex: '#BB6802', ink: '#0A0E17', name: 'Brown line' },
}

/** The Rejected terminus: status-critical red, validated adjacent to the gold line. */
export const REJECT = { hex: '#D81327', ink: '#FFFFFF' }

export const STATUS: Record<HealthState, { hex: string; label: string }> = {
  ok: { hex: '#3FB950', label: 'Operational' },
  degraded: { hex: '#E3B341', label: 'Degraded' },
  down: { hex: '#D81327', label: 'Down' },
  unconfigured: { hex: '#8B96A8', label: 'Not configured' },
}

export const INK = {
  ground: '#0A0E17',
  surface: '#0E1320',
  station: '#F4F7FB',
  text: '#E7ECF3',
  text2: '#A7B1C2',
  text3: '#8B96A8',
  hair: '#222B3C',
  neutralLine: '#5B677C',
}

// ── One fixed magnitude ramp (24h authentications) ────────────────────────────
// Line weight on the route map, event-dot size and every volume glyph read from this
// single ramp, so the same weight means the same volume on every screen and tenant.
export const RAMP: Array<{ min: number; max: number | null; width: number; label: string }> = [
  { min: 1, max: 4, width: 2, label: '1–4' },
  { min: 5, max: 14, width: 3.5, label: '5–14' },
  { min: 15, max: 39, width: 5, label: '15–39' },
  { min: 40, max: 99, width: 7, label: '40–99' },
  { min: 100, max: null, width: 9.5, label: '100+' },
]
export const IDLE_WIDTH = 2

export function rampStep(count: number) {
  if (count <= 0) return -1
  for (let i = RAMP.length - 1; i >= 0; i--) if (count >= RAMP[i].min) return i
  return 0
}
export const lineWidth = (count: number) => (count <= 0 ? IDLE_WIDTH : RAMP[rampStep(count)].width)
/** Event dots ride the line they travel on: diameter = line weight + 3px. */
export const dotRadius = (count: number) => lineWidth(count) / 2 + 1.5

// ── Line form carries state as well as hue ─────────────────────────────────────
export type LineForm = 'live' | 'idle' | 'degraded' | 'disabled'
export const LINE_FORM_LABEL: Record<LineForm, string> = {
  live: 'Solid: live traffic',
  idle: 'Dashed: configured, idle',
  degraded: 'Faded: stale or degraded',
  disabled: 'Struck: disabled',
}
export function formStyle(form: LineForm, width: number) {
  switch (form) {
    case 'idle':
      return { strokeDasharray: `${Math.max(4, width * 2)} ${Math.max(4, width * 1.6)}`, opacity: 0.9 }
    case 'degraded':
      return { strokeDasharray: undefined, opacity: 0.38 }
    case 'disabled':
      return { strokeDasharray: undefined, opacity: 0.5 }
    default:
      return { strokeDasharray: undefined, opacity: 1 }
  }
}

export const vlanColor = (v: Vlan | undefined | null) => (v ? LINE[v.color] : { hex: INK.neutralLine, ink: '#FFFFFF', name: 'No line' })

// Relative times read against the fixed demo clock. The store stamps rows created during this
// session (revocations, new controllers, rotations, audit entries) with the wall clock, so those
// are read against the wall clock instead; everything else stays on DEMO_NOW.
const sessionKeys = new Set<string>()
export const markSession = (key: string) => sessionKeys.add(key)
export const isSession = (key: string) => sessionKeys.has(key)
export const isSessionAudit = (id: string) => /^au-\d+-\d{12,}$/.test(id)
export const isSessionClient = (id: string) => /nas-\d+-\d{12,}$/.test(id)

export function ago(iso: string | null, live = false) {
  if (!iso) return 'Never'
  return relativeTime(iso, live ? new Date() : now())
}

export function healthWorst(states: HealthState[]): HealthState {
  if (states.includes('down')) return 'down'
  if (states.includes('degraded')) return 'degraded'
  if (states.every((s) => s === 'unconfigured')) return 'unconfigured'
  if (states.includes('unconfigured')) return 'degraded'
  return 'ok'
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`
