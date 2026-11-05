import { now } from '@/prototype/store'
import { relativeTime } from '@/ui/lib'

/** Relative time against the demo clock. Store mutations stamp real wall-clock times, which can sit
 *  after the fixed demo clock; those read as "just now" rather than "in 3 hours". */
export function rel(iso: string | null): string {
  if (!iso) return 'Never'
  if (new Date(iso).getTime() > now().getTime()) return 'just now'
  return relativeTime(iso, now())
}

/** Compact age for telemetry: 4s · 11m · 3h 12m · 26h · 3d 4h */
export function formatAge(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds)) return '—'
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 24) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`
  const d = Math.floor(h / 24)
  if (d < 3) return `${h}h`
  return h % 24 ? `${d}d ${h % 24}h` : `${d}d`
}

export const secondsSince = (iso: string | null, at: Date = now()) => (iso ? Math.max(0, (at.getTime() - new Date(iso).getTime()) / 1000) : null)
export const secondsUntil = (iso: string | null, at: Date = now()) => (iso ? (new Date(iso).getTime() - at.getTime()) / 1000 : null)

/** 10:42:05 UTC from a Date */
export const clockUTC = (d: Date) => d.toISOString().slice(11, 19)
/** 10:42 from an ISO string */
export const hhmm = (iso: string) => iso.slice(11, 16)

/** Short serial for table cells: 3F9A 0C11 7B2E… (full serial lives in the inspector). */
export const shortSerial = (serial: string) => `${serial.slice(0, 4)} ${serial.slice(4, 8)} ${serial.slice(8, 12)}…`

export const pluralize = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`

export const initials = (name: string) =>
  name
    .split(/\s+/)
    .map((p) => p[0])
    .join('')
    .slice(0, 2)
    .toUpperCase()
