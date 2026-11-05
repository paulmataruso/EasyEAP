import type { AuditEvent } from '@/domain/types'
import { daysUntil, formatDate, formatDateTime, relativeTime } from '@/ui/lib'
import { now } from '@/prototype/store'

// The shared store stamps mutations (revocations, secret rotations, new controllers and their
// audit rows) with the real clock, while every seeded record is relative to the fixed demo clock.
// Every mutation also writes an audit row whose id ends in its real creation time
// (`au-<n>-<Date.now()>`), so those instants identify session-created timestamps exactly. They are
// re-expressed on the demo clock (demo now − real elapsed), so a revocation made a moment ago
// reads "just now" instead of hours in the past or future. Seeded values are never shifted.
let sessionStamps: number[] = []

export function registerSessionStamps(audit: AuditEvent[]) {
  const next: number[] = []
  for (const a of audit) {
    const m = /^au-\d+-(\d{13})$/.exec(a.id)
    if (m) next.push(Date.parse(a.at))
  }
  sessionStamps = next
}

export function onDemoClock(iso: string | null): string | null {
  if (!iso || !sessionStamps.length) return iso
  const t = Date.parse(iso)
  if (Number.isNaN(t) || !sessionStamps.some((s) => Math.abs(s - t) < 2000)) return iso
  return new Date(now().getTime() - Math.max(0, Date.now() - t)).toISOString()
}

export const ago = (iso: string | null) => relativeTime(onDemoClock(iso), now())
export const at = (iso: string | null) => formatDateTime(onDemoClock(iso))
export const day = (iso: string | null) => formatDate(onDemoClock(iso))
export const daysLeft = (iso: string) => daysUntil(iso, now())

export function expiryText(iso: string): string {
  const n = daysLeft(iso)
  if (n < 0) return `Expired ${Math.abs(n)} ${Math.abs(n) === 1 ? 'day' : 'days'} ago`
  if (n === 0) return 'Expires today'
  return `${n} ${n === 1 ? 'day' : 'days'} left`
}

export const hhmm = (iso: string) => new Date(iso).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' })
