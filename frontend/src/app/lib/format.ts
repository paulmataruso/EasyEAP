// One formatter for every date in the console: explicit years, the viewer's time zone named, and true relative
// future ("in 5 days"), never "just now" for a time that hasn't happened yet.

const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
const dateFmt = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
const dateTimeFmt = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZoneName: 'short' })
const timeFmt = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
const timeSecFmt = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' })
const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })

const valid = (iso: string | null | undefined): iso is string => !!iso && !Number.isNaN(new Date(iso).getTime())

/** "5 Nov 2026" */
export const fmtDate = (iso: string | null | undefined) => (valid(iso) ? dateFmt.format(new Date(iso)) : '—')
/** "5 Nov 2026, 10:42 GMT+1" */
export const fmtDateTime = (iso: string | null | undefined) => (valid(iso) ? dateTimeFmt.format(new Date(iso)) : '—')
/** "10:42" (local); use only beside a date or in a list already grouped by day. */
export const fmtTime = (iso: string | null | undefined, seconds = false) => (valid(iso) ? (seconds ? timeSecFmt : timeFmt).format(new Date(iso)) : '—')
export const timeZoneName = tz

/** "3 minutes ago", "in 5 days", "yesterday". Sub-minute: "less than a minute ago" / "in under a minute". */
export function relative(iso: string | null | undefined, now: Date = new Date()): string {
  if (!valid(iso)) return 'never'
  const diff = new Date(iso).getTime() - now.getTime()
  const abs = Math.abs(diff)
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [['year', 31_536e6], ['month', 2_592e6], ['week', 6048e5], ['day', 864e5], ['hour', 36e5], ['minute', 6e4]]
  for (const [unit, ms] of units) {
    if (abs >= ms) {
      // Avoid "in 0 days" from rounding: floor toward zero, minimum 1.
      const n = Math.max(1, Math.floor(abs / ms))
      return rtf.format(diff < 0 ? -n : n, unit)
    }
  }
  return diff < 0 ? 'less than a minute ago' : 'in under a minute'
}

/** Whole days from now until iso (negative when past). */
export const daysUntil = (iso: string, now: Date = new Date()) => Math.floor((new Date(iso).getTime() - now.getTime()) / 864e5)

/** Validity remaining as a right-aligned figure: "212 days", "9 hours", "Expired 3 days ago". */
export function remaining(iso: string, now: Date = new Date()): string {
  const ms = new Date(iso).getTime() - now.getTime()
  if (ms <= 0) return `Expired ${relative(iso, now)}`
  const d = Math.floor(ms / 864e5)
  if (d >= 1) return `${d} day${d === 1 ? '' : 's'}`
  const h = Math.max(1, Math.floor(ms / 36e5))
  return `${h} hour${h === 1 ? '' : 's'}`
}

/** "a few seconds" / "12 minutes" / "3 hours" / "2 days" for durations in seconds. */
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—'
  const s = Math.round(seconds)
  if (s < 60) return `${s} second${s === 1 ? '' : 's'}`
  if (s < 3600) { const m = Math.round(s / 60); return `${m} minute${m === 1 ? '' : 's'}` }
  if (s < 86_400) { const h = Math.round(s / 360) / 10; return `${h} hour${h === 1 ? '' : 's'}` }
  const d = Math.round(s / 8640) / 10
  return `${d} day${d === 1 ? '' : 's'}`
}

export const fmtPercent = (n: number | null | undefined, digits = 1) => (n === null || n === undefined ? '—' : `${(n * 100).toFixed(digits)}%`)
export const fmtCount = (n: number | null | undefined) => (n === null || n === undefined ? '—' : n.toLocaleString('en-GB'))
export const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString('en-GB')} ${n === 1 ? one : many}`

/** Hex serial grouped in 4-character blocks: "3F9A 0C11 …". */
export const fmtSerial = (serial: string) => serial.toUpperCase().match(/.{1,4}/g)?.join(' ') ?? serial
export const shortSerial = (serial: string) => `${fmtSerial(serial.slice(0, 12))}…`
/** SHA-256 fingerprint as colon pairs. */
export const fmtFingerprint = (hex: string) => hex.toUpperCase().match(/.{2}/g)?.join(':') ?? hex
