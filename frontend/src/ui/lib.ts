import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs))

const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
/** "3 minutes ago" / "in 12 days" relative to `now` (pass DEMO_NOW in prototypes). */
export function relativeTime(iso: string | null, now: Date): string {
  if (!iso) return 'Never'
  const diff = new Date(iso).getTime() - now.getTime()
  const abs = Math.abs(diff)
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [['year', 31536e6], ['month', 2592e6], ['day', 864e5], ['hour', 36e5], ['minute', 6e4]]
  for (const [unit, ms] of units) if (abs >= ms) return rtf.format(Math.round(diff / ms), unit)
  return 'just now'
}

export const formatDate = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }) : '—')
export const formatDateTime = (iso: string | null) => (iso ? new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }) + ' UTC' : '—')
export const formatTime = (iso: string) => new Date(iso).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: 'UTC' })
export const formatPercent = (n: number | null, digits = 1) => (n === null ? '—' : `${(n * 100).toFixed(digits)}%`)
export const daysUntil = (iso: string, now: Date) => Math.ceil((new Date(iso).getTime() - now.getTime()) / 864e5)
/** Groups a hex serial into 4-char blocks for legibility: 3F9A 0C11 … */
export const formatSerial = (serial: string) => serial.match(/.{1,4}/g)?.join(' ') ?? serial
export const formatDuration = (seconds: number) => (seconds >= 86400 ? `${Math.round(seconds / 86400)}d` : seconds >= 3600 ? `${Math.round(seconds / 3600)}h` : seconds >= 60 ? `${Math.round(seconds / 60)}m` : `${seconds}s`)

/** Copy text to the clipboard; returns a promise resolving true on success. */
export async function copyText(text: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(text); return true } catch { return false }
}
