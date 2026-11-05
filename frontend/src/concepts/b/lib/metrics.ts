import { now } from '@/prototype/store'
import type { AuthEvent } from '@/domain/types'
import type { HourPoint } from '@/ui/charts'

/** 24 hourly buckets ending at the demo clock (same bucketing as useMetrics().auth.hourly). */
export function bucketHourly(events: AuthEvent[]): HourPoint[] {
  const t0 = now().getTime()
  const buckets = Array.from({ length: 24 }, (_, h) => ({ hourEnd: new Date(t0 - (23 - h) * 3600_000), accept: 0, reject: 0 }))
  for (const e of events) {
    const age = t0 - new Date(e.at).getTime()
    if (age < 0 || age >= 24 * 3600_000) continue
    const idx = 23 - Math.floor(age / 3600_000)
    const b = buckets[idx]
    if (!b) continue
    if (e.result === 'accept') b.accept++
    else b.reject++
  }
  return buckets
}
