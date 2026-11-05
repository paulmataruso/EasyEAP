import type { LucideIcon } from 'lucide-react'
import { CircleCheck, CircleDashed, CircleX, Info, TriangleAlert } from 'lucide-react'
import type { CertStatus, HealthState } from '@/domain/types'

export type Tone = 'ok' | 'warn' | 'crit' | 'neutral' | 'info'

export const toneIcon: Record<Tone, LucideIcon> = {
  ok: CircleCheck,
  warn: TriangleAlert,
  crit: CircleX,
  neutral: CircleDashed,
  info: Info,
}

export const healthTone: Record<HealthState, Tone> = { ok: 'ok', degraded: 'warn', down: 'crit', unconfigured: 'neutral' }
export const healthLabel: Record<HealthState, string> = { ok: 'Healthy', degraded: 'Degraded', down: 'Down', unconfigured: 'Not set up' }

export const certTone: Record<CertStatus, Tone> = { active: 'ok', expiring: 'warn', expired: 'crit', revoked: 'neutral', pending: 'info' }

const rank: Record<Tone, number> = { crit: 4, warn: 3, neutral: 1, info: 1, ok: 0 }
/** Worst tone wins (crit > warn > neutral > ok). */
export function worstTone(tones: Tone[]): Tone {
  return tones.reduce<Tone>((w, t) => (rank[t] > rank[w] ? t : w), 'ok')
}
