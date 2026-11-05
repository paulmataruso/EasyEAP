import type { ReactNode } from 'react'
import { Ban, CircleCheck, CircleDashed, CircleX, Clock, TriangleAlert, type LucideIcon } from 'lucide-react'
import type { CertStatus, HealthState, RuleAction } from '@/domain/types'
import { certStatusLabels } from '@/domain/explain'

export type Tone = 'ok' | 'warn' | 'crit' | 'neutral'

/** Icon + label, always together: status colour never carries meaning alone. */
export function StatusMark({ tone, icon: Icon, label, sub, size = 16 }: { tone: Tone; icon: LucideIcon; label: ReactNode; sub?: ReactNode; size?: number }) {
  return (
    <span className="c-status" data-tone={tone}>
      <Icon size={size} strokeWidth={1.9} aria-hidden="true" />
      <span>
        {label}
        {sub ? <span className="c-status-sub"> · {sub}</span> : null}
      </span>
    </span>
  )
}

export const healthMeta: Record<HealthState, { tone: Tone; icon: LucideIcon; label: string }> = {
  ok: { tone: 'ok', icon: CircleCheck, label: 'Healthy' },
  degraded: { tone: 'warn', icon: TriangleAlert, label: 'Degraded' },
  down: { tone: 'crit', icon: CircleX, label: 'Down' },
  unconfigured: { tone: 'neutral', icon: CircleDashed, label: 'Not set up' },
}

export function HealthMark({ state, label, sub }: { state: HealthState; label?: string; sub?: ReactNode }) {
  const m = healthMeta[state]
  return <StatusMark tone={m.tone} icon={m.icon} label={label ?? m.label} sub={sub} />
}

export const certMeta: Record<CertStatus | 'none', { tone: Tone; icon: LucideIcon; label: string }> = {
  active: { tone: 'ok', icon: CircleCheck, label: certStatusLabels.active },
  expiring: { tone: 'warn', icon: Clock, label: certStatusLabels.expiring },
  expired: { tone: 'crit', icon: CircleX, label: certStatusLabels.expired },
  revoked: { tone: 'neutral', icon: Ban, label: certStatusLabels.revoked },
  pending: { tone: 'neutral', icon: CircleDashed, label: certStatusLabels.pending },
  none: { tone: 'neutral', icon: CircleDashed, label: 'No certificate' },
}

export function CertMark({ status, sub }: { status: CertStatus | 'none'; sub?: ReactNode }) {
  const m = certMeta[status]
  return <StatusMark tone={m.tone} icon={m.icon} label={m.label} sub={sub} />
}

export function AccessMark({ outcome, sub }: { outcome: RuleAction; sub?: ReactNode }) {
  return outcome === 'allow' ? <StatusMark tone="ok" icon={CircleCheck} label="Allowed" sub={sub} /> : <StatusMark tone="crit" icon={Ban} label="Denied" sub={sub} />
}
