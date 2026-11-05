import { Ban, CircleCheck, CircleDashed, CircleMinus, CircleX, Clock, Lock, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import type { CertStatus, HealthState } from '@/domain/types'
import { certStatusLabels } from '@/domain/explain'
import { remaining } from '../model/derive'
import type { Certificate } from '@/domain/types'

export type StatusTone = 'ok' | 'warn' | 'crit' | 'off'

export function StatusMark({ tone, icon, children, className }: { tone: StatusTone; icon?: ReactNode; children: ReactNode; className?: string }) {
  const Icon = tone === 'ok' ? CircleCheck : tone === 'warn' ? TriangleAlert : tone === 'crit' ? CircleX : CircleDashed
  return (
    <span className={`d-status ${className ?? ''}`} data-tone={tone}>
      {icon ?? <Icon aria-hidden="true" />}
      <span>{children}</span>
    </span>
  )
}

const HEALTH: Record<HealthState, { tone: StatusTone; label: string }> = {
  ok: { tone: 'ok', label: 'Healthy' },
  degraded: { tone: 'warn', label: 'Degraded' },
  down: { tone: 'crit', label: 'Down' },
  unconfigured: { tone: 'off', label: 'Not set up' },
}

export function HealthMark({ state, label }: { state: HealthState; label?: string }) {
  const h = HEALTH[state]
  return <StatusMark tone={h.tone}>{label ?? h.label}</StatusMark>
}
export const healthLabel = (s: HealthState) => HEALTH[s].label
export const healthTone = (s: HealthState) => HEALTH[s].tone

export function AccessMark({ outcome, reason }: { outcome: 'allow' | 'deny'; reason?: string }) {
  return outcome === 'allow' ? (
    <StatusMark tone="ok">Allowed</StatusMark>
  ) : (
    <StatusMark tone="crit" icon={<Ban aria-hidden="true" />}>
      {reason ?? 'Denied'}
    </StatusMark>
  )
}

const CERT_TONE: Record<CertStatus, StatusTone> = { active: 'ok', expiring: 'warn', expired: 'crit', revoked: 'off', pending: 'off' }

export function CertStatusMark({ status, label }: { status: CertStatus | 'none'; label?: string }) {
  if (status === 'none') return <StatusMark tone="off" icon={<CircleMinus aria-hidden="true" />}>{label ?? 'No certificate'}</StatusMark>
  const icon = status === 'revoked' ? <Ban aria-hidden="true" /> : status === 'expiring' ? <Clock aria-hidden="true" /> : status === 'pending' ? <Lock aria-hidden="true" /> : undefined
  return <StatusMark tone={CERT_TONE[status]} icon={icon}>{label ?? certStatusLabels[status]}</StatusMark>
}

/** Remaining lifetime, right-aligned tabular figures tight to the margin. */
export function Remaining({ cert }: { cert: Pick<Certificate, 'notAfter' | 'status'> }) {
  const r = remaining(cert)
  const aria = cert.status === 'revoked' ? 'Revoked' : r.days <= 0 ? `Expired ${Math.abs(r.days)} days ago` : `${r.days} days remaining`
  return (
    <span className="d-remaining" data-tone={r.tone === 'ok' ? undefined : r.tone} aria-label={aria} title={aria}>
      {r.text}
    </span>
  )
}
