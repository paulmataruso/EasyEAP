import { Ban, BadgeCheck, CircleCheck, CircleDashed, CircleMinus, CircleX, Clock, FolderTree, Hourglass, Lock, OctagonAlert, TriangleAlert, UserRound, UserX } from 'lucide-react'
import type { AccountState, AuthResult, CertStatus, HealthState, IdentitySource, RuleAction, Vlan } from '@/domain/types'
import { certStatusLabels } from '@/domain/explain'
import { cn } from '@/ui/lib'
import { vlanHex } from '../lib/vlan'
import { Pill, type Tone } from './primitives'

// Status colours are reserved for state and always ship with an icon and a label.

const CERT: Record<CertStatus | 'none', { tone: Tone; icon: typeof CircleCheck }> = {
  active: { tone: 'ok', icon: BadgeCheck },
  expiring: { tone: 'warn', icon: Hourglass },
  expired: { tone: 'danger', icon: Clock },
  revoked: { tone: 'danger', icon: Ban },
  pending: { tone: 'info', icon: CircleDashed },
  none: { tone: 'neutral', icon: CircleMinus },
}

export function CertStatusPill({ status, className }: { status: CertStatus | 'none'; className?: string }) {
  const s = CERT[status]
  return (
    <Pill tone={s.tone} icon={s.icon} className={className}>
      {status === 'none' ? 'No certificate' : certStatusLabels[status]}
    </Pill>
  )
}

export const healthLabels: Record<HealthState, string> = { ok: 'Operational', degraded: 'Degraded', down: 'Down', unconfigured: 'Not configured' }
const HEALTH: Record<HealthState, { tone: Tone; icon: typeof CircleCheck }> = {
  ok: { tone: 'ok', icon: CircleCheck },
  degraded: { tone: 'warn', icon: TriangleAlert },
  down: { tone: 'danger', icon: OctagonAlert },
  unconfigured: { tone: 'neutral', icon: CircleDashed },
}

export function HealthPill({ state, label, className }: { state: HealthState; label?: string; className?: string }) {
  const h = HEALTH[state]
  return (
    <Pill tone={h.tone} icon={h.icon} className={className}>
      {label ?? healthLabels[state]}
    </Pill>
  )
}

export const healthIcon = (state: HealthState) => HEALTH[state].icon
export const healthTextClass = (state: HealthState) =>
  ({ ok: 'text-[var(--a-ok-text)]', degraded: 'text-[var(--a-warn-text)]', down: 'text-[var(--a-danger-text)]', unconfigured: 'text-[var(--a-text-3)]' })[state]

/** A small status dot. Always paired with a text label nearby or an sr-only label. */
export function HealthDot({ state, label, className }: { state: HealthState; label?: string; className?: string }) {
  const color = { ok: 'var(--a-ok)', degraded: 'var(--a-warn)', down: 'var(--a-danger)', unconfigured: 'transparent' }[state]
  return (
    <span className={cn('inline-flex items-center', className)}>
      <span
        className="a-dot"
        style={{ background: color, boxShadow: state === 'unconfigured' ? 'inset 0 0 0 1.5px #94a3b8' : undefined }}
        aria-hidden
      />
      <span className="sr-only">{label ?? healthLabels[state]}</span>
    </span>
  )
}

export function AccessPill({ outcome, className }: { outcome: RuleAction; className?: string }) {
  return outcome === 'allow' ? (
    <Pill tone="ok" icon={CircleCheck} className={className}>
      Allowed
    </Pill>
  ) : (
    <Pill tone="danger" icon={CircleX} className={className}>
      Denied
    </Pill>
  )
}

export function RuleActionPill({ action }: { action: RuleAction }) {
  return action === 'allow' ? (
    <Pill tone="ok" icon={CircleCheck}>
      Allow
    </Pill>
  ) : (
    <Pill tone="danger" icon={Ban}>
      Deny
    </Pill>
  )
}

export function ResultPill({ result }: { result: AuthResult }) {
  return result === 'accept' ? (
    <Pill tone="ok" icon={CircleCheck}>
      Accepted
    </Pill>
  ) : (
    <Pill tone="danger" icon={CircleX}>
      Rejected
    </Pill>
  )
}

const ACCOUNT: Record<AccountState, { tone: Tone; icon: typeof CircleCheck; label: string }> = {
  enabled: { tone: 'ok', icon: CircleCheck, label: 'Account enabled' },
  disabled: { tone: 'danger', icon: UserX, label: 'Account disabled' },
  locked: { tone: 'warn', icon: Lock, label: 'Account locked' },
  deleted: { tone: 'danger', icon: CircleX, label: 'Deleted in directory' },
}

export function AccountPill({ state }: { state: AccountState }) {
  const a = ACCOUNT[state]
  return (
    <Pill tone={a.tone} icon={a.icon}>
      {a.label}
    </Pill>
  )
}

export function SourceBadge({ source, className }: { source: IdentitySource; className?: string }) {
  return source === 'ad' ? (
    <span className={cn('a-tag', className)} title="Synchronised from Active Directory">
      <FolderTree className="size-3.5 text-[#a5b4fc]" aria-hidden />
      Active Directory
    </span>
  ) : (
    <span className={cn('a-tag', className)} title="Local EasyEAP account">
      <UserRound className="size-3.5 text-[#5eead4]" aria-hidden />
      Local
    </span>
  )
}

/** VLAN identity: swatch + number + name. The colour follows the VLAN everywhere in Concept A. */
export function VlanChip({ vlan, compact = false, className }: { vlan: Vlan | null | undefined; compact?: boolean; className?: string }) {
  if (!vlan) return <span className="text-[13px] text-[var(--a-text-3)]">No VLAN</span>
  return (
    <span className={cn('a-tag', className)} title={`${vlan.name}: ${vlan.description}`}>
      <span className="a-vlan-swatch" style={{ background: vlanHex(vlan) }} aria-hidden />
      <span className="a-num text-[var(--a-text)]">{vlan.vlanId}</span>
      {!compact && <span className="truncate">{vlan.name}</span>}
    </span>
  )
}
