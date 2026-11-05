import type { ReactNode } from 'react'
import { Ban, Building2, CircleCheck, CircleX, Database, UserRound } from 'lucide-react'
import { cn } from '@/ui/lib'
import { certStatusLabels } from '@/domain/explain'
import type { CertStatus, HealthState, IdentitySource, RuleAction, Vlan } from '@/domain/types'
import { certTone, healthLabel, healthTone, toneIcon, type Tone } from '../lib/status'
import { VLAN_HEX } from '../lib/vlan'

/** Status always ships as icon + label; colour never carries the meaning alone. */
export function StatusBadge({ tone, children, className, title }: { tone: Tone; children: ReactNode; className?: string; title?: string }) {
  const Icon = toneIcon[tone]
  return (
    <span className={cn('b-badge', `b-tone-${tone}`, className)} title={title}>
      <Icon aria-hidden />
      {children}
    </span>
  )
}

/** Icon + text in the tone's ink without the badge box (for dense rows). */
export function StatusText({ tone, children, className }: { tone: Tone; children: ReactNode; className?: string }) {
  const Icon = toneIcon[tone]
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap', `b-ink-${tone}`, className)}>
      <Icon className="size-3.5 shrink-0" aria-hidden />
      <span>{children}</span>
    </span>
  )
}

export function HealthBadge({ state, label }: { state: HealthState; label?: string }) {
  return <StatusBadge tone={healthTone[state]}>{label ?? healthLabel[state]}</StatusBadge>
}

export function CertStatusBadge({ status }: { status: CertStatus }) {
  return <StatusBadge tone={certTone[status]}>{certStatusLabels[status]}</StatusBadge>
}

export function AccessBadge({ outcome }: { outcome: RuleAction }) {
  return outcome === 'allow' ? (
    <span className="b-badge b-tone-ok">
      <CircleCheck aria-hidden />
      Allowed
    </span>
  ) : (
    <span className="b-badge b-tone-crit">
      <CircleX aria-hidden />
      Denied
    </span>
  )
}

export function RuleActionBadge({ action }: { action: RuleAction }) {
  return action === 'allow' ? (
    <span className="b-badge b-tone-ok">
      <CircleCheck aria-hidden />
      Allow
    </span>
  ) : (
    <span className="b-badge b-tone-crit">
      <Ban aria-hidden />
      Deny
    </span>
  )
}

export function SourceBadge({ source }: { source: IdentitySource }) {
  return source === 'ad' ? (
    <span className="b-chip" title="Synchronised from Active Directory">
      <Database className="size-3" aria-hidden />
      AD
    </span>
  ) : (
    <span className="b-chip" title="Local account managed in EasyEAP" style={{ color: 'var(--b-text)' }}>
      <UserRound className="size-3" aria-hidden />
      Local
    </span>
  )
}

/** A VLAN reads the same everywhere: its swatch, its number, then (optionally) its name. */
export function VlanChip({ vlan, showName = true, className }: { vlan: Vlan | undefined | null; showName?: boolean; className?: string }) {
  if (!vlan) return <span className="b-t3">—</span>
  return (
    <span className={cn('b-chip', className)} title={`VLAN ${vlan.vlanId} · ${vlan.name}`}>
      <i className="b-swatch" style={{ background: VLAN_HEX[vlan.color] }} aria-hidden />
      <span className="b-cond b-num font-semibold" style={{ color: 'var(--b-text)', fontSize: 12.5 }}>
        {vlan.vlanId}
      </span>
      {showName && <span className="truncate">{vlan.name}</span>}
    </span>
  )
}

export function TenantGlyph({ className }: { className?: string }) {
  return <Building2 className={cn('size-3.5', className)} aria-hidden />
}
