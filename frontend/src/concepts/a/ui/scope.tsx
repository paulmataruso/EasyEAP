import type { ComponentType, ReactNode } from 'react'
import { ChevronRight, Network } from 'lucide-react'
import type { HealthState } from '@/domain/types'
import { cn } from '@/ui/lib'
import { HealthDot } from './badges'

// Signature move — "glass depth = scope". Each chip wears the glass of the layer it names,
// so the trail at the top of the screen (and in every dialog that changes something) shows
// exactly which scope an action affects: platform (MSP) › tenant › record.

type IconType = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>

export function ScopeChip({ depth, icon: Icon, children, className, health }: { depth: 'platform' | 'tenant' | 'record'; icon?: IconType; children: ReactNode; className?: string; health?: HealthState }) {
  return (
    <span className={cn('a-scope', `a-scope-${depth}`, className)}>
      {health && <HealthDot state={health} />}
      {Icon && <Icon className="size-4 shrink-0 opacity-80" aria-hidden />}
      <span className="truncate">{children}</span>
    </span>
  )
}

export const ScopeSeparator = () => <ChevronRight className="size-4 shrink-0 text-[var(--a-text-3)]" aria-hidden />

/** Compact "Affects" line for dialogs: tenant › record, each at its own depth. */
export function AffectsLine({ tenant, tenantHealth, record, recordIcon, platform }: { tenant?: string; tenantHealth?: HealthState; record?: string; recordIcon?: IconType; platform?: boolean }) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[12px] text-[var(--a-text-3)]">
      <span className="mr-0.5">Affects</span>
      {platform && (
        <ScopeChip depth="platform" icon={Network} className="!h-7 !text-[12px]">
          All tenants
        </ScopeChip>
      )}
      {tenant && (
        <ScopeChip depth="tenant" health={tenantHealth} className="!h-7 !text-[12px]">
          {tenant}
        </ScopeChip>
      )}
      {tenant && record && <ScopeSeparator />}
      {record && (
        <ScopeChip depth="record" icon={recordIcon} className="!h-7 max-w-[260px] !text-[12px]">
          {record}
        </ScopeChip>
      )}
    </div>
  )
}
