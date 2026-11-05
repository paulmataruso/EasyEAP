import type { Vlan } from '@/domain/types'

/** VLAN identity colours. Fixed slot order (validated against the ground, dark mode). */
export const VLAN_COLORS: Record<Vlan['color'], string> = {
  blue: 'var(--c-vlan-blue)',
  violet: 'var(--c-vlan-violet)',
  teal: 'var(--c-vlan-teal)',
  orange: 'var(--c-vlan-orange)',
  amber: 'var(--c-vlan-amber)',
  rose: 'var(--c-vlan-rose)',
  green: 'var(--c-vlan-green)',
  slate: 'var(--c-vlan-slate)',
}

export function VlanSwatch({ vlan }: { vlan: Vlan }) {
  return <span className="c-vlan-swatch" style={{ background: VLAN_COLORS[vlan.color] }} aria-hidden="true" />
}

/** Swatch + number + name. The same mark everywhere a VLAN appears. */
export function VlanTag({ vlan, showName = true }: { vlan: Vlan | undefined | null; showName?: boolean }) {
  if (!vlan) return <span className="c-faint">No VLAN</span>
  return (
    <span className="c-vlan" title={`VLAN ${vlan.vlanId} · ${vlan.name}`}>
      <VlanSwatch vlan={vlan} />
      <span className="c-vlan-id">{vlan.vlanId}</span>
      {showName ? <span className="c-vlan-name">{vlan.name}</span> : <span className="sr-only">{vlan.name}</span>}
    </span>
  )
}
