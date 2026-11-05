import type { Vlan } from '@/domain/types'

/**
 * Concept A VLAN palette. Validated with the dataviz validator in VLAN-id order
 * (blue, violet, teal, orange, amber, rose, green) against the tenant panel surface #1B2336, dark mode:
 * band PASS, chroma PASS, adjacent CVD ΔE 12.4 (target ≥ 8), normal-vision ΔE 18.3 (floor 15).
 * Violet and orange sit below 3:1 against the surface, so every VLAN mark ships with its
 * number + name as a visible label (relief rule). Hues deliberately avoid the reserved status
 * hues (green, amber, red, sky).
 */
export const VLAN_HEX: Record<Vlan['color'], string> = {
  blue: '#3f90dd',
  violet: '#7d40c8',
  teal: '#2fa094',
  orange: '#a44c1d',
  amber: '#ab942f',
  rose: '#a84f8e',
  green: '#708c34',
  slate: '#64748b',
}

export const vlanHex = (v: Pick<Vlan, 'color'> | null | undefined) => (v ? VLAN_HEX[v.color] : '#64748b')
