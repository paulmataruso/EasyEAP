import type { Vlan } from '@/domain/types'

/**
 * VLAN categorical palette, fixed order (blue, violet, teal, orange, amber, rose, green).
 * Validated with the dataviz validator against the panel surface #111821 (dark):
 * lightness band, chroma floor, adjacent CVD ΔE ≥ 8 and normal-vision ΔE ≥ 15 all pass.
 * Slate is the neutral "unassigned" swatch and sits outside the categorical set.
 */
export const VLAN_HEX: Record<Vlan['color'], string> = {
  blue: '#2963cc',
  violet: '#9b7fec',
  teal: '#12a084',
  orange: '#bf3f1d',
  amber: '#b39000',
  rose: '#c8487a',
  green: '#4f9a2a',
  slate: '#6b7a8f',
}

/** Ink for a label set inside a VLAN fill: white or near-black by luminance. */
export function inkOn(hex: string): string {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
  const L = 0.2126 * r + 0.7152 * g + 0.0722 * b
  return (1.05 / (L + 0.05)) >= ((L + 0.05) / 0.055) ? '#ffffff' : '#0b0f14'
}
