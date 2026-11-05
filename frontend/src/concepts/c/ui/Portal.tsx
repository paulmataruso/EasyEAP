import type { ReactNode } from 'react'

/**
 * Radix portals render into <body>, outside the concept root. Wrapping portalled content in a
 * scoped element keeps the concept's tokens and classes applying to menus, sheets and tooltips.
 */
export function ConceptPortal({ children }: { children: ReactNode }) {
  return <div data-concept="c">{children}</div>
}
