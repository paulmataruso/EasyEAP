import { createContext, useContext } from 'react'

/** Radix portals render into this element so overlays inherit the concept's scoped tokens. */
export const PortalContext = createContext<HTMLElement | null>(null)
export const usePortal = () => useContext(PortalContext) ?? undefined
