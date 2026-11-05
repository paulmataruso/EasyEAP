import { createContext, useContext } from 'react'

/** Radix portals render into this element (inside [data-concept="a"]) so scoped styles apply. */
const PortalContext = createContext<HTMLElement | null>(null)

export const PortalProvider = PortalContext.Provider
export const usePortalContainer = () => useContext(PortalContext) ?? undefined
