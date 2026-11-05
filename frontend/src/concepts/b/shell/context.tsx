import { createContext, useContext, useEffect, useRef } from 'react'
import type { ScreenId } from '@/concepts/contract'

export interface Intent {
  id: number
  screen: ScreenId
  /** Scroll target: element id `b-sec-<section>` */
  section?: string
  /** Initial filter values for the target screen's table */
  filters?: Record<string, string>
}

export interface GoOptions {
  entityId?: string
  section?: string
  filters?: Record<string, string>
}

export interface ShellApi {
  screen: ScreenId
  entityId?: string
  go: (screen: ScreenId, opts?: GoOptions) => void
  intent: Intent | null
  clearIntent: () => void
  reducedMotion: boolean
}

export const ShellContext = createContext<ShellApi | null>(null)

export function useShell(): ShellApi {
  const ctx = useContext(ShellContext)
  if (!ctx) throw new Error('Concept B shell missing')
  return ctx
}

/** Applies a pending navigation intent (filters / section scroll) addressed to this screen, once. */
export function useIntent(screen: ScreenId, apply?: (intent: Intent) => void) {
  const { intent, clearIntent, reducedMotion } = useShell()
  const applyRef = useRef(apply)
  useEffect(() => {
    applyRef.current = apply
  })
  useEffect(() => {
    if (!intent || intent.screen !== screen) return
    applyRef.current?.(intent)
    if (intent.section) {
      const id = `b-sec-${intent.section}`
      requestAnimationFrame(() => document.getElementById(id)?.scrollIntoView({ block: 'start', behavior: reducedMotion ? 'auto' : 'smooth' }))
    }
    clearIntent()
  }, [intent, screen, clearIntent, reducedMotion])
}
