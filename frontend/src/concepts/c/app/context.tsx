// Concept-level navigation and feedback. Screens call `go(screen, { intent })` to move; an intent
// carries the initial state for the destination (a filter, a row to expand, a flow to open).
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import type { ScreenId } from '../../contract'
import type { CertStatus } from '@/domain/types'

export interface UserFilters {
  source: 'all' | 'ad' | 'local'
  access: 'all' | 'allow' | 'deny'
  cert: 'all' | CertStatus | 'none'
  group: string
}

export interface Intent {
  users?: Partial<UserFilters>
  certificates?: { status?: CertStatus | 'all'; expand?: string; focusCas?: boolean }
  radius?: { add?: boolean; expand?: string; focus?: 'controllers' | 'server' }
  policies?: { testIdentityId?: string; focus?: 'test' | 'vlans' | 'rules' }
  user?: { issue?: { deviceName?: string; platform?: string } }
  dashboard?: { focus?: 'failures' | 'activity' }
}

export interface ToastMessage {
  id: number
  title: string
  description?: string
}

interface Ctx {
  go: (screen: ScreenId, opts?: { entityId?: string; intent?: Intent }) => void
  intent: Intent
  /** Increments on every navigation so a screen remounts with fresh initial state. */
  visit: number
  toasts: ToastMessage[]
  toast: (title: string, description?: string) => void
  dismissToast: (id: number) => void
}

const ConceptContext = createContext<Ctx | null>(null)

export function ConceptProvider({ navigate, children }: { navigate: (screen: ScreenId, entityId?: string) => void; children: ReactNode }) {
  const [nav, setNav] = useState<{ intent: Intent; visit: number }>({ intent: {}, visit: 0 })
  const [toasts, setToasts] = useState<ToastMessage[]>([])
  const toastId = useRef(0)
  const navRef = useRef(navigate)
  useEffect(() => {
    navRef.current = navigate
  }, [navigate])

  const go = useCallback<Ctx['go']>((screen, opts) => {
    setNav((n) => ({ intent: opts?.intent ?? {}, visit: n.visit + 1 }))
    navRef.current(screen, opts?.entityId)
  }, [])
  const toast = useCallback((title: string, description?: string) => {
    toastId.current += 1
    const id = toastId.current
    setToasts((ts) => [...ts.slice(-2), { id, title, description }])
  }, [])
  const dismissToast = useCallback((id: number) => setToasts((ts) => ts.filter((t) => t.id !== id)), [])

  const value = useMemo(() => ({ go, intent: nav.intent, visit: nav.visit, toasts, toast, dismissToast }), [go, nav, toasts, toast, dismissToast])
  return <ConceptContext.Provider value={value}>{children}</ConceptContext.Provider>
}

export function useConcept() {
  const ctx = useContext(ConceptContext)
  if (!ctx) throw new Error('ConceptProvider missing')
  return ctx
}
