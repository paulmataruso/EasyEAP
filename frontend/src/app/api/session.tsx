// The signed-in administrator. /api/auth/me is the source of truth; the CSRF token it carries is installed on the
// client for every unsafe request.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, onUnauthorized, setCsrfToken } from './client'
import type { Me } from './types'

interface SessionValue {
  me: Me | null
  loading: boolean
  needsSetup: boolean | null
  signIn: (me: Me) => void
  signOut: () => Promise<void>
  /** Platform-wide permission check from the platform role (tenant permissions come from useTenant()). */
  isPlatform: boolean
  canManageAdmins: boolean
  canCreateTenants: boolean
}

const SessionContext = createContext<SessionValue | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [me, setMe] = useState<Me | null>(null)
  const setup = useQuery({ queryKey: ['setup-status'], queryFn: () => api.get<{ needs_setup: boolean }>('/api/setup/status'), staleTime: 60_000 })
  const meQuery = useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      try { return await api.get<Me>('/api/auth/me') } catch (e) { if (e instanceof ApiError && e.status === 401) return null; throw e }
    },
    enabled: setup.data?.needs_setup === false,
    retry: false,
    staleTime: 5 * 60_000,
  })

  useEffect(() => {
    if (meQuery.data !== undefined) {
      setMe(meQuery.data)
      setCsrfToken(meQuery.data?.csrf_token ?? null)
    }
  }, [meQuery.data])

  useEffect(() => onUnauthorized(() => {
    setMe(null)
    setCsrfToken(null)
    qc.setQueryData(['me'], null)
  }), [qc])

  const signIn = useCallback((m: Me) => {
    setCsrfToken(m.csrf_token)
    setMe(m)
    qc.setQueryData(['me'], m)
    qc.setQueryData(['setup-status'], { needs_setup: false })
  }, [qc])

  const signOut = useCallback(async () => {
    try { await api.post('/api/auth/logout') } catch { /* already signed out */ }
    setCsrfToken(null)
    setMe(null)
    qc.clear()
    qc.setQueryData(['setup-status'], { needs_setup: false })
    qc.setQueryData(['me'], null)
  }, [qc])

  const value = useMemo<SessionValue>(() => ({
    me,
    loading: setup.isLoading || (setup.data?.needs_setup === false && meQuery.isLoading),
    needsSetup: setup.data?.needs_setup ?? null,
    signIn,
    signOut,
    isPlatform: !!me?.platform_role,
    canManageAdmins: me?.platform_role === 'platform_owner',
    canCreateTenants: me?.platform_role === 'platform_owner' || me?.platform_role === 'platform_operator',
  }), [me, setup.isLoading, setup.data, meQuery.isLoading, signIn, signOut])

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}

export function useSession() {
  const ctx = useContext(SessionContext)
  if (!ctx) throw new Error('SessionProvider missing')
  return ctx
}
