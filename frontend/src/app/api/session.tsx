// The signed-in administrator. /api/auth/me is the source of truth; the CSRF token it carries is installed on the
// client for every unsafe request.
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from 'react'
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
const isSessionKey = (key: readonly unknown[]) => key[0] === 'me' || key[0] === 'setup-status'

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const setup = useQuery({ queryKey: ['setup-status'], queryFn: () => api.get<{ needs_setup: boolean }>('/api/setup/status'), staleTime: 60_000 })
  // `me` is read straight from the query (never copied into state in an effect), so there is no render in which
  // loading is false but the session isn't known yet: deep links opened in a new tab survive the first load.
  const meQuery = useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      try {
        const m = await api.get<Me>('/api/auth/me')
        setCsrfToken(m.csrf_token)
        return m
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) { setCsrfToken(null); return null }
        throw e
      }
    },
    enabled: setup.data?.needs_setup === false,
    retry: false,
    staleTime: 5 * 60_000,
  })
  const me = meQuery.data ?? null

  useEffect(() => { setCsrfToken(meQuery.data?.csrf_token ?? null) }, [meQuery.data])

  useEffect(() => onUnauthorized(() => {
    setCsrfToken(null)
    qc.setQueryData(['me'], null)
  }), [qc])

  const signIn = useCallback((m: Me) => {
    setCsrfToken(m.csrf_token)
    qc.setQueryData(['me'], m)
    qc.setQueryData(['setup-status'], { needs_setup: false })
  }, [qc])

  const signOut = useCallback(async () => {
    try { await api.post('/api/auth/logout') } catch { /* already signed out */ }
    setCsrfToken(null)
    // Clear the session through the cache entry the mounted observers watch, so every screen sees "signed out" now and
    // RequireSession sends the browser to sign-in. (queryClient.clear() would detach those observers: the page would
    // stay up and every later request would just fail with "sign in".) Then drop everything else this admin loaded.
    qc.setQueryData(['me'], null)
    qc.setQueryData(['setup-status'], { needs_setup: false })
    void qc.cancelQueries({ predicate: (q) => !isSessionKey(q.queryKey) })
    qc.removeQueries({ predicate: (q) => !isSessionKey(q.queryKey) })
  }, [qc])

  const value = useMemo<SessionValue>(() => ({
    me,
    loading: setup.isLoading || (setup.data?.needs_setup === false && meQuery.data === undefined && !meQuery.isError),
    needsSetup: setup.data?.needs_setup ?? null,
    signIn,
    signOut,
    isPlatform: !!me?.platform_role,
    canManageAdmins: me?.platform_role === 'platform_owner',
    canCreateTenants: me?.platform_role === 'platform_owner' || me?.platform_role === 'platform_operator',
  }), [me, setup.isLoading, setup.data, meQuery.data, meQuery.isError, signIn, signOut])

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}

export function useSession() {
  const ctx = useContext(SessionContext)
  if (!ctx) throw new Error('SessionProvider missing')
  return ctx
}
