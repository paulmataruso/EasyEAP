// Concept-level view state: list filters survive opening a record and coming back,
// and the secondary panel's saved views drive the same filters.
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import type { CertStatus } from '@/domain/types'
import type { UserCertState } from './derive'

export interface UsersFilter {
  query: string
  source: 'all' | 'ad' | 'local'
  access: 'all' | 'allow' | 'deny'
  cert: 'all' | UserCertState
  group: 'all' | string
}
export interface CertsFilter {
  query: string
  status: 'all' | CertStatus
  purpose: 'all' | 'user' | 'device' | 'radius-server'
}
export type TenantsView = 'all' | 'attention' | 'setup'

export const EMPTY_USERS: UsersFilter = { query: '', source: 'all', access: 'all', cert: 'all', group: 'all' }
export const EMPTY_CERTS: CertsFilter = { query: '', status: 'all', purpose: 'all' }

interface ViewState {
  users: UsersFilter
  setUsers: (patch: Partial<UsersFilter> | UsersFilter) => void
  certs: CertsFilter
  setCerts: (patch: Partial<CertsFilter> | CertsFilter) => void
  tenantsView: TenantsView
  setTenantsView: (v: TenantsView) => void
  /** Identity ids in the order the Users list last showed them (j/k on user detail). */
  userOrder: string[]
  setUserOrder: (ids: string[]) => void
  radiusSelected: string | null
  setRadiusSelected: (id: string | null) => void
  /** Certificate to open in the inspector when the Certificates screen mounts. */
  certInspect: string | null
  setCertInspect: (id: string | null) => void
  resetForTenant: () => void
  portal: HTMLElement | null
  setPortal: (el: HTMLElement | null) => void
}

const Ctx = createContext<ViewState | null>(null)

export function ViewStateProvider({ children }: { children: ReactNode }) {
  const [users, setUsersState] = useState<UsersFilter>(EMPTY_USERS)
  const [certs, setCertsState] = useState<CertsFilter>(EMPTY_CERTS)
  const [tenantsView, setTenantsView] = useState<TenantsView>('all')
  const [userOrder, setUserOrder] = useState<string[]>([])
  const [radiusSelected, setRadiusSelected] = useState<string | null>(null)
  const [portal, setPortal] = useState<HTMLElement | null>(null)
  const [certInspect, setCertInspect] = useState<string | null>(null)

  const setUsers = useCallback((patch: Partial<UsersFilter> | UsersFilter) => setUsersState((u) => ({ ...u, ...patch })), [])
  const setCerts = useCallback((patch: Partial<CertsFilter> | CertsFilter) => setCertsState((c) => ({ ...c, ...patch })), [])
  const resetForTenant = useCallback(() => {
    setUsersState(EMPTY_USERS)
    setCertsState(EMPTY_CERTS)
    setUserOrder([])
    setRadiusSelected(null)
    setCertInspect(null)
  }, [])

  const value = useMemo(
    () => ({ users, setUsers, certs, setCerts, tenantsView, setTenantsView, userOrder, setUserOrder, radiusSelected, setRadiusSelected, certInspect, setCertInspect, resetForTenant, portal, setPortal }),
    [users, setUsers, certs, setCerts, tenantsView, userOrder, radiusSelected, certInspect, resetForTenant, portal],
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useViewState() {
  const v = useContext(Ctx)
  if (!v) throw new Error('ViewStateProvider missing')
  return v
}

export const usePortal = () => useViewState().portal ?? undefined
