import { createContext, useContext, type ComponentType } from 'react'
import { Building2, FileBadge, LayoutDashboard, Router, Users, Waypoints } from 'lucide-react'
import type { ConceptProps, ScreenId } from '../../contract'

export interface NavContextValue {
  screen: ScreenId
  entityId?: string
  navigate: ConceptProps['navigate']
}

const NavContext = createContext<NavContextValue | null>(null)
export const NavProvider = NavContext.Provider
export function useNav(): NavContextValue {
  const ctx = useContext(NavContext)
  if (!ctx) throw new Error('NavProvider missing')
  return ctx
}

export interface NavItem {
  screen: ScreenId
  label: string
  icon: ComponentType<{ className?: string; 'aria-hidden'?: boolean }>
  /** Platform-scoped destinations wear the platform glass in the nav */
  platform?: boolean
  /** Screens that highlight this item */
  also?: ScreenId[]
}

export const NAV: Array<{ group: string; items: NavItem[] }> = [
  { group: 'Overview', items: [{ screen: 'dashboard', label: 'Dashboard', icon: LayoutDashboard }] },
  { group: 'Identity', items: [{ screen: 'users', label: 'Users', icon: Users, also: ['user'] }] },
  { group: 'Certificates', items: [{ screen: 'certificates', label: 'Certificates', icon: FileBadge }] },
  {
    group: 'Network',
    items: [
      { screen: 'radius', label: 'RADIUS', icon: Router },
      { screen: 'policies', label: 'VLAN policies', icon: Waypoints },
    ],
  },
  { group: 'System', items: [{ screen: 'tenants', label: 'Tenants', icon: Building2, platform: true }] },
]

export const SCREEN_TITLES: Record<ScreenId, string> = {
  dashboard: 'Dashboard',
  users: 'Users',
  user: 'User details',
  certificates: 'Certificates',
  radius: 'RADIUS',
  policies: 'VLAN policies',
  tenants: 'Tenants',
}
