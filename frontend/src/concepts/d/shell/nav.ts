import { Building2, FileBadge, LayoutDashboard, RadioTower, Users, Waypoints, type LucideIcon } from 'lucide-react'
import type { ScreenId } from '../../contract'

export type SectionId = 'overview' | 'users' | 'certificates' | 'radius' | 'policy' | 'tenants'

export interface SectionDef { id: SectionId; label: string; short: string; screen: ScreenId; icon: LucideIcon }

export const SECTIONS: SectionDef[] = [
  { id: 'overview', label: 'Overview', short: 'Overview', screen: 'dashboard', icon: LayoutDashboard },
  { id: 'users', label: 'Users', short: 'Users', screen: 'users', icon: Users },
  { id: 'certificates', label: 'Certificates', short: 'Certs', screen: 'certificates', icon: FileBadge },
  { id: 'radius', label: 'RADIUS', short: 'RADIUS', screen: 'radius', icon: RadioTower },
  { id: 'policy', label: 'VLAN policies', short: 'Policy', screen: 'policies', icon: Waypoints },
  { id: 'tenants', label: 'Tenants', short: 'Tenants', screen: 'tenants', icon: Building2 },
]

export function sectionOf(screen: ScreenId): SectionId {
  switch (screen) {
    case 'dashboard': return 'overview'
    case 'users':
    case 'user': return 'users'
    case 'certificates': return 'certificates'
    case 'radius': return 'radius'
    case 'policies': return 'policy'
    case 'tenants': return 'tenants'
  }
}

/** In-page anchors for sections whose pages are one long administration sheet. */
export const ANCHORS: Partial<Record<SectionId, Array<{ id: string; label: string }>>> = {
  overview: [
    { id: 'needs-action', label: 'Needs action' },
    { id: 'metrics', label: 'Metrics' },
    { id: 'authentication', label: 'Authentication, 24 h' },
    { id: 'system', label: 'System status' },
    { id: 'activity', label: 'Recent activity' },
  ],
  radius: [
    { id: 'server', label: 'Server settings' },
    { id: 'controllers', label: 'Wireless controllers' },
    { id: 'snippet', label: 'Controller configuration' },
  ],
  policy: [
    { id: 'vlans', label: 'VLANs' },
    { id: 'test', label: 'Test a user' },
    { id: 'rules', label: 'Access rules' },
  ],
}
