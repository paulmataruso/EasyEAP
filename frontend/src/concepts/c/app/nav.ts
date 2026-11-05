import { Activity, BadgeCheck, Ban, Building2, Clock, FlaskConical, Gauge, Landmark, Network, Plus, Router, UserRound, Users, type LucideIcon } from 'lucide-react'
import type { ScreenId } from '../../contract'
import type { Intent } from './context'

export interface NavItem {
  label: string
  description: string
  screen: ScreenId
  intent?: Intent
  icon: LucideIcon
}

export interface NavSection {
  id: 'overview' | 'identity' | 'certificates' | 'network' | 'system'
  label: string
  screens: ScreenId[]
  items: NavItem[]
}

/** Top navigation: five sections, each a menu of real destinations. */
export const SECTIONS: NavSection[] = [
  {
    id: 'overview',
    label: 'Overview',
    screens: ['dashboard'],
    items: [{ label: 'Overview', description: 'Posture, attention and activity', screen: 'dashboard', icon: Gauge }],
  },
  {
    id: 'identity',
    label: 'Identity',
    screens: ['users', 'user'],
    items: [
      { label: 'All users', description: 'Everyone who can request Wi-Fi access', screen: 'users', icon: Users },
      { label: 'Directory users', description: 'Synchronised from Active Directory', screen: 'users', intent: { users: { source: 'ad' } }, icon: Building2 },
      { label: 'Local accounts', description: 'Created in EasyEAP, not in the directory', screen: 'users', intent: { users: { source: 'local' } }, icon: UserRound },
      { label: 'Denied users', description: 'People the policy currently keeps off Wi-Fi', screen: 'users', intent: { users: { access: 'deny' } }, icon: Ban },
    ],
  },
  {
    id: 'certificates',
    label: 'Certificates',
    screens: ['certificates'],
    items: [
      { label: 'All certificates', description: 'Every certificate this tenant has issued', screen: 'certificates', icon: BadgeCheck },
      { label: 'Expiring soon', description: 'Valid for fewer than 30 more days', screen: 'certificates', intent: { certificates: { status: 'expiring' } }, icon: Clock },
      { label: 'Revoked', description: 'Published in the revocation list', screen: 'certificates', intent: { certificates: { status: 'revoked' } }, icon: Ban },
      { label: 'Certificate authorities', description: 'Offline root, issuing CA, CRL and OCSP', screen: 'certificates', intent: { certificates: { focusCas: true } }, icon: Landmark },
    ],
  },
  {
    id: 'network',
    label: 'Network',
    screens: ['radius', 'policies'],
    items: [
      { label: 'RADIUS', description: 'Server settings and wireless controllers', screen: 'radius', icon: Router },
      { label: 'Add a controller', description: 'Register a WLC or UniFi controller', screen: 'radius', intent: { radius: { add: true } }, icon: Plus },
      { label: 'VLAN policies', description: 'VLANs and access rules in precedence order', screen: 'policies', icon: Network },
      { label: 'Test a user', description: 'See the decision and RADIUS reply for anyone', screen: 'policies', intent: { policies: { focus: 'test' } }, icon: FlaskConical },
    ],
  },
  {
    id: 'system',
    label: 'System',
    screens: ['tenants'],
    items: [
      { label: 'Tenants', description: 'Every customer you manage: health and setup', screen: 'tenants', icon: Building2 },
      { label: 'Recent changes', description: 'Audit trail for the current tenant', screen: 'dashboard', intent: { dashboard: { focus: 'activity' } }, icon: Activity },
    ],
  },
]

export const PAGE_LABEL: Record<ScreenId, string> = {
  dashboard: 'Overview',
  users: 'Users',
  user: 'Users',
  certificates: 'Certificates',
  radius: 'RADIUS',
  policies: 'VLAN policies',
  tenants: 'Tenants',
}

export const sectionOf = (screen: ScreenId) => SECTIONS.find((s) => s.screens.includes(screen))
