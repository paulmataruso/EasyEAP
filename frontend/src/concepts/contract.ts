import type { ComponentType } from 'react'

export type ScreenId = 'dashboard' | 'users' | 'user' | 'certificates' | 'radius' | 'policies' | 'tenants'

export const SCREENS: Array<{ id: ScreenId; label: string; sampleEntity?: string }> = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'users', label: 'Users' },
  { id: 'user', label: 'User details', sampleEntity: 't-harborview:u-pnatarajan' },
  { id: 'certificates', label: 'Certificates' },
  { id: 'radius', label: 'RADIUS' },
  { id: 'policies', label: 'VLAN policies' },
  { id: 'tenants', label: 'Tenants (MSP)' },
]

export interface ConceptProps {
  screen: ScreenId
  /** Identity id for the `user` screen */
  entityId?: string
  navigate: (screen: ScreenId, entityId?: string) => void
}

export interface ConceptModule {
  id: 'a' | 'b' | 'c' | 'd' | 'e' | 'f'
  name: string
  skill: 'UI/UX Pro Max' | 'Impeccable'
  summary: string
  Root: ComponentType<ConceptProps>
}
