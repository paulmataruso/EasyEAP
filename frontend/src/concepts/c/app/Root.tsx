import { useEffect, useLayoutEffect } from 'react'
import { Tooltip } from 'radix-ui'
import { useTenantData, useTenants } from '@/prototype/store'
import { SCREENS, type ConceptProps } from '../../contract'
import { ConceptProvider, useConcept } from './context'
import { TopBar } from './TopBar'
import { Toaster } from '../ui/Toaster'
import { Dashboard } from '../screens/Dashboard'
import { UsersScreen } from '../screens/Users'
import { UserDetail } from '../screens/UserDetail'
import { CertificatesScreen } from '../screens/Certificates'
import { RadiusScreen } from '../screens/Radius'
import { PoliciesScreen } from '../screens/Policies'
import { TenantsScreen } from '../screens/Tenants'
import { useRememberCurrentTenant } from '../lib/portfolio'

export function Root(props: ConceptProps) {
  return (
    <ConceptProvider navigate={props.navigate}>
      <Tooltip.Provider delayDuration={250}>
        <Shell {...props} />
      </Tooltip.Provider>
    </ConceptProvider>
  )
}

function Shell({ screen, entityId }: ConceptProps) {
  const { current } = useTenants()
  const d = useTenantData()
  const { visit, intent } = useConcept()
  useRememberCurrentTenant()
  const userId = screen === 'user' ? resolveUserId(entityId, d) : entityId
  const person = screen === 'user' ? d.identities.find((i) => i.id === userId) : undefined

  // Every navigation starts at the top of the page, unless an intent scrolls somewhere specific.
  useLayoutEffect(() => {
    window.scrollTo({ top: 0 })
  }, [screen, entityId, visit, current.id])

  useEffect(() => {
    document.title = `${person?.displayName ?? PAGE_TITLES[screen]} · ${current.name} · EasyEAP`
  }, [screen, person, current.name])

  const key = `${screen}:${entityId ?? ''}:${visit}:${current.id}`
  return (
    <div data-concept="c" className="c-app">
      <a href="#c-main" className="c-skip">
        Skip to content
      </a>
      <TopBar screen={screen} entityLabel={person?.displayName} />
      <main id="c-main" tabIndex={-1} className="c-container c-main" key={key} style={{ outline: 'none' }}>
        {screen === 'dashboard' && <Dashboard intent={intent} />}
        {screen === 'users' && <UsersScreen intent={intent} />}
        {screen === 'user' && <UserDetail identityId={userId} intent={intent} />}
        {screen === 'certificates' && <CertificatesScreen intent={intent} />}
        {screen === 'radius' && <RadiusScreen intent={intent} />}
        {screen === 'policies' && <PoliciesScreen intent={intent} />}
        {screen === 'tenants' && <TenantsScreen />}
      </main>
      <footer className="c-container">
        <div className="c-footer">
          <span>EasyEAP · Enterprise Wi-Fi Authentication, Simplified.</span>
          <span>Synthetic demonstration data. Demo clock: Nov 5, 2026, 10:42 UTC.</span>
        </div>
      </footer>
      <Toaster />
    </div>
  )
}

/**
 * The contract's sample entity (t-harborview:u-pnatarajan) is not produced by the sample-data
 * generator. When that exact id is missing, show the person from the tenant's latest certificate
 * issue instead (matched by first name), so the user-details screen always has someone to show.
 * Any other unknown id still gets the not-found state.
 */
function resolveUserId(entityId: string | undefined, d: ReturnType<typeof useTenantData>): string | undefined {
  if (!entityId || d.identities.some((i) => i.id === entityId)) return entityId
  if (entityId !== SCREENS.find((s) => s.id === 'user')?.sampleEntity) return entityId
  const first = d.audit.find((a) => a.action === 'certificate.issue' && a.tenantId === d.tenantId)?.target.split(' ')[0]
  const byName = first ? d.identities.find((i) => i.displayName.startsWith(`${first} `)) : undefined
  return (byName ?? d.identities.find((i) => d.devices.some((x) => x.identityId === i.id)))?.id ?? entityId
}

const PAGE_TITLES: Record<ConceptProps['screen'], string> = {
  dashboard: 'Overview',
  users: 'Users',
  user: 'User',
  certificates: 'Certificates',
  radius: 'RADIUS',
  policies: 'VLAN policies',
  tenants: 'Tenants',
}
