import '@fontsource/fira-sans/400.css'
import '@fontsource/fira-sans/500.css'
import '@fontsource/fira-sans/600.css'
import '@fontsource/fira-sans/700.css'
import '@fontsource/fira-code/400.css'
import '@fontsource/fira-code/500.css'
import './concept.css'
import { useEffect, useMemo, useState } from 'react'
import { Tooltip } from 'radix-ui'
import { useTenantData, useTenants } from '@/prototype/store'
import type { ConceptModule, ConceptProps, ScreenId } from '../contract'
import { AppShell } from './shell/AppShell'
import { NavProvider, SCREEN_TITLES } from './shell/nav'
import { PortalProvider } from './ui/portal'
import { ToastProvider } from './ui/toast'
import { registerSessionStamps } from './lib/time'
import { Certificates } from './screens/Certificates'
import { Dashboard } from './screens/Dashboard'
import { Policies } from './screens/Policies'
import { Radius } from './screens/Radius'
import { Tenants } from './screens/Tenants'
import { UserDetail } from './screens/UserDetail'
import { Users } from './screens/Users'

const SCREENS: Record<ScreenId, () => React.JSX.Element> = {
  dashboard: Dashboard,
  users: Users,
  user: UserDetail,
  certificates: Certificates,
  radius: Radius,
  policies: Policies,
  tenants: Tenants,
}

function Root({ screen, entityId, navigate }: ConceptProps) {
  const [portal, setPortal] = useState<HTMLDivElement | null>(null)
  const { current } = useTenants()
  const { audit } = useTenantData()
  // Must run before children render so session-created timestamps display on the demo clock.
  useMemo(() => registerSessionStamps(audit), [audit])
  const nav = useMemo(() => ({ screen, entityId, navigate }), [screen, entityId, navigate])
  const Screen = SCREENS[screen]

  useEffect(() => {
    window.scrollTo({ top: 0 })
  }, [screen, current.id])
  useEffect(() => {
    document.title = `${SCREEN_TITLES[screen]} · ${screen === 'tenants' ? 'All tenants' : current.name} · EasyEAP`
  }, [screen, current.name])

  return (
    <div data-concept="a">
      <PortalProvider value={portal}>
        <NavProvider value={nav}>
          <Tooltip.Provider delayDuration={250}>
            <ToastProvider>
              <AppShell>
                <Screen key={`${screen}:${current.id}`} />
              </AppShell>
            </ToastProvider>
          </Tooltip.Provider>
        </NavProvider>
      </PortalProvider>
      <div ref={setPortal} />
    </div>
  )
}

const concept: ConceptModule = {
  id: 'a',
  name: 'Dark Glass Enterprise',
  skill: 'UI/UX Pro Max',
  summary: 'Frosted sidebar console on slate with status-green actions. Signature: glass depth = scope — platform, tenant and record layers sit at three distinct glass depths, mirrored by the scope trail in the top bar and the "Affects" line in every dialog.',
  Root,
}
export default concept
