import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Tooltip } from 'radix-ui'
import type { ConceptProps, ScreenId } from '@/concepts/contract'
import { PortalContext } from '../ui/portal'
import { ToastHost } from '../ui/Toast'
import { useReducedMotion } from '../lib/hooks'
import { ShellContext, type GoOptions, type Intent, type ShellApi } from './context'
import { PortfolioProvider } from './portfolio'
import { InspectorHost } from './Inspectors'
import { IconRail } from './IconRail'
import { TenantTabs } from './TenantTabs'
import { ServiceStrip } from './ServiceStrip'
import { Dashboard } from '../screens/Dashboard'
import { UsersScreen } from '../screens/Users'
import { UserDetail } from '../screens/UserDetail'
import { CertificatesScreen } from '../screens/Certificates'
import { RadiusScreen } from '../screens/Radius'
import { PoliciesScreen } from '../screens/Policies'
import { TenantsScreen } from '../screens/Tenants'

/** Concept B app shell: icon rail · pinned-tenant tabs · live service strip · screen. */
export function Shell({ screen, entityId, navigate }: ConceptProps) {
  const [portalEl, setPortalEl] = useState<HTMLDivElement | null>(null)
  const [intent, setIntent] = useState<Intent | null>(null)
  const seq = useRef(0)
  const reducedMotion = useReducedMotion()
  const navRef = useRef(navigate)
  useEffect(() => {
    navRef.current = navigate
  })

  const go = useCallback((s: ScreenId, opts?: GoOptions) => {
    if (opts?.section || opts?.filters) setIntent({ id: ++seq.current, screen: s, section: opts.section, filters: opts.filters })
    navRef.current(s, opts?.entityId)
  }, [])
  const clearIntent = useCallback(() => setIntent(null), [])

  const api = useMemo<ShellApi>(() => ({ screen, entityId, go, intent, clearIntent, reducedMotion }), [screen, entityId, go, intent, clearIntent, reducedMotion])

  useEffect(() => {
    window.scrollTo({ top: 0 })
  }, [screen, entityId])

  return (
    <div data-concept="b">
      <PortalContext.Provider value={portalEl}>
        <Tooltip.Provider delayDuration={350} skipDelayDuration={150}>
          <ToastHost>
            <ShellContext.Provider value={api}>
              <PortfolioProvider>
                <InspectorHost>
                  <button
                    type="button"
                    className="sr-only fixed top-2 left-2 z-[100] focus:not-sr-only focus:rounded focus:bg-[var(--b-cyan)] focus:px-3 focus:py-1.5 focus:text-[var(--b-cyan-ink)]"
                    onClick={() => document.getElementById('b-main')?.focus()}
                  >
                    Skip to content
                  </button>
                  <IconRail />
                  <div className="b-main">
                    <header className="b-header">
                      <TenantTabs />
                      <ServiceStrip />
                    </header>
                    <main id="b-main" tabIndex={-1} className="mx-auto w-full max-w-[1760px] px-4 pt-4 pb-8 outline-none">
                      <ScreenView screen={screen} entityId={entityId} />
                    </main>
                  </div>
                </InspectorHost>
              </PortfolioProvider>
            </ShellContext.Provider>
          </ToastHost>
        </Tooltip.Provider>
      </PortalContext.Provider>
      <div ref={setPortalEl} />
    </div>
  )
}

function ScreenView({ screen, entityId }: { screen: ScreenId; entityId?: string }) {
  switch (screen) {
    case 'dashboard':
      return <Dashboard />
    case 'users':
      return <UsersScreen />
    case 'user':
      return <UserDetail entityId={entityId} />
    case 'certificates':
      return <CertificatesScreen />
    case 'radius':
      return <RadiusScreen />
    case 'policies':
      return <PoliciesScreen />
    case 'tenants':
      return <TenantsScreen />
  }
}
