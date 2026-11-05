import '@fontsource-variable/overpass'
import '@fontsource-variable/overpass-mono'
import './concept.css'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Toast, Tooltip } from 'radix-ui'
import type { ConceptModule, ConceptProps, ScreenId } from '../contract'
import { Shell } from './Shell'
import { CommandPalette } from './CommandPalette'
import { ConceptCtx, ToastLayer, useToasts, type Intent } from './ui'
import { useRecordTenantStats } from './bits'
import { Dashboard } from './screens/Dashboard'
import { Users } from './screens/Users'
import { UserDetail } from './screens/UserDetail'
import { Certificates } from './screens/Certificates'
import { Radius } from './screens/Radius'
import { Policies } from './screens/Policies'
import { Tenants } from './screens/Tenants'

const TITLES: Record<ScreenId, string> = {
  dashboard: 'Dashboard', users: 'Users', user: 'User details', certificates: 'Certificates', radius: 'RADIUS', policies: 'VLAN policies', tenants: 'Tenants',
}

function Root({ screen, entityId, navigate }: ConceptProps) {
  const [container, setContainer] = useState<HTMLDivElement | null>(null)
  // Intents are addressed to a screen, so the screen being left never consumes one meant for the next.
  const [pending, setPending] = useState<{ screen: ScreenId; intent: Intent } | null>(null)
  const intent = pending && pending.screen === screen ? pending.intent : null
  const [palette, setPalette] = useState(false)
  const toasts = useToasts()

  const go = useCallback((s: ScreenId, opts?: { entityId?: string; intent?: Intent }) => {
    setPending(opts?.intent ? { screen: s, intent: opts.intent } : null)
    navigate(s, opts?.entityId)
  }, [navigate])
  const clearIntent = useCallback(() => setPending(null), [])
  const openPalette = useCallback(() => setPalette(true), [])
  const ctx = useMemo(() => ({ navigate, go, container, toast: toasts.push, intent, clearIntent, openPalette }), [navigate, go, container, toasts.push, intent, clearIntent, openPalette])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      const typing = !!target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((p) => !p) }
      else if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey) { e.preventDefault(); setPalette(true) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    window.scrollTo(0, 0)
    document.title = `${TITLES[screen]} · EasyEAP`
  }, [screen, entityId])

  return (
    <div data-concept="e" ref={setContainer}>
      <ConceptCtx.Provider value={ctx}>
        <Tooltip.Provider delayDuration={250}>
          <Toast.Provider swipeDirection="down" label="Notification">
            <StatsRecorder />
            <Shell screen={screen}>
              {screen === 'dashboard' && <Dashboard />}
              {screen === 'users' && <Users />}
              {screen === 'user' && <UserDetail entityId={entityId} />}
              {screen === 'certificates' && <Certificates entityId={entityId} />}
              {screen === 'radius' && <Radius entityId={entityId} />}
              {screen === 'policies' && <Policies />}
              {screen === 'tenants' && <Tenants />}
            </Shell>
            <CommandPalette open={palette} onOpenChange={setPalette} />
            <ToastLayer items={toasts.items} remove={toasts.remove} />
          </Toast.Provider>
        </Tooltip.Provider>
      </ConceptCtx.Provider>
    </div>
  )
}

function StatsRecorder() {
  useRecordTenantStats()
  return null
}

const concept: ConceptModule = {
  id: 'e',
  name: 'Advanced Network Operations Center',
  skill: 'Impeccable',
  summary: 'Transit-diagram NOC: authentication drawn as a route map, controllers to the policy interchange to VLAN termini, with line weight for volume and line form for state.',
  Root,
}
export default concept
