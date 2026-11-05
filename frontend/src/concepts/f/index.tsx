import '@fontsource-variable/hanken-grotesk'
import '@fontsource-variable/red-hat-mono'
import './concept.css'
import { useEffect, useState } from 'react'
import { Toast, Tooltip } from 'radix-ui'
import { Ban, Check, TriangleExclamationPoint, X } from 'lucide-react'
import { useTenantData, useTenants } from '@/prototype/store'
import type { ConceptModule, ConceptProps } from '../contract'
import { IssueCertificateDialog } from './dialogs'
import { PortalContext, toastStore, useToasts } from './lib'
import { computeStats, recordLiveStats } from './portfolio'
import { Shell } from './shell'
import { Btn } from './ui'
import { Dashboard } from './screens/Dashboard'
import { UserScreen, UsersScreen } from './screens/Users'
import { CertificatesScreen } from './screens/Certificates'
import { RadiusScreen } from './screens/Radius'
import { PoliciesScreen } from './screens/Policies'
import { TenantsScreen } from './screens/Tenants'

function Toasts() {
  const toasts = useToasts()
  return (
    <>
      {toasts.map((t) => (
        <Toast.Root
          key={t.id}
          className="f-toast"
          data-risk={t.tone}
          duration={5000}
          onOpenChange={(open) => { if (!open) toastStore.set((prev) => prev.filter((x) => x.id !== t.id)) }}
        >
          <span className="mt-0.5 [&_svg]:size-4" aria-hidden>
            {t.tone === 'crit' ? <Ban className="text-[var(--f-crit-ink)]" /> : t.tone === 'warn' ? <TriangleExclamationPoint className="text-[var(--f-warn)]" /> : <Check className={t.tone === 'gold' ? 'text-[var(--f-gold)]' : 'text-[var(--f-valid)]'} />}
          </span>
          <div className="min-w-0 flex-1">
            <Toast.Title className="text-[13.5px] font-semibold">{t.title}</Toast.Title>
            {t.body && <Toast.Description className="f-small f-ink-2 mt-0.5">{t.body}</Toast.Description>}
          </div>
          <Toast.Close asChild><Btn size="sm" variant="ghost" icon aria-label="Dismiss"><X aria-hidden /></Btn></Toast.Close>
        </Toast.Root>
      ))}
      <Toast.Viewport className="f-toast-viewport" />
    </>
  )
}

/** Keeps the MSP portfolio's figure for this tenant current after in-session changes. */
function LiveStats() {
  const d = useTenantData()
  const { current } = useTenants()
  useEffect(() => {
    recordLiveStats(current.id, computeStats(d, current.health.directory !== 'unconfigured'))
  }, [d, current.id, current.health.directory])
  return null
}

function Root({ screen, entityId, navigate }: ConceptProps) {
  const [portal, setPortal] = useState<HTMLDivElement | null>(null)
  const [issue, setIssue] = useState<{ open: boolean; identityId?: string }>({ open: false })
  const d = useTenantData()
  const onIssue = (identityId?: string) => setIssue({ open: true, identityId })
  const issueIdentity = d.identities.find((i) => i.id === issue.identityId)

  useEffect(() => {
    document.title = `EasyEAP · ${screen[0].toUpperCase()}${screen.slice(1)}`
  }, [screen])
  useEffect(() => {
    window.scrollTo({ top: 0 })
  }, [screen, screen === 'user' ? entityId : null]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div data-concept="f">
      <PortalContext.Provider value={portal}>
        <Tooltip.Provider delayDuration={250}>
          <Toast.Provider swipeDirection="right" label="Notification">
            <LiveStats />
            <Shell screen={screen} navigate={navigate} onIssue={() => onIssue()}>
              {screen === 'dashboard' && <Dashboard navigate={navigate} onIssue={onIssue} />}
              {screen === 'users' && <UsersScreen navigate={navigate} onIssue={onIssue} />}
              {screen === 'user' && <UserScreen entityId={entityId} navigate={navigate} onIssue={onIssue} />}
              {screen === 'certificates' && <CertificatesScreen entityId={entityId} navigate={navigate} />}
              {screen === 'radius' && <RadiusScreen entityId={entityId} navigate={navigate} />}
              {screen === 'policies' && <PoliciesScreen key={entityId ?? 'policies'} entityId={entityId} navigate={navigate} />}
              {screen === 'tenants' && <TenantsScreen navigate={navigate} />}
            </Shell>
            <IssueCertificateDialog
              key={issue.identityId ?? 'pick'}
              open={issue.open}
              onOpenChange={(open) => setIssue((s) => ({ ...s, open }))}
              identity={issueIdentity}
            />
            <Toasts />
          </Toast.Provider>
        </Tooltip.Provider>
      </PortalContext.Provider>
      <div ref={setPortal} />
    </div>
  )
}

const concept: ConceptModule = {
  id: 'f',
  name: 'Modern Security Management',
  skill: 'Impeccable',
  summary:
    'Security-printed identity documents: every certificate and identity renders as a credential data page with a verifiable machine-readable line (ICAO 9303 check digits) and a serial-seeded guilloché watermark; every access decision reads as a ledger. Search-first shell with the tenant scope inside the search.',
  Root,
}
export default concept
