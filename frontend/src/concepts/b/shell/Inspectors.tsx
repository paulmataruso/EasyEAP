import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import type { Platform } from '@/domain/types'
import { CertificateDrawer, type CertMode } from '../features/CertificateDrawer'
import { AuthEventDrawer } from '../features/AuthEventDrawer'
import { IssueCertificateDrawer } from '../features/IssueCertificateDrawer'
import { useShell } from './context'

type Prefill = { deviceName?: string; platform?: Platform }
type Payload = { kind: 'cert'; id: string; mode: CertMode } | { kind: 'event'; id: string } | { kind: 'issue'; identityId: string; prefill?: Prefill }

interface InspectorApi {
  openCertificate: (id: string, mode?: CertMode) => void
  openEvent: (id: string) => void
  openIssue: (identityId: string, prefill?: Prefill) => void
  /** What is open right now (screens highlight the matching row) */
  active: Payload | null
}

const InspectorContext = createContext<InspectorApi | null>(null)
export function useInspector(): InspectorApi {
  const ctx = useContext(InspectorContext)
  if (!ctx) throw new Error('InspectorHost missing')
  return ctx
}

/** One host for the shared slide-over inspectors, so any screen can open a certificate, an event or the issue flow. */
export function InspectorHost({ children }: { children: ReactNode }) {
  const { go, screen, entityId } = useShell()
  // `payload` stays mounted while closing so the exit animation can run; `seq` remounts each open.
  const [state, setState] = useState<{ payload: Payload; open: boolean; seq: number } | null>(null)
  // Leaving the screen (back button, deep link) closes whatever inspector was open on it.
  const route = `${screen}/${entityId ?? ''}`
  const [openedOn, setOpenedOn] = useState(route)
  if (openedOn !== route) {
    setOpenedOn(route)
    if (state?.open) setState({ ...state, open: false })
  }
  const show = useCallback((payload: Payload) => setState((s) => ({ payload, open: true, seq: (s?.seq ?? 0) + 1 })), [])
  const close = useCallback((open: boolean) => {
    if (!open) setState((s) => (s ? { ...s, open: false } : s))
  }, [])

  const api = useMemo<InspectorApi>(
    () => ({
      openCertificate: (id, mode = 'view') => show({ kind: 'cert', id, mode }),
      openEvent: (id) => show({ kind: 'event', id }),
      openIssue: (identityId, prefill) => show({ kind: 'issue', identityId, prefill }),
      active: state?.open ? state.payload : null,
    }),
    [show, state],
  )

  const openUser = (identityId: string) => {
    close(false)
    go('user', { entityId: identityId })
  }

  const p = state?.payload
  return (
    <InspectorContext.Provider value={api}>
      {children}
      {state && p?.kind === 'cert' && (
        <CertificateDrawer
          key={state.seq}
          certId={p.id}
          mode={p.mode}
          open={state.open}
          onOpenChange={close}
          onOpenUser={openUser}
          onIssueReplacement={(identityId, prefill) => show({ kind: 'issue', identityId, prefill })}
        />
      )}
      {state && p?.kind === 'event' && <AuthEventDrawer key={state.seq} eventId={p.id} open={state.open} onOpenChange={close} onOpenUser={openUser} onOpenCertificate={(id) => show({ kind: 'cert', id, mode: 'view' })} />}
      {state && p?.kind === 'issue' && <IssueCertificateDrawer key={state.seq} identityId={p.identityId} prefill={p.prefill} open={state.open} onOpenChange={close} />}
    </InspectorContext.Provider>
  )
}
