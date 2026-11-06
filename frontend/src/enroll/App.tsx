import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Wordmark } from '@/ui/Logo'
import { EnrollError, getLink, isPending, type PendingInfo } from './api'
import { Flow } from './Flow'
import { GoneScreen, LoadFailure } from './Gone'
import { closedReason, type GoneReason } from './model'
import { detectEnvironment } from './platform'

function tokenFromHash(): string | null {
  const m = /^#\/t\/([A-Za-z0-9_-]{16,128})\/?$/.exec(window.location.hash)
  return m ? m[1] : null
}

type State =
  | { kind: 'loading' }
  | { kind: 'failed'; error: unknown }
  | { kind: 'gone'; reason: GoneReason; tenant?: string }
  | { kind: 'ready'; info: PendingInfo }

function Frame({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="en-root">
      <div className="en-wrap">
        <header className="en-top">
          <Wordmark className="text-[17px] text-[var(--ee-ink)]" markClassName="size-7" />
          <span className="en-small">Wi-Fi setup</span>
        </header>
      </div>
      <main className="en-main" id="main">
        <div className="en-wrap">{children}</div>
      </main>
      <div className="en-wrap"><footer className="en-foot">{footer}</footer></div>
    </div>
  )
}

export function EnrollApp() {
  const [token, setToken] = useState(tokenFromHash)
  const [state, setState] = useState<State>(() => (token ? { kind: 'loading' } : { kind: 'gone', reason: 'no-token' }))
  const env = useMemo(() => detectEnvironment(), [])

  useEffect(() => {
    const h = () => setToken(tokenFromHash())
    window.addEventListener('hashchange', h)
    return () => window.removeEventListener('hashchange', h)
  }, [])

  const load = useCallback(async (t: string | null) => {
    if (!t) { setState({ kind: 'gone', reason: 'no-token' }); return }
    setState({ kind: 'loading' })
    try {
      const info = await getLink(t)
      if (isPending(info)) setState({ kind: 'ready', info })
      else setState({ kind: 'gone', reason: closedReason(info), tenant: info.tenant })
    } catch (e) {
      if (e instanceof EnrollError && e.kind === 'gone') setState({ kind: 'gone', reason: 'invalid' })
      else setState({ kind: 'failed', error: e })
    }
  }, [])

  useEffect(() => { load(token) }, [token, load])

  useEffect(() => {
    document.title = state.kind === 'ready' ? `Set up Wi-Fi · ${state.info.tenant}` : 'Wi-Fi setup · EasyEAP'
  }, [state])

  // Focus the heading of a terminal screen so it's announced.
  useEffect(() => {
    if (state.kind === 'gone' || state.kind === 'failed') document.querySelector<HTMLElement>('[data-autofocus]')?.focus()
  }, [state])

  const onGone = useCallback((reason: GoneReason) => {
    setState((s) => ({ kind: 'gone', reason, tenant: s.kind === 'ready' ? s.info.tenant : undefined }))
  }, [])

  if (state.kind === 'loading') {
    return (
      <Frame>
        <section className="ee-panel en-card" data-risk="neutral" role="status" aria-label="Checking your link">
          <span className="ee-skeleton block h-7 w-3/4" aria-hidden />
          <span className="ee-skeleton mt-4 block h-4 w-full" aria-hidden />
          <span className="ee-skeleton mt-2 block h-4 w-5/6" aria-hidden />
          <span className="ee-skeleton mt-8 block h-12 w-full" aria-hidden />
          <p className="en-small mt-5">Checking your link…</p>
        </section>
      </Frame>
    )
  }
  if (state.kind === 'failed') {
    return (
      <Frame>
        <section className="ee-panel en-card" data-risk="warn"><LoadFailure error={state.error} onRetry={() => load(token)} /></section>
      </Frame>
    )
  }
  if (state.kind === 'gone') {
    return (
      <Frame>
        <section className="ee-panel en-card" data-risk={state.reason === 'lost-response' ? 'crit' : 'neutral'}><GoneScreen reason={state.reason} tenant={state.tenant} /></section>
      </Frame>
    )
  }
  const keyHere = state.info.method === 'link'
  return (
    <Frame
      footer={
        keyHere
          ? <>Private keys made by this page are created on this device and never leave it. Nothing is stored in your browser.</>
          : <>Your IT administrator prepared this certificate. It can be downloaded once.</>
      }
    >
      <Flow token={token!} info={state.info} env={env} onGone={onGone} />
    </Frame>
  )
}
