import { useCallback, useEffect, useState } from 'react'
import type { PendingInfo, Platform } from './api'
import { ConnectStep } from './Connect'
import { BrowserCreate, HelperCreate, PackageCreate } from './Create'
import { DetailsStep } from './Details'
import { handoff } from './files'
import { InstallStep } from './Install'
import { guideCtx, routeFor, type FlowResult, type GoneReason } from './model'
import type { Environment } from './platform'
import { Steps } from './ui'

export function useNow(intervalMs = 30_000): Date {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}

export function Flow({ token, info, env, onGone }: { token: string; info: PendingInfo; env: Environment; onGone: (r: GoneReason) => void }) {
  const [platform, setPlatform] = useState<Platform>(info.platform)
  const [helperRoute, setHelperRoute] = useState<'helper' | 'browser'>('helper')
  const [step, setStep] = useState(0)
  const [result, setResult] = useState<FlowResult | null>(null)
  const now = useNow()
  const route = routeFor(info, platform, helperRoute)

  // A link that runs out before anything was created is simply expired.
  useEffect(() => {
    if (!result && new Date(info.expires_at).getTime() <= now.getTime()) onGone('expired')
  }, [now, result, info.expires_at, onGone])

  // Once a certificate exists only in this page's memory, closing the page would lose it.
  useEffect(() => {
    if (!result || result.kind === 'helper' || step >= 3) return
    const h = (e: BeforeUnloadEvent) => {
      if (Date.now() < handoff.until) return // handing a profile to iOS, not leaving
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', h)
    return () => window.removeEventListener('beforeunload', h)
  }, [result, step])

  const labels = ['Check your details', info.method === 'server' ? 'Download certificate' : 'Create certificate', 'Install', 'Connect']
  const c = guideCtx(info, platform, result)
  const useBrowser = () => { setHelperRoute('browser'); setResult(null); setStep(1) }
  const onResult = useCallback((r: FlowResult) => setResult(r), [])
  const created = (r: FlowResult) => { setResult(r); setStep(2) }
  const createProps = { token, info, platform, onBack: () => setStep(0), onGone }

  return (
    <>
      <Steps labels={labels} current={step} />
      <section className="ee-panel en-card" data-risk={step === 3 ? 'ok' : 'gold'} aria-label={labels[step]}>
        {step === 0 && (
          <DetailsStep
            info={info}
            env={env}
            platform={platform}
            setPlatform={setPlatform}
            route={route}
            now={now}
            onContinue={() => setStep(1)}
            onUseHelper={() => setHelperRoute('helper')}
          />
        )}
        {step === 1 && route === 'package' && <PackageCreate {...createProps} onDone={created} />}
        {step === 1 && route === 'helper' && <HelperCreate {...createProps} onDone={created} onUseBrowser={useBrowser} />}
        {step === 1 && (route === 'profile' || route === 'p12') && <BrowserCreate {...createProps} onDone={created} />}
        {step === 2 && result && (
          <InstallStep token={token} info={info} platform={platform} route={route} result={result} c={c} onResult={onResult} onNext={() => setStep(3)} onUseBrowser={useBrowser} onGone={onGone} />
        )}
        {step === 3 && result && <ConnectStep platform={platform} route={route} result={result} c={c} onBack={() => setStep(2)} />}
      </section>
    </>
  )
}
