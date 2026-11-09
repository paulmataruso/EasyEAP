import { ArrowLeft, Wifi } from 'lucide-react'
import { fmtDate, fmtSerial } from '@/app/lib/format'
import type { Platform } from './api'
import { ConnectSteps, Troubleshoot, type GuideCtx, type Route } from './guides'
import type { FlowResult } from './model'
import { Button, Note, StepHeading } from './ui'

export function ConnectStep({ platform, route, result, c, onBack }: { platform: Platform; route: Route; result: FlowResult; c: GuideCtx; onBack: () => void }) {
  const csr = result.kind === 'browser' ? result.csr : null
  const password = result.kind === 'browser' && result.generated ? result.password : null
  const leftovers = result.kind !== 'helper' && (platform === 'android' || platform === 'windows' || (platform === 'macos' && !c.files.profile))
  return (
    <div className="en-enter">
      <StepHeading focusKey="connect" lede={<>Your device proves who you are with its certificate, so there’s no Wi-Fi password to type.</>}>
        Connect to {c.ssid}
      </StepHeading>

      <section aria-labelledby="h-connect">
        <h2 id="h-connect" className="sr-only">How to connect</h2>
        <ConnectSteps platform={platform} route={route} c={c} password={password} />
      </section>

      {csr && (
        <Note tone="valid" icon={<Wifi aria-hidden />} className="mt-6">
          Your certificate works until <b>{fmtDate(csr.not_after)}</b>.
        </Note>
      )}

      <section className="en-section en-section-gap" aria-labelledby="h-help">
        <h2 id="h-help" className="en-h2 mb-3">If it doesn’t connect</h2>
        <Troubleshoot c={c} platform={platform} route={route} serial={csr ? fmtSerial(csr.serial) : null} />
      </section>

      <section className="en-section" aria-labelledby="h-done">
        <h2 id="h-done" className="en-h2 mb-2">When you’re connected</h2>
        <p className="en-body">
          You can close this page. Nothing from it is kept.
          {leftovers && ' You can also delete the downloaded certificate file: your device keeps its own copy.'}
        </p>
      </section>

      <div className="en-actions">
        <Button variant="ghost" onClick={onBack}><ArrowLeft aria-hidden />Back to the install steps</Button>
      </div>
    </div>
  )
}
