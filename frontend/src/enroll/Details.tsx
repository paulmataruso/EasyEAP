import { useState } from 'react'
import { ArrowRight, Laptop, Monitor, Smartphone, Tablet } from 'lucide-react'
import { fmtDateTime, relative } from '@/app/lib/format'
import { PLATFORMS, type PendingInfo, type Platform } from './api'
import { webCryptoAvailable } from './pem'
import { canDownload } from './files'
import type { Route } from './guides'
import { platformA, platformName, type Environment } from './platform'
import { Button, CopyButton, Disclosure, Note, StepHeading, Value } from './ui'

const icon: Record<Platform, typeof Laptop> = { ios: Smartphone, macos: Laptop, android: Tablet, windows: Laptop, linux: Monitor }

export function PlatformChoice({ value, onChange }: { value: Platform; onChange: (p: Platform) => void }) {
  return (
    <fieldset>
      <legend className="sr-only">Device type</legend>
      <div className="en-choices">
        {PLATFORMS.map((p) => {
          const I = icon[p]
          return (
            <label key={p} className="en-choice">
              <input type="radio" name="platform" value={p} checked={value === p} onChange={() => onChange(p)} />
              <span className="en-choice-dot" aria-hidden />
              <I aria-hidden />
              <span className="en-choice-label">{platformName[p]}</span>
            </label>
          )
        })}
      </div>
    </fieldset>
  )
}

export function DetailsStep({ info, env, platform, setPlatform, route, now, onContinue, onUseHelper }: {
  info: PendingInfo
  env: Environment
  platform: Platform
  setPlatform: (p: Platform) => void
  route: Route
  now: Date
  onContinue: () => void
  onUseHelper: () => void
}) {
  const [browserOverride, setBrowserOverride] = useState(false)
  const chosen = info.platform
  const mismatch = env.detected !== null && env.detected !== chosen
  const needsKeyHere = route === 'profile' || route === 'p12'
  const noCrypto = needsKeyHere && !webCryptoAvailable()
  const noSsid = !info.network.ssid
  const needsSafari = platform === 'ios' && env.iosNotSafari
  const inApp = env.inAppBrowser && !needsSafari
  const browserBlocked = (needsSafari || inApp) && !browserOverride
  const blocked = noSsid || noCrypto || browserBlocked
  const link = typeof window !== 'undefined' ? window.location.href : ''

  return (
    <div className="en-enter">
      <StepHeading focusKey="details" lede={<>This page installs a certificate on your device. <b>The certificate is how your device proves it’s you, so you won’t need a Wi-Fi password.</b></>}>
        Set up Wi-Fi for {info.tenant}
      </StepHeading>

      <div className="space-y-3 empty:hidden [&:not(:empty)]:mb-7" aria-live="polite">
        {noSsid && (
          <Note tone="crit" title="The Wi-Fi network isn’t ready yet" role="alert">
            {info.tenant} hasn’t finished setting up its Wi-Fi network, so there’s nothing to connect to yet. Ask your IT administrator to finish setup, then open this link again. It works until {fmtDateTime(info.expires_at)}.
          </Note>
        )}
        {noCrypto && (
          <Note tone="crit" title="This page needs a secure connection" role="alert">
            <p>Your browser only creates private keys on secure (https) pages, and this one isn’t. Ask your IT administrator for a link that starts with <b>https://</b>.</p>
            {platform === 'windows' && (
              <div className="mt-3"><Button onClick={onUseHelper}>Use the Windows setup helper instead</Button></div>
            )}
          </Note>
        )}
        {needsSafari && !browserOverride && (
          <Note tone="crit" title="Open this link in Safari" role="alert">
            <p>iPhone and iPad only install Wi-Fi settings from Safari. {env.appName ? `This page is open inside ${env.appName}.` : 'This page is open in another browser or app.'} Use the app’s <b>Share</b> or menu button and choose <b>Open in Safari</b>, or copy the link and paste it into Safari.</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <CopyButton text={link} what="link" label="Copy link" />
              <Button variant="ghost" onClick={() => setBrowserOverride(true)}>I’m already in Safari</Button>
            </div>
          </Note>
        )}
        {inApp && !browserOverride && (
          <Note tone="crit" title="Open this link in your browser" role="alert">
            <p>{env.appName ? `This page is open inside ${env.appName}` : 'This page is open inside an app'}, which may not be able to save the files you need. Use the app’s menu to choose <b>Open in browser</b> (or <b>Open in Chrome</b>), or copy the link into your browser.</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <CopyButton text={link} what="link" label="Copy link" />
              <Button variant="ghost" onClick={() => setBrowserOverride(true)}>I’m already in my browser</Button>
            </div>
          </Note>
        )}
        {!canDownload() && !blocked && (
          <Note tone="warn" title="This browser may not save files">
            If nothing happens when you download in the next steps, open this link in Safari, Chrome, Edge or Firefox.
          </Note>
        )}
      </div>

      <section className="en-section" aria-labelledby="h-check">
        <h2 id="h-check" className="en-h2 mb-3">Check these details</h2>
        <dl className="en-dl">
          <div><dt>Organisation</dt><dd>{info.tenant}</dd></div>
          <div>
            <dt>Your account</dt>
            <dd>{info.user.display_name}<span className="block text-[14px] text-[var(--ee-ink-2)] ee-mono">{info.user.upn}</span></dd>
          </div>
          <div><dt>Device</dt><dd>{info.device_name} <span className="text-[var(--ee-ink-3)]">· {platformName[chosen]}</span></dd></div>
          {info.network.ssid && <div><dt>Wi-Fi network</dt><dd className="font-semibold">{info.network.ssid}</dd></div>}
          {info.network.server_name && (
            <div>
              <dt>Server your device will trust</dt>
              <dd><Value value={info.network.server_name} what="server name" copy={false} /></dd>
            </div>
          )}
          <div>
            <dt>This link works until</dt>
            <dd><time dateTime={info.expires_at}>{fmtDateTime(info.expires_at)}</time> <span className="text-[var(--ee-ink-3)]">· {relative(info.expires_at, now)}</span></dd>
          </div>
        </dl>
        <p className="en-small mt-3">If anything here looks wrong, stop and ask your IT administrator for a new link.</p>
      </section>

      <section className="en-section" aria-labelledby="h-device">
        <h2 id="h-device" className="en-h2 mb-3">This device</h2>
        {mismatch ? (
          <Note tone="warn" title={`This link was set up for ${info.device_name}`}>
            Your IT administrator chose {platformName[chosen]}, but this looks like {platformA[env.detected!]}. If you can, open the link on {info.device_name} instead. If you’re sure this is the device you want to set up, choose its type below.
          </Note>
        ) : env.detected === chosen ? (
          <Note tone="valid">This looks like {platformA[chosen]}, which is what your IT administrator set this link up for.</Note>
        ) : (
          <Note>Your IT administrator set this link up for {platformA[chosen]}. If this is a different kind of device, choose it below.</Note>
        )}
        <div className="mt-3">
          {mismatch || env.detected === null || platform !== chosen ? (
            <PlatformChoice value={platform} onChange={setPlatform} />
          ) : (
            <Disclosure summary="Setting up a different kind of device?">
              <PlatformChoice value={platform} onChange={setPlatform} />
            </Disclosure>
          )}
        </div>
      </section>

      <div className="en-actions">
        <Button variant="primary" block onClick={onContinue} disabled={blocked}>
          Continue
          <ArrowRight aria-hidden />
        </Button>
        {!blocked && <p className="en-small">Nothing is installed until you choose to install it.</p>}
      </div>
    </div>
  )
}
