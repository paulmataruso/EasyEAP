import { useEffect, useId, useRef, useState } from 'react'
import { ArrowLeft, Circle, CircleCheck, CircleX, Download, Eye, EyeOff, KeyRound, LoaderCircle } from 'lucide-react'
import { EnrollError, getCaChain, getWifiXml, getWindowsHelper, submitCsr, takePackage, type CsrResult, type PendingInfo, type Platform } from './api'
import type { DeviceKey } from './crypto'
import { fillMobileconfig, generatePassword, profileDisplayName } from './pem'
import { MIME, saveFile } from './files'
import { APPLE, closedMeanwhile, fileNames, rootPemOf, type BrowserResult, type GoneReason, type HelperResult, type PackageResult } from './model'

/** pkijs is large: load it when the create step needs it (and prefetch it when that step opens). */
const loadCrypto = () => import('./crypto')
async function rootCnOf(chainPem: string | null): Promise<string | null> {
  try { return chainPem ? (await loadCrypto()).commonNameOf(rootPemOf(chainPem)) : null } catch { return null }
}
import { platformShort } from './platform'
import { Button, Checkbox, Note, StepHeading } from './ui'

export interface CreateProps {
  token: string
  info: PendingInfo
  platform: Platform
  onBack: () => void
  onGone: (r: GoneReason) => void
}

/** Plain-language explanation for a failed request, with whether trying again makes sense. */
export function explain(e: unknown): { title: string; body: string; retry: boolean } {
  if (e instanceof EnrollError) {
    if (e.kind === 'network') return { title: 'This device couldn’t reach the enrollment service', body: 'Check that you’re connected to the internet. You aren’t on the new Wi-Fi network yet, so use mobile data or your usual Wi-Fi, then try again.', retry: true }
    if (e.kind === 'rate') return { title: 'Too many attempts', body: 'Wait a minute, then try again.', retry: true }
    if (e.kind === 'server') return { title: 'Something went wrong on the server', body: 'Try again in a few minutes. If it keeps happening, tell your IT administrator.', retry: true }
    if (e.kind === 'rejected') return { title: 'Your certificate couldn’t be created', body: `${e.message} Ask your IT administrator for help.`, retry: false }
  }
  const msg = e instanceof Error && e.message ? e.message : 'Unknown error.'
  return { title: 'This browser couldn’t finish', body: `${msg} Try again, or open the link in a different browser such as Safari, Chrome, Edge or Firefox.`, retry: true }
}

// ── Browser keygen (default) ─────────────────────────────────────────────
type Phase = 'idle' | 'key' | 'sign' | 'pack' | 'done'
const PHASES: Array<[Exclude<Phase, 'idle' | 'done'>, string, string]> = [
  ['key', 'Creating a private key on this device', 'Private key created on this device'],
  ['sign', 'Asking your organisation to sign your certificate', 'Certificate signed'],
  ['pack', 'Locking the certificate file with your password', 'Certificate file locked with your password'],
]

export function BrowserCreate({ token, info, platform, onBack, onGone, onDone }: CreateProps & { onDone: (r: BrowserResult) => void }) {
  const [mode, setMode] = useState<'generated' | 'own'>('generated')
  const [generated] = useState(() => generatePassword())
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [show, setShow] = useState(false)
  const [touched, setTouched] = useState(false)
  const [phase, setPhase] = useState<Phase>('idle')
  const [failedAt, setFailedAt] = useState<Phase | null>(null)
  const [error, setError] = useState<unknown>(null)
  // After the certificate is signed, keep the key and response so a packaging failure can be retried
  // without spending a new link. Cleared as soon as the PKCS#12 exists.
  const signed = useRef<{ key: DeviceKey; res: CsrResult } | null>(null)
  const submitUncertain = useRef(false)
  const ids = { pw: useId(), pw2: useId(), err: useId() }

  const pwError = mode === 'own' && touched ? (pw.length < 8 ? 'Use at least 8 characters.' : pw !== pw2 ? 'The two passwords don’t match.' : null) : null
  const pwOk = mode === 'generated' || (pw.length >= 8 && pw === pw2)
  const busy = phase === 'key' || phase === 'sign' || phase === 'pack'

  useEffect(() => { loadCrypto().catch(() => undefined) }, [])

  const pack = async (key: DeviceKey, res: CsrResult, password: string) => {
    setPhase('pack')
    const k = await loadCrypto()
    const p12 = await k.buildPkcs12({ key, certificatePem: res.certificate_pem, chainPems: [res.issuing_ca_pem, res.root_ca_pem], password, friendlyName: `${res.identity} Wi-Fi` })
    let mobileconfig: string | null = null
    let profileName: string | null = null
    if (APPLE.includes(platform)) {
      const tpl = res.profiles.mobileconfig_template
      if (!tpl) throw new Error('The server didn’t provide a Wi-Fi profile for this network.')
      mobileconfig = fillMobileconfig(tpl, res.profiles.mobileconfig_marker, p12)
      profileName = profileDisplayName(tpl)
    }
    signed.current = null // drop the last reference to the private key
    setPhase('done')
    onDone({ kind: 'browser', csr: res, p12, password, generated: mode === 'generated', mobileconfig, profileName, rootCn: k.commonNameOf(res.root_ca_pem ?? res.issuing_ca_pem) })
  }

  const run = async () => {
    setTouched(true)
    if (!pwOk) return
    const password = mode === 'generated' ? generated : pw
    setError(null)
    setFailedAt(null)
    if (signed.current) {
      try { await pack(signed.current.key, signed.current.res, password) } catch (e) { setFailedAt('pack'); setError(e); setPhase('idle') }
      return
    }
    let step: Phase = 'key'
    try {
      setPhase('key')
      const k = await loadCrypto()
      let key: DeviceKey | null = await k.generateDeviceKey()
      const csr = await k.buildCsr(key)
      step = 'sign'
      setPhase('sign')
      let res: CsrResult
      try {
        res = await submitCsr(token, csr, `Browser on ${platformShort[platform]}`)
      } catch (e) {
        if (e instanceof EnrollError && e.kind === 'gone') { key = null; onGone(await closedMeanwhile(token, submitUncertain.current)); return }
        if (e instanceof EnrollError && e.kind === 'network') submitUncertain.current = true
        key = null
        throw e
      }
      signed.current = { key, res }
      key = null
      step = 'pack'
      await pack(signed.current.key, res, password)
    } catch (e) {
      setFailedAt(step)
      setError(e)
      setPhase('idle')
    }
  }

  const failure = error ? explain(error) : null

  return (
    <div className="en-enter">
      <StepHeading focusKey="create" lede={<>Your device now creates a <b>private key</b>, a secret that never leaves it. {info.tenant} then signs a certificate that matches it.</>}>
        Create your certificate
      </StepHeading>

      <section className="en-section" aria-labelledby="h-pw">
        <h2 id="h-pw" className="en-h2">Protect the certificate file</h2>
        <p className="en-body mt-1.5">The file is locked with a password. You’ll enter it once, while installing{platform === 'ios' ? ' on this iPhone or iPad' : ''}.</p>
        <fieldset className="mt-3" disabled={busy || phase === 'done'}>
          <legend className="sr-only">Certificate file password</legend>
          <div className="en-choices !grid-cols-1">
            <label className="en-choice">
              <input type="radio" name="pwmode" checked={mode === 'generated'} onChange={() => setMode('generated')} />
              <span className="en-choice-dot" aria-hidden />
              <span>
                <span className="en-choice-label">Create a password for me</span>
                <span className="en-choice-hint">Recommended. You can copy it on the next screen.</span>
              </span>
            </label>
            <label className="en-choice">
              <input type="radio" name="pwmode" checked={mode === 'own'} onChange={() => setMode('own')} />
              <span className="en-choice-dot" aria-hidden />
              <span>
                <span className="en-choice-label">I’ll choose a password</span>
                <span className="en-choice-hint">At least 8 characters.</span>
              </span>
            </label>
          </div>
          {mode === 'own' && (
            <div className="mt-4 grid gap-4">
              <div>
                <label htmlFor={ids.pw} className="en-field-label">Password</label>
                <div className="flex gap-2">
                  <input id={ids.pw} className="en-input" type={show ? 'text' : 'password'} autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} onBlur={() => pw && setTouched(true)} aria-invalid={!!pwError || undefined} aria-describedby={pwError ? ids.err : undefined} />
                  <button type="button" className="en-btn en-btn-copy" onClick={() => setShow((s) => !s)} aria-pressed={show} aria-label={show ? 'Hide password' : 'Show password'}>
                    {show ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
                  </button>
                </div>
              </div>
              <div>
                <label htmlFor={ids.pw2} className="en-field-label">Type it again</label>
                <input id={ids.pw2} className="en-input" type={show ? 'text' : 'password'} autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} onBlur={() => pw2 && setTouched(true)} aria-invalid={!!pwError || undefined} aria-describedby={pwError ? ids.err : undefined} />
                {pwError && <p id={ids.err} className="en-error-text" role="alert">{pwError}</p>}
              </div>
            </div>
          )}
        </fieldset>
      </section>

      <section className="en-section" aria-labelledby="h-go">
        <h2 id="h-go" className="sr-only">Create</h2>
        {phase === 'idle' && !failure && (
          <Note tone="gold" title="Keep this page open until you’ve finished">
            This link works only once. After the next step, your certificate exists only on this page until you install it. If you close the page before then, you’ll need a new link.
          </Note>
        )}
        {(busy || failedAt) && (
          <ol className="en-progress mt-1" aria-label="Progress">
            {PHASES.map(([p, doing, done]) => {
              const idx = PHASES.findIndex(([x]) => x === p)
              const cur = PHASES.findIndex(([x]) => x === (failedAt ?? phase))
              const state = failedAt === p ? 'failed' : idx < cur || phase === 'done' ? 'done' : idx === cur && busy ? 'active' : 'waiting'
              return (
                <li key={p} data-state={state}>
                  {state === 'done' ? <CircleCheck aria-hidden /> : state === 'active' ? <LoaderCircle className="en-spin" aria-hidden /> : state === 'failed' ? <CircleX aria-hidden /> : <Circle aria-hidden />}
                  <span>{state === 'done' ? done : doing}</span>
                </li>
              )
            })}
          </ol>
        )}
        <p className="sr-only" role="status" aria-live="polite">
          {phase === 'key' ? 'Creating a private key on this device.' : phase === 'sign' ? 'Asking your organisation to sign your certificate.' : phase === 'pack' ? 'Locking the certificate file.' : ''}
        </p>
        {failure && (
          <Note tone="crit" title={failure.title} role="alert" className="mt-4">
            {failure.body}
            {submitUncertain.current && failedAt === 'sign' && ' If trying again says the link has been used, ask your IT administrator for a new one.'}
          </Note>
        )}
      </section>

      <div className="en-actions">
        {(!failure || failure.retry) && (
          <Button variant="primary" block onClick={run} busy={busy} disabled={!pwOk && touched}>
            {!busy && <KeyRound aria-hidden />}
            {busy ? 'Creating your certificate…' : failure ? 'Try again' : 'Create my certificate'}
          </Button>
        )}
        {!busy && !signed.current && <Button variant="ghost" onClick={onBack}><ArrowLeft aria-hidden />Back</Button>}
      </div>
    </div>
  )
}

// ── Windows helper ───────────────────────────────────────────────────────
export function HelperCreate({ token, info, onBack, onGone, onDone, onUseBrowser }: CreateProps & { onDone: (r: HelperResult) => void; onUseBrowser: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const get = async () => {
    setBusy(true)
    setError(null)
    try {
      const script = await getWindowsHelper(token)
      const caPem = await getCaChain(token).catch(() => null)
      saveFile(script, 'EasyEAP-WiFi-Setup.ps1', MIME.ps1)
      onDone({ kind: 'helper', script, caPem, rootCn: await rootCnOf(caPem), finished: false })
    } catch (e) {
      if (e instanceof EnrollError && e.kind === 'gone') { onGone(await closedMeanwhile(token)); return }
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  const failure = error ? explain(error) : null
  return (
    <div className="en-enter">
      <StepHeading focusKey="create-helper" lede={<>On Windows, a small setup helper from {info.tenant} does this for you. It creates your private key inside Windows, where it can’t be copied off this computer, then gets your certificate and adds the <b>{info.network.ssid}</b> network.</>}>
        Create your certificate
      </StepHeading>
      <ul className="en-bullets">
        <li>It runs as you and doesn’t need administrator rights.</li>
        <li>It’s a PowerShell script made for this link. Don’t share it: anyone who runs it before you could use your link.</li>
      </ul>
      {failure && <Note tone="crit" title={failure.title} role="alert" className="mt-5">{failure.body}</Note>}
      <div className="en-actions">
        <Button variant="primary" block onClick={get} busy={busy}>
          {!busy && <Download aria-hidden />}
          Download the setup helper
        </Button>
        <Button variant="ghost" onClick={onBack}><ArrowLeft aria-hidden />Back</Button>
      </div>
      <p className="en-small mt-5">
        Can’t run PowerShell scripts on this computer?{' '}
        <button type="button" className="underline underline-offset-[3px] text-[var(--ee-ink)] min-h-[44px]" onClick={onUseBrowser}>Create the certificate in this browser instead</button>
      </p>
    </div>
  )
}

// ── Server-generated package ─────────────────────────────────────────────
export function PackageCreate({ token, info, platform, onBack, onGone, onDone }: CreateProps & { onDone: (r: PackageResult) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  // iPhone, iPad and Mac get the same package wrapped in a profile that also adds the CA and the network.
  const format = APPLE.includes(platform) ? 'mobileconfig' : 'p12'
  const take = async () => {
    setBusy(true)
    setError(null)
    try {
      const caPem = await getCaChain(token).catch(() => null)
      // The Wi-Fi settings for Windows are only served while the link is pending: get them before the package
      // spends it. "No network configured" (409) isn't fatal; anything else stops here, before the one download.
      let wifiXml: string | null = null
      if (platform === 'windows') {
        try { wifiXml = await getWifiXml(token) } catch (e) { if (!(e instanceof EnrollError && e.kind === 'rejected')) throw e }
      }
      const { data, filename } = await takePackage(token, format)
      const name = filename ?? (format === 'mobileconfig' ? fileNames(info.network.ssid).mobileconfig : 'wifi-certificate.p12')
      saveFile(data, name, format === 'mobileconfig' ? MIME.mobileconfig : MIME.p12, { open: platform === 'ios' })
      const profileName = format === 'mobileconfig' ? profileDisplayName(await data.text()) : null
      onDone({ kind: 'package', format, data, filename: name, profileName, wifiXml, caPem, rootCn: await rootCnOf(caPem) })
    } catch (e) {
      if (e instanceof EnrollError && e.kind === 'gone') { onGone(await closedMeanwhile(token)); return }
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  const failure = error ? explain(error) : null
  const what = format === 'mobileconfig' ? 'Wi-Fi profile' : 'certificate'
  return (
    <div className="en-enter">
      <StepHeading
        focusKey="create-package"
        lede={
          format === 'mobileconfig'
            ? <>Your IT administrator has already prepared a certificate for <b>{info.device_name}</b>. It comes as a Wi-Fi profile that also sets up <b>{info.network.ssid}</b>. You can download it <b>only once</b>.</>
            : <>Your IT administrator has already prepared a certificate for <b>{info.device_name}</b>. Download it on this device: you can download it <b>only once</b>.</>
        }
      >
        Download your certificate
      </StepHeading>
      <Note tone="gold" title="You’ll need a password from your IT administrator">
        The {what} is locked with a password that your IT administrator sends you separately, for example by text message or phone. It isn’t shown on this page, so the link alone can’t unlock it. If you don’t have it yet, ask for it before you continue.
      </Note>
      {platform === 'ios' && <p className="en-small mt-4">When Safari asks whether to allow a configuration profile, tap <b>Allow</b>.</p>}
      {failure && <Note tone="crit" title={failure.title} role="alert" className="mt-5">{failure.body}</Note>}
      <div className="en-actions">
        <Button variant="primary" block onClick={take} busy={busy}>
          {!busy && <Download aria-hidden />}
          {platform === 'ios' ? `Open the ${what}` : `Download the ${what}`}
        </Button>
        <Button variant="ghost" onClick={onBack}><ArrowLeft aria-hidden />Back</Button>
      </div>
    </div>
  )
}

export function PackageAck({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return <Checkbox checked={checked} onChange={onChange}>I have the password from my IT administrator</Checkbox>
}
