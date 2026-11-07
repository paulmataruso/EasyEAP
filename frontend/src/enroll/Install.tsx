import { useEffect, useState, type ReactNode } from 'react'
import { ArrowRight, CircleCheck, Download, FileCheck2, LoaderCircle } from 'lucide-react'
import { EnrollError, getLink, isPending, type PendingInfo, type Platform } from './api'
import { PackageAck } from './Create'
import { MIME, saveFile } from './files'
import { InstallSteps, type GuideCtx, type Route } from './guides'
import { closedReason, fileNames, type FlowResult, type GoneReason, type HelperResult } from './model'
import { Button, Command, CopyButton, Disclosure, Note, StepHeading } from './ui'

function SavedFile({ name, onAgain, againLabel = 'Download again' }: { name: string; onAgain: () => void; againLabel?: string }) {
  return (
    <div className="en-file">
      <FileCheck2 aria-hidden />
      <div className="en-file-text">
        <p className="en-small">Saved</p>
        <p className="en-file-name">{name}</p>
      </div>
      <button type="button" className="en-btn en-btn-copy" onClick={onAgain}>{againLabel}</button>
    </div>
  )
}

/** A download that remembers it happened, so the step can say "Saved" and offer it again. */
function DownloadItem({ label, filename, primary, onSave, hint }: { label: string; filename: string; primary?: boolean; onSave: () => void; hint?: ReactNode }) {
  const [saved, setSaved] = useState(false)
  const save = () => { onSave(); setSaved(true) }
  return (
    <div>
      {saved ? <SavedFile name={filename} onAgain={save} /> : (
        <Button variant={primary ? 'primary' : 'default'} block onClick={save}>
          <Download aria-hidden />
          {label}
        </Button>
      )}
      {hint && !saved && <p className="en-small mt-2">{hint}</p>}
    </div>
  )
}

function Password({ password, generated }: { password: string; generated: boolean }) {
  if (!generated) return <Note title="Certificate password">Use the password you chose on the previous screen.</Note>
  return (
    <section aria-labelledby="h-secret">
      <h2 id="h-secret" className="en-h2">Your certificate password</h2>
      <p className="en-body mt-1.5 mb-3">You’ll paste this while installing. It isn’t saved anywhere: once you close this page, it’s gone.</p>
      <div className="en-secret">
        <code aria-label="Certificate password">{password}</code>
        <CopyButton text={password} what="certificate password" />
      </div>
    </section>
  )
}

export function InstallStep({ token, info, platform, route, result, c, onResult, onNext, onUseBrowser, onGone }: {
  token: string
  info: PendingInfo
  platform: Platform
  route: Route
  result: FlowResult
  c: GuideCtx
  onResult: (r: FlowResult) => void
  onNext: () => void
  onUseBrowser: () => void
  onGone: (r: GoneReason) => void
}) {
  const [ack, setAck] = useState(false)
  const n = fileNames(info.network.ssid)
  const canNext = result.kind !== 'package' || ack

  return (
    <div className="en-enter">
      <StepHeading
        focusKey={`install-${route}`}
        lede={
          route === 'helper' ? <>Run the helper you just downloaded. It installs your certificate and the <b>{c.ssid}</b> network.</>
          : result.kind === 'package' ? <>Your {result.format === 'mobileconfig' ? 'Wi-Fi profile' : 'certificate file'} is on this device. Now install it.</>
          : <>Your certificate is ready. It’s only on this page until you install it, so keep the page open.</>
        }
      >
        {route === 'helper' ? 'Install with the setup helper' : 'Install your certificate'}
      </StepHeading>

      {result.kind === 'browser' && (
        <div className="space-y-6">
          <Password password={result.password} generated={result.generated} />
          <section aria-labelledby="h-files" className="space-y-3">
            <h2 id="h-files" className={route === 'profile' ? 'sr-only' : 'en-h2'}>{route === 'profile' ? 'The Wi-Fi profile' : 'Your files'}</h2>
            {route === 'profile' && result.mobileconfig && (
              <DownloadItem
                primary
                label="Download the Wi-Fi profile"
                filename={n.mobileconfig}
                onSave={() => saveFile(result.mobileconfig!, n.mobileconfig, MIME.mobileconfig, { open: platform === 'ios' })}
                hint={platform === 'ios' ? <>Copy the password first. When Safari asks, tap <b>Allow</b>.</> : undefined}
              />
            )}
            {route === 'p12' && (
              <>
                <DownloadItem primary label="Download the certificate" filename={n.p12} onSave={() => saveFile(result.p12, n.p12, MIME.p12)} />
                {platform === 'windows' && result.csr.profiles.windows_xml && (
                  <DownloadItem label="Download the Wi-Fi settings" filename={n.xml} onSave={() => saveFile(result.csr.profiles.windows_xml!, n.xml, MIME.xml)} />
                )}
                {(platform === 'android' || platform === 'linux') && (
                  <DownloadItem
                    label="Download the CA certificate"
                    filename={platform === 'android' ? n.caCrt : n.caPem}
                    onSave={() => saveFile(result.csr.issuing_ca_pem + (result.csr.root_ca_pem ?? ''), platform === 'android' ? n.caCrt : n.caPem, platform === 'android' ? MIME.crt : MIME.pem)}
                    hint={platform === 'android' ? 'Usually not needed: your phone takes it from the certificate file. Keep it in case the next step asks for it.' : 'Your computer uses it to check it’s talking to the real Wi-Fi server.'}
                  />
                )}
              </>
            )}
          </section>
          <section aria-labelledby="h-steps">
            <h2 id="h-steps" className="en-h2 mb-4">Then follow these steps</h2>
            <InstallSteps platform={platform} route={route} c={c} />
          </section>
          {platform === 'linux' && <LinuxAdvanced result={result} c={c} n={n} />}
        </div>
      )}

      {result.kind === 'helper' && (
        <HelperInstall token={token} result={result} c={c} onResult={onResult} onUseBrowser={onUseBrowser} onGone={onGone} />
      )}

      {result.kind === 'package' && (
        <div className="space-y-6">
          <SavedFile
            name={result.filename}
            againLabel="Save again"
            onAgain={() => saveFile(result.data, result.filename, result.format === 'mobileconfig' ? MIME.mobileconfig : MIME.p12, { open: platform === 'ios' })}
          />
          <section aria-labelledby="h-ack">
            <h2 id="h-ack" className="en-h2">Your certificate password</h2>
            <p className="en-body mt-1.5">Use the password your IT administrator sent you. EasyEAP doesn’t show it here.</p>
            <div className="mt-2"><PackageAck checked={ack} onChange={setAck} /></div>
          </section>
          {platform === 'windows' && result.wifiXml && (
            <DownloadItem label="Download the Wi-Fi settings" filename={n.xml} onSave={() => saveFile(result.wifiXml!, n.xml, MIME.xml)} />
          )}
          {result.caPem && (platform === 'android' || platform === 'linux') && (
            <DownloadItem
              label="Download the CA certificate"
              filename={platform === 'android' ? n.caCrt : n.caPem}
              onSave={() => saveFile(result.caPem!, platform === 'android' ? n.caCrt : n.caPem, platform === 'android' ? MIME.crt : MIME.pem)}
              hint={platform === 'android' ? 'Usually not needed: your phone takes it from the certificate file. Keep it in case the next step asks for it.' : 'Your computer uses it to check it’s talking to the real Wi-Fi server.'}
            />
          )}
          <section aria-labelledby="h-steps">
            <h2 id="h-steps" className="en-h2 mb-4">Then follow these steps</h2>
            <InstallSteps platform={platform} route="package" c={c} />
          </section>
        </div>
      )}

      <div className="en-actions">
        <Button variant="primary" block onClick={onNext} disabled={!canNext}>
          Next: connect to Wi-Fi
          <ArrowRight aria-hidden />
        </Button>
        {!canNext && <p className="en-small">Tick the box above when you have the password.</p>}
      </div>
    </div>
  )
}

function HelperInstall({ token, result, c, onResult, onUseBrowser, onGone }: {
  token: string
  result: HelperResult
  c: GuideCtx
  onResult: (r: FlowResult) => void
  onUseBrowser: () => void
  onGone: (r: GoneReason) => void
}) {
  // The helper posts the certificate request itself, and the link then reads "completed": that's the signal.
  // If it closes any other way first (expired, cancelled), the helper can't finish: say which.
  useEffect(() => {
    if (result.finished) return
    let stop = false
    const tick = async () => {
      if (document.visibilityState !== 'visible') return
      try {
        const i = await getLink(token)
        if (stop || isPending(i)) return
        stop = true
        if (i.status === 'completed') onResult({ ...result, finished: true })
        else onGone(closedReason(i))
      } catch (e) {
        if (!stop && e instanceof EnrollError && e.kind === 'gone') { stop = true; onGone('closed') }
        // Network or rate-limit hiccups: keep polling.
      }
    }
    const id = window.setInterval(tick, 6000)
    return () => { stop = true; window.clearInterval(id) }
  }, [token, result, onResult, onGone])

  const cmd = `powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\${c.files.helper}"`
  return (
    <div className="space-y-6">
      <SavedFile name={c.files.helper ?? 'EasyEAP-WiFi-Setup.ps1'} onAgain={() => saveFile(result.script, c.files.helper ?? 'EasyEAP-WiFi-Setup.ps1', MIME.ps1)} />
      <section aria-labelledby="h-run">
        <h2 id="h-run" className="en-h2 mb-4">Run it</h2>
        <InstallSteps platform="windows" route="helper" c={c} />
      </section>
      <div role="status" aria-live="polite">
        {result.finished ? (
          <Note tone="valid" title="Your certificate was issued" icon={<CircleCheck aria-hidden />}>
            The helper used this link to get your certificate. When it says <b>Done</b>, the Wi-Fi profile is installed and you can connect.
          </Note>
        ) : (
          <Note icon={<LoaderCircle className="en-spin" aria-hidden />} title="Waiting for the helper to finish">
            This page checks every few seconds. If the helper says <b>Done</b>, you can continue.
          </Note>
        )}
      </div>
      <Disclosure summary="Prefer to type a command?">
        <p className="en-body mb-3">Open <b>PowerShell</b> (press Start, type <b>PowerShell</b>, press Enter), paste this and press Enter. The window stays open and says <b>Done</b> when it’s finished.</p>
        <Command value={cmd} what="PowerShell command" />
        <p className="en-small mt-2">If the file isn’t in your Downloads folder, change the path to where it is.</p>
      </Disclosure>
      <Disclosure summary="What the helper does">
        <ul className="en-bullets">
          <li>Creates an ECDSA P-256 private key that Windows marks as not exportable. It tries the computer’s security chip (TPM) first, and uses Windows’ software key storage if the chip can’t create one. The window shows which it used.</li>
          <li>Sends only a certificate request, never the key, to {c.tenant} using this link, which then stops working.</li>
          <li>Installs your certificate in your personal certificate store, {c.rootCn ? `“${c.rootCn}”` : 'the root certificate'} in your trusted root store and the issuing certificate in your intermediate store.</li>
          <li>Adds the <b>{c.ssid}</b> Wi-Fi network for your user only. It only trusts the server <b>{c.serverName}</b>.</li>
          <li>Needs no administrator rights and deletes its temporary files when it’s done.</li>
          <li>If it can’t finish, it shows the reason in red. Tell your IT administrator what it says.</li>
        </ul>
      </Disclosure>
      {!result.finished && (
        <p className="en-small">
          The helper didn’t work?{' '}
          <button type="button" className="underline underline-offset-[3px] text-[var(--ee-ink)] min-h-[44px]" onClick={onUseBrowser}>Create the certificate in this browser instead</button>
        </p>
      )}
    </div>
  )
}

function LinuxAdvanced({ result, c, n }: { result: Extract<FlowResult, { kind: 'browser' }>; c: GuideCtx; n: ReturnType<typeof fileNames> }) {
  const nm = result.csr.profiles.networkmanager
  const wpa = result.csr.profiles.wpa_supplicant
  const nmWired = result.csr.profiles.networkmanager_wired ?? null
  const wpaWired = result.csr.profiles.wpa_supplicant_wired ?? null
  if (!nm && !wpa && !nmWired && !wpaWired) return null
  const prep = [
    'sudo mkdir -p /etc/easyeap',
    `sudo cp ${n.caPem} /etc/easyeap/ca-chain.pem`,
    `openssl pkcs12 -in ${n.p12} -clcerts -nokeys -out client.pem`,
    `openssl pkcs12 -in ${n.p12} -nocerts -nodes -out client.key`,
    'sudo install -m 644 client.pem /etc/easyeap/client.pem',
    'sudo install -m 600 client.key /etc/easyeap/client.key && rm client.key',
  ].join('\n')
  return (
    <Disclosure summary={nmWired || wpaWired ? 'For IT staff: NetworkManager or wpa_supplicant (Wi-Fi and wired)' : 'For IT staff: NetworkManager or wpa_supplicant'}>
      <p className="en-body">EasyEAP’s configuration files expect the CA chain, the certificate and an unencrypted private key in <span className="ee-mono">/etc/easyeap/</span>. From the folder with your downloads, run (OpenSSL asks for the certificate password):</p>
      <pre className="ee-code mt-3">{prep}</pre>
      <div className="mt-2"><CopyButton text={prep} what="preparation commands" /></div>
      {nm && (
        <>
          <h3 className="en-h2 mt-5 text-[15px]">NetworkManager</h3>
          <pre className="ee-code mt-2">{nm}</pre>
          <div className="mt-2"><CopyButton text={nm} what="NetworkManager profile" /></div>
        </>
      )}
      {wpa && (
        <>
          <h3 className="en-h2 mt-5 text-[15px]">wpa_supplicant</h3>
          <pre className="ee-code mt-2">{wpa}</pre>
          <div className="mt-2"><CopyButton text={wpa} what="wpa_supplicant block" /></div>
        </>
      )}
      {(nmWired || wpaWired) && (
        <>
          <h3 className="en-h2 mt-6 text-[15px]">Wired network ports (802.1X)</h3>
          <p className="en-body mt-1">For computers plugged into a network port that asks for 802.1X. They use the same files in <span className="ee-mono">/etc/easyeap/</span>. On a port without 802.1X the NetworkManager connection still comes up.</p>
          {nmWired && (
            <>
              <h3 className="en-h2 mt-4 text-[15px]">NetworkManager (wired)</h3>
              <pre className="ee-code mt-2">{nmWired}</pre>
              <div className="mt-2"><CopyButton text={nmWired} what="wired NetworkManager profile" /></div>
            </>
          )}
          {wpaWired && (
            <>
              <h3 className="en-h2 mt-4 text-[15px]">wpa_supplicant (wired)</h3>
              <pre className="ee-code mt-2">{wpaWired}</pre>
              <div className="mt-2"><CopyButton text={wpaWired} what="wired wpa_supplicant file" /></div>
            </>
          )}
        </>
      )}
      <p className="en-small mt-3">{[nm, wpa, nmWired, wpaWired].filter(Boolean).length > 1 ? 'Each one checks' : 'It checks'} that the server is <b>{c.serverName}</b>.</p>
    </Disclosure>
  )
}
