import { useEffect, useState, type ReactNode } from 'react'
import { ArrowRight, CircleCheck, Download, FileCheck2, LoaderCircle } from 'lucide-react'
import { EnrollError, getLink, isPending, type PendingInfo, type Platform } from './api'
import { PackageAck } from './Create'
import { MIME, saveFile } from './files'
import { InstallSteps, linuxCommand, type GuideCtx, type Route } from './guides'
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
          route === 'helper' ? <>Run the {platform === 'linux' ? 'setup script' : 'helper'} you just downloaded. It installs your certificate and the <b>{c.ssid}</b> network.</>
          : result.kind === 'package' ? <>Your {result.format === 'mobileconfig' ? 'Wi-Fi profile' : 'certificate file'} is on this device. Now install it.</>
          : <>Your certificate is ready. It’s only on this page until you install it, so keep the page open.</>
        }
      >
        {route === 'helper' ? (platform === 'linux' ? 'Run the setup script' : 'Install with the setup helper') : 'Install your certificate'}
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
                    onSave={() => saveFile(platform === 'linux' ? (result.csr.root_ca_pem ?? '') + result.csr.issuing_ca_pem : result.csr.issuing_ca_pem + (result.csr.root_ca_pem ?? ''), platform === 'android' ? n.caCrt : n.caPem, platform === 'android' ? MIME.crt : MIME.pem)}
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
        <HelperInstall token={token} platform={platform} result={result} c={c} onResult={onResult} onUseBrowser={onUseBrowser} onGone={onGone} />
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
              onSave={() => saveFile(platform === 'linux' ? rootFirst(result.caPem!) : result.caPem!, platform === 'android' ? n.caCrt : n.caPem, platform === 'android' ? MIME.crt : MIME.pem)}
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

function HelperInstall({ token, platform, result, c, onResult, onUseBrowser, onGone }: {
  token: string
  platform: Platform
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

  const linux = platform === 'linux'
  const file = c.files.helper ?? (linux ? 'EasyEAP-WiFi-Setup.sh' : 'EasyEAP-WiFi-Setup.ps1')
  const what = linux ? 'script' : 'helper'
  return (
    <div className="space-y-6">
      <SavedFile name={file} onAgain={() => saveFile(result.script, file, linux ? MIME.sh : MIME.ps1)} />
      <section aria-labelledby="h-run">
        <h2 id="h-run" className="en-h2 mb-4">Run it</h2>
        <InstallSteps platform={platform} route="helper" c={c} />
      </section>
      <div role="status" aria-live="polite">
        {result.finished ? (
          <Note tone="valid" title="Your certificate was issued" icon={<CircleCheck aria-hidden />}>
            The {what} used this link to get your certificate. When it says <b>Done</b>, {linux ? 'the network is set up' : 'the Wi-Fi profile is installed'} and you can connect.
          </Note>
        ) : (
          <Note icon={<LoaderCircle className="en-spin" aria-hidden />} title={`Waiting for the ${what} to finish`}>
            This page checks every few seconds. If the {what} says <b>Done</b>, you can continue.
          </Note>
        )}
      </div>
      {linux ? <LinuxHelperDetails c={c} file={file} /> : <WindowsHelperDetails c={c} file={file} />}
      {!result.finished && (
        <p className="en-small">
          The {what} didn’t work?{' '}
          <button type="button" className="underline underline-offset-[3px] text-[var(--ee-ink)] min-h-[44px]" onClick={onUseBrowser}>Create the certificate in this browser instead</button>
        </p>
      )}
    </div>
  )
}

function WindowsHelperDetails({ c, file }: { c: GuideCtx; file: string }) {
  const cmd = `powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\${file}"`
  return (
    <>
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
    </>
  )
}

function LinuxHelperDetails({ c, file }: { c: GuideCtx; file: string }) {
  return (
    <>
      <Disclosure summary="Check first, without changing anything">
        <p className="en-body mb-3">This shows what the script found on your computer and what it would do. It doesn’t use your link or change anything:</p>
        <Command value={`${linuxCommand(file)} --check`} what="check command" />
      </Disclosure>
      <Disclosure summary="What the script does">
        <ul className="en-bullets">
          <li>Finds what your computer uses for networks: NetworkManager (Ubuntu, Debian, Fedora, Linux Mint, Raspberry Pi OS and most desktops), iwd, or wpa_supplicant with systemd-networkd (Ubuntu Server).</li>
          <li>Creates a private key on this computer and sends only a certificate request, never the key, to {c.tenant} using this link, which then stops working.</li>
          <li>Saves the certificate, the key and {c.rootCn ? `“${c.rootCn}”` : 'your organisation’s certificate authority'} in <span className="ee-mono">/etc/easyeap/</span>. Only administrators can read the key.</li>
          <li>Adds <b>{c.ssid}</b> for everyone who uses this computer{c.wired ? ', and network ports that ask for 802.1X,' : ''} and connects if it’s in range. It only trusts the server <b>{c.serverName}</b>, and nothing asks for a password.</li>
          <li>Replaces settings for <b>{c.ssid}</b> left by an earlier try, and renews the certificate by itself before it expires.</li>
          <li><span className="ee-mono">{linuxCommand(file)} --remove</span> undoes all of it.</li>
        </ul>
      </Disclosure>
    </>
  )
}

/** Issuing CA then Root CA (as the API returns it) → Root CA first. */
function rootFirst(chainPem: string): string {
  const blocks = chainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\s*/g)
  return blocks && blocks.length > 1 ? [...blocks].reverse().join('') : chainPem
}

function LinuxAdvanced({ result, c, n }: { result: Extract<FlowResult, { kind: 'browser' }>; c: GuideCtx; n: ReturnType<typeof fileNames> }) {
  const q = (v: string) => (/^[\w@%+=:,./-]+$/.test(v) ? v : `'${v.replace(/'/g, `'\\''`)}'`)
  const dir = '/etc/easyeap'
  const p12 = `${dir}/${n.p12}`
  const ca = `${dir}/${n.caPem}`
  const copy = [
    `sudo mkdir -p ${dir}`,
    `sudo cp ~/Downloads/${q(n.p12)} ~/Downloads/${q(n.caPem)} ${dir}/`,
    `sudo chmod 600 ${q(p12)}`,
  ].join('\n')
  const nm = [
    `sudo nmcli connection add type wifi con-name ${q(c.ssid)} ssid ${q(c.ssid)} wifi-sec.key-mgmt wpa-eap \\`,
    `  802-1x.eap tls 802-1x.identity ${q(c.identity)} 802-1x.domain-suffix-match ${q(c.serverName)} \\`,
    `  802-1x.ca-cert ${q(ca)} 802-1x.client-cert ${q(p12)} 802-1x.private-key ${q(p12)} \\`,
    `  802-1x.private-key-password-flags 0 802-1x.private-key-password ${q(result.password)}${c.wpa3 ? ' wifi-sec.pmf required' : ''}`,
    `sudo nmcli connection up ${q(c.ssid)}`,
  ].join('\n')
  const wiredName = `Wired 802.1X (${c.tenant})`
  const nmWired = [
    `sudo nmcli connection add type ethernet con-name ${q(wiredName)} connection.autoconnect-priority 10 \\`,
    `  802-1x.eap tls 802-1x.identity ${q(c.identity)} 802-1x.domain-suffix-match ${q(c.serverName)} \\`,
    `  802-1x.ca-cert ${q(ca)} 802-1x.client-cert ${q(p12)} 802-1x.private-key ${q(p12)} \\`,
    `  802-1x.private-key-password-flags 0 802-1x.private-key-password ${q(result.password)} 802-1x.optional yes`,
  ].join('\n')
  // Hex: wpa_supplicant takes any value this way, quotes and # included.
  const hex = (v: string) => [...new TextEncoder().encode(v)].map((b) => b.toString(16).padStart(2, '0')).join('')
  const wpa = [
    'network={',
    `    ssid=${hex(c.ssid)}`,
    '    key_mgmt=WPA-EAP WPA-EAP-SHA256',
    `    ieee80211w=${c.wpa3 ? 2 : 1}`,
    '    eap=TLS',
    `    identity=${hex(c.identity)}`,
    `    ca_cert="${ca}"`,
    `    private_key="${p12}"`,
    `    private_key_passwd=${hex(result.password)}`,
    `    domain_suffix_match="${c.serverName}"`,
    '}',
  ].join('\n')
  return (
    <Disclosure summary="For IT staff: set it up from a terminal instead">
      <p className="en-body">The <b>Linux setup script</b> does all of this by itself, with a key made on the computer and no password to keep: go back to the first step and choose it. To use the files from this page instead:</p>
      <ol className="en-howto mt-4" aria-label="Terminal setup">
        <li>
          Copy both files to <span className="ee-mono">{dir}</span>, where only administrators can read the certificate:
          <pre className="ee-code mt-2">{copy}</pre>
          <div className="mt-2"><CopyButton text={copy} what="copy commands" /></div>
        </li>
        <li>
          <b>NetworkManager</b> (Ubuntu and Debian desktops, Fedora, Linux Mint, Raspberry Pi OS): add the network for all users. The certificate password is saved with it, so nothing asks for it when connecting:
          <pre className="ee-code mt-2">{nm}</pre>
          <div className="mt-2"><CopyButton text={nm} what="NetworkManager commands" /></div>
          <span className="en-sub">If a <b>{c.ssid}</b> connection is already saved, delete it first: <span className="ee-mono">sudo nmcli connection delete {q(c.ssid)}</span>.</span>
          {c.wired && (
            <>
              <span className="en-sub">For network ports that ask for 802.1X (other ports keep working as before):</span>
              <pre className="ee-code mt-2">{nmWired}</pre>
              <div className="mt-2"><CopyButton text={nmWired} what="wired NetworkManager command" /></div>
            </>
          )}
        </li>
        <li>
          <b>No NetworkManager</b> (Ubuntu Server, minimal installs): find the Wi-Fi interface with <span className="ee-mono">iw dev</span> (for example <span className="ee-mono">wlan0</span>). Put this in <span className="ee-mono">/etc/wpa_supplicant/wpa_supplicant-wlan0.conf</span>, with the line <span className="ee-mono">ctrl_interface=/run/wpa_supplicant</span> above it if the file is new, and make the file <span className="ee-mono">chmod 600</span>:
          <pre className="ee-code mt-2">{wpa}</pre>
          <div className="mt-2"><CopyButton text={wpa} what="wpa_supplicant settings" /></div>
          <span className="en-sub">Start it now and at every boot with <span className="ee-mono">sudo systemctl enable --now wpa_supplicant@wlan0</span>, and get an address with <span className="ee-mono">DHCP=yes</span> in a systemd-networkd <span className="ee-mono">.network</span> file for <span className="ee-mono">wlan0</span>. <span className="ee-mono">wpa_cli -i wlan0 status</span> shows <span className="ee-mono">wpa_state=COMPLETED</span> once it’s connected.</span>
        </li>
      </ol>
      <p className="en-small mt-3">Both only trust the server <b>{c.serverName}</b>. Renewing is up to you: this certificate expires and won’t renew itself.</p>
    </Disclosure>
  )
}
