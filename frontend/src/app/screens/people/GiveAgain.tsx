// Handing an enrollment over, and giving a waiting one again without making a new one (routers/enrollments.py
// show_link, windows_setup_again, linux_script_again): a link to copy, with what its platform needs (a QR code a phone
// scans, the Linux setup script, the next steps); a Windows setup file downloaded again with the same one-time codes.
// Each time is in the audit log; nothing is cached here. Used by the Issue dialog, a user's page and the Users list.
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { Download, Hourglass, Link2 } from 'lucide-react'
import { saveBlob } from '../../api/client'
import { downloadLinuxScript, downloadSetupAgain, saveSetupFile, showEnrollmentLink, useRadius, type IdentityListItem, type WaitingEnrollment } from '../../api/people'
import { useTenant } from '../../api/tenant'
import { paths } from '../../routes'
import { Btn, Callout, CopyButton, EDialog, LoadingBlock, errorMessage, platformLabels, toast } from '../../ui'
import { fmtDateTime } from '../../lib/format'
import { QrCode } from '../account/QrCode'
import { qrMatrix } from '../account/qr'

/** What the dialog and the download need of a waiting enrollment. */
export interface Waiting { id: string; device_name: string; expires_at: string; platform: string }

const first = (name: string) => name.split(' ')[0] || name
export const platformShort: Record<string, string> = { windows: 'Windows', macos: 'Mac', ios: 'iPhone/iPad', android: 'Android', linux: 'Linux' }

/** What the person does with a link, on its platform. */
export function nextSteps(platform: string, who: string, ssid: string, server: string, wired = false): string[] {
  const net = ssid ? `“${ssid}”` : 'the Wi-Fi network'
  switch (platform) {
    case 'windows':
      return [`${who} opens the link on the Windows device itself, in Edge or Chrome.`,
        'The page creates the key on the device, then offers an enrollment helper to run in PowerShell. It installs the certificate, trusts your Root CA and adds the Wi-Fi profile.',
        `${who} connects to ${net}. No password is needed.`,
        'This is the user’s certificate only. For the computer’s certificate as well (network at the sign-in screen), use Windows setup.']
    case 'macos':
    case 'ios':
      return [`${who} opens the link on the ${platform === 'ios' ? 'iPhone or iPad' : 'Mac'} itself, in Safari.`,
        platform === 'ios' ? 'They download the profile, then open Settings → Profile Downloaded → Install.'
          : 'They download the profile, then install it in System Settings → General → Device Management (Privacy & Security → Profiles before macOS 15).',
        `When asked for the certificate password, they enter the one shown on the enrollment page, then join ${net}.`]
    case 'android':
      return [`${who} opens the link on the Android device itself, in Chrome.`,
        'They download the certificate file and install it from Settings → Security → More security settings → Install from device storage → Wi-Fi certificate.',
        `They join ${net} with EAP method TLS, the installed CA certificate${server ? ` and domain ${server}` : ''}.`]
    default:
      return [`${who} opens the link on the Linux computer and downloads the setup script, or you hand it over (Download setup script).`,
        'In Terminal: bash ~/Downloads/EasyEAP-WiFi-Setup.sh, then their password once. The key is made on the computer and kept for the whole computer (root only).',
        `The computer joins ${net}${wired ? ' and wired 802.1X' : ''} at boot, before anyone signs in, and renews its certificate itself.`]
  }
}

/** Saves a waiting Linux link's setup script (the one its page gives, with the same one-time code). */
export async function saveLinuxScript(tid: string, e: { id: string }, identityName: string): Promise<boolean> {
  try {
    const res = await downloadLinuxScript(tid, e.id)
    saveBlob(new Blob([res.content], { type: 'text/x-shellscript' }), res.filename)
    toast('Setup script downloaded', `For ${identityName}: it works once, until ${fmtDateTime(res.expires_at)}. They run it with: bash EasyEAP-WiFi-Setup.sh`)
    return true
  } catch (err) {
    toast('The setup script can’t be downloaded', errorMessage(err), 'crit')
    return false
  }
}

/** What helps hand a link over on its platform: a QR code a phone scans, the Linux setup script, the next steps. */
export function LinkHandover({ tid, e, link, identityName }: { tid: string; e: Waiting; link: string; identityName: string }) {
  const radius = useRadius(tid)
  const settings = radius.data?.settings
  const [busy, setBusy] = useState(false)
  // A QR code only where the device has a camera to scan it, and only when the link fits one (versions 1–10).
  const scannable = useMemo(() => (e.platform === 'ios' || e.platform === 'android') && qrMatrix(link) !== null, [e.platform, link])
  return (
    <div className="space-y-4">
      {scannable && (
        <div className="flex flex-wrap items-center gap-4">
          <QrCode text={link} label={`QR code of the enrollment link for ${e.device_name}`} />
          <p className="ee-small ee-ink-2 max-w-[280px]">
            {first(identityName)} can scan this with the {e.platform === 'ios' ? 'iPhone’s or iPad’s' : 'phone’s'} camera to open the link on the device itself, without anyone emailing it.
          </p>
        </div>
      )}
      {e.platform === 'linux' && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <Btn onClick={async () => { setBusy(true); await saveLinuxScript(tid, e, identityName); setBusy(false) }} busy={busy}><Download aria-hidden />Download setup script</Btn>
          <span className="ee-small ee-ink-3">The script the link’s page gives, with the same one-time code: hand it over, or copy it to a computer without a browser.</span>
        </div>
      )}
      <div>
        <p className="text-[13px] font-semibold">Next steps on {platformLabels[e.platform] ?? e.platform}</p>
        <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-[13px] ee-ink-2 marker:text-[var(--ee-ink-3)]">
          {nextSteps(e.platform, first(identityName), settings?.ssid ?? '', settings?.server_hostname ?? '', !!settings?.wired_enabled).map((step) => <li key={step}>{step}</li>)}
        </ol>
      </div>
    </div>
  )
}

/** A pending link, shown again: fetched when the dialog opens (each showing is audited) and dropped when it closes. */
export function ShowLinkDialog({ tid, identityName, e, onClose }: { tid: string; identityName: string; e: Waiting | null; onClose: () => void }) {
  const [link, setLink] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const id = e?.id
  useEffect(() => {
    setLink(null); setError(null)
    if (!id) return
    let live = true
    showEnrollmentLink(tid, id).then((r) => { if (live) setLink(r.link) }, (err) => { if (live) setError(errorMessage(err)) })
    return () => { live = false }
  }, [tid, id])
  return (
    <EDialog open={!!e} onOpenChange={(o) => { if (!o) onClose() }} title={`Enrollment link for ${e?.device_name ?? ''}`}
      description={<>Send it to {identityName} again. It still works once, on the device itself, until {e ? fmtDateTime(e.expires_at) : ''}.</>}
      footer={<Btn onClick={onClose}>Done</Btn>}>
      {error ? <Callout tone="crit" title="The link can’t be shown">{error}</Callout>
        : link && e ? (
          <div className="space-y-5">
            <div className="flex items-center gap-2">
              <code className="ee-secret min-w-0 flex-1 break-all text-[13px]" aria-label="Enrollment link">{link}</code>
              <CopyButton text={link} what="enrollment link" />
            </div>
            <LinkHandover tid={tid} e={e} link={link} identityName={identityName} />
          </div>
        ) : <LoadingBlock label="Getting the link" />}
    </EDialog>
  )
}

/** Saves the waiting Windows setup file again: the program, or the .cmd (asCmd). It goes straight to the downloads. */
export async function saveSetupAgain(tid: string, e: Waiting, identityName: string, asCmd = false): Promise<boolean> {
  try {
    const res = await downloadSetupAgain(tid, e.id)
    const saved = saveSetupFile(res, asCmd)
    toast('Setup file downloaded again', `${saved}, for ${identityName}: the same one-time codes, which still work once, until ${fmtDateTime(res.expires_at)}.`)
    return true
  } catch (err) {
    toast('The setup file can’t be downloaded again', errorMessage(err), 'crit')
    return false
  }
}

const waitingWhat = (w: WaitingEnrollment) =>
  w.method === 'windows-setup' ? 'Windows setup file' : w.method === 'server' ? 'Package' : `${platformShort[w.platform] ?? ''} link`.trim()

/** Links, Windows setup files and packages waiting for a device: give a link or setup file again from here. */
export function WaitingList({ u, onShow, align }: { u: IdentityListItem; onShow: (w: WaitingEnrollment) => void; align?: 'end' }) {
  const { tid, can } = useTenant()
  const [busy, setBusy] = useState<string | null>(null)
  if (!u.waiting?.length) return null
  // A disabled account's codes can't be used (they stay, and work again once it's enabled): its page says so.
  const manage = can('enrollment:manage') && u.account_state === 'enabled'
  return (
    <span className={`mt-1 flex flex-wrap gap-1.5 ${align === 'end' ? 'justify-end' : ''}`}>
      {u.waiting.map((w) => {
        const label = `${waitingWhat(w)} waiting`
        const until = `until ${fmtDateTime(w.expires_at)}`
        const title = `${w.device_name} · expires ${fmtDateTime(w.expires_at)}`
        if (manage && w.available && w.method === 'link') {
          return <Btn key={w.id} size="sm" variant="ghost" title={title} aria-label={`${label} for ${w.device_name} ${until}: show it`} onClick={() => onShow(w)}><Link2 aria-hidden />{label}</Btn>
        }
        if (manage && w.available && w.method === 'windows-setup') {
          return (
            <Btn key={w.id} size="sm" variant="ghost" title={title} aria-label={`${label} for ${u.display_name} ${until}: download it again`} busy={busy === w.id}
              onClick={async () => { setBusy(w.id); await saveSetupAgain(tid, w, u.display_name); setBusy(null) }}>
              <Download aria-hidden />{label}
            </Btn>
          )
        }
        return (
          <Link key={w.id} to={paths.user(tid, u.id)} title={title} aria-label={`${label} for ${w.device_name} ${until}: open ${u.display_name}’s page`}
            className="ee-small ee-ink-2 inline-flex items-center gap-1 hover:underline"><Hourglass aria-hidden className="size-3.5" />{label}</Link>
        )
      })}
    </span>
  )
}
