// Windows setup for one user: POST /api/tenants/{tid}/enrollments/windows-setup (routers/enrollments.py,
// docs/plans/windows-setup.md). One file that sets up a Windows 11 PC (a program users double-click, or the .cmd it
// carries): CA trust, Wi-Fi and wired profiles, the user's certificate and the computer's (so the sign-in screen has
// network), and their renewal. It carries one-time codes, never a key; the file is saved straight to the browser's
// downloads and kept here only until the dialog closes.
import { useState, type RefObject } from 'react'
import { Download, MonitorCheck } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { useAutoenroll } from '../../api/autoenroll'
import { useTenant } from '../../api/tenant'
import { createWindowsSetup, invalidatePeople, saveSetupFile, useRadius, type WindowsSetupResult } from '../../api/people'
import { Btn, Callout, EDialog, ESelect, ESwitch, errorMessage, Field } from '../../ui'
import { fmtDateTime } from '../../lib/format'

const TTL = [
  { value: '24', label: '24 hours' },
  { value: '72', label: '3 days' },
  { value: '168', label: '7 days' },
  { value: '336', label: '14 days' },
]

export const MODE_TEXT: Record<WindowsSetupResult['sign_in_mode'], string> = {
  machineOrUser: 'The computer’s certificate at the sign-in screen, then the user’s.',
  machine: 'The computer’s certificate, always. Anyone who signs in on the PC keeps the network.',
  user: 'The user’s certificate, after they sign in. The sign-in screen has no network on 802.1X ports.',
}

export function WindowsSetupDialog({ identity, open, onOpenChange, returnFocus }: {
  identity: { id: string; display_name: string; username: string; upn: string | null }
  open: boolean
  onOpenChange: (o: boolean) => void
  returnFocus?: RefObject<HTMLElement | null>
}) {
  const { tid, can } = useTenant()
  const qc = useQueryClient()
  const radius = useRadius(tid, open)
  const ae = useAutoenroll(tid, open && can('directory:read')).data?.config
  const gpoComputers = !!(ae?.enabled && ae.computers)
  const settings = radius.data?.settings
  const [userCert, setUserCert] = useState(true)
  const [computerCert, setComputerCert] = useState(true)
  const [wifi, setWifi] = useState(true)
  const [wired, setWired] = useState<boolean | null>(null)
  const [shared, setShared] = useState(false)
  const [ttl, setTtl] = useState('72')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<(WindowsSetupResult & { saved: string }) | null>(null)

  const hasSsid = !!settings?.ssid
  const wiredOn = wired ?? !!settings?.wired_enabled
  const wifiOn = wifi && hasSsid
  const name = identity.display_name.split(' ')[0] || identity.display_name
  const nothing = !userCert && !computerCert ? 'Choose at least one certificate.' : !wifiOn && !wiredOn ? 'Choose Wi-Fi, wired, or both.' : null

  const close = (o: boolean) => {
    if (!o) { setDone(null); setError(null) }
    onOpenChange(o)
  }

  const create = async () => {
    setBusy(true); setError(null)
    try {
      const res = await createWindowsSetup(tid, {
        identity_id: identity.id, user_certificate: userCert, computer_certificate: computerCert, wifi: wifiOn, wired: wiredOn,
        shared_pc: shared && computerCert, ttl_hours: Number(ttl),
      })
      setDone({ ...res, saved: saveSetupFile(res) })  // kept until the dialog closes, for "Download the .cmd instead"
      invalidatePeople(qc, tid)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  if (done) {
    return (
      <EDialog open={open} onOpenChange={close} returnFocus={returnFocus} title={`Windows setup for ${identity.display_name}`}
        description={`Saved as ${done.saved}. Its codes work once and expire ${fmtDateTime(done.expires_at)}.`}
        footer={<>
          {done.saved !== done.filename && <Btn variant="ghost" onClick={() => saveSetupFile(done, true)}>Download the .cmd instead</Btn>}
          <Btn variant="primary" onClick={() => close(false)}>Done</Btn>
        </>}>
        <ol className="ee-small ee-ink-2 list-decimal space-y-1.5 pl-5">
          <li>Copy the file to the PC, or send it to {name}. It holds no key: the PC makes its own (in the TPM, or a non-exportable software key on PCs without one).</li>
          <li>{name} signs in on the PC as themselves and double-clicks it. If Windows says it protected the PC, choose <b>More info</b>, then <b>Run anyway</b> (the file isn’t code-signed).</li>
          <li>Windows asks for administrator approval for the computer part. A standard user needs IT to enter an administrator’s password there.</li>
          <li>The window lists what was set up. Certificates renew themselves before they expire.</li>
        </ol>
        <p className="ee-small ee-ink-3 mt-3">Network sign-in: {MODE_TEXT[done.sign_in_mode]}</p>
      </EDialog>
    )
  }

  return (
    <EDialog open={open} onOpenChange={close} returnFocus={returnFocus} wide title={`Windows setup for ${identity.display_name}`}
      description="One file that sets up a Windows 11 PC: trust in your CA, the Wi-Fi and wired networks, the certificates, and their renewal. Run it on the PC, signed in as this user."
      footer={<><Btn variant="ghost" onClick={() => close(false)} disabled={busy}>Cancel</Btn>
        <Btn variant="primary" onClick={create} busy={busy} disabled={!!nothing || radius.isLoading || !settings}><Download aria-hidden />Download setup</Btn></>}>
      {!radius.isLoading && !settings && <Callout tone="warn" title="Save the RADIUS settings first">The Wi-Fi and wired profiles need the RADIUS server name.</Callout>}
      <div className="grid gap-5 sm:grid-cols-2">
        <fieldset className="space-y-2.5">
          <legend className="ee-label mb-2">Certificates</legend>
          <ESwitch checked={userCert} onChange={setUserCert} label={`${name}’s certificate`} />
          <ESwitch checked={computerCert} onChange={setComputerCert} label="The computer’s certificate (network at the sign-in screen)" />
          {computerCert && <ESwitch checked={shared} onChange={setShared} label="Shared PC: always connect with the computer’s certificate" />}
          {computerCert && gpoComputers && (
            <Callout tone="warn" title="Group Policy gives domain PCs their own certificate">
              Computer autoenrollment is on. On a domain PC, leave the computer’s certificate off: autoenrollment replaces it at the next policy refresh, and the PC then connects as itself (its AD groups), not as {name}.
            </Callout>
          )}
        </fieldset>
        <fieldset className="space-y-2.5">
          <legend className="ee-label mb-2">Networks</legend>
          <ESwitch checked={wifiOn} onChange={setWifi} disabled={!hasSsid} label={hasSsid ? `Wi-Fi (${settings?.ssid})` : 'Wi-Fi (no network name in RADIUS settings)'} />
          <ESwitch checked={wiredOn} onChange={(v) => setWired(v)} label="Wired 802.1X (switch ports)" />
          <Field label="Codes expire after" htmlFor="ws-ttl">
            <ESelect id="ws-ttl" value={ttl} onChange={setTtl} options={TTL} label="Codes expire after" />
          </Field>
        </fieldset>
      </div>
      <p className="ee-small ee-ink-2 mt-4 flex gap-2">
        <MonitorCheck className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>Network sign-in: {MODE_TEXT[computerCert && (shared || !userCert) ? 'machine' : computerCert ? 'machineOrUser' : 'user']}
          {' '}The computer’s certificate belongs to {name}, so the PC gets {name}’s access.</span>
      </p>
      {nothing && <p className="ee-small mt-2 text-[var(--ee-warn-ink)]">{nothing}</p>}
      {error && <Callout tone="crit" className="mt-3" title="The setup couldn’t be created">{error}</Callout>}
      <p className="ee-small ee-ink-3 mt-3">Domain PCs can get certificates through Group Policy instead (RADIUS → Windows Group Policy).</p>
    </EDialog>
  )
}
