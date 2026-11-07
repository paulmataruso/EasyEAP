// Device administration: a device's configuration guide (with the TACACS+ key filled in when it has just been shown)
// and key rotation. The key is shown once: the dialog that shows it can't be dismissed until it's been copied or the
// administrator ticks that it's saved.
import { Fragment, useEffect, useId, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { ADDRESS_PLACEHOLDER } from '../../api/radius'
import { KEY_PLACEHOLDER, fillConfig, useDeviceConfig, useRotateKey, type AdminDevice, type DeviceAdminOverview } from '../../api/deviceAdmin'
import { useTenant } from '../../api/tenant'
import { fmtDateTime } from '../../lib/format'
import { Btn, Callout, CopyButton, EDialog, ErrorState, Field, LoadingBlock, OneTimeSecret, Seg, errorMessage } from '../../ui'
import { Marked } from '../radius/Guide'

/** `code` spans in the guide's prose, and <placeholders> marked. */
export function Prose({ text }: { text: string }) {
  return <>{text.split(/(`[^`]+`)/g).map((p, i) => (p.startsWith('`') && p.endsWith('`') && p.length > 1
    ? <code key={i} className="ee-mono text-[12.5px]">{p.slice(1, -1)}</code>
    : <Fragment key={i}><Marked text={p} /></Fragment>))}</>
}

export function ConfigDialog({ device, secret, server, onClose }: {
  device: AdminDevice | null
  /** The key just created or rotated: shown once, and filled into the configuration. */
  secret: string | null
  server: DeviceAdminOverview['server']
  onClose: () => void
}) {
  const { tid } = useTenant()
  const id = useId()
  const [legacy, setLegacy] = useState(false)
  const [address, setAddress] = useState('')
  const [saved, setSaved] = useState(false)
  // Reset when another device opens, not when this one's row refreshes (a login while the dialog is open).
  const deviceId = device?.id
  const classic = device?.classic ?? false
  useEffect(() => { if (deviceId) { setLegacy(classic); setSaved(false) } }, [deviceId, classic])
  const q = useDeviceConfig(tid, device?.id ?? null, legacy)
  const guide = q.data
  const needsAddress = !!guide && guide.config.includes(ADDRESS_PLACEHOLDER)
  const fill = (t: string) => fillConfig(t, secret, needsAddress ? address.trim() || null : null)
  const config = guide ? fill(guide.config) : ''
  const left = [...new Set(config.match(/<[a-z][a-z0-9-]*>/g) ?? [])]
  const mustAck = !!secret && !saved
  return (
    <EDialog open={!!device} onOpenChange={(o) => !o && onClose()} wide blockDismiss={mustAck}
      title={device ? `Admin logins on ${device.name}` : ''}
      description="Paste this on the device so administrators log in with their AD or EasyEAP account. The device keeps its own local accounts for when EasyEAP can’t be reached."
      footer={<Btn variant={mustAck ? 'default' : 'primary'} disabled={mustAck} onClick={onClose}>Done</Btn>}>
      <div className="space-y-5">
        {secret && (
          <section aria-label="The device's key, shown once" className="space-y-2">
            <p className="text-[13px] font-semibold">TACACS+ key for {device?.name}</p>
            <OneTimeSecret value={secret} what="TACACS+ key" acknowledged={saved} onAcknowledge={setSaved}
              note={<>EasyEAP shows this key once and has filled it into the configuration below. If it’s lost, rotate the key: the old one keeps working for a day.</>} />
          </section>
        )}
        {needsAddress && (
          <Field label="EasyEAP address" htmlFor={`${id}-addr`} hint={server.radius_address_problem ?? 'This EasyEAP server has no RADIUS address configured (EASYEAP_RADIUS_ADDRESS in the deploy .env). Enter the address devices reach it on: TACACS+ uses TCP 49 to the same address.'}>
            <input id={`${id}-addr`} className="ee-input ee-mono max-w-[260px]" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.10" autoComplete="off" spellCheck={false} />
          </Field>
        )}
        <Seg label="IOS version" value={legacy ? 'legacy' : 'current'} onChange={(v) => setLegacy(v === 'legacy')}
          options={[{ value: 'current', label: 'IOS-XE and IOS 15.2+' }, { value: 'legacy', label: 'Older IOS (tacacs-server host)' }]} />
        {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="The configuration couldn’t be loaded" /> : !guide ? <LoadingBlock rows={6} label="Loading the configuration" /> : (
          <>
            <Callout tone="warn" title="Not yet verified on Cisco hardware">
              EasyEAP’s TACACS+ service is tested against a client that follows IOS’s login sequence. Keep a session open and use <code className="ee-mono text-[12.5px]">reload in 15</code> as the steps say.
            </Callout>
            <section aria-label="Check the device first">
              <p className="text-[13px] font-semibold mb-2">1. Check the device first</p>
              <ol className="space-y-2">
                {guide.preflight.map((c) => (
                  <li key={c.command} className="grid gap-1 sm:grid-cols-[minmax(0,22rem)_minmax(0,1fr)] sm:gap-4">
                    <code className="ee-mono text-[12.5px] break-all">{fill(c.command)}</code>
                    <span className="ee-small ee-ink-2">{c.look_for}</span>
                  </li>
                ))}
              </ol>
            </section>
            <section aria-label="Configuration">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <p className="text-[13px] font-semibold">2. Configuration</p>
                <CopyButton text={config} what={`${device?.name} admin login configuration`} label="Copy configuration" />
              </div>
              <pre className="ee-code max-h-[420px] overflow-auto" tabIndex={0} aria-label="Admin login configuration"><Marked text={config} /></pre>
            </section>
            <section aria-label="Steps">
              <p className="text-[13px] font-semibold mb-2">3. Paste it safely</p>
              <ol className="list-decimal space-y-1.5 pl-5 text-[13.5px] marker:text-[var(--ee-ink-3)] marker:tabular-nums">
                {guide.steps.map((s) => <li key={s} className="pl-1"><Prose text={s} /></li>)}
              </ol>
            </section>
            <details className="rounded-[10px] border border-[var(--ee-line)] p-3">
              <summary className="cursor-pointer text-[13px] font-semibold">Rollback: back to local logins only</summary>
              <div className="mt-3 space-y-2">
                <div className="flex justify-end"><CopyButton text={fill(guide.rollback)} what="rollback configuration" label="Copy rollback" /></div>
                <pre className="ee-code max-h-[260px] overflow-auto" tabIndex={0} aria-label="Rollback configuration">{fill(guide.rollback)}</pre>
              </div>
            </details>
            <ul className="list-disc space-y-1 pl-5 ee-small ee-ink-2 marker:text-[var(--ee-ink-3)]">{guide.notes.map((n) => <li key={n} className="pl-1">{n}</li>)}</ul>
            {left.length > 0 && (
              <div className="ee-small ee-ink-3">
                <p>Replace the highlighted values before you paste:</p>
                <ul className="mt-1 space-y-0.5">
                  {left.map((p) => (
                    <li key={p}><mark className="ee-mono rounded-[3px] bg-[rgba(226,194,117,0.16)] px-1 text-[var(--ee-gold)]">{p}</mark>{' '}
                      {p === KEY_PLACEHOLDER ? 'the TACACS+ key EasyEAP showed when admin logins were turned on (rotate the key to get a new one)' : p === ADDRESS_PLACEHOLDER ? 'the address devices use to reach EasyEAP' : 'a value from your device'}</li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </EDialog>
  )
}

export function RotateKeyDialog({ device, onClose, onRotated }: { device: AdminDevice | null; onClose: () => void; onRotated: (d: AdminDevice, key: string) => void }) {
  const { tid } = useTenant()
  const rotate = useRotateKey(tid)
  const [error, setError] = useState<string | null>(null)
  const deviceId = device?.id
  useEffect(() => { if (deviceId) setError(null) }, [deviceId])
  return (
    <EDialog open={!!device} onOpenChange={(o) => !o && onClose()} risk="warn" title={`Rotate the TACACS+ key for ${device?.name}?`}
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="primary" busy={rotate.isPending} onClick={() => device && rotate.mutate(device.id, {
          onSuccess: (r) => onRotated(r.device, r.key),
          onError: (e) => setError(errorMessage(e)),
        })}><RefreshCw aria-hidden />Rotate key</Btn></>}>
      <div className="space-y-3 text-[13.5px] ee-ink-2">
        <p>EasyEAP creates a new key and shows it once. The current key keeps working for 24 hours, so you can change the device in that time.</p>
        {device?.previous_key_until && <Callout tone="warn">The key before the last rotation still works until {fmtDateTime(device.previous_key_until)}. Rotating now ends that early: only the current key and the new one will work.</Callout>}
        {error && <Callout tone="crit">{error}</Callout>}
      </div>
    </EDialog>
  )
}
