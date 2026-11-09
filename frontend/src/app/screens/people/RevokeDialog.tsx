// Revoke a certificate. Used by the certificate list, the certificate page and the user page.
// What the backend does (routers/certificates.py → revoke): revokes the serial in the tenant's issuing CA (the CRL is
// rebuilt), recomputes every decision, bumps the RADIUS snapshot, and, when `disconnect` is true, queues a CoA
// Disconnect-Request (radius/coa.py) for sessions that authenticated with this serial in the last two days, but only
// to controllers with CoA enabled. Sessions on other controllers last until the controller re-authenticates them.
// A renewed certificate's successors (renewed with its key) are revoked with it unless the admin unticks that
// (docs/plans/cert-renewal.md §15b item 4).
import { useEffect, useState, type RefObject } from 'react'
import { Link } from 'react-router'
import { RadioGroup } from 'radix-ui'
import { CircleAlert, RadioTower, ShieldX, TimerReset, Undo2 } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { cn } from '@/ui/lib'
import { useTenant } from '../../api/tenant'
import { invalidatePeople, REVOCATION_REASONS, revokeCertificate, useCertificate, useRadius, type Certificate, type RevocationReason, type RevokeResult } from '../../api/people'
import { Btn, Callout, EDialog, errorMessage, PlatformIcon, toast } from '../../ui'
import { duration, fmtSerial, plural } from '../../lib/format'
import { paths } from '../../routes'
import { joinNames, REASON_META } from './shared'

type RevokeTarget = Pick<Certificate, 'id' | 'serial' | 'common_name' | 'status' | 'purpose'> & {
  identity?: { id: string; display_name: string } | null
  device?: { name: string; platform: string } | null
}

/** Plain summary of what the CoA step did. */
export function disconnectSummary(r: RevokeResult['disconnect'], timeout: number | null): string {
  if (r.sessions === 0) return 'No recent sessions used this certificate, so there was nothing to disconnect.'
  const parts: string[] = []
  if (r.queued) parts.push(`Disconnect queued for ${plural(r.queued, 'session')} on controllers with CoA.`)
  if (r.without_coa) parts.push(`${plural(r.without_coa, 'session')} on controllers without CoA stay${r.without_coa === 1 ? 's' : ''} connected until the session timeout${timeout ? ` (${duration(timeout)})` : ''}.`)
  return parts.join(' ')
}

export function RevokeDialog({ cert, open, onOpenChange, returnFocus, onRevoked }: {
  cert: RevokeTarget | null
  open: boolean
  onOpenChange: (o: boolean) => void
  /** Where focus goes after a successful revoke (the changed row). Cancel returns focus to the opener. */
  returnFocus?: RefObject<HTMLElement | null>
  onRevoked?: (result: RevokeResult) => void
}) {
  const { tid } = useTenant()
  const qc = useQueryClient()
  const radius = useRadius(tid, open)
  const [reason, setReason] = useState<RevocationReason | ''>('')
  const [disconnect, setDisconnect] = useState(true)
  const [withSuccessors, setWithSuccessors] = useState(true)
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  // Fresh form each time it opens.
  useEffect(() => {
    if (open) { setReason(''); setDisconnect(true); setWithSuccessors(true); setTouched(false); setError(null); setBusy(false); setDone(false) }
  }, [open, cert?.id])
  // What revoking it would revoke too (the chain renewed from it), whatever its status: an expired certificate can have
  // a valid renewal. Cached when opened from the certificate's own page. Nothing cascades unless it was shown here.
  const detail = useCertificate(tid, open && cert && cert.status !== 'revoked' ? cert.id : null)
  const successors = detail.data?.revoke_also ?? []
  const checking = detail.isLoading

  const clients = radius.data?.clients ?? []
  const coa = clients.filter((c) => c.coa_enabled)
  const noCoa = clients.filter((c) => !c.coa_enabled)
  const timeout = radius.data?.settings?.session_timeout_seconds ?? null
  // A disconnect can only be offered when a controller can receive it. `disconnect` records the admin's choice; what is
  // sent is that choice AND at least one CoA controller, so the checkbox never promises an effect that can't happen.
  const canCoa = coa.length > 0
  const sendDisconnect = canCoa && disconnect
  const who = cert?.device?.name ? `${cert.device.name}${cert.identity ? ` (${cert.identity.display_name})` : ''}` : cert?.identity?.display_name ?? cert?.common_name ?? ''

  const confirm = async () => {
    setTouched(true)
    if (!cert || !reason) return
    setBusy(true)
    setError(null)
    try {
      const res = await revokeCertificate(tid, cert.id, reason, sendDisconnect, withSuccessors && successors.length > 0)
      setDone(true)
      const also = res.successors?.length ? ` The ${plural(res.successors.length, 'certificate')} renewed from it ${res.successors.length === 1 ? 'was' : 'were'} revoked too.` : ''
      toast(`Certificate ${fmtSerial(cert.serial).slice(0, 14)}… revoked${also ? ' with its renewals' : ''}`,
        `${REASON_META[reason].label}.${also} RADIUS rejects new connections with it once the update is applied, normally within seconds. ${sendDisconnect ? disconnectSummary(res.disconnect, res.session_timeout_seconds ?? timeout) : canCoa ? 'No disconnect was sent; connected devices stay online until the session timeout.' : 'No controller has CoA, so connected devices stay online until the session timeout.'}`,
        'valid')
      onRevoked?.(res)
      onOpenChange(false)
      void invalidatePeople(qc, tid)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  return (
    <EDialog
      open={open && !!cert}
      onOpenChange={(o) => { if (!busy) onOpenChange(o) }}
      title={`Revoke the certificate for ${who}?`}
      description={cert ? <>Serial <span className="ee-mono">{fmtSerial(cert.serial)}</span></> : undefined}
      risk="crit"
      wide
      returnFocus={done ? returnFocus : undefined}
      footer={
        <>
          <Btn variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>Keep certificate</Btn>
          <Btn variant="danger-solid" onClick={confirm} busy={busy} disabled={checking}><ShieldX aria-hidden />Revoke certificate</Btn>
        </>
      }
    >
      {cert && (
        <div className="space-y-5">
          {cert.device && (
            <p className="flex items-center gap-2 text-[13px] ee-ink-2"><PlatformIcon platform={cert.device.platform} />{cert.device.name} · {cert.common_name}</p>
          )}
          {error && <Callout tone="crit" title="The certificate wasn’t revoked">{error}</Callout>}

          <fieldset>
            <legend className="mb-2 text-[13px] font-semibold">Reason <span className="font-normal ee-ink-3">required, published in the CRL and the audit log</span></legend>
            <RadioGroup.Root
              value={reason}
              onValueChange={(v) => { setReason(v as RevocationReason); setError(null) }}
              className="grid gap-2 sm:grid-cols-2"
              aria-label="Revocation reason"
              aria-required
              aria-invalid={touched && !reason}
            >
              {REVOCATION_REASONS.map((r) => (
                <RadioGroup.Item key={r} value={r} className={cn('ee-radio-card', r === 'unspecified' && 'sm:col-span-2')}>
                  <span className="ee-radio-dot" aria-hidden />
                  <span className="min-w-0">
                    <span className="block text-[13.5px] font-semibold">{REASON_META[r].label}</span>
                    <span className="ee-small ee-ink-2 mt-0.5 block">{REASON_META[r].explain}</span>
                  </span>
                </RadioGroup.Item>
              ))}
            </RadioGroup.Root>
            {touched && !reason && <p className="ee-field-error mt-2" role="alert">Choose a reason. It is published in the CRL and recorded in the audit log.</p>}
          </fieldset>

          <div className="rounded-[8px] border border-[var(--ee-line)] bg-[rgba(6,9,17,0.4)] px-4 py-3 text-[13px]">
            <p className="font-semibold">What happens</p>
            <ul className="mt-2 space-y-2.5 ee-ink-2">
              <li className="flex gap-2.5">
                <ShieldX className="mt-0.5 size-4 shrink-0 text-[var(--ee-crit-ink)]" aria-hidden />
                <span><span className="text-[var(--ee-ink)]">New connections are rejected within seconds.</span> EasyEAP publishes a new CRL and rebuilds the RADIUS authorization snapshot now; RADIUS rejects this certificate as soon as it applies the update, normally within seconds.</span>
              </li>
              <li className="flex gap-2.5">
                <RadioTower className="mt-0.5 size-4 shrink-0 text-[var(--ee-warn)]" aria-hidden />
                <span>
                  <span className="text-[var(--ee-ink)]">A device that is already connected stays online</span> until a CoA disconnect ends its session or the controller re-authenticates it at the session timeout{timeout ? ` (${duration(timeout)})` : ''}.{' '}
                  {radius.isLoading ? 'Checking which controllers support CoA…'
                    : clients.length === 0 ? 'This tenant has no controllers registered.'
                      : <>
                        {coa.length === 0
                          ? <>No controller in this tenant has CoA turned on, so connected devices stay online until the session timeout.</>
                          : noCoa.length === 0
                            ? <>CoA is on for {joinNames(coa)}.</>
                            : <>CoA is on for {joinNames(coa)} and off for {joinNames(noCoa)}, so devices connected through {noCoa.length === 1 ? 'that controller' : 'those controllers'} stay online until the session timeout.</>}
                      </>}
                </span>
              </li>
              <li className="flex gap-2.5">
                <Undo2 className="mt-0.5 size-4 shrink-0 text-[var(--ee-crit-ink)]" aria-hidden />
                <span><span className="text-[var(--ee-ink)]">Revocation is permanent. There is no undo.</span> If this device should connect again, issue it a new certificate.</span>
              </li>
            </ul>
            <label className={cn('mt-3 flex items-start gap-2.5 border-t border-[var(--ee-line)] pt-3', !canCoa && 'ee-ink-3')}>
              <input type="checkbox" className="ee-check mt-0.5" checked={sendDisconnect} disabled={!canCoa} aria-describedby="revoke-coa-hint" onChange={(e) => setDisconnect(e.target.checked)} />
              <span>
                <span className={canCoa ? 'text-[var(--ee-ink)]' : undefined}>Send a CoA disconnect for sessions that used this certificate</span>
                <span id="revoke-coa-hint" className="ee-small ee-ink-3 block">
                  {radius.isLoading ? 'Checking which controllers support CoA…'
                    : canCoa ? 'EasyEAP looks for sessions from the last two days and queues a Disconnect-Request for the RADIUS agent to send. Only controllers with CoA enabled receive it.'
                      : <>Not available: no controller in this tenant has CoA turned on. You can turn it on for each controller in <Link className="underline" to={paths.radius(tid)}>RADIUS</Link>.</>}
                </span>
              </span>
            </label>
          </div>

          {successors.length > 0 && (
            <label className="flex items-start gap-2.5 rounded-[8px] border border-[var(--ee-line)] px-4 py-3 text-[13px]">
              <input type="checkbox" className="ee-check mt-0.5" checked={withSuccessors} aria-describedby="revoke-succ-hint" onChange={(e) => setWithSuccessors(e.target.checked)} />
              <span>
                <span className="text-[var(--ee-ink)]">
                  Also revoke the {successors.length === 1 ? 'newer certificate' : `${successors.length} newer certificates`} renewed from it
                  {' '}(<span className="ee-mono">{successors.map((n) => fmtSerial(n.serial).slice(0, 14) + '…').join(', ')}</span>)
                </span>
                <span id="revoke-succ-hint" className="ee-small ee-ink-3 block">
                  {successors.length === 1 ? 'It was' : 'They were'} renewed from this certificate, with its key. Leave this on when the device is gone or the key may
                  have been copied. Turn it off to revoke only this older certificate: the device keeps connecting with the newer one.
                </span>
              </span>
            </label>
          )}

          {(cert.status === 'expired') && (
            <Callout tone="neutral" icon={<TimerReset aria-hidden />}>This certificate has already expired, so RADIUS rejects it anyway. Revoking it records the reason in the CRL.</Callout>
          )}
          {cert.purpose === 'radius-server' && (
            <Callout tone="warn" icon={<CircleAlert aria-hidden />}>This is the RADIUS server certificate. Rotate it from RADIUS settings instead.</Callout>
          )}
        </div>
      )}
    </EDialog>
  )
}
