import { CircleAlert, Info } from 'lucide-react'
import { RadioGroup } from 'radix-ui'
import { useState } from 'react'
import type { Certificate, RevocationReason } from '@/domain/types'
import { revocationReasonLabels } from '@/domain/explain'
import { useTenantData } from '@/prototype/store'
import { useConceptActions } from '../model/actions'
import { formatDate, formatDuration, formatSerial } from '@/ui/lib'
import { codeText, certCode } from '../model/codes'
import { Modal } from '../ui/Dialog'
import { Notice } from '../ui/Section'
import { CertTape } from '../ui/Tape'
import { useToast } from '../ui/Toast'

const RFC_CODES: Record<RevocationReason, number> = { unspecified: 0, keyCompromise: 1, affiliationChanged: 3, superseded: 4, cessationOfOperation: 5, certificateHold: 6 }
const ORDER: RevocationReason[] = ['keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'unspecified']

/** Revoke flow: RFC 5280 reason, honest consequences, explicit confirmation, immediate status + audit. */
export function RevokeDialog({ cert, open, onOpenChange }: { cert: Certificate | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const d = useTenantData()
  const { revokeCertificate } = useConceptActions()
  const toast = useToast()
  const [reason, setReason] = useState<RevocationReason | ''>('')
  const [error, setError] = useState<string | null>(null)
  if (!cert) return null
  const device = d.devices.find((x) => x.id === cert.deviceId)
  const ident = d.identities.find((i) => i.id === cert.identityId)
  const lastEvent = d.authEvents.find((e) => e.certSerial === cert.serial && e.result === 'accept')
  const lastNas = d.radiusClients.find((n) => n.id === lastEvent?.nasClientId)
  const coa = d.radiusClients.filter((n) => n.coaEnabled)
  const noCoa = d.radiusClients.filter((n) => !n.coaEnabled)
  const crl = d.cas.find((c) => c.id === cert.issuerCaId)?.crl
  const timeout = d.radiusSettings?.sessionTimeoutSeconds ?? 28800

  const close = (o: boolean) => { if (!o) { setReason(''); setError(null) } onOpenChange(o) }
  const confirm = () => {
    if (!reason) { setError('Choose a reason. It is recorded in the CRL and the audit log.'); return }
    revokeCertificate(cert.id, reason)
    toast({ title: `${codeText(certCode(cert))} revoked`, description: `Added to the CRL${crl ? ` (next #${crl.number + 1})` : ''}. New authentications with this certificate are rejected.` })
    close(false)
  }

  return (
    <Modal
      open={open}
      onOpenChange={close}
      width={620}
      title="Revoke certificate"
      tape={<CertTape cert={cert} />}
      description={<>{device?.name ?? cert.commonName}{ident ? ` · ${ident.displayName}` : ''} · serial <span className="mono">{formatSerial(cert.serial)}</span> · expires {formatDate(cert.notAfter)}</>}
      footer={
        <>
          <button type="button" className="d-btn" onClick={() => close(false)}>Cancel</button>
          <button type="button" className="d-btn d-btn--danger" onClick={confirm}>Revoke certificate</button>
        </>
      }
    >
      <fieldset>
        <legend className="d-field-label mb-2">Reason (RFC 5280 CRLReason)</legend>
        <RadioGroup.Root className="grid gap-1.5" value={reason} onValueChange={(v) => { setReason(v as RevocationReason); setError(null) }} aria-describedby={error ? 'revoke-err' : undefined}>
          {ORDER.map((r) => (
            <RadioGroup.Item key={r} value={r} className="d-radio-card !py-2">
              <span className="d-radio-dot"><RadioGroup.Indicator asChild><span /></RadioGroup.Indicator></span>
              <span className="flex flex-wrap items-baseline justify-between gap-x-3">
                <span className="text-[13.5px]">{revocationReasonLabels[r]}</span>
                <span className="mono text-[11px] text-[var(--d-ink-3)]">{r} ({RFC_CODES[r]})</span>
              </span>
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
        {error && <p id="revoke-err" className="d-field-error mt-2" role="alert"><CircleAlert aria-hidden="true" />{error}</p>}
      </fieldset>

      <div className="grid gap-2 text-[13px] text-[var(--d-ink-2)]">
        <p className="d-h3 text-[var(--d-ink)]">What happens</p>
        <ul className="grid list-disc gap-1.5 pl-5">
          <li><span className="text-[var(--d-ink)]">Within seconds</span>, the serial is added to the CRL and the RADIUS authorization snapshot; new authentications with this certificate are rejected.</li>
          <li>A device that is <span className="text-[var(--d-ink)]">already connected stays online</span> until it reauthenticates (session timeout {formatDuration(timeout)}) or the controller receives a CoA disconnect.</li>
          {lastNas ? (
            <li>
              This device last connected through <span className="text-[var(--d-ink)]">{lastNas.name}</span>,{' '}
              {lastNas.coaEnabled ? `which has CoA enabled: EasyEAP sends a disconnect on UDP ${lastNas.coaPort}.` : 'which does not have CoA enabled: the device stays connected until it reauthenticates.'}
            </li>
          ) : (
            <li>{coa.length ? `CoA disconnects are sent through ${coa.map((n) => n.name).join(', ')}.` : 'No controller has CoA enabled.'}{noCoa.length ? ` ${noCoa.map((n) => n.name).join(', ')} ${noCoa.length === 1 ? 'has' : 'have'} no CoA: clients there stay connected until they reauthenticate.` : ''}</li>
          )}
        </ul>
      </div>
      <Notice icon={<Info aria-hidden="true" />}>
        Revocation is permanent for every reason except <strong>Temporary hold</strong>. To restore access afterwards, issue the device a new certificate.
      </Notice>
    </Modal>
  )
}
