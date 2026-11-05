import { useMemo, useState } from 'react'
import { AlertDialog } from 'radix-ui'
import { Ban, FileBadge, Info, Radio, Unplug } from 'lucide-react'
import type { Certificate, RevocationReason } from '@/domain/types'
import { revocationReasonLabels, vendorLabels } from '@/domain/explain'
import { formatDuration, formatSerial } from '@/ui/lib'
import { useActions, useTenantData, useTenants } from '@/prototype/store'
import { ChoiceGroup } from '../ui/fields'
import { ConfirmDialog, Stepper } from '../ui/dialog'
import { Button, Mono } from '../ui/primitives'
import { AffectsLine } from '../ui/scope'
import { useToast } from '../ui/toast'
import { tenantHealth, useLookups } from '../lib/model'

const REASONS = Object.keys(revocationReasonLabels) as RevocationReason[]
const REASON_HELP: Record<RevocationReason, string> = {
  unspecified: 'Use only when no other reason fits.',
  keyCompromise: 'The private key may be in someone else’s hands.',
  affiliationChanged: 'The person no longer needs this access.',
  superseded: 'A new certificate already replaces this one.',
  cessationOfOperation: 'The device is no longer in use.',
  certificateHold: 'Suspend while you investigate. Still blocks Wi-Fi access.',
}

/** Two-step revoke: reason, then an honest confirmation of what happens to connected devices. */
export function RevokeDialog({ certificate, open, onOpenChange }: { certificate: Certificate; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [step, setStep] = useState(0)
  const [reason, setReason] = useState<RevocationReason | ''>('')
  const { revokeCertificate } = useActions()
  const d = useTenantData()
  const { current } = useTenants()
  const { identityById, deviceById, nasById } = useLookups()
  const toast = useToast()
  const identity = certificate.identityId ? identityById.get(certificate.identityId) : undefined
  const device = certificate.deviceId ? deviceById.get(certificate.deviceId) : undefined
  const recordLabel = device ? `${device.name}` : certificate.commonName

  const lastSession = useMemo(() => d.authEvents.find((e) => e.certSerial === certificate.serial && e.result === 'accept'), [d.authEvents, certificate.serial])
  const lastNas = lastSession?.nasClientId ? nasById.get(lastSession.nasClientId) : undefined
  const coaControllers = d.radiusClients.filter((c) => c.coaEnabled)
  const noCoa = d.radiusClients.filter((c) => !c.coaEnabled)
  const sessionTimeout = d.radiusSettings?.sessionTimeoutSeconds ?? 28_800

  const reset = (o: boolean) => {
    onOpenChange(o)
    if (!o) {
      setStep(0)
      setReason('')
    }
  }

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={reset}
      width={600}
      title="Revoke certificate"
      description={
        <>
          <Mono>{formatSerial(certificate.serial)}</Mono> · {identity?.displayName ?? certificate.commonName}
          {device ? ` · ${device.name}` : ''}
        </>
      }
      footerStart={<AffectsLine tenant={current.name} tenantHealth={tenantHealth(current, d.radiusClients).state} record={recordLabel} recordIcon={FileBadge} />}
      confirm={
        step === 0 ? (
          <Button variant="primary" disabled={!reason} onClick={() => setStep(1)}>
            Continue
          </Button>
        ) : (
          <AlertDialog.Action asChild>
            <Button
              variant="danger"
              icon={Ban}
              onClick={() => {
                if (!reason) return
                revokeCertificate(certificate.id, reason)
                toast({ title: 'Certificate revoked', description: `${formatSerial(certificate.serial)} · ${revocationReasonLabels[reason]}. New authentications are rejected; audit entry recorded.` })
                setStep(0)
                setReason('')
              }}
            >
              Revoke certificate
            </Button>
          </AlertDialog.Action>
        )
      }
    >
      <div className="-mx-6 mb-4">
        <Stepper steps={['Reason', 'Confirm']} current={step} />
      </div>
      {step === 0 ? (
        <div>
          <p className="mb-3 text-[14px] text-[var(--a-text-2)]">Why is this certificate being revoked? The reason is published in the CRL (RFC 5280).</p>
          <ChoiceGroup
            label="Revocation reason"
            value={reason}
            onChange={(v) => setReason(v as RevocationReason)}
            className="sm:grid-cols-2"
            options={REASONS.map((r) => ({ value: r, title: revocationReasonLabels[r], description: REASON_HELP[r] }))}
          />
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <div className="flex gap-3 rounded-[10px] border border-[rgba(248,113,113,0.24)] bg-[rgba(239,68,68,0.07)] p-3.5">
            <Ban className="mt-0.5 size-4 shrink-0 text-[var(--a-danger-text)]" aria-hidden />
            <div className="text-[14px] text-[var(--a-text-2)]">
              <p className="font-semibold text-[var(--a-text)]">New connections are rejected within seconds.</p>
              <p className="mt-0.5">EasyEAP publishes a new CRL and updates the RADIUS authorization snapshot. Revocation cannot be undone; the device needs a new certificate to connect again.</p>
            </div>
          </div>
          <div className="flex gap-3 rounded-[10px] border border-white/10 bg-white/[0.03] p-3.5">
            <Radio className="mt-0.5 size-4 shrink-0 text-[var(--a-info-text)]" aria-hidden />
            <div className="text-[14px] text-[var(--a-text-2)]">
              <p className="font-semibold text-[var(--a-text)]">Devices already connected stay online until they reauthenticate.</p>
              <p className="mt-0.5">
                That happens at the latest when the session timeout ({formatDuration(sessionTimeout)}) ends, unless a CoA disconnect is sent. EasyEAP sends one only to controllers with CoA enabled.
              </p>
              {lastNas ? (
                <p className="mt-2 flex items-start gap-2 text-[13px]">
                  <Unplug className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                  <span>
                    Last accepted on <span className="text-[var(--a-text)]">{lastNas.name}</span> ({vendorLabels[lastNas.vendor]}):{' '}
                    {lastNas.coaEnabled ? <span className="text-[var(--a-ok-text)]">CoA enabled, the session is disconnected now.</span> : <span className="text-[var(--a-warn-text)]">CoA is off, the session continues until it reauthenticates.</span>}
                  </span>
                </p>
              ) : (
                <p className="mt-2 flex items-start gap-2 text-[13px]">
                  <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                  No accepted session for this certificate in the last 24 hours.
                </p>
              )}
              {d.radiusClients.length > 0 && (
                <p className="mt-1.5 text-[12px] text-[var(--a-text-3)]">
                  CoA enabled: {coaControllers.map((c) => c.name).join(', ') || 'none'}
                  {noCoa.length > 0 && <> · CoA off: {noCoa.map((c) => c.name).join(', ')}</>}
                </p>
              )}
            </div>
          </div>
          {reason && (
            <p className="text-[13px] text-[var(--a-text-3)]">
              Reason: <span className="text-[var(--a-text)]">{revocationReasonLabels[reason]}</span>{' '}
              <button type="button" className="a-link ml-1" onClick={() => setStep(0)}>
                Change
              </button>
            </p>
          )}
        </div>
      )}
    </ConfirmDialog>
  )
}
