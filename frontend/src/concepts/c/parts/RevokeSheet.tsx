import { useState } from 'react'
import { AlertDialog } from 'radix-ui'
import { Info, Unplug } from 'lucide-react'
import { useActions, useTenantData } from '@/prototype/store'
import { revocationReasonLabels } from '@/domain/explain'
import type { Certificate, RevocationReason } from '@/domain/types'
import { formatDuration } from '@/ui/lib'
import { ConfirmSheet } from '../ui/Sheet'
import { ChoiceList, Toggle } from '../ui/Field'
import { Note } from '../ui/Layout'
import { useConcept } from '../app/context'
import { list, shortSerial } from '../lib/format'

const REASONS: RevocationReason[] = ['keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'unspecified']

/**
 * Revoke one certificate: reason (RFC 5280 labels) → honest consequences → confirm.
 * Status and audit update immediately through the store.
 */
export function RevokeSheet({ certificate, open, onOpenChange }: { certificate: Certificate | null; open: boolean; onOpenChange: (open: boolean) => void }) {
  const d = useTenantData()
  const { revokeCertificate } = useActions()
  const { toast } = useConcept()
  const [reason, setReason] = useState<RevocationReason | ''>('')
  const [disconnect, setDisconnect] = useState(true)

  if (!certificate) return null
  const owner = d.identities.find((i) => i.id === certificate.identityId)
  const device = d.devices.find((x) => x.id === certificate.deviceId)
  const coaClients = d.radiusClients.filter((c) => c.coaEnabled)
  const noCoa = d.radiusClients.filter((c) => !c.coaEnabled)
  const sessionTimeout = d.radiusSettings ? formatDuration(d.radiusSettings.sessionTimeoutSeconds) : '8h'
  const subject = device ? device.name : owner ? owner.displayName : certificate.commonName

  const close = (o: boolean) => {
    onOpenChange(o)
    if (!o) {
      setReason('')
      setDisconnect(true)
    }
  }

  const confirm = () => {
    if (!reason) return
    revokeCertificate(certificate.id, reason)
    const coaNote = disconnect && coaClients.length ? ` Disconnect sent to ${list(coaClients.map((c) => c.name))}.` : ''
    toast(`Certificate revoked for ${subject}`, `Serial ${shortSerial(certificate.serial)}. The revocation list was regenerated and RADIUS rejects it from now on.${coaNote}`)
    close(false)
  }

  return (
    <ConfirmSheet
      open={open}
      onOpenChange={close}
      wide
      title={`Revoke the certificate for ${subject}?`}
      description={`${owner ? `${owner.displayName} · ` : ''}serial ${shortSerial(certificate.serial)}. Choose why; the reason is published in the revocation list.`}
      confirm={
        <AlertDialog.Action asChild>
          <button
            type="button"
            className="c-btn is-danger-solid"
            disabled={!reason}
            onClick={(e) => {
              e.preventDefault()
              confirm()
            }}
          >
            Revoke certificate
          </button>
        </AlertDialog.Action>
      }
    >
      <ChoiceList
        label="Revocation reason"
        value={reason}
        onChange={(v) => setReason(v as RevocationReason)}
        choices={REASONS.map((r) => ({ value: r, title: revocationReasonLabels[r] }))}
      />
      <Note icon={Info}>
        <strong>New authentications are rejected within seconds.</strong> Devices already connected stay online until they reauthenticate (session timeout {sessionTimeout}) or a disconnect (CoA) reaches their controller.
        {reason === 'certificateHold' ? ' A hold can be released later; every other reason is permanent.' : ' This cannot be undone.'}
      </Note>
      {coaClients.length ? (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
          <Toggle id="c-revoke-coa" checked={disconnect} onChange={setDisconnect} label="Send a disconnect to controllers with CoA enabled" />
          <label htmlFor="c-revoke-coa" className="c-small" style={{ cursor: 'pointer' }}>
            <span style={{ display: 'block', color: 'var(--c-text)', fontWeight: 500, fontSize: 14 }}>Disconnect now where possible</span>
            <span className="c-muted">
              Sends CoA to {list(coaClients.map((c) => c.name))}.
              {noCoa.length ? ` ${list(noCoa.map((c) => c.name))} ${noCoa.length === 1 ? 'has' : 'have'} CoA off; a device connected there stays online until it reauthenticates.` : ''}
            </span>
          </label>
        </div>
      ) : (
        <Note icon={Unplug}>No controller has CoA enabled, so connected devices stay online until they reauthenticate.</Note>
      )}
    </ConfirmSheet>
  )
}
