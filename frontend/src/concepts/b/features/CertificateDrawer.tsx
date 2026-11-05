import { useMemo, useState } from 'react'
import { RadioGroup } from 'radix-ui'
import { ArrowLeft, Ban, CircleCheck, FileKey2, Router, ShieldX, UserRound, Wifi } from 'lucide-react'
import { now, useActions, useTenantData } from '@/prototype/store'
import { revocationReasonLabels } from '@/domain/explain'
import type { Certificate, Platform, RevocationReason } from '@/domain/types'
import { daysUntil, formatDate, formatDateTime, formatDuration, formatSerial } from '@/ui/lib'
import { Drawer } from '../ui/Drawer'
import { Button } from '../ui/Button'
import { CertStatusBadge, VlanChip } from '../ui/Badge'
import { KeyValue, Notice } from '../ui/Panel'
import { Confirm } from '../ui/Confirm'
import { CopyButton } from '../ui/CopyButton'
import { useToast } from '../ui/Toast'
import { keyAlgorithmLabels, keyOriginLabels, purposeLabels } from '../lib/labels'
import { rel } from '../lib/format'
import { PlatformIcon } from './PlatformIcon'

export type CertMode = 'view' | 'revoke'

const REASONS = Object.keys(revocationReasonLabels) as RevocationReason[]

export function CertificateDrawer({
  certId,
  mode: initialMode,
  open,
  onOpenChange,
  onOpenUser,
  onIssueReplacement,
}: {
  certId: string
  mode: CertMode
  open: boolean
  onOpenChange: (open: boolean) => void
  onOpenUser: (identityId: string) => void
  onIssueReplacement: (identityId: string, prefill: { deviceName?: string; platform?: Platform }) => void
}) {
  const d = useTenantData()
  const { revokeCertificate } = useActions()
  const toast = useToast()
  const cert = d.certificates.find((c) => c.id === certId)
  const [mode, setMode] = useState<CertMode>(initialMode)
  const [reason, setReason] = useState<RevocationReason | ''>('')
  const [confirming, setConfirming] = useState(false)
  const [justRevoked, setJustRevoked] = useState(false)

  const ctx = useMemo(() => {
    if (!cert) return null
    const identity = d.identities.find((i) => i.id === cert.identityId)
    const device = d.devices.find((x) => x.id === cert.deviceId)
    const issuer = d.cas.find((c) => c.id === cert.issuerCaId)
    const template = d.templates.find((t) => t.id === cert.templateId)
    const lastEvent = d.authEvents.find((e) => e.certSerial === cert.serial)
    const lastAccept = d.authEvents.find((e) => e.certSerial === cert.serial && e.result === 'accept')
    const lastNas = lastAccept ? d.radiusClients.find((n) => n.id === lastAccept.nasClientId) : undefined
    const auditRow = d.audit.find((a) => a.action === 'certificate.revoke' && a.target === cert.commonName)
    return { identity, device, issuer, template, lastEvent, lastAccept, lastNas, auditRow }
  }, [cert, d])

  if (!cert || !ctx) {
    return (
      <Drawer open={open} onOpenChange={onOpenChange} title="Certificate not found">
        <Notice tone="warn">This certificate is not in the current tenant. Switch back to its tenant to inspect it.</Notice>
      </Drawer>
    )
  }

  const { identity, device, issuer, template, lastEvent, lastAccept, lastNas, auditRow } = ctx
  const days = daysUntil(cert.notAfter, now())
  const coaOn = d.radiusClients.filter((n) => n.coaEnabled)
  const coaOff = d.radiusClients.filter((n) => !n.coaEnabled)
  const sessionTimeout = d.radiusSettings?.sessionTimeoutSeconds ?? 28800
  const title = device?.name ?? cert.commonName
  const canRevoke = cert.status !== 'revoked'

  const doRevoke = () => {
    if (!reason) return
    revokeCertificate(cert.id, reason)
    setJustRevoked(true)
    setMode('view')
    toast({ tone: 'ok', title: `Revoked ${title}`, description: `Serial ${formatSerial(cert.serial).slice(0, 14)}… · ${revocationReasonLabels[reason]}. New authentications are rejected from now on.` })
  }

  const footer =
    mode === 'revoke' ? (
      <>
        <Button variant="ghost" icon={ArrowLeft} onClick={() => setMode('view')}>
          Back to details
        </Button>
        <span className="b-t3 ml-auto text-[12px]">{reason ? '' : 'Choose a reason to continue'}</span>
        <Button variant="danger-solid" icon={Ban} disabled={!reason} onClick={() => setConfirming(true)}>
          Revoke certificate…
        </Button>
      </>
    ) : (
      <>
        {identity && (
          <Button variant="secondary" icon={UserRound} onClick={() => onOpenUser(identity.id)}>
            Open user
          </Button>
        )}
        {identity && cert.status !== 'active' && (
          <Button variant="secondary" icon={FileKey2} onClick={() => onIssueReplacement(identity.id, { deviceName: device?.name, platform: device?.platform })}>
            Issue replacement
          </Button>
        )}
        {canRevoke && (
          <Button variant="danger" icon={Ban} className="ml-auto" onClick={() => setMode('revoke')}>
            Revoke
          </Button>
        )}
      </>
    )

  return (
    <>
      <Drawer
        open={open}
        onOpenChange={onOpenChange}
        title={mode === 'revoke' ? `Revoke ${title}` : title}
        description={<span className="b-mono">{cert.commonName}</span>}
        meta={
          <>
            <CertStatusBadge status={cert.status} />
            {template && <span className="b-chip">{purposeLabels[template.purpose]}</span>}
            <span className="b-chip">{keyAlgorithmLabels[cert.keyAlgorithm]}</span>
          </>
        }
        footer={footer}
      >
        {mode === 'revoke' ? (
          <RevokeStep
            cert={cert}
            reason={reason}
            setReason={setReason}
            coaOn={coaOn.map((n) => `${n.name} (UDP ${n.coaPort})`)}
            coaOff={coaOff.map((n) => n.name)}
            lastNas={lastNas ? { name: lastNas.name, coa: lastNas.coaEnabled, at: lastAccept!.at } : null}
            sessionTimeout={sessionTimeout}
            crlNumber={issuer?.crl?.number ?? null}
          />
        ) : (
          <div className="space-y-4">
            {justRevoked && cert.status === 'revoked' && (
              <Notice tone="ok" title="Certificate revoked">
                The CRL was regenerated and the authorization snapshot updated; RADIUS rejects this certificate on its next authentication.
                {auditRow && (
                  <span className="mt-1 block">
                    Audit entry recorded: <span className="b-mono text-[var(--b-text)]">{auditRow.action}</span> by {auditRow.actor}.
                  </span>
                )}
              </Notice>
            )}
            {cert.status === 'revoked' && !justRevoked && (
              <Notice tone="neutral" title={`Revoked ${cert.revokedAt ? formatDate(cert.revokedAt) : ''}`}>
                {cert.revocationReason ? revocationReasonLabels[cert.revocationReason] : 'No reason recorded'}
                {cert.revokedBy && ` · by ${cert.revokedBy}`}. New authentications with this certificate are rejected.
              </Notice>
            )}
            {cert.status === 'expiring' && (
              <Notice tone="warn" title={`Expires in ${days} ${days === 1 ? 'day' : 'days'}`}>
                The device keeps connecting until {formatDate(cert.notAfter)}. Issue a replacement before then to avoid an outage for {identity?.displayName ?? 'this device'}.
              </Notice>
            )}
            {cert.status === 'expired' && (
              <Notice tone="crit" title={`Expired ${formatDate(cert.notAfter)}`}>
                RADIUS rejects this certificate. Issue a replacement so the device can reconnect.
              </Notice>
            )}
            <KeyValue
              rows={[
                [
                  'Serial',
                  <span key="s" className="flex flex-wrap items-center gap-2">
                    <span className="b-mono break-all">{formatSerial(cert.serial)}</span>
                    <CopyButton text={cert.serial} label="Copy" />
                  </span>,
                ],
                ['Subject', <span key="sub" className="b-mono break-all">{cert.subject}</span>],
                ['Subject alt. names', <span key="san" className="b-mono flex flex-col break-all">{cert.sans.map((s) => <span key={s}>{s}</span>)}</span>],
                identity && [
                  'User',
                  <button key="u" type="button" className="b-link" onClick={() => onOpenUser(identity.id)}>
                    {identity.displayName}
                  </button>,
                ],
                device && [
                  'Device',
                  <span key="d" className="inline-flex items-center gap-1.5">
                    <PlatformIcon platform={device.platform} className="text-[var(--b-text-2)]" />
                    {device.name}
                    {device.lastSeenMac && <span className="b-mono b-t3">{device.lastSeenMac}</span>}
                  </span>,
                ],
                ['Issued by', issuer ? `${issuer.commonName}${issuer.offline ? ' (offline)' : ''}` : '—'],
                ['Template', template?.name ?? '—'],
                ['Private key', keyOriginLabels[cert.keyOrigin]],
                ['Valid from', formatDateTime(cert.notBefore)],
                ['Valid until', <span key="exp">{formatDateTime(cert.notAfter)} <span className="b-t3">({rel(cert.notAfter)})</span></span>],
                [
                  'SHA-256',
                  <span key="fp" className="flex flex-col items-start gap-1.5">
                    <span className="b-mono break-all text-[11.5px] leading-relaxed text-[var(--b-text-2)]">{cert.fingerprintSha256.match(/.{1,2}/g)?.join(':')}</span>
                    <CopyButton text={cert.fingerprintSha256} label="Copy fingerprint" />
                  </span>,
                ],
                cert.status === 'revoked' && ['Revocation', <span key="r">{cert.revocationReason ? revocationReasonLabels[cert.revocationReason] : '—'} · {cert.revokedAt ? formatDateTime(cert.revokedAt) : ''}</span>],
              ]}
            />
            <section aria-labelledby="cert-last-auth">
              <h3 id="cert-last-auth" className="b-label mb-1.5">
                Last authentication
              </h3>
              {lastEvent ? (
                <p className="flex flex-wrap items-center gap-2 text-[13px]">
                  {lastEvent.result === 'accept' ? <CircleCheck className="b-ink-ok size-4" aria-hidden /> : <ShieldX className="b-ink-crit size-4" aria-hidden />}
                  <span>{lastEvent.result === 'accept' ? 'Accepted' : 'Rejected'}</span>
                  <span className="b-t2">{rel(lastEvent.at)}</span>
                  {lastEvent.nasClientId && <span className="b-t2">on {d.radiusClients.find((n) => n.id === lastEvent.nasClientId)?.name}</span>}
                  {lastEvent.vlanId && <VlanChip vlan={d.vlans.find((v) => v.id === lastEvent.vlanId)} />}
                </p>
              ) : (
                <p className="b-t2 text-[13px]">No authentication with this certificate in the last 24 hours.</p>
              )}
            </section>
          </div>
        )}
      </Drawer>
      <Confirm
        open={confirming}
        onOpenChange={setConfirming}
        title={`Revoke the certificate for ${title}?`}
        confirmLabel="Revoke certificate"
        onConfirm={doRevoke}
      >
        <p>
          Serial <span className="b-mono text-[var(--b-text)]">{formatSerial(cert.serial)}</span> is added to the CRL as “{reason ? revocationReasonLabels[reason] : ''}”. New authentications are rejected within seconds.
        </p>
        <p>Revocation cannot be undone. To restore access, issue a new certificate. Already-connected sessions end at reauthentication{coaOn.length ? ' or when the CoA disconnect reaches the controller' : ''}.</p>
      </Confirm>
    </>
  )
}

function RevokeStep({
  cert,
  reason,
  setReason,
  coaOn,
  coaOff,
  lastNas,
  sessionTimeout,
  crlNumber,
}: {
  cert: Certificate
  reason: RevocationReason | ''
  setReason: (r: RevocationReason) => void
  coaOn: string[]
  coaOff: string[]
  lastNas: { name: string; coa: boolean; at: string } | null
  sessionTimeout: number
  crlNumber: number | null
}) {
  return (
    <div className="space-y-5">
      <fieldset>
        <legend className="mb-2 text-[13.5px] font-semibold text-[var(--b-text)]">Reason</legend>
        <RadioGroup.Root value={reason} onValueChange={(v) => setReason(v as RevocationReason)} className="grid gap-1.5" aria-label="Revocation reason">
          {REASONS.map((r) => (
            <RadioGroup.Item key={r} value={r} className="b-radio-card">
              <span className="b-radio-dot" aria-hidden />
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] text-[var(--b-text)]">{revocationReasonLabels[r]}</span>
                <span className="b-mono b-t3 text-[11px]">CRLReason {r}</span>
              </span>
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
      </fieldset>

      <section aria-labelledby="revoke-effects">
        <h3 id="revoke-effects" className="mb-2 text-[13.5px] font-semibold text-[var(--b-text)]">
          What happens next
        </h3>
        <ul className="space-y-2.5 text-[13px] leading-relaxed">
          <li className="flex gap-2.5">
            <ShieldX className="b-ink-crit mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              <strong className="font-semibold text-[var(--b-text)]">New authentications are rejected within seconds.</strong>{' '}
              <span className="b-t2">EasyEAP publishes CRL #{crlNumber !== null ? crlNumber + 1 : '—'} and updates the authorization snapshot that RADIUS reads.</span>
            </span>
          </li>
          <li className="flex gap-2.5">
            <Wifi className="b-ink-warn mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              <strong className="font-semibold text-[var(--b-text)]">A device that is already connected stays online</strong>{' '}
              <span className="b-t2">until it reauthenticates (session timeout {formatDuration(sessionTimeout)}) or a CoA disconnect reaches its controller.</span>
            </span>
          </li>
          <li className="flex gap-2.5">
            <Router className="mt-0.5 size-4 shrink-0 text-[var(--b-text-2)]" aria-hidden />
            <span className="b-t2">
              {coaOn.length ? (
                <>
                  CoA disconnect is sent to controllers with CoA enabled: <span className="text-[var(--b-text)]">{coaOn.join(', ')}</span>.
                </>
              ) : (
                'No controller in this tenant has CoA enabled, so no disconnect is sent.'
              )}
              {coaOff.length > 0 && <> No CoA on {coaOff.join(', ')}: clients there stay connected until they reauthenticate.</>}
            </span>
          </li>
        </ul>
        {lastNas && (
          <Notice tone={lastNas.coa ? 'info' : 'warn'} className="mt-3">
            This device last connected through <strong>{lastNas.name}</strong> {rel(lastNas.at)}.{' '}
            {lastNas.coa ? 'CoA is enabled there, so the session is disconnected now.' : 'CoA is disabled there, so the session continues until it reauthenticates.'}
          </Notice>
        )}
      </section>
      <p className="b-t3 text-[12px]">
        Serial <span className="b-mono">{formatSerial(cert.serial)}</span>. Revocation cannot be undone.
      </p>
    </div>
  )
}
