import { useState } from 'react'
import { Ban, UserRound } from 'lucide-react'
import type { Certificate } from '@/domain/types'
import { revocationReasonLabels, platformLabels } from '@/domain/explain'
import { formatSerial } from '@/ui/lib'
import { CertStatusPill } from '../ui/badges'
import { Drawer } from '../ui/dialog'
import { Button, CopyButton, KeyValues, Mono } from '../ui/primitives'
import { useLookups } from '../lib/model'
import { ago, at, day, expiryText } from '../lib/time'
import { useNav } from '../shell/nav'
import { keyOriginLabels, PlatformIcon } from './platform'
import { RevokeDialog } from './RevokeDialog'

const ALGO: Record<Certificate['keyAlgorithm'], string> = { 'ecdsa-p256': 'ECDSA P-256', 'ecdsa-p384': 'ECDSA P-384', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072', 'rsa-4096': 'RSA 4096' }
export const algoLabel = (a: Certificate['keyAlgorithm']) => ALGO[a]

/** Record-depth inspector for one certificate, with the revoke flow. */
export function CertificateInspector({ certificate, open, onOpenChange }: { certificate: Certificate | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { identityById, deviceById, caById, templateById } = useLookups()
  const { navigate } = useNav()
  const [revokeOpen, setRevokeOpen] = useState(false)
  if (!certificate) return null
  const c = certificate
  const identity = c.identityId ? identityById.get(c.identityId) : undefined
  const device = c.deviceId ? deviceById.get(c.deviceId) : undefined
  const ca = caById.get(c.issuerCaId)
  const tpl = templateById.get(c.templateId)
  const revocable = c.status !== 'revoked'
  return (
    <>
      <Drawer
        open={open}
        onOpenChange={onOpenChange}
        title={c.commonName}
        description={tpl ? `${tpl.name} certificate` : 'Certificate'}
        headerExtra={
          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            <CertStatusPill status={c.status} />
            {c.status !== 'revoked' && <span className="a-num text-[12px] text-[var(--a-text-3)]">{expiryText(c.notAfter)}</span>}
          </div>
        }
        footer={
          <>
            <CopyButton text={c.serial} label="Copy serial" />
            {revocable ? (
              <Button variant="danger-ghost" icon={Ban} onClick={() => setRevokeOpen(true)}>
                Revoke certificate
              </Button>
            ) : (
              <span className="text-[13px] text-[var(--a-text-3)]">Revoked certificates cannot be reinstated.</span>
            )}
          </>
        }
      >
        {c.status === 'revoked' && (
          <div className="mb-4 rounded-[10px] border border-[rgba(248,113,113,0.24)] bg-[rgba(239,68,68,0.07)] p-3.5 text-[13px] text-[var(--a-text-2)]">
            <p className="font-semibold text-[var(--a-danger-text)]">Revoked {ago(c.revokedAt)}</p>
            <p className="mt-0.5">
              {c.revocationReason ? revocationReasonLabels[c.revocationReason] : 'No reason recorded'} · by <Mono>{c.revokedBy ?? 'unknown'}</Mono> · {at(c.revokedAt)}
            </p>
          </div>
        )}
        {(identity || device) && (
          <div className="mb-4 flex items-center gap-3 rounded-[10px] border border-white/10 bg-white/[0.03] p-3">
            {device ? <PlatformIcon platform={device.platform} className="size-5 text-[var(--a-text-2)]" /> : <UserRound className="size-5 text-[var(--a-text-2)]" aria-hidden />}
            <div className="min-w-0 flex-1">
              <p className="truncate text-[14px] font-medium text-[var(--a-text)]">{identity?.displayName ?? 'Unknown user'}</p>
              <p className="truncate text-[12px] text-[var(--a-text-3)]">
                {device ? `${device.name} · ${platformLabels[device.platform]}` : 'No device recorded'}
                {device?.lastSeenMac && (
                  <>
                    {' · '}
                    <Mono>{device.lastSeenMac}</Mono>
                  </>
                )}
              </p>
            </div>
            {identity && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  onOpenChange(false)
                  navigate('user', identity.id)
                }}
              >
                Open user
              </Button>
            )}
          </div>
        )}
        <KeyValues
          items={[
            { label: 'Serial', value: <Mono className="break-all">{formatSerial(c.serial)}</Mono> },
            { label: 'Subject', value: <Mono className="break-all">{c.subject}</Mono> },
            { label: 'SANs', value: <div className="flex flex-col items-end gap-0.5">{c.sans.map((s) => <Mono key={s} className="break-all">{s}</Mono>)}</div> },
            { label: 'Issued by', value: ca?.commonName ?? c.issuerCaId },
            { label: 'Valid from', value: day(c.notBefore) },
            { label: 'Expires', value: day(c.notAfter) },
            { label: 'Key', value: algoLabel(c.keyAlgorithm), hint: keyOriginLabels[c.keyOrigin] },
            { label: 'Template', value: tpl ? `${tpl.name}` : c.templateId, hint: tpl ? `${tpl.extendedKeyUsage.join(', ')} · ${tpl.validityDays} days` : undefined },
            { label: 'SHA-256', value: <Mono className="block text-[12px] break-all">{c.fingerprintSha256.match(/.{2}/g)?.join(':')}</Mono> },
          ]}
        />
      </Drawer>
      {revocable && <RevokeDialog certificate={c} open={revokeOpen} onOpenChange={setRevokeOpen} />}
    </>
  )
}
