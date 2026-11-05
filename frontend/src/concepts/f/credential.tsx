import { useId, useMemo, useState, type ReactNode } from 'react'
import { Check, ScanLine, Stamp } from 'lucide-react'
import { cn, formatDate, formatSerial } from '@/ui/lib'
import { now } from '@/prototype/store'
import type { Certificate, CertificateAuthority, CertificateTemplate, Decision, Device, Identity, Tenant, Vlan } from '@/domain/types'
import { Guilloche } from './guilloche'
import { certificateMrz, identityMrz, verifyLine2, type Mrz } from './mrz'
import { certLabel, certTone, keyOriginLabel, keyOriginShort, platformLabel, remainingDays, remainingLabel, tenantCode, type Tone } from './lib'
import { Btn, CertChip, CopyButton, Dl, Panel, PlatformIcon } from './ui'

// ── Lifeline: validity drawn as a line from issue to expiry with "now" marked ──
export function Lifeline({ cert, className }: { cert: Pick<Certificate, 'notBefore' | 'notAfter' | 'status' | 'revokedAt'>; className?: string }) {
  const start = new Date(cert.notBefore).getTime()
  const end = new Date(cert.notAfter).getTime()
  const t = now().getTime()
  const span = Math.max(1, end - start)
  const nowPct = Math.min(100, Math.max(0, ((t - start) / span) * 100))
  const tone: Tone = certTone[cert.status]
  const color = tone === 'valid' ? 'var(--f-valid)' : tone === 'warn' ? 'var(--f-warn)' : 'var(--f-crit)'
  const revokedPct = cert.revokedAt ? Math.min(100, Math.max(0, ((Math.min(new Date(cert.revokedAt).getTime(), t) - start) / span) * 100)) : null
  const label = `Valid ${formatDate(cert.notBefore)} to ${formatDate(cert.notAfter)}; ${cert.status === 'revoked' ? 'revoked' : remainingDays(cert.notAfter) >= 0 ? `${remainingDays(cert.notAfter)} days remaining` : 'expired'}`
  return (
    <div className={cn('f-life', className)} role="img" aria-label={label} title={label}>
      {cert.status === 'revoked' ? (
        <div className="f-life-fill" style={{ width: `${revokedPct ?? nowPct}%`, background: 'rgba(244,63,94,0.55)' }} />
      ) : cert.status === 'expired' ? (
        <div className="f-life-fill" style={{ width: '100%', background: 'rgba(244,63,94,0.4)' }} />
      ) : (
        <>
          <div className="f-life-fill" style={{ width: `${nowPct}%`, background: 'rgba(237,234,227,0.16)' }} />
          <div className="f-life-fill" style={{ left: `${nowPct}%`, right: 0, width: 'auto', background: color, opacity: 0.85, borderRadius: '0 3px 3px 0' }} />
        </>
      )}
      <div className="f-life-now" style={{ left: `calc(${cert.status === 'revoked' ? revokedPct ?? nowPct : nowPct}% - 1px)` }} />
    </div>
  )
}

/** Validity remaining, right-aligned in tabular figures (every credential row carries it). */
export function Remaining({ cert, className }: { cert: Pick<Certificate, 'notAfter' | 'status'>; className?: string }) {
  const d = remainingDays(cert.notAfter)
  const tone = cert.status === 'revoked' || d < 0 ? 'text-[var(--f-crit-ink)]' : cert.status === 'expiring' ? 'text-[var(--f-warn-ink)]' : 'text-[var(--f-ink)]'
  return <span className={cn('f-num whitespace-nowrap text-right font-semibold', tone, className)}>{remainingLabel(cert)}</span>
}

// ── Machine-readable zone ────────────────────────────────────────────────
export function MrzZone({ mrz, size = 'md', subject }: { mrz: Mrz; size?: 'md' | 'sm'; subject: string }) {
  const [decode, setDecode] = useState(false)
  const [active, setActive] = useState<string | null>(null)
  const decodeId = useId()
  const valid = verifyLine2(mrz.text[1])
  const lineKey = mrz.text.join('')
  return (
    <div className="f-mrz-zone px-5 py-3.5">
      <div className="flex flex-wrap items-end justify-between gap-x-5 gap-y-3">
        <div className="min-w-0 max-w-full overflow-x-auto">
          <div key={lineKey} className={cn('f-mrz f-mrz-scan', size === 'sm' && 'text-[11.5px] tracking-[0.07em]')} aria-hidden="true">
            {mrz.lines.map((segs, li) => (
              <div key={li}>
                {segs.map((s, si) => (
                  <span key={si} className="f-mrz-seg" data-active={active === `${li}:${s.key}`}>
                    {s.text}
                  </span>
                ))}
              </div>
            ))}
          </div>
          <p className="sr-only">Machine-readable line for {subject}: {mrz.text[0]} {mrz.text[1]}. {valid ? 'All check digits verify.' : 'Check digits do not verify.'}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="f-small inline-flex items-center gap-1.5 text-[var(--f-valid-ink)]">
            <Check className="size-3.5" aria-hidden />
            {valid ? 'Check digits verify' : 'Check digits fail'}
          </span>
          <Btn size="sm" variant="ghost" aria-expanded={decode} aria-controls={decodeId} onClick={() => setDecode((v) => !v)}>
            <ScanLine aria-hidden />
            {decode ? 'Hide decode' : 'Decode'}
          </Btn>
          <CopyButton text={mrz.text.join('\n')} what={`machine-readable line for ${subject}`} label="Copy" />
        </div>
      </div>
      {decode && (
        <div id={decodeId} className="mt-3 overflow-x-auto">
          <table className="f-table f-small">
            <caption className="sr-only">Decoded machine-readable line</caption>
            <thead>
              <tr>
                <th>Line</th>
                <th>Characters</th>
                <th>Field</th>
                <th>Reads as</th>
              </tr>
            </thead>
            <tbody>
              {mrz.lines.flatMap((segs, li) =>
                segs.map((s) => (
                  <tr
                    key={`${li}:${s.key}`}
                    tabIndex={0}
                    onMouseEnter={() => setActive(`${li}:${s.key}`)}
                    onMouseLeave={() => setActive(null)}
                    onFocus={() => setActive(`${li}:${s.key}`)}
                    onBlur={() => setActive(null)}
                  >
                    <td className="f-num f-ink-3">{li + 1}</td>
                    <td className="f-mono whitespace-pre">{s.text.replace(/<+$/, (m) => (m.length > 3 ? '<…' : m))}</td>
                    <td className="f-ink-2">{s.check ? `Check digit · ${s.check.of}` : s.label}</td>
                    <td>{s.check ? <span className="inline-flex items-center gap-1 text-[var(--f-valid-ink)]"><Check className="size-3.5" aria-hidden />{s.value}</span> : s.value}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
          <p className="f-small f-ink-3 mt-2">Layout follows ICAO 9303 (TD3): two 44-character lines, 7-3-1 weighted check digits, filler “&lt;”.</p>
        </div>
      )}
    </div>
  )
}

// ── Certificate data page ───────────────────────────────────────────────
export interface CertContext {
  tenant: Tenant
  holder?: Identity
  device?: Device
  issuer?: CertificateAuthority
  template?: CertificateTemplate
}

export function useCertMrz(cert: Certificate, ctx: CertContext) {
  return useMemo(
    () =>
      certificateMrz({
        serial: cert.serial,
        kind: !cert.identityId ? 'server' : ctx.template?.purpose === 'device' ? 'device' : 'user',
        authority: tenantCode(ctx.tenant),
        authorityName: ctx.issuer?.commonName ?? ctx.tenant.name,
        holderName: ctx.holder?.displayName ?? null,
        commonName: cert.commonName,
        platform: ctx.device?.platform ?? null,
        platformLabel: platformLabel(ctx.device?.platform),
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
        keyOrigin: cert.keyOrigin,
        keyOriginLabel: keyOriginLabel[cert.keyOrigin],
        status: cert.status,
        statusLabel: certLabel[cert.status],
        keyAlgorithm: cert.keyAlgorithm,
        dateLabel: formatDate,
      }),
    [cert, ctx.tenant, ctx.template, ctx.holder, ctx.device, ctx.issuer],
  )
}

const algLabel = (a: string) => a.replace('ecdsa-p', 'ECDSA P-').replace('rsa-', 'RSA ')

export function CertificateDataPage({ cert, ctx, headingLevel = 2, size = 'md', actions }: { cert: Certificate; ctx: CertContext; headingLevel?: 1 | 2; size?: 'md' | 'sm'; actions?: ReactNode }) {
  const mrz = useCertMrz(cert, ctx)
  const H = headingLevel === 1 ? 'h1' : 'h2'
  const title = ctx.holder?.displayName ?? cert.commonName
  return (
    <Panel risk={certTone[cert.status]} className="f-credential" as="article" aria-label={`Certificate ${formatSerial(cert.serial)}`}>
      <Guilloche seed={cert.serial} />
      <div className="px-5 pb-4 pt-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <H className={cn(headingLevel === 1 ? 'f-h1' : 'f-h2 text-[19px]', 'break-words')}>{title}</H>
            <p className="f-small f-ink-2 mt-1 flex flex-wrap items-center gap-x-1.5 gap-y-1">
              {ctx.device && (
                <>
                  <PlatformIcon platform={ctx.device.platform} className="size-3.5" />
                  <span>{ctx.device.name}</span>
                  <span className="f-ink-3" aria-hidden>·</span>
                </>
              )}
              <span>{ctx.template?.name ?? 'Certificate'}</span>
            </p>
          </div>
          <CertChip status={cert.status} />
        </div>

        <div className="mt-4 flex items-center gap-2 text-[13px]">
          <Stamp className="size-4 text-[var(--f-gold)]" aria-hidden />
          <span className="f-ink-2">Issued by</span>
          <span className="font-semibold text-[var(--f-gold)]">{ctx.issuer?.commonName ?? 'Unknown authority'}</span>
        </div>

        <div className="mt-4">
          <Dl
            cols={size === 'sm' ? 2 : 3}
            items={[
              ['Serial number', <span className="f-mono text-[12.5px]">{formatSerial(cert.serial)}</span>, size === 'sm' && 'wide'],
              ['Subject', <span className="break-all">{cert.subject}</span>, size === 'sm' && 'wide'],
              ['Key', <span title={keyOriginLabel[cert.keyOrigin]}>{algLabel(cert.keyAlgorithm)} · <span className="f-ink-2">{keyOriginShort[cert.keyOrigin]}</span></span>, size === 'sm' && 'wide'],
              ['Valid from', <span className="f-num">{formatDate(cert.notBefore)}</span>],
              ['Valid to', <span className="f-num">{formatDate(cert.notAfter)}</span>],
              ['SHA-256 fingerprint', <span className="f-mono text-[12px] f-ink-2" title={cert.fingerprintSha256}>{cert.fingerprintSha256.slice(0, 16)}…</span>],
            ]}
          />
        </div>

        <div className="mt-5 flex items-center gap-4">
          <Lifeline cert={cert} className="flex-1" />
          <span className="f-small f-ink-3 whitespace-nowrap">{cert.status === 'revoked' ? 'revoked' : remainingDays(cert.notAfter) < 0 ? 'expired' : 'remaining'}</span>
          <Remaining cert={cert} className="min-w-[4.5rem] text-[15px]" />
        </div>
        {actions && <div className="mt-4 flex flex-wrap gap-2">{actions}</div>}
      </div>
      <MrzZone mrz={mrz} size={size} subject={title} />
    </Panel>
  )
}

// ── Identity data page ──────────────────────────────────────────────────
export function useIdentityMrz(identity: Identity, tenant: Tenant, decision: Decision | null, vlan: Vlan | undefined, rulePriority: number | null) {
  return useMemo(
    () =>
      identityMrz({
        username: identity.username,
        displayName: identity.displayName,
        authority: tenantCode(tenant),
        authorityName: tenant.name,
        source: identity.source,
        lastSyncedAt: identity.lastSyncedAt,
        accountState: identity.accountState,
        lastAuthAt: identity.lastAuthAt,
        outcome: decision?.outcome ?? 'deny',
        vlanNumber: vlan?.vlanId ?? null,
        rulePriority,
        groupCount: identity.groupIds.length,
        dateLabel: (iso) => (iso ? formatDate(iso) : 'Never'),
      }),
    [identity, tenant, decision, vlan, rulePriority],
  )
}
