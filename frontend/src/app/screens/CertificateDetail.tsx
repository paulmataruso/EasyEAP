// One certificate: identity, chain, fingerprint, validity, key, the RADIUS decision stored for it, and revocation.
// GET /api/tenants/{tid}/certificates/{id} and …/pem (routers/certificates.py); CA names from GET /api/tenants/{tid}/pki.
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router'
import { ArrowLeft, Download, FileBadge, KeyRound, Landmark, ShieldX, UserRound } from 'lucide-react'
import { ApiError, saveBlob } from '../api/client'
import { useTenant } from '../api/tenant'
import { fetchPem, useCertificate, useCertificateEvents, useIdentity, usePki, usePolicy, type CertificateDetail as Cert } from '../api/people'
import { paths } from '../routes'
import { Btn, Callout, CertChip, Chip, CopyButton, Dl, ErrorState, LoadingBlock, PageHeader, Panel, PlatformIcon, platformLabels, SectionHeader, toast, toastError } from '../ui'
import { DecisionLedger } from '../ui/ledger'
import { ago, fmtDate, fmtDateTime, fmtFingerprint, fmtSerial, relative, remaining, shortSerial } from '../lib/format'
import { pushRecent } from '../lib/recent'
import { useNow } from '../lib/useNow'
import { RevokeDialog } from './people/RevokeDialog'
import { certTone, EventList, keyAlgorithm, keyOrigin, REASON_META } from './people/shared'

export default function CertificateDetail() {
  const { id = '' } = useParams()
  const { tid, tenant } = useTenant()
  const q = useCertificate(tid, id)

  useEffect(() => {
    if (q.data) pushRecent(tid, { kind: 'certificate', id: q.data.id, label: q.data.device?.name ?? q.data.common_name, sub: `Certificate ${shortSerial(q.data.serial)}` })
  }, [tid, q.data])

  const back = <Link to={paths.certificates(tid)} className="ee-btn ee-btn-ghost ee-btn-sm mb-4 -ml-2.5 inline-flex"><ArrowLeft aria-hidden />All certificates</Link>
  if (q.isLoading) return <div>{back}<LoadingBlock rows={6} label="Loading certificate" /></div>
  if (q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      return <div>{back}<PageHeader title="Certificate not found" lede={`No certificate in ${tenant.name} matches this link. It may belong to another tenant.`} /><Link to={paths.certificates(tid)} className="ee-btn">Search certificates</Link></div>
    }
    return <div>{back}<ErrorState error={q.error} onRetry={() => q.refetch()} /></div>
  }
  if (!q.data) return null
  return <div>{back}<CertRecord c={q.data} /></div>
}

function CertRecord({ c }: { c: Cert }) {
  const { tid, can } = useTenant()
  const now = useNow()
  const pki = usePki(tid)
  const policy = usePolicy(tid)
  const events = useCertificateEvents(tid, c.serial, can('events:read'))
  // The holder's groups let the ledger name the group that matched each rule.
  const holderQ = useIdentity(tid, c.identity?.id ?? '', !!c.identity && !!c.decision)
  const [revokeOpen, setRevokeOpen] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const heading = useRef<HTMLElement | null>(null)
  useEffect(() => { heading.current = document.querySelector<HTMLElement>('[data-page-heading]') })

  const root = pki.data?.authorities.find((a) => a.role === 'root' && a.status === 'active')
  const issuingCa = pki.data?.authorities.find((a) => a.common_name === c.issuer) ?? pki.data?.authorities.find((a) => a.role === 'issuing' && a.status === 'active')
  const origin = keyOrigin(c.key_origin)
  const isServerCert = c.purpose === 'radius-server'
  const revocable = c.status !== 'revoked' && !isServerCert && can('certificates:revoke')
  const holder = c.identity?.display_name ?? c.common_name
  const title = c.device ? `${c.device.name}` : holder
  const sanList = c.sans.map((s) => {
    const [kind, ...rest] = s.split(':')
    const label = kind === 'upn' ? 'UPN' : kind === 'email' ? 'Email' : kind === 'dns' ? 'DNS' : kind
    return { label, value: rest.join(':') || s }
  })
  // The certificate's own decision, as stored for the RADIUS snapshot.
  const decision = c.decision
  const holder_ = holderQ.data

  const downloadPem = async () => {
    setDownloading(true)
    try {
      const pem = await fetchPem(tid, c.id)
      saveBlob(new Blob([pem], { type: 'application/x-pem-file' }), `${(c.device?.name ?? c.common_name).replace(/[^A-Za-z0-9._-]+/g, '-')}-${c.serial.slice(0, 8)}.pem`)
      toast('Certificate downloaded', 'The PEM file holds the public certificate only, never a private key.')
    } catch (e) {
      toastError('Download failed')(e)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <>
      <PageHeader
        title={title}
        lede={<>{c.purpose === 'device' ? 'Device' : c.purpose === 'radius-server' ? 'RADIUS server' : 'User'} certificate{c.identity ? <> for {c.identity.display_name}</> : null} · serial <span className="ee-mono">{fmtSerial(c.serial).slice(0, 19)}…</span></>}
        actions={
          <>
            <Btn onClick={downloadPem} busy={downloading}><Download aria-hidden />Download PEM</Btn>
            {revocable && <Btn variant="danger" onClick={() => setRevokeOpen(true)}><ShieldX aria-hidden />Revoke</Btn>}
          </>
        }
      >
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
          <CertChip status={c.status} />
          {c.stored_status === 'superseded' && <Chip tone="neutral">Renewed: a newer certificate replaced it</Chip>}
          <span className="ee-small ee-ink-2">
            {c.status === 'revoked' ? <>Revoked {ago(c.revoked_at, now)}</> : c.status === 'expired' ? <>Expired {relative(c.not_after, now)}</> : <>Valid for {remaining(c.not_after, now)}, until {fmtDate(c.not_after)}</>}
          </span>
          {c.identity && <Link to={paths.user(tid, c.identity.id)} className="ee-small inline-flex items-center gap-1 underline hover:text-[var(--ee-ink)] ee-ink-2"><UserRound className="size-3.5" aria-hidden />Open {c.identity.display_name}</Link>}
        </div>
      </PageHeader>

      {c.status === 'revoked' && (
        <Panel risk="crit" className="mb-6 px-5 py-4" aria-labelledby="cd-rev">
          <SectionHeader id="cd-rev" title="Revocation" />
          <Dl cols={3} items={[
            ['Revoked', <time dateTime={c.revoked_at ?? undefined} className="ee-num">{fmtDateTime(c.revoked_at)}</time>],
            ['Reason', c.revocation_reason ? <>{REASON_META[c.revocation_reason]?.label ?? c.revocation_reason}<span className="ee-small ee-ink-3 block">{REASON_META[c.revocation_reason]?.explain}</span></> : '—'],
            ['By', c.revoked_by ?? '—'],
          ]} />
          <p className="ee-small ee-ink-2 mt-3 max-w-[80ch]">RADIUS rejects new connections with this certificate. A session that was already connected ends only on a CoA disconnect or when the controller re-authenticates it at the session timeout. Revocation is permanent; to reconnect this device, issue it a new certificate.</p>
        </Panel>
      )}
      {isServerCert && (
        <Callout tone="gold" className="mb-6" title="This is the RADIUS server certificate" action={<Link to={paths.radius(tid)} className="ee-btn ee-btn-sm">Open RADIUS</Link>}>
          It isn’t revoked from here. Rotate it from RADIUS settings; devices trust the CA, not this certificate, so rotation is seamless.
        </Callout>
      )}

      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,6fr)_minmax(0,5fr)]">
        <div className="min-w-0 space-y-6">
          <Panel risk={certTone(c.status)} className="px-5 py-4" aria-labelledby="cd-id">
            <SectionHeader id="cd-id" title="Identity" />
            <Dl items={[
              ['Subject', <span className="ee-mono text-[12.5px] break-words">{c.subject}</span>, 'wide'],
              ['Common name', <span className="break-all">{c.common_name}</span>],
              ['Holder', c.identity ? <Link to={paths.user(tid, c.identity.id)} className="underline hover:text-[var(--ee-gold)]">{c.identity.display_name}</Link> : <span className="ee-ink-3">No user linked</span>],
              ['Device', c.device ? <span className="inline-flex items-center gap-2"><PlatformIcon platform={c.device.platform} />{c.device.name}<span className="ee-ink-3">{platformLabels[c.device.platform] ?? c.device.platform}</span></span> : <span className="ee-ink-3">None recorded</span>],
              ['Purpose', c.purpose === 'device' ? 'Device authentication' : c.purpose === 'radius-server' ? 'RADIUS server' : 'User authentication'],
              ['Subject alternative names', sanList.length === 0 ? <span className="ee-ink-3">None</span> : (
                <ul className="space-y-0.5">{sanList.map((s) => <li key={s.label + s.value} className="break-all"><span className="ee-ink-3 mr-2 text-[12px]">{s.label}</span><span className="ee-mono text-[12.5px]">{s.value}</span></li>)}</ul>
              ), 'wide'],
            ]} />
          </Panel>

          <Panel className="px-5 py-4" aria-labelledby="cd-chain">
            <SectionHeader id="cd-chain" title="Issuer chain" meta={pki.data ? `${tenantCas(pki.data.authorities.length)}` : undefined} />
            {pki.isLoading ? <LoadingBlock rows={3} label="Loading certificate authorities" /> : (
              <ol className="space-y-0" aria-label="Certificate chain, from the root down">
                <ChainStep icon={<Landmark aria-hidden />} name={root?.common_name ?? 'Root CA'} sub={root ? `Root CA · ${root.offline ? 'key kept offline' : 'online'} · ${keyAlgorithm(root.key_algorithm)} · valid to ${fmtDate(root.not_after)}` : 'Root CA'} />
                <ChainStep icon={<Landmark aria-hidden />} name={c.issuer ?? issuingCa?.common_name ?? 'Issuing CA'} sub={issuingCa ? `Issuing CA · signs certificates online · ${keyAlgorithm(issuingCa.key_algorithm)} · valid to ${fmtDate(issuingCa.not_after)}` : 'Issuing CA'} />
                <ChainStep icon={<FileBadge aria-hidden />} name={c.common_name} sub="This certificate" current />
              </ol>
            )}
            <div className="mt-4">
              <p className="ee-label">SHA-256 fingerprint</p>
              <div className="mt-1 flex flex-wrap items-start gap-2">
                <code className="ee-mono min-w-0 flex-1 text-[12.5px] leading-relaxed ee-ink-2">
                  {fpLines(fmtFingerprint(c.fingerprint_sha256)).map((l) => <span key={l} className="block break-all">{l}</span>)}
                </code>
                <CopyButton text={fmtFingerprint(c.fingerprint_sha256)} what="SHA-256 fingerprint" />
              </div>
              <p className="ee-small ee-ink-3 mt-1">Compare it with the fingerprint the device shows for its installed certificate.</p>
            </div>
          </Panel>

          <Panel className="px-5 py-4" aria-labelledby="cd-val">
            <SectionHeader id="cd-val" title="Validity and key" />
            <Dl items={[
              ['Valid from', <time dateTime={c.not_before} className="ee-num">{fmtDateTime(c.not_before)}</time>],
              ['Valid until', <><time dateTime={c.not_after} className="ee-num">{fmtDateTime(c.not_after)}</time><span className="ee-small ee-ink-3 block">{c.status === 'revoked' ? 'No longer valid: revoked' : remaining(c.not_after, now).startsWith('Expired') ? remaining(c.not_after, now) : `${remaining(c.not_after, now)} remaining`}</span></>],
              ['Key algorithm', keyAlgorithm(c.key_algorithm)],
              ['Key generated', <span className="inline-flex items-start gap-1.5"><KeyRound className="mt-0.5 size-3.5 shrink-0 ee-ink-3" aria-hidden /><span>{origin.short}<span className="ee-small ee-ink-3 block">{origin.long}</span></span></span>],
              ['Issued', <time dateTime={c.created_at ?? undefined} className="ee-num">{fmtDateTime(c.created_at)}</time>],
              ['Serial', <span className="ee-mono text-[12.5px] break-words">{fmtSerial(c.serial)}</span>],
            ]} />
          </Panel>
        </div>

        <div className="min-w-0 space-y-6">
          <Panel className="px-5 py-4" aria-labelledby="cd-dec">
            <SectionHeader id="cd-dec" title="RADIUS decision for this certificate" meta={decision ? <>computed {ago(decision.computed_at, now)}</> : undefined} />
            {!decision ? (
              <p className="ee-small ee-ink-2">No decision is stored for this certificate. RADIUS rejects certificates it has no decision for.</p>
            ) : policy.isLoading || holderQ.isLoading ? <LoadingBlock rows={4} label="Loading rules" /> : (
              <>
                <DecisionLedger outcome={decision} rules={policy.data?.rules ?? []} vlans={policy.data?.vlans ?? []} identityGroups={holder_?.groups ?? []}
                  accountState={holder_?.account_state} source={holder_?.source} />
                <p className="ee-small ee-ink-3 mt-3">This is what the RADIUS snapshot holds for this serial. It is recalculated whenever rules, groups or the certificate change.</p>
              </>
            )}
          </Panel>

          {can('events:read') && (
            <Panel className="px-5 py-4" aria-labelledby="cd-ev">
              <SectionHeader id="cd-ev" title="Recent use" meta="last 30 days" />
              {events.isLoading ? <LoadingBlock rows={3} label="Loading authentications" />
                : events.error ? <ErrorState error={events.error} onRetry={() => events.refetch()} title="Authentications couldn’t be loaded" />
                  : <EventList tid={tid} events={(events.data?.items ?? []).filter((e) => e.cert_serial === c.serial)} now={now} vlans={policy.data?.vlans} deviceName={() => c.device?.name ?? null}
                    emptyText="RADIUS hasn’t seen this certificate in the last 30 days." />}
            </Panel>
          )}
        </div>
      </div>

      <RevokeDialog cert={c} open={revokeOpen} onOpenChange={setRevokeOpen} returnFocus={heading} />
    </>
  )
}

/** 32 colon pairs → two lines of 16, so the fingerprint never breaks inside a pair. */
const fpLines = (fp: string) => { const p = fp.split(':'); return [p.slice(0, 16).join(':'), p.slice(16).join(':')].filter(Boolean) }

const tenantCas = (n: number) => (n === 1 ? '1 authority in this tenant' : `${n} authorities in this tenant`)

function ChainStep({ icon, name, sub, current }: { icon: ReactNode; name: string; sub: string; current?: boolean }) {
  return (
    <li className="relative grid grid-cols-[22px_minmax(0,1fr)] gap-x-3 pb-3 last:pb-0">
      {!current && <span aria-hidden className="absolute left-[10.5px] top-[24px] bottom-0 w-px bg-[var(--ee-line-2)]" />}
      <span className={`relative z-[1] grid size-[22px] place-items-center rounded-full border [&_svg]:size-3 ${current ? 'border-[rgba(226,194,117,0.7)] bg-[rgba(226,194,117,0.1)] text-[var(--ee-gold)]' : 'border-[var(--ee-line-2)] bg-[var(--ee-panel-solid)] ee-ink-2'}`}>{icon}</span>
      <span className="min-w-0 pt-[1px]">
        <span className="block break-words text-[13.5px] font-semibold">{name}</span>
        <span className="ee-small ee-ink-3 block">{sub}</span>
      </span>
    </li>
  )
}
