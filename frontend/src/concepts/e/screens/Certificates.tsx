import { useEffect, useMemo, useState } from 'react'
import { FileKey, ShieldCheck, X } from 'lucide-react'
import { useTenantData, now } from '@/prototype/store'
import type { Certificate, CertStatus } from '@/domain/types'
import { certStatusLabels, platformLabels, revocationReasonLabels } from '@/domain/explain'
import { daysUntil, formatDate, formatDateTime, formatSerial } from '@/ui/lib'
import { useTable, type Column } from '@/ui/useTable'
import { DataTable } from '../DataTable'
import { Inspector, InspectorSection } from '../Inspector'
import { RevokeDialog } from '../flows'
import { CertStatusMark } from '../bits'
import { ago, isSession, isSessionAudit } from '../theme'
import { Button, CopyButton, EmptyState, PageHeader, Panel, SearchInput, Select, StatusMark, useE, useIntent, useScrollIntent } from '../ui'

type StatusFilter = 'all' | CertStatus
type Purpose = 'all' | 'user' | 'device' | 'radius-server'

export function Certificates({ entityId }: { entityId?: string }) {
  const d = useTenantData()
  const { go, navigate } = useE()
  const [status, setStatus] = useState<StatusFilter>('all')
  const [purpose, setPurpose] = useState<Purpose>('all')
  const [openId, setOpenId] = useState<string | null>(entityId ?? null)
  const [revoke, setRevoke] = useState<Certificate | null>(null)
  useEffect(() => { if (entityId) setOpenId(entityId) }, [entityId])
  useIntent('certs.filter', (i) => setStatus(i.status as StatusFilter))
  useScrollIntent()

  const ca = (id: string) => d.cas.find((c) => c.id === id)
  const owner = (c: Certificate) => d.identities.find((i) => i.id === c.identityId)
  const device = (c: Certificate) => d.devices.find((x) => x.id === c.deviceId)

  const columns = useMemo<Column<Certificate>[]>(() => [
    { key: 'serial', value: (c) => c.serial },
    { key: 'cn', value: (c) => c.commonName },
    { key: 'owner', value: (c) => `${d.identities.find((i) => i.id === c.identityId)?.displayName ?? ''} ${d.devices.find((x) => x.id === c.deviceId)?.name ?? ''}` },
    { key: 'issued', value: (c) => new Date(c.notBefore).getTime(), searchable: false },
    { key: 'expires', value: (c) => new Date(c.notAfter).getTime(), searchable: false },
    { key: 'status', value: (c) => c.status },
  ], [d.identities, d.devices])
  const filter = useMemo(() => (c: Certificate) => (status === 'all' || c.status === status) && (purpose === 'all' || (d.templates.find((t) => t.id === c.templateId)?.purpose ?? 'user') === purpose), [status, purpose, d.templates])
  const t = useTable(d.certificates, columns, { initialSort: { key: 'expires', dir: 'asc' }, filter })

  const count = (s: CertStatus) => d.certificates.filter((c) => c.status === s).length
  const root = d.cas.find((c) => c.role === 'root')
  const iss = d.cas.find((c) => c.role === 'issuing')
  const selected = d.certificates.find((c) => c.id === openId) ?? null
  const filtered = status !== 'all' || purpose !== 'all' || !!t.query

  const totals: Array<{ key: StatusFilter; label: string; n: number }> = [
    { key: 'all', label: 'All certificates', n: d.certificates.length },
    { key: 'active', label: 'Active', n: count('active') },
    { key: 'expiring', label: 'Expiring soon', n: count('expiring') },
    { key: 'expired', label: 'Expired', n: count('expired') },
    { key: 'revoked', label: 'Revoked', n: count('revoked') },
  ]

  return (
    <>
      <PageHeader title="Certificates" meta={<><span>Issued by {iss?.commonName ?? 'no issuing CA'}</span><span aria-hidden className="t3">·</span><span>One certificate per device, individually revocable</span></>} actions={<Button variant="primary" onClick={() => go('users', { intent: { kind: 'issue' } })}><ShieldCheck />Issue Wi-Fi certificate</Button>} />

      <div className="e-strip mb-4 grid-cols-2 min-[900px]:grid-cols-5" role="group" aria-label="Filter by status">
        {totals.map((x) => (
          <button key={x.key} type="button" aria-pressed={status === x.key} onClick={() => setStatus(x.key)} className="text-left transition-colors hover:bg-[rgba(167,177,194,0.04)] aria-pressed:bg-[var(--e-select)] max-[899px]:!border-l-0 max-[899px]:[&:nth-child(n+3)]:border-t max-[899px]:[&:nth-child(n+3)]:border-[var(--e-hair)]">
            <span className="e-label block">{x.label}</span>
            <span className="mt-1 block text-[26px] font-semibold leading-tight tracking-[-0.02em]">{x.n}</span>
          </button>
        ))}
      </div>

      <section id="ca-status" aria-labelledby="ca-status-title" className="e-strip mb-4 grid-cols-1 min-[900px]:grid-cols-2">
        <div>
          <div className="mb-2 flex items-center justify-between gap-2">
            <h2 id="ca-status-title" tabIndex={-1} className="text-[14px] font-bold">Root CA</h2>
            {root ? <StatusMark state="ok" label="Offline, key not held by EasyEAP" /> : <StatusMark state="unconfigured" />}
          </div>
          {root && (
            <dl className="e-dl">
              <dt>Subject</dt><dd>{root.subject}</dd>
              <dt>Key</dt><dd>ECDSA P-384</dd>
              <dt>Valid until</dt><dd className="num">{formatDate(root.notAfter)} <span className="t2">· {Math.round(daysUntil(root.notAfter, now()) / 365)} years</span></dd>
              <dt>CRL</dt><dd className="num">#{root.crl?.number} · next update {formatDate(root.crl?.nextUpdate ?? null)}</dd>
              <dt>SHA-256</dt><dd className="mono text-[11.5px]">{formatSerial(root.fingerprintSha256).slice(0, 39)}…</dd>
            </dl>
          )}
        </div>
        <div>
          <div className="mb-2 flex items-center justify-between gap-2">
            <h2 className="text-[14px] font-bold">Issuing CA</h2>
            {iss ? <StatusMark state="ok" label="Online, signing" /> : <StatusMark state="unconfigured" />}
          </div>
          {iss && (
            <dl className="e-dl">
              <dt>Subject</dt><dd>{iss.subject}</dd>
              <dt>Expires</dt><dd className="num">{formatDate(iss.notAfter)} <span className="t2">· in {daysUntil(iss.notAfter, now())} days</span></dd>
              <dt>CRL</dt><dd className="num">#{iss.crl?.number} published {ago(iss.crl?.lastIssued ?? null)} · next {formatDateTime(iss.crl?.nextUpdate ?? null)}</dd>
              <dt>OCSP</dt><dd>{iss.ocsp?.enabled ? <>Responding · <span className="mono text-[12px]">{iss.ocsp.url}</span></> : 'Disabled'}</dd>
              <dt>CRL URL</dt><dd className="mono text-[12px]">{iss.crl?.url}</dd>
            </dl>
          )}
        </div>
      </section>

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--e-hair)] p-3">
          <SearchInput className="w-full sm:w-[300px]" value={t.query} onChange={t.setQuery} placeholder="Search serial, subject, user, device" label="Search certificates" />
          <Select<StatusFilter> label="Status" value={status} onValueChange={setStatus} options={[{ value: 'all', label: 'Any status' }, ...(['active', 'expiring', 'expired', 'revoked'] as CertStatus[]).map((s) => ({ value: s, label: certStatusLabels[s] }))]} />
          <Select<Purpose> label="Purpose" value={purpose} onValueChange={setPurpose} options={[{ value: 'all', label: 'Any purpose' }, { value: 'user', label: 'User Wi-Fi' }, { value: 'device', label: 'Device Wi-Fi' }, { value: 'radius-server', label: 'RADIUS server' }]} />
          {filtered && <Button size="sm" variant="ghost" onClick={() => { setStatus('all'); setPurpose('all'); t.setQuery('') }}><X />Clear filters</Button>}
          <span className="t2 num ml-auto text-[12.5px]" aria-live="polite">Showing {t.rows.length} of {d.certificates.length}</span>
        </div>
        <DataTable
          caption="Certificates"
          rows={t.rows}
          rowKey={(c) => c.id}
          selectedKey={openId}
          onActivate={(c) => setOpenId(c.id)}
          sort={t.sort}
          onSort={t.toggleSort}
          ariaSort={t.ariaSort}
          maxHeight={640}
          empty={filtered
            ? <EmptyState icon={<FileKey />} title="No certificates match" body="Clear a filter, or search by another serial or name." />
            : <EmptyState icon={<FileKey />} title="No certificates issued yet" body="Issue a Wi-Fi certificate from a user’s page; each device gets its own." action={<Button variant="primary" onClick={() => go('users', { intent: { kind: 'issue' } })}><ShieldCheck />Choose a user</Button>} />}
          columns={[
            { key: 'serial', header: 'Serial', sortable: true, cell: (c) => <button type="button" data-row-primary className="e-rowlink mono text-[12px] !font-medium" onClick={() => setOpenId(c.id)}>{formatSerial(c.serial).slice(0, 14)}…</button> },
            { key: 'cn', header: 'Subject', sortable: true, cell: (c) => <span className="block max-w-[260px] truncate">{c.commonName}</span> },
            { key: 'owner', header: 'User and device', sortable: true, hideBelow: 'md', cell: (c) => {
              const o = owner(c), dv = device(c)
              return o ? <span className="block max-w-[220px] truncate">{o.displayName}<span className="t2 block truncate text-[12px]">{dv?.name ?? '—'}</span></span> : <span className="t2">RADIUS server</span>
            } },
            { key: 'ca', header: 'Issuing CA', hideBelow: 'xl', cell: (c) => <span className="t2">{ca(c.issuerCaId)?.commonName ?? '—'}</span> },
            { key: 'issued', header: 'Issued', sortable: true, hideBelow: 'lg', cell: (c) => <span className="num t2">{formatDate(c.notBefore)}</span> },
            { key: 'expires', header: 'Expires', sortable: true, cell: (c) => <span className="num">{formatDate(c.notAfter)}</span> },
            { key: 'status', header: 'Status', sortable: true, cell: (c) => <CertStatusMark cert={c} /> },
            { key: 'rev', header: 'Revocation', hideBelow: 'lg', cell: (c) => c.status === 'revoked' ? <span className="block max-w-[200px] truncate text-[12.5px]">{c.revocationReason ? revocationReasonLabels[c.revocationReason] : 'Revoked'}<span className="t2 block">{ago(c.revokedAt, isSession(`rev:${c.id}`))}</span></span> : <span className="t3">—</span> },
          ]}
        />
      </Panel>

      {selected && (
        <Inspector open onClose={() => { setOpenId(null); if (entityId) navigate('certificates') }} title={selected.commonName} subtitle={`Serial ${formatSerial(selected.serial).slice(0, 19)}…`} label="Certificate detail"
          footer={<>
            {owner(selected) && <Button variant="ghost" onClick={() => go('user', { entityId: selected.identityId! })}>Open user</Button>}
            {(selected.status === 'active' || selected.status === 'expiring') && <Button variant="danger" onClick={() => setRevoke(selected)}>Revoke certificate</Button>}
          </>}>
          <CertDetail cert={selected} />
        </Inspector>
      )}
      <RevokeDialog cert={revoke} open={!!revoke} onOpenChange={(o) => !o && setRevoke(null)} deviceName={revoke ? device(revoke)?.name : undefined} />
    </>
  )
}

function CertDetail({ cert: c }: { cert: Certificate }) {
  const d = useTenantData()
  const o = d.identities.find((i) => i.id === c.identityId)
  const dv = d.devices.find((x) => x.id === c.deviceId)
  const tpl = d.templates.find((t) => t.id === c.templateId)
  const iss = d.cas.find((x) => x.id === c.issuerCaId)
  const audit = d.audit.filter((a) => a.action.startsWith('certificate.') && (a.detail.includes(c.serial) || (dv && o && a.target === `${o.displayName} · ${dv.name.split("'s ")[1] ?? ''}`)))
  const lastAuth = d.authEvents.find((e) => e.certSerial === c.serial)
  return (
    <>
      <div className="mb-4"><CertStatusMark cert={c} /></div>
      {c.status === 'revoked' && (
        <div className="e-callout mb-4" data-tone="crit">
          <div>
            <p className="font-semibold">Revoked {ago(c.revokedAt, isSession(`rev:${c.id}`))}{c.revocationReason ? `: ${revocationReasonLabels[c.revocationReason]}` : ''}</p>
            <p className="t2 mt-0.5">By {c.revokedBy}. Listed on CRL #{iss?.crl?.number} and answered as revoked by OCSP. Devices already connected stay online until they reauthenticate or a CoA disconnect is sent.</p>
          </div>
        </div>
      )}
      <dl className="e-dl">
        <dt>Subject</dt><dd>{c.subject}</dd>
        <dt>User</dt><dd>{o ? o.displayName : 'Service certificate'}</dd>
        <dt>Device</dt><dd>{dv ? `${dv.name} · ${platformLabels[dv.platform]}` : '—'}</dd>
        <dt>Template</dt><dd>{tpl?.name ?? '—'}</dd>
        <dt>Issuing CA</dt><dd>{iss?.commonName}</dd>
        <dt>Valid</dt><dd className="num">{formatDate(c.notBefore)} to {formatDate(c.notAfter)}</dd>
        <dt>Key</dt><dd>ECDSA P-256 · {c.keyOrigin === 'server' ? 'generated by EasyEAP (admin mode)' : 'generated on the device'}</dd>
        <dt>SANs</dt><dd className="mono text-[12px]">{c.sans.map((s) => <span key={s} className="block">{s}</span>)}</dd>
        <dt>Last used</dt><dd>{lastAuth ? ago(lastAuth.at) : 'Not in the last 24 hours'}</dd>
      </dl>
      <InspectorSection title="Serial and fingerprint" aside={<CopyButton text={c.serial} label="Copy serial" />}>
        <p className="mono rounded-md bg-[#070A11] p-2.5 text-[12px] leading-relaxed break-all">{formatSerial(c.serial)}</p>
        <p className="t2 mb-1 mt-3 text-[12px]">SHA-256</p>
        <p className="mono rounded-md bg-[#070A11] p-2.5 text-[11.5px] leading-relaxed break-all">{formatSerial(c.fingerprintSha256)}</p>
      </InspectorSection>
      {audit.length > 0 && (
        <InspectorSection title="Audit">
          <ul className="space-y-2 text-[12.5px]">
            {audit.map((a) => <li key={a.id}><span className="font-semibold">{a.action}</span> <span className="t2">by {a.actor} · {ago(a.at, isSessionAudit(a.id))}</span><span className="t2 block">{a.detail}</span></li>)}
          </ul>
        </InspectorSection>
      )}
    </>
  )
}
