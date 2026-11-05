import { ChevronLeft, ChevronRight, FileBadge, Lock, SearchX } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { Certificate } from '@/domain/types'
import { certStatusLabels, revocationReasonLabels } from '@/domain/explain'
import { useTenantData, useTenants } from '@/prototype/store'
import { formatDate, formatDateTime, formatSerial } from '@/ui/lib'
import { useTable, type Column } from '@/ui/useTable'
import type { ScreenId } from '../../contract'
import { auditLabel, relTime } from '../model/derive'
import { EMPTY_CERTS, useViewState, type CertsFilter } from '../model/state'
import { RevokeDialog } from '../flows/RevokeDialog'
import { CopyButton, SearchInput, SelectField } from '../ui/Controls'
import { Sheet } from '../ui/Dialog'
import { EmptyState, KV, MetaSep, PageHeader, Section } from '../ui/Section'
import { CertStatusMark, Remaining, StatusMark } from '../ui/Status'
import { DataTable, type TableColumn } from '../ui/Table'
import { CaTape, CertTape } from '../ui/Tape'
import { siteCode } from '../model/codes'

type Nav = (s: ScreenId, id?: string) => void

const PURPOSE_LABEL = { user: 'User Wi-Fi', device: 'Device Wi-Fi', 'radius-server': 'RADIUS server', admin: 'Administrator' } as const

const SORT: Column<Certificate>[] = [
  { key: 'serial', value: (c) => c.serial },
  { key: 'subject', value: (c) => c.commonName },
  { key: 'issued', value: (c) => c.notBefore },
  { key: 'expires', value: (c) => c.notAfter },
  { key: 'status', value: (c) => c.status },
  { key: 'remaining', value: (c) => (c.status === 'revoked' ? null : new Date(c.notAfter).getTime()) },
]

function isTyping(el: EventTarget | null) {
  const t = el as HTMLElement | null
  return !!t && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))
}

export function Certificates({ navigate }: { navigate: Nav }) {
  const { current } = useTenants()
  const d = useTenantData()
  const vs = useViewState()
  const f = vs.certs
  const [selected, setSelected] = useState<string | null>(null)
  const [revoke, setRevoke] = useState<Certificate | null>(null)
  const [page, setPage] = useState(0)
  const { certInspect, setCertInspect } = vs

  useEffect(() => {
    if (certInspect) { setSelected(certInspect); setCertInspect(null) }
  }, [certInspect, setCertInspect])

  const templates = useMemo(() => new Map(d.templates.map((t) => [t.id, t])), [d.templates])
  const filter = useCallback((c: Certificate) => matches(c, f, templates.get(c.templateId)?.purpose, d), [f, templates, d])
  const table = useTable(d.certificates, SORT, { initialSort: { key: 'expires', dir: 'asc' }, filter })
  const rows = table.rows
  const PAGE = 20
  const pages = Math.max(1, Math.ceil(rows.length / PAGE))
  const pageIdx = Math.min(page, pages - 1)
  const pageRows = rows.slice(pageIdx * PAGE, pageIdx * PAGE + PAGE)
  const filterKey = `${f.query}|${f.status}|${f.purpose}`
  const [lastFilter, setLastFilter] = useState(filterKey)
  if (lastFilter !== filterKey) { setLastFilter(filterKey); setPage(0) }
  const cert = d.certificates.find((c) => c.id === selected) ?? null
  const root = d.cas.find((c) => c.role === 'root')
  const iss = d.cas.find((c) => c.role === 'issuing')
  const userCerts = d.certificates.filter((c) => c.identityId)
  const site = siteCode(current)
  const certAudit = d.audit.filter((a) => a.action.startsWith('certificate.') || a.action.startsWith('pki.')).slice(0, 6)

  const columns: TableColumn<Certificate>[] = [
    { key: 'serial', header: 'Label / serial', group: 'Certificate', sortable: true, cell: (c) => <><CertTape cert={c} size="sm" /><span className="d-sub mono nowrap">{formatSerial(c.serial).slice(0, 14)}…</span></> },
    {
      key: 'subject', header: 'Subject', group: 'Certificate', sortable: true,
      cell: (c) => (
        <>
          <button type="button" className="d-rowlink" onClick={() => setSelected(c.id)}>{c.commonName}</button>
          <span className="d-sub">{PURPOSE_LABEL[templates.get(c.templateId)?.purpose ?? 'user']}</span>
        </>
      ),
    },
    {
      key: 'holder', header: 'User / device', group: 'Certificate', hideSm: true,
      cell: (c) => {
        const u = d.identities.find((i) => i.id === c.identityId)
        const dev = d.devices.find((x) => x.id === c.deviceId)
        return u ? <><span className="block nowrap">{u.displayName}</span><span className="d-sub nowrap">{dev?.name ?? '—'}</span></> : <span className="ink-2 nowrap">Service certificate</span>
      },
    },
    {
      key: 'issued', header: 'Issued / CA', group: 'Validity', sortable: true, hideSm: true,
      cell: (c) => <><span className="tnum nowrap block">{formatDate(c.notBefore)}</span><span className="d-sub nowrap">{d.cas.find((x) => x.id === c.issuerCaId)?.commonName.replace(`${current.name.split(' ')[0]} `, '') ?? '—'}</span></>,
    },
    { key: 'expires', header: 'Expires', group: 'Validity', sortable: true, cell: (c) => <span className="tnum nowrap">{formatDate(c.notAfter)}</span> },
    { key: 'status', header: 'Status', group: 'State', sortable: true, cell: (c) => <CertStatusMark status={c.status} /> },
    {
      key: 'revocation', header: 'Revocation', group: 'State', hideSm: true,
      cell: (c) => (c.status === 'revoked' && c.revocationReason ? <><span className="block text-[12.5px]">{revocationReasonLabels[c.revocationReason]}</span><span className="d-sub">{relTime(c.revokedAt)} · {c.revokedBy?.split('@')[0]}</span></> : <span className="ink-3">—</span>),
    },
    { key: 'remaining', header: 'Remaining', group: 'State', sortable: true, align: 'right', cell: (c) => <Remaining cert={c} /> },
  ]

  const idx = cert ? rows.findIndex((r) => r.id === cert.id) : -1
  const select = useCallback((id: string) => { setSelected(id); const i = rows.findIndex((r) => r.id === id); if (i >= 0) setPage(Math.floor(i / PAGE)) }, [rows])
  const prev = idx > 0 ? rows[idx - 1] : null
  const next = idx >= 0 && idx < rows.length - 1 ? rows[idx + 1] : null
  useEffect(() => {
    if (!cert) return
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target) || revoke) return
      if (e.key === 'j' && next) { e.preventDefault(); select(next.id) }
      else if (e.key === 'k' && prev) { e.preventDefault(); select(prev.id) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [cert, next, prev, revoke, select])

  const active = f.query !== '' || f.status !== 'all' || f.purpose !== 'all'
  const holder = cert ? d.identities.find((i) => i.id === cert.identityId) : undefined
  const device = cert ? d.devices.find((x) => x.id === cert.deviceId) : undefined
  const tpl = cert ? templates.get(cert.templateId) : undefined

  return (
    <>
      <PageHeader
        title="Certificates"
        meta={<><span>{iss?.commonName ?? 'No issuing CA'}</span><MetaSep /><span className="tnum">{d.certificates.length} issued</span><MetaSep /><span>Revocation published by CRL and OCSP</span></>}
      />

      <div className="d-strip" style={{ gridTemplateColumns: 'repeat(5, minmax(0, 1fr))' }}>
        {([
          ['All certificates', d.certificates.length, `${userCerts.length} user and device, ${d.certificates.length - userCerts.length} service`],
          ['Active', userCerts.filter((c) => c.status === 'active').length, 'Valid for Wi-Fi'],
          ['Expiring soon', userCerts.filter((c) => c.status === 'expiring').length, 'Within 30 days'],
          ['Expired', userCerts.filter((c) => c.status === 'expired').length, 'Rejected at authentication'],
          ['Revoked', userCerts.filter((c) => c.status === 'revoked').length, 'Listed in the CRL'],
        ] as const).map(([label, n, sub]) => (
          <div key={label}><p className="d-label">{label}</p><p className="d-fig">{n}</p><p className="d-fig-sub">{sub}</p></div>
        ))}
      </div>

      <Section id="cas" title="Certificate authorities" description="The root stays offline; only the issuing CA signs device certificates.">
        <div className="d-table-wrap">
          <table className="d-table">
            <caption className="sr-only">Certificate authorities</caption>
            <thead><tr className="d-th-cols"><th scope="col">Label</th><th scope="col">Authority</th><th scope="col">State</th><th scope="col" className="d-hide-sm">Revocation</th><th scope="col" data-align="right">Remaining</th></tr></thead>
            <tbody>
              {[root, iss].filter(Boolean).map((ca) => ca && (
                <tr key={ca.id}>
                  <td><CaTape ca={ca} size="sm" /></td>
                  <td><span className="block">{ca.commonName}</span><span className="d-sub">{ca.keyAlgorithm.toUpperCase().replace('ECDSA-', 'ECDSA ')} · valid {formatDate(ca.notBefore)} to {formatDate(ca.notAfter)}</span></td>
                  <td>{ca.offline ? <StatusMark tone="ok" icon={<Lock aria-hidden="true" />}>Offline</StatusMark> : <StatusMark tone="ok">Issuing</StatusMark>}<span className="d-sub">{ca.offline ? 'Private key not held by EasyEAP' : 'Online in OpenBao'}</span></td>
                  <td className="d-hide-sm">
                    {ca.crl ? <><span className="block text-[13px]">CRL #{ca.crl.number} · issued {relTime(ca.crl.lastIssued).toLowerCase()}</span><span className="d-sub">Next update {relTime(ca.crl.nextUpdate).toLowerCase()}{ca.ocsp?.enabled ? ' · OCSP enabled' : ''}</span></> : <span className="ink-3">—</span>}
                  </td>
                  <td data-align="right"><Remaining cert={{ notAfter: ca.notAfter, status: 'active' }} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section id="list" title="Issued certificates" description="Sorted by expiry. Select a row for the full record; revoke from the record or the user’s page.">
        <div className="d-toolbar" role="search" aria-label="Filter certificates">
          <SearchInput className="w-full sm:w-72" value={f.query} onChange={(query) => vs.setCerts({ query })} placeholder="Search serial, subject, user, device" label="Search certificates" />
          <SelectField label="Status" hideLabel prefix="Status:" value={f.status} onChange={(status) => vs.setCerts({ status })} options={[{ value: 'all', label: 'Any' }, ...(['active', 'expiring', 'expired', 'revoked'] as const).map((s) => ({ value: s, label: certStatusLabels[s] }))]} />
          <SelectField label="Purpose" hideLabel prefix="Purpose:" value={f.purpose} onChange={(purpose) => vs.setCerts({ purpose })} options={[{ value: 'all', label: 'Any' }, { value: 'user', label: 'User Wi-Fi' }, { value: 'device', label: 'Device Wi-Fi' }, { value: 'radius-server', label: 'RADIUS server' }]} />
          {active && <button type="button" className="d-btn d-btn--ghost d-btn--sm" onClick={() => vs.setCerts(EMPTY_CERTS)}>Clear filters</button>}
          <span className="ml-auto text-[12.5px] text-[var(--d-ink-2)] tnum" aria-live="polite">{rows.length} of {d.certificates.length} shown</span>
        </div>
        <DataTable
          caption="Issued certificates"
          columns={columns}
          rows={pageRows}
          rowKey={(c) => c.id}
          selectedKey={selected}
          onRowClick={(c) => setSelected(c.id)}
          sort={{ sortKey: table.sort?.key, sortDir: table.sort?.dir, onSort: table.toggleSort, ariaSort: table.ariaSort }}
          empty={d.certificates.length === 0 ? (
            <EmptyState icon={<FileBadge className="d-empty-icon" aria-hidden="true" />} title="No certificates issued yet" action={<button type="button" className="d-btn d-btn--sm" onClick={() => navigate('users')}>Choose a user</button>}>
              {current.name} has its CAs ready. Issue the first Wi-Fi certificate from a user’s record; it appears here with its label {site}·CRT·…
            </EmptyState>
          ) : (
            <EmptyState icon={<SearchX className="d-empty-icon" aria-hidden="true" />} title="No certificates match these filters" action={<button type="button" className="d-btn d-btn--sm" onClick={() => vs.setCerts(EMPTY_CERTS)}>Clear filters</button>} />
          )}
        />
        {rows.length > PAGE && (
          <nav className="flex flex-wrap items-center justify-between gap-3 pt-3" aria-label="Certificate pages">
            <span className="tnum text-[12.5px] text-[var(--d-ink-2)]">Showing {pageIdx * PAGE + 1}–{Math.min(rows.length, pageIdx * PAGE + PAGE)} of {rows.length}</span>
            <span className="flex items-center gap-1">
              <button type="button" className="d-btn d-btn--sm" disabled={pageIdx === 0} onClick={() => setPage(pageIdx - 1)}>Previous</button>
              {Array.from({ length: pages }, (_, i) => (
                <button key={i} type="button" className="d-btn d-btn--sm d-btn--icon tnum" aria-current={i === pageIdx ? 'page' : undefined} style={i === pageIdx ? { borderColor: 'var(--d-signal-ring)', background: 'var(--d-signal-tint)' } : undefined} onClick={() => setPage(i)} aria-label={`Page ${i + 1}`}>{i + 1}</button>
              ))}
              <button type="button" className="d-btn d-btn--sm" disabled={pageIdx === pages - 1} onClick={() => setPage(pageIdx + 1)}>Next</button>
            </span>
          </nav>
        )}
      </Section>

      <Section title="Certificate audit" description="Issuance, revocation and CRL publication, newest first.">
        {certAudit.length === 0 ? <EmptyState title="No certificate activity yet" /> : (
          <ol className="d-rows">
            {certAudit.map((a) => (
              <li key={a.id} className="grid gap-x-4 py-2.5 sm:grid-cols-[180px_minmax(0,1fr)_auto]">
                <span className="font-medium">{auditLabel(a)}</span>
                <span className="min-w-0 text-[13px]">{a.target} <span className="text-[var(--d-ink-2)]">· {a.detail}</span></span>
                <span className="tnum text-[12px] text-[var(--d-ink-3)]">{relTime(a.at)} · <span className="mono text-[11px]">{a.actor}</span></span>
              </li>
            ))}
          </ol>
        )}
      </Section>

      <Sheet
        open={!!cert}
        onOpenChange={(o) => !o && setSelected(null)}
        title={cert?.commonName ?? ''}
        tape={cert ? <CertTape cert={cert} /> : null}
        description={cert ? <>{tpl ? PURPOSE_LABEL[tpl.purpose] : 'Certificate'} · {certStatusLabels[cert.status]} · {idx + 1} of {rows.length} in this list</> : undefined}
        footer={cert ? (
          <>
            <div className="mr-auto flex items-center gap-1">
              <button type="button" className="d-btn d-btn--icon" disabled={!prev} onClick={() => prev && select(prev.id)} aria-label="Previous certificate (k)"><ChevronLeft aria-hidden="true" /></button>
              <button type="button" className="d-btn d-btn--icon" disabled={!next} onClick={() => next && select(next.id)} aria-label="Next certificate (j)"><ChevronRight aria-hidden="true" /></button>
              <span className="ml-1 inline-flex items-center gap-1 text-[12px] text-[var(--d-ink-3)]"><kbd className="d-kbd">k</kbd><kbd className="d-kbd">j</kbd></span>
            </div>
            {holder && <button type="button" className="d-btn" onClick={() => navigate('user', holder.id)}>Open user</button>}
            {cert.status !== 'revoked' && <button type="button" className="d-btn d-btn--danger" onClick={() => setRevoke(cert)}>Revoke…</button>}
          </>
        ) : undefined}
      >
        {cert && (
          <>
            <div className="flex items-center justify-between gap-3 border-b border-[var(--d-line)] pb-3">
              <CertStatusMark status={cert.status} />
              <span className="flex items-baseline gap-2 text-[12.5px] text-[var(--d-ink-2)]">Remaining <Remaining cert={cert} /></span>
            </div>
            <KV items={[
              ['Serial', <span key="s" className="flex items-start justify-between gap-2"><span className="mono">{formatSerial(cert.serial)}</span><CopyButton text={cert.serial} what="serial" small iconOnly /></span>],
              ['Subject', <span key="sub" className="mono">{cert.subject}</span>],
              ['SANs', <span key="san" className="mono grid">{cert.sans.map((s) => <span key={s}>{s}</span>)}</span>],
              ['Holder', holder ? <button key="h" type="button" className="d-link" onClick={() => navigate('user', holder.id)}>{holder.displayName}</button> : 'Service certificate'],
              ['Device', device ? `${device.name}` : '—'],
              ['Template', tpl ? `${tpl.name} · ${tpl.validityDays} days` : '—'],
              ['Issuer', d.cas.find((c) => c.id === cert.issuerCaId)?.commonName ?? '—'],
              ['Key', `${cert.keyAlgorithm.toUpperCase()} · ${cert.keyOrigin === 'server' ? 'generated by EasyEAP (admin mode)' : 'generated on the device'}`],
              ['Valid', `${formatDateTime(cert.notBefore)} → ${formatDateTime(cert.notAfter)}`],
              ['SHA-256', <span key="fp" className="flex items-start justify-between gap-2"><span className="mono text-[11px]">{cert.fingerprintSha256.match(/.{1,8}/g)?.join(' ')}</span><CopyButton text={cert.fingerprintSha256} what="fingerprint" small iconOnly /></span>],
              ...(cert.status === 'revoked' ? [
                ['Revoked', `${relTime(cert.revokedAt)} by ${cert.revokedBy ?? 'unknown'}`] as [string, string],
                ['Reason', cert.revocationReason ? `${revocationReasonLabels[cert.revocationReason]} (${cert.revocationReason})` : '—'] as [string, string],
              ] : []),
            ]} />
            {cert.status === 'revoked' && (
              <p className="text-[13px] text-[var(--d-ink-2)]">New authentications with this certificate are rejected. To restore access, issue the device a new certificate.</p>
            )}
            <div>
              <h3 className="d-h3 mb-1">Authentications, 24 h</h3>
              <AuthMini serial={cert.serial} />
            </div>
          </>
        )}
      </Sheet>
      <RevokeDialog cert={revoke} open={!!revoke} onOpenChange={(o) => !o && setRevoke(null)} />
    </>
  )
}

function AuthMini({ serial }: { serial: string }) {
  const d = useTenantData()
  const ev = d.authEvents.filter((e) => e.certSerial === serial)
  if (!ev.length) return <p className="text-[13px] text-[var(--d-ink-2)]">No attempts with this certificate in the last 24 hours.</p>
  const acc = ev.filter((e) => e.result === 'accept').length
  return <p className="text-[13px] text-[var(--d-ink-2)] tnum">{ev.length} attempts · {acc} accepted · {ev.length - acc} rejected · last {relTime(ev[0].at).toLowerCase()}</p>
}

function matches(c: Certificate, f: CertsFilter, purpose: string | undefined, d: ReturnType<typeof useTenantData>) {
  if (f.status !== 'all' && c.status !== f.status) return false
  if (f.purpose !== 'all' && purpose !== f.purpose) return false
  const q = f.query.trim().toLowerCase().replace(/[\s:]/g, '')
  if (!q) return true
  const u = d.identities.find((i) => i.id === c.identityId)
  const dev = d.devices.find((x) => x.id === c.deviceId)
  return [c.serial, c.commonName, c.subject, u?.displayName, dev?.name].some((v) => v?.toLowerCase().replace(/[\s:]/g, '').includes(q))
}
