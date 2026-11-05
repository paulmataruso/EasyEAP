import { useEffect, useMemo, useState } from 'react'
import { BadgeCheck, CircleCheck, FileKey, Lock, SearchX, UserRound } from 'lucide-react'
import { now, useMetrics, useTenantData } from '@/prototype/store'
import { revocationReasonLabels } from '@/domain/explain'
import type { Certificate, CertificateAuthority, CertStatus } from '@/domain/types'
import { daysUntil, formatDate, formatDateTime, formatSerial } from '@/ui/lib'
import { useTable, type Column } from '@/ui/useTable'
import { useConcept, type Intent } from '../app/context'
import { Button } from '../ui/Button'
import { CopyButton } from '../ui/Code'
import { Cell, DataTable, toggleInSet, type ColumnDef } from '../ui/DataTable'
import { FilterSelect, SearchInput, Segmented } from '../ui/Field'
import { DefList, Empty, Lede, Note, Section } from '../ui/Layout'
import { CertMark, StatusMark } from '../ui/Status'
import { RevokeSheet } from '../parts/RevokeSheet'
import { auditActionLabel, formatFingerprint, keyAlgorithmLabel, keyOriginLabel, plural, shortSerial, since, until } from '../lib/format'

type StatusFilter = CertStatus | 'all'

export function CertificatesScreen({ intent }: { intent: Intent }) {
  const d = useTenantData()
  const m = useMetrics()
  const { go } = useConcept()
  const [status, setStatus] = useState<StatusFilter>(intent.certificates?.status ?? 'all')
  const [purpose, setPurpose] = useState('all')
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(intent.certificates?.expand ? [intent.certificates.expand] : []))
  const [revoking, setRevoking] = useState<Certificate | null>(null)

  useEffect(() => {
    if (intent.certificates?.focusCas) document.getElementById('c-cas')?.scrollIntoView({ block: 'start' })
  }, [intent])

  const owner = (c: Certificate) => d.identities.find((i) => i.id === c.identityId)
  const device = (c: Certificate) => d.devices.find((x) => x.id === c.deviceId)
  const ca = (c: Certificate) => d.cas.find((x) => x.id === c.issuerCaId)
  const template = (c: Certificate) => d.templates.find((t) => t.id === c.templateId)

  const filter = useMemo(() => (c: Certificate) => (status === 'all' || c.status === status) && (purpose === 'all' || d.templates.find((t) => t.id === c.templateId)?.purpose === purpose), [status, purpose, d.templates])
  const columns = useMemo<Column<Certificate>[]>(
    () => [
      { key: 'serial', value: (c) => c.serial },
      { key: 'subject', value: (c) => `${c.commonName} ${d.identities.find((i) => i.id === c.identityId)?.displayName ?? ''} ${d.devices.find((x) => x.id === c.deviceId)?.name ?? ''}` },
      { key: 'issued', value: (c) => new Date(c.notBefore).getTime(), searchable: false },
      { key: 'expires', value: (c) => new Date(c.notAfter).getTime(), searchable: false },
      { key: 'status', value: (c) => c.status, searchable: false },
    ],
    [d.identities, d.devices],
  )
  const table = useTable(d.certificates, columns, { initialSort: { key: 'expires', dir: 'asc' }, filter })
  const countBy = (s: CertStatus) => d.certificates.filter((c) => c.status === s).length
  const valid = m.certificates.active + m.certificates.expiring
  const issuing = d.cas.find((c) => c.role === 'issuing')

  const columnsDef: ColumnDef<Certificate>[] = [
    {
      key: 'subject',
      header: 'Issued to',
      sortable: true,
      cell: (c) => {
        const o = owner(c)
        return <Cell primary={o ? o.displayName : c.commonName} secondary={o ? `${device(c)?.name ?? 'Device'} · ${c.commonName}` : `${template(c)?.name ?? 'Certificate'} · ${c.sans.join(', ')}`} />
      },
    },
    {
      key: 'serial',
      header: 'Serial and issuer',
      sortable: true,
      hide: 'md',
      cell: (c) => <Cell primary={<span className="c-mono" style={{ fontWeight: 400, whiteSpace: 'nowrap' }} title={formatSerial(c.serial)}>{shortSerial(c.serial)}</span>} secondary={ca(c)?.commonName ?? '—'} />,
    },
    { key: 'issued', header: 'Issued', sortable: true, hide: 'lg', cell: (c) => <span className="c-muted tnum" style={{ whiteSpace: 'nowrap' }}>{formatDate(c.notBefore)}</span> },
    {
      key: 'expires',
      header: 'Expires',
      sortable: true,
      hide: 'sm',
      cell: (c) => <Cell primary={<span className="tnum" style={{ fontWeight: 400, whiteSpace: 'nowrap' }}>{formatDate(c.notAfter)}</span>} secondary={c.status === 'revoked' ? 'Revoked first' : until(c.notAfter)} />,
    },
    {
      key: 'status',
      header: 'Status',
      sortable: true,
      cell: (c) => <Cell primary={<CertMark status={c.status} />} secondary={c.status === 'revoked' ? `${c.revocationReason ? revocationReasonLabels[c.revocationReason] : 'Revoked'}, ${since(c.revokedAt)}` : c.status === 'expiring' ? `${daysUntil(c.notAfter, now())} days left` : undefined} />,
    },
  ]

  const revocations = d.audit.filter((a) => a.action === 'certificate.revoke' || a.action === 'pki.crl.publish')

  return (
    <>
      <Lede
        page="Certificates"
        state={
          m.certificates.total ? (
            <>
              <strong>{valid}</strong> <span className="c-nowrap">Wi-Fi</span> certificates are valid.
            </>
          ) : (
            'No Wi-Fi certificates have been issued yet.'
          )
        }
        rest={m.certificates.total ? (m.certificates.expiring ? `${m.certificates.expiring} of them expire within 30 days.` : 'None expire within 30 days.') : undefined}
        detail={
          m.certificates.total
            ? `${plural(m.certificates.expired, 'expired certificate')} and ${m.certificates.revoked} revoked stay listed for the record. All are signed by ${issuing?.commonName ?? 'the issuing CA'}.`
            : `${issuing?.commonName ?? 'The issuing CA'} is ready. Issue the first certificate from a person’s page.`
        }
        actions={!m.certificates.total ? <Button variant="primary" icon={<UserRound size={16} aria-hidden="true" />} onClick={() => go('users')}>Choose a person</Button> : undefined}
      />

      <Section id="c-cas" title="Certificate authorities" description="The root stays offline; only the issuing CA signs device certificates, publishes the CRL and answers OCSP.">
        <CaList cas={d.cas} />
      </Section>

      <Section title="All certificates" description={`One row per certificate${d.certificates.some((c) => !c.identityId) ? ', including the RADIUS server certificate' : ''}. Open a row for its details and to revoke it.`}>
        <div className="c-filters">
          <SearchInput value={table.query} onChange={table.setQuery} placeholder="Search person, device, subject or serial" label="Search certificates" />
          <Segmented
            label="Status"
            value={status}
            onChange={(v) => setStatus(v as StatusFilter)}
            options={[
              { value: 'all', label: 'All', count: d.certificates.length },
              { value: 'active', label: 'Active', count: countBy('active') },
              { value: 'expiring', label: 'Expiring', count: countBy('expiring') },
              { value: 'expired', label: 'Expired', count: countBy('expired') },
              { value: 'revoked', label: 'Revoked', count: countBy('revoked') },
            ]}
          />
          <FilterSelect
            label="Template"
            value={purpose}
            onChange={setPurpose}
            options={[{ value: 'all', label: 'Any' }, ...d.templates.map((t) => ({ value: t.purpose, label: t.name, count: d.certificates.filter((c) => c.templateId === t.id).length }))]}
          />
        </div>
        <p className="c-results" aria-live="polite">
          {table.rows.length === d.certificates.length ? `Showing all ${plural(d.certificates.length, 'certificate')}` : `Showing ${table.rows.length} of ${plural(d.certificates.length, 'certificate')}`}
        </p>
        <DataTable
          caption="Certificates"
          columns={columnsDef}
          rows={table.rows}
          rowKey={(c) => c.id}
          sort={table}
          expanded={expanded}
          onToggle={(k) => setExpanded((s) => toggleInSet(s, k))}
          expandLabel={(c) => owner(c)?.displayName ?? c.commonName}
          renderExpanded={(c) => <CertDetail cert={c} onRevoke={() => setRevoking(c)} />}
          pageSize={20}
          noun="certificates"
          empty={
            d.certificates.length === 0 ? (
              <Empty icon={FileKey} title="No certificates yet">Certificates appear here as people enroll their devices.</Empty>
            ) : (
              <Empty icon={SearchX} title="No certificates match" action={<Button size="sm" onClick={() => { setStatus('all'); setPurpose('all'); table.setQuery('') }}>Clear filters</Button>}>
                Nothing matches this search and filter combination.
              </Empty>
            )
          }
        />
      </Section>

      <Section title="Revocation log" description="Every revocation and the CRL it triggered. Entries cannot be edited.">
        {revocations.length === 0 ? (
          <Empty icon={CircleCheck} title="Nothing has been revoked" />
        ) : (
          <ul className="c-list">
            {revocations.map((a) => (
              <li key={a.id}>
                <div className="c-listrow c-logrow">
                  <span className="c-faint c-small tnum c-logrow-when">
                    {since(a.at)}
                  </span>
                  <span className="c-listrow-main">
                    <span style={{ fontWeight: 500 }}>{auditActionLabel[a.action] ?? a.action}</span>
                    <span className="c-muted"> · {a.target}</span>
                    <span className="c-cell-secondary">{a.detail}</span>
                  </span>
                  <span className="c-faint c-small c-hide-md" style={{ marginTop: 2 }}>
                    {a.actor === 'system' ? 'EasyEAP' : a.actor}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <RevokeSheet certificate={revoking} open={Boolean(revoking)} onOpenChange={(o) => !o && setRevoking(null)} />
    </>
  )
}

function CaList({ cas }: { cas: CertificateAuthority[] }) {
  const sorted = [...cas].sort((a, b) => (a.role === 'root' ? 0 : 1) - (b.role === 'root' ? 0 : 1))
  const columns: ColumnDef<CertificateAuthority>[] = [
    { key: 'name', header: 'Authority', cell: (c) => <Cell primary={c.commonName} secondary={c.role === 'root' ? 'Root CA' : 'Issuing CA'} /> },
    { key: 'key', header: 'Key', hide: 'lg', cell: (c) => <span className="c-muted">{keyAlgorithmLabel[c.keyAlgorithm]}</span> },
    { key: 'valid', header: 'Valid until', hide: 'sm', cell: (c) => <Cell primary={<span className="tnum" style={{ fontWeight: 400 }}>{formatDate(c.notAfter)}</span>} secondary={until(c.notAfter)} /> },
    {
      key: 'crl',
      header: 'Revocation',
      hide: 'md',
      cell: (c) => (
        <Cell
          primary={<span style={{ fontWeight: 400 }}>{c.crl ? `CRL #${c.crl.number}, published ${since(c.crl.lastIssued)}` : 'No CRL'}</span>}
          secondary={c.crl?.nextUpdate ? `Next update ${until(c.crl.nextUpdate)}${c.ocsp?.enabled ? ' · OCSP responding' : c.role === 'root' ? ' · re-signed offline' : ''}` : undefined}
        />
      ),
    },
    {
      key: 'state',
      header: 'State',
      cell: (c) => (c.offline ? <StatusMark tone="neutral" icon={Lock} label="Offline" sub="key not held" /> : <StatusMark tone="ok" icon={BadgeCheck} label="Online" sub="signing" />),
    },
  ]
  if (!cas.length) return <Empty icon={FileKey} title="No certificate authority yet">Initialise the PKI to create an offline root and an issuing CA.</Empty>
  return <DataTable caption="Certificate authorities" columns={columns} rows={sorted} rowKey={(c) => c.id} />
}

function CertDetail({ cert: c, onRevoke }: { cert: Certificate; onRevoke: () => void }) {
  const d = useTenantData()
  const { go } = useConcept()
  const o = d.identities.find((i) => i.id === c.identityId)
  const issuer = d.cas.find((x) => x.id === c.issuerCaId)
  const tpl = d.templates.find((t) => t.id === c.templateId)
  const isServer = tpl?.purpose === 'radius-server'
  return (
    <div className="c-split" style={{ gap: 40 }}>
      <DefList
        items={[
          { label: 'Subject', value: <span className="c-mono">{c.subject}</span> },
          { label: 'Alternative names', value: <span className="c-mono">{c.sans.join(', ')}</span> },
          { label: 'Serial number', value: <span className="c-mono">{formatSerial(c.serial)}</span> },
          { label: 'SHA-256 fingerprint', value: <span className="c-mono c-small">{formatFingerprint(c.fingerprintSha256)}</span> },
          { label: 'Key', value: `${keyAlgorithmLabel[c.keyAlgorithm]} · ${keyOriginLabel[c.keyOrigin]}` },
          { label: 'Template', value: tpl ? `${tpl.name} (${tpl.validityDays} days)` : '—' },
          { label: 'Validity', value: <span className="tnum">{formatDateTime(c.notBefore)} to {formatDateTime(c.notAfter)}</span> },
          { label: 'Issued by', value: issuer?.commonName ?? '—' },
          ...(c.status === 'revoked'
            ? [
                { label: 'Revoked', value: `${formatDateTime(c.revokedAt)} (${since(c.revokedAt)}) by ${c.revokedBy ?? 'unknown'}` },
                { label: 'Reason', value: c.revocationReason ? revocationReasonLabels[c.revocationReason] : 'Unspecified' },
              ]
            : []),
        ]}
      />
      <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
        {c.status === 'revoked' ? (
          <Note icon={Lock}>
            <strong>Revoked and published in the CRL.</strong> RADIUS rejects this certificate. Issue a new one if the device should keep access.
          </Note>
        ) : isServer ? (
          <Note icon={Lock}>
            This is the RADIUS server certificate. Devices check its name before sending their own certificate; replace it from RADIUS settings rather than revoking it here.
          </Note>
        ) : (
          <Button variant="danger" onClick={onRevoke}>
            Revoke certificate
          </Button>
        )}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {o ? (
            <Button size="sm" variant="secondary" icon={<UserRound size={15} aria-hidden="true" />} onClick={() => go('user', { entityId: o.id })}>
              Open {o.displayName}
            </Button>
          ) : null}
          <CopyButton text={c.serial} label="Copy serial" variant="secondary" />
        </div>
      </div>
    </div>
  )
}
