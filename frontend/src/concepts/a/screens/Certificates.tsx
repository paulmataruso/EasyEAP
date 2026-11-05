import { useMemo, useState } from 'react'
import { DropdownMenu } from 'radix-ui'
import { Ban, Copy, Ellipsis, FileBadge, FileSearch, KeyRound, Lock, SearchX, ShieldCheck } from 'lucide-react'
import type { Certificate, CertStatus } from '@/domain/types'
import { revocationReasonLabels } from '@/domain/explain'
import { cn, copyText, formatSerial } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { CertStatusPill, HealthPill } from '../ui/badges'
import { DataTable, useDataTable, type TableColumn } from '../ui/DataTable'
import { SearchInput, SelectField } from '../ui/fields'
import { Button, EmptyState, IconButton, Mono, PageHeader, Panel } from '../ui/primitives'
import { usePortalContainer } from '../ui/portal'
import { useToast } from '../ui/toast'
import { CertificateInspector, algoLabel } from '../features/CertificateInspector'
import { RevokeDialog } from '../features/RevokeDialog'
import { useLookups } from '../lib/model'
import { ago, day, expiryText } from '../lib/time'
import { useNav } from '../shell/nav'

type StatusFilter = 'all' | CertStatus

const TOTALS: Array<{ key: StatusFilter; label: string; color: string }> = [
  { key: 'all', label: 'All', color: '#7c8aa5' },
  { key: 'active', label: 'Active', color: 'var(--a-ok)' },
  { key: 'expiring', label: 'Expiring ≤ 30 days', color: 'var(--a-warn)' },
  { key: 'expired', label: 'Expired', color: '#ec835a' },
  { key: 'revoked', label: 'Revoked', color: 'var(--a-danger)' },
]

function RowMenu({ cert, onInspect, onRevoke }: { cert: Certificate; onInspect: () => void; onRevoke: () => void }) {
  const container = usePortalContainer()
  const toast = useToast()
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="a-icon-btn" aria-label={`More actions for ${formatSerial(cert.serial)}`}>
        <Ellipsis aria-hidden />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <DropdownMenu.Content align="end" sideOffset={4} className="a-menu a-overlay-glass">
          <DropdownMenu.Item className="a-menu-item" onSelect={onInspect}>
            <FileSearch aria-hidden /> View details
          </DropdownMenu.Item>
          <DropdownMenu.Item
            className="a-menu-item"
            onSelect={async () => {
              await copyText(cert.serial)
              toast({ title: 'Serial copied', description: formatSerial(cert.serial), tone: 'info' })
            }}
          >
            <Copy aria-hidden /> Copy serial
          </DropdownMenu.Item>
          {cert.status !== 'revoked' && (
            <>
              <DropdownMenu.Separator className="a-menu-sep" />
              <DropdownMenu.Item className="a-menu-item a-menu-item-danger" onSelect={onRevoke}>
                <Ban aria-hidden /> Revoke certificate
              </DropdownMenu.Item>
            </>
          )}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

export function Certificates() {
  const d = useTenantData()
  const { current } = useTenants()
  const { entityId, navigate } = useNav()
  const { identityById, deviceById, caById, templateById } = useLookups()
  const [status, setStatus] = useState<StatusFilter>('all')
  const [template, setTemplate] = useState('all')
  const [revokeId, setRevokeId] = useState<string | null>(null)

  const userCerts = d.certificates.filter((c) => c.identityId)
  const counts: Record<StatusFilter, number> = {
    all: userCerts.length,
    active: userCerts.filter((c) => c.status === 'active').length,
    expiring: userCerts.filter((c) => c.status === 'expiring').length,
    expired: userCerts.filter((c) => c.status === 'expired').length,
    revoked: userCerts.filter((c) => c.status === 'revoked').length,
    pending: userCerts.filter((c) => c.status === 'pending').length,
  }
  const issuing = d.cas.find((c) => c.role === 'issuing')
  const root = d.cas.find((c) => c.role === 'root')
  const serverCerts = d.certificates.length - userCerts.length

  const inspect = (c: Certificate) => navigate('certificates', c.id)
  const columns = useMemo<TableColumn<Certificate>[]>(
    () => [
      {
        key: 'serial',
        header: 'Serial',
        sortValue: (c) => c.serial,
        cell: (c) => (
          <button type="button" onClick={() => navigate('certificates', c.id)} className="a-mono rounded text-left text-[13px] whitespace-nowrap text-[var(--a-text)] underline-offset-[3px] hover:underline" title={formatSerial(c.serial)}>
            {formatSerial(c.serial).split(' ').slice(0, 3).join(' ')} …
          </button>
        ),
      },
      {
        key: 'subject',
        header: 'Subject and owner',
        sortValue: (c) => c.commonName,
        cell: (c) => {
          const u = c.identityId ? identityById.get(c.identityId) : undefined
          const dev = c.deviceId ? deviceById.get(c.deviceId) : undefined
          return (
            <div className="min-w-0 max-w-[340px]">
              <Mono className="block truncate text-[13px] text-[var(--a-text)]">{c.subject}</Mono>
              <span className="block truncate text-[12px] text-[var(--a-text-3)]">{u ? `${u.displayName}${dev ? ` · ${dev.name}` : ''}` : (templateById.get(c.templateId)?.name ?? 'Service certificate')}</span>
            </div>
          )
        },
      },
      { key: 'ca', header: 'Issuing CA', className: 'hidden 2xl:table-cell', sortValue: (c) => caById.get(c.issuerCaId)?.commonName ?? '', cell: (c) => <span className="whitespace-nowrap">{caById.get(c.issuerCaId)?.commonName ?? '—'}</span> },
      { key: 'issued', header: 'Issued', className: 'hidden xl:table-cell', sortValue: (c) => c.notBefore, cell: (c) => <span className="a-num whitespace-nowrap">{day(c.notBefore)}</span> },
      {
        key: 'expires',
        header: 'Expires',
        sortValue: (c) => c.notAfter,
        cell: (c) => (
          <div className="whitespace-nowrap">
            <span className="a-num block">{day(c.notAfter)}</span>
            {c.status !== 'revoked' && <span className={cn('a-num block text-[11px]', c.status === 'expiring' ? 'text-[var(--a-warn-text)]' : 'text-[var(--a-text-3)]')}>{expiryText(c.notAfter)}</span>}
          </div>
        ),
      },
      { key: 'status', header: 'Status', sortValue: (c) => c.status, cell: (c) => <CertStatusPill status={c.status} /> },
      {
        key: 'revocation',
        header: 'Revocation',
        className: 'hidden lg:table-cell',
        sortValue: (c) => c.revokedAt,
        cell: (c) =>
          c.status === 'revoked' ? (
            <div className="max-w-[200px]">
              <span className="block truncate text-[13px] text-[var(--a-text-2)]">{c.revocationReason ? revocationReasonLabels[c.revocationReason] : 'Unspecified'}</span>
              <span className="a-num block text-[11px] text-[var(--a-text-3)]">{ago(c.revokedAt)}</span>
            </div>
          ) : (
            <span className="text-[var(--a-text-3)]">—</span>
          ),
      },
      {
        key: 'actions',
        header: 'Actions',
        srHeader: true,
        align: 'right',
        cell: (c) => (
          <div className="a-row-actions">
            {c.status !== 'revoked' && (
              <span className="a-row-hover">
                <IconButton label={`Revoke ${formatSerial(c.serial)}`} icon={Ban} onClick={() => setRevokeId(c.id)} className="hover:!text-[var(--a-danger-text)]" />
              </span>
            )}
            <RowMenu cert={c} onInspect={() => navigate('certificates', c.id)} onRevoke={() => setRevokeId(c.id)} />
          </div>
        ),
      },
    ],
    [identityById, deviceById, caById, templateById, navigate],
  )

  const filter = useMemo(() => (c: Certificate) => (status === 'all' ? true : c.status === status) && (template === 'all' || c.templateId === template), [status, template])
  const searchText = useMemo(
    () => (c: Certificate) => {
      const u = c.identityId ? identityById.get(c.identityId) : undefined
      const dev = c.deviceId ? deviceById.get(c.deviceId) : undefined
      return `${c.serial} ${formatSerial(c.serial)} ${c.subject} ${c.sans.join(' ')} ${u?.displayName ?? ''} ${dev?.name ?? ''} ${dev?.lastSeenMac ?? ''}`
    },
    [identityById, deviceById],
  )
  const table = useDataTable(d.certificates, columns, { searchText, filter, initialSort: { key: 'expires', dir: 'asc' } })
  const selected = entityId ? (d.certificates.find((c) => c.id === entityId) ?? null) : null
  const revokeCert = d.certificates.find((c) => c.id === revokeId) ?? null
  const filtered = table.query || status !== 'all' || template !== 'all'
  const clear = () => {
    table.setQuery('')
    setStatus('all')
    setTemplate('all')
  }

  return (
    <>
      <PageHeader
        title="Certificates"
        description={
          issuing ? (
            <>
              {counts.all} issued to users and devices by {issuing.commonName}
              {serverCerts > 0 && ` · ${serverCerts} RADIUS server certificate`}
            </>
          ) : (
            'No issuing CA yet'
          )
        }
        actions={
          <Button variant="primary" icon={FileBadge} onClick={() => navigate('users')}>
            Issue for a user
          </Button>
        }
      />

      {/* Totals: each segment filters the table below. */}
      <section aria-label="Certificate totals" className="a-panel a-depth-tenant mb-4">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
          {TOTALS.map((t, i) => (
            <button
              key={t.key}
              type="button"
              aria-pressed={status === t.key}
              onClick={() => setStatus(status === t.key && t.key !== 'all' ? 'all' : t.key)}
              className={cn(
                'relative flex flex-col items-start gap-1 px-[18px] py-3.5 text-left transition-colors hover:bg-white/[0.03]',
                i > 0 && 'lg:border-l lg:border-[var(--a-line)]',
                status === t.key && 'bg-white/[0.05]',
              )}
            >
              <span className="flex items-center gap-2 text-[13px] text-[var(--a-text-2)]">
                <span className="size-2 rounded-[2px]" style={{ background: t.color }} aria-hidden />
                {t.label}
              </span>
              <span className="text-[24px] leading-none font-semibold text-[var(--a-text)]">{counts[t.key]}</span>
              {status === t.key && <span className="absolute inset-x-[18px] bottom-0 h-0.5 rounded-full bg-[var(--a-accent)]" aria-hidden />}
            </button>
          ))}
        </div>
      </section>

      <Panel title="Certificate authority" description="Tenant PKI. The root key is held offline; only the issuing CA signs device certificates." className="mb-4">
        {issuing && root ? (
          <div className="grid border-t border-[var(--a-line)] sm:grid-cols-2 xl:grid-cols-4">
            <div className="px-[18px] py-3.5">
              <div className="flex items-center justify-between gap-2">
                <h3 className="flex items-center gap-2 text-[14px] font-semibold text-[var(--a-text)]">
                  <Lock className="size-4 text-[#a5b4fc]" aria-hidden />
                  Root CA
                </h3>
                <HealthPill state="ok" label="Offline" />
              </div>
              <p className="mt-1.5 text-[13px] text-[var(--a-text-2)]">{root.commonName}</p>
              <p className="a-num text-[12px] text-[var(--a-text-3)]">
                {algoLabel(root.keyAlgorithm)} · valid until {day(root.notAfter)}
              </p>
              <p className="a-num text-[12px] text-[var(--a-text-3)]">Root CRL next update {ago(root.crl?.nextUpdate ?? null)}</p>
            </div>
            <div className="border-t border-[var(--a-line)] px-[18px] py-3.5 sm:border-t-0 sm:border-l">
              <div className="flex items-center justify-between gap-2">
                <h3 className="flex items-center gap-2 text-[14px] font-semibold text-[var(--a-text)]">
                  <KeyRound className="size-4 text-[var(--a-text-3)]" aria-hidden />
                  Issuing CA
                </h3>
                <HealthPill state={current.health.pki} label={current.health.pki === 'ok' ? 'Signing' : undefined} />
              </div>
              <p className="mt-1.5 text-[13px] text-[var(--a-text-2)]">{issuing.commonName}</p>
              <p className="a-num text-[12px] text-[var(--a-text-3)]">
                {algoLabel(issuing.keyAlgorithm)} · expires {day(issuing.notAfter)} ({ago(issuing.notAfter)})
              </p>
              <Mono className="block truncate text-[12px] text-[var(--a-text-3)]" title={issuing.fingerprintSha256}>
                SHA-256 {issuing.fingerprintSha256.slice(0, 16)}…
              </Mono>
            </div>
            <div className="border-t border-[var(--a-line)] px-[18px] py-3.5 xl:border-t-0 xl:border-l">
              <div className="flex items-center justify-between gap-2">
                <h3 className="flex items-center gap-2 text-[14px] font-semibold text-[var(--a-text)]">
                  <ShieldCheck className="size-4 text-[var(--a-text-3)]" aria-hidden />
                  CRL
                </h3>
                <HealthPill state={issuing.crl?.nextUpdate ? 'ok' : 'unconfigured'} label={issuing.crl ? `#${issuing.crl.number}` : undefined} />
              </div>
              <p className="a-num mt-1.5 text-[13px] text-[var(--a-text-2)]">Published {ago(issuing.crl?.lastIssued ?? null)}</p>
              <p className="a-num text-[12px] text-[var(--a-text-3)]">Next update {ago(issuing.crl?.nextUpdate ?? null)}</p>
              <Mono className="block truncate text-[12px] text-[var(--a-text-3)]">{issuing.crl?.url}</Mono>
            </div>
            <div className="border-t border-[var(--a-line)] px-[18px] py-3.5 sm:border-l xl:border-t-0">
              <div className="flex items-center justify-between gap-2">
                <h3 className="flex items-center gap-2 text-[14px] font-semibold text-[var(--a-text)]">
                  <ShieldCheck className="size-4 text-[var(--a-text-3)]" aria-hidden />
                  OCSP
                </h3>
                <HealthPill state={issuing.ocsp?.enabled ? 'ok' : 'unconfigured'} label={issuing.ocsp?.enabled ? 'Enabled' : 'Off'} />
              </div>
              <p className="mt-1.5 text-[13px] text-[var(--a-text-2)]">Answers status checks for this CA’s certificates</p>
              <Mono className="block truncate text-[12px] text-[var(--a-text-3)]">{issuing.ocsp?.url ?? 'No responder URL'}</Mono>
            </div>
          </div>
        ) : (
          <EmptyState icon={KeyRound} title="PKI not initialised">
            Create the offline root and issuing CA to start issuing certificates.
          </EmptyState>
        )}
      </Panel>

      <section aria-label="Certificate list" className="a-panel a-depth-tenant">
        <div className="flex flex-wrap items-center gap-2.5 px-[18px] py-3.5">
          <SearchInput value={table.query} onChange={table.setQuery} label="Search certificates" placeholder="Serial, subject, user, device or MAC" className="w-full sm:w-[320px]" />
          <SelectField
            label="Status"
            hideLabel
            value={status}
            onChange={(v) => setStatus(v as StatusFilter)}
            options={[
              { value: 'all', label: 'Any status' },
              { value: 'active', label: 'Active' },
              { value: 'expiring', label: 'Expiring soon' },
              { value: 'expired', label: 'Expired' },
              { value: 'revoked', label: 'Revoked' },
            ]}
          />
          <SelectField label="Template" hideLabel value={template} onChange={setTemplate} options={[{ value: 'all', label: 'Any template' }, ...d.templates.map((t) => ({ value: t.id, label: t.name }))]} />
          <p className="a-num ml-auto text-[13px] text-[var(--a-text-3)]" aria-live="polite">
            {table.rows.length} of {d.certificates.length}
            {filtered && (
              <button type="button" className="a-link ml-3" onClick={clear}>
                Clear filters
              </button>
            )}
          </p>
        </div>
        <DataTable
          caption="Certificates"
          columns={columns}
          table={table}
          rowKey={(c) => c.id}
          selectedKey={selected?.id}
          onRowClick={inspect}
          empty={
            d.certificates.length === 0 ? (
              <EmptyState icon={FileBadge} title="No certificates issued yet" action={<Button variant="primary" onClick={() => navigate('users')}>Choose a user</Button>}>
                Certificates appear here as soon as a device completes enrollment. Start from a user’s page.
              </EmptyState>
            ) : (
              <EmptyState icon={SearchX} title="No certificates match" action={<Button onClick={clear}>Clear filters</Button>}>
                {table.query ? `Nothing matches “${table.query}”.` : 'No certificates have this status or template.'}
              </EmptyState>
            )
          }
        />
      </section>

      <CertificateInspector certificate={selected} open={!!selected} onOpenChange={(o) => !o && navigate('certificates')} />
      {revokeCert && <RevokeDialog key={revokeCert.id} certificate={revokeCert} open={!!revokeId} onOpenChange={(o) => !o && setRevokeId(null)} />}
    </>
  )
}
