import { useEffect, useMemo, useState, useSyncExternalStore } from 'react'
import { Dialog } from 'radix-ui'
import { Ban, FileKey, Search, Stamp, UserRound, X } from 'lucide-react'
import { formatDate, formatDateTime, formatSerial, relativeTime } from '@/ui/lib'
import { now, useTenantData, useTenants } from '@/prototype/store'
import { revocationReasonLabels } from '@/domain/explain'
import type { Certificate, CertificateAuthority, CertStatus } from '@/domain/types'
import { useTable, type Column } from '@/ui/useTable'
import { CertificateDataPage, Lifeline, Remaining, type CertContext } from '../credential'
import { Guilloche } from '../guilloche'
import { RevokeDialog } from '../dialogs'
import { ago, auditLabels, certLabel, intentStore, pushRecent, usePortal } from '../lib'
import type { Navigate } from '../shell'
import { Btn, CertChip, Chip, Dl, Empty, FSelect, PageHeader, Panel, PlatformIcon, Seg, SectionHeader, SortTh } from '../ui'

export function useMediaQuery(q: string) {
  return useSyncExternalStore(
    (cb) => { const m = window.matchMedia(q); m.addEventListener('change', cb); return () => m.removeEventListener('change', cb) },
    () => window.matchMedia(q).matches,
    () => false,
  )
}

function AuthorityPanel({ ca }: { ca: CertificateAuthority }) {
  const days = Math.ceil((new Date(ca.notAfter).getTime() - now().getTime()) / 864e5)
  const tone = days < 90 ? 'warn' : 'gold'
  return (
    <Panel risk={tone} className="f-credential" aria-label={ca.commonName}>
      <Guilloche seed={ca.serial} height={240} />
      <div className="px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="f-h2 flex items-center gap-2"><Stamp className="size-4 text-[var(--f-gold)]" aria-hidden />{ca.commonName}</h2>
            <p className="f-small f-ink-2 mt-0.5">{ca.role === 'root' ? 'Root CA' : 'Issuing CA'} · {ca.keyAlgorithm.replace('ecdsa-p', 'ECDSA P-')}</p>
          </div>
          {ca.role === 'root' ? (
            <Chip tone="gold">{ca.offline ? 'Offline · key not held by EasyEAP' : 'Online'}</Chip>
          ) : (
            <Chip tone="valid">Online · signing</Chip>
          )}
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Lifeline cert={{ notBefore: ca.notBefore, notAfter: ca.notAfter, status: 'active', revokedAt: null }} className="flex-1" />
          <span className="f-small f-ink-3">to {formatDate(ca.notAfter)}</span>
          <span className="f-num min-w-[4.5rem] text-right font-semibold">{days} d</span>
        </div>
        <div className="mt-3 grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-2">
          <p className="flex justify-between gap-3"><span className="f-ink-2">CRL last issued</span><span className="f-num">{ca.crl?.lastIssued ? ago(ca.crl.lastIssued) : '—'}</span></p>
          <p className="flex justify-between gap-3"><span className="f-ink-2">CRL next update</span><span className="f-num">{ca.crl?.nextUpdate ? relativeTime(ca.crl.nextUpdate, now()) : '—'}</span></p>
          <p className="flex justify-between gap-3"><span className="f-ink-2">CRL number</span><span className="f-num">{ca.crl?.number ?? '—'}</span></p>
          <p className="flex justify-between gap-3"><span className="f-ink-2">OCSP</span><span>{ca.ocsp?.enabled ? 'Responding' : ca.role === 'root' ? 'Not used (CRL only)' : 'Off'}</span></p>
        </div>
      </div>
    </Panel>
  )
}

type StatusFilter = 'all' | CertStatus

export function CertificatesScreen({ entityId, navigate }: { entityId?: string; navigate: Navigate }) {
  const { current } = useTenants()
  const d = useTenantData()
  const wide = useMediaQuery('(min-width: 1280px)')
  const [status, setStatus] = useState<StatusFilter>(() => {
    const f = intentStore.get().certFilter
    return f ?? 'all'
  })
  const [template, setTemplate] = useState('any')
  const [closed, setClosed] = useState(false)
  const [revoking, setRevoking] = useState(false)
  const container = usePortal()
  useEffect(() => { if (intentStore.get().certFilter) intentStore.set({}) }, [])

  const holder = (c: Certificate) => d.identities.find((i) => i.id === c.identityId)
  const device = (c: Certificate) => d.devices.find((x) => x.id === c.deviceId)
  const columns = useMemo<Column<Certificate>[]>(() => [
    { key: 'serial', value: (c) => c.serial },
    { key: 'holder', value: (c) => d.identities.find((i) => i.id === c.identityId)?.displayName ?? c.commonName },
    { key: 'device', value: (c) => d.devices.find((x) => x.id === c.deviceId)?.name ?? '' },
    { key: 'subject', value: (c) => c.subject },
    { key: 'issued', value: (c) => c.notBefore, searchable: false },
    { key: 'expires', value: (c) => c.notAfter, searchable: false },
    { key: 'status', value: (c) => c.status, searchable: false },
  ], [d.identities, d.devices])
  const filter = useMemo(() => (c: Certificate) => (status === 'all' || c.status === status) && (template === 'any' || c.templateId === template), [status, template])
  const table = useTable(d.certificates, columns, { initialSort: { key: 'expires', dir: 'asc' }, filter })
  const counts = (s: CertStatus) => d.certificates.filter((c) => c.status === s).length

  const selectedId = entityId ?? (wide && !closed ? table.rows[0]?.id : undefined)
  const selected = d.certificates.find((c) => c.id === selectedId)
  const paneOpen = !!selected && wide
  const issuing = d.cas.find((c) => c.role === 'issuing')
  const root = d.cas.find((c) => c.role === 'root')

  useEffect(() => {
    if (!entityId) return
    const c = d.certificates.find((x) => x.id === entityId)
    if (c) pushRecent(current.id, { kind: 'certificate', id: c.id, label: d.devices.find((x) => x.id === c.deviceId)?.name ?? c.commonName, sub: `Certificate ${c.serial.slice(0, 8)}…` })
  }, [entityId, current.id, d.certificates, d.devices])

  const select = (id: string) => { setClosed(false); navigate('certificates', id) }
  const closePane = () => { setClosed(true); navigate('certificates') }

  const ctx = (c: Certificate): CertContext => ({ tenant: current, holder: holder(c), device: device(c), issuer: d.cas.find((x) => x.id === c.issuerCaId), template: d.templates.find((t) => t.id === c.templateId) })

  const detail = selected && <CertDetail cert={selected} ctx={ctx(selected)} onRevoke={() => setRevoking(true)} navigate={navigate} onClose={closePane} />

  return (
    <div>
      <PageHeader title="Certificates" lede={<>{d.certificates.length} certificates in {current.name}{issuing && <> · issued by {issuing.commonName}</>}</>} />

      {d.cas.length > 0 && (
        <div className="mb-9 grid gap-4 lg:grid-cols-2">
          {root && <AuthorityPanel ca={root} />}
          {issuing && <AuthorityPanel ca={issuing} />}
        </div>
      )}

      {d.certificates.length === 0 ? (
        <Empty icon={<FileKey />} title={`No certificates issued in ${current.name} yet`} action={<Btn variant="primary" onClick={() => navigate('users')}>Choose a user to enroll</Btn>}>
          The PKI is ready. Open a user’s record and issue a Wi-Fi certificate for their device.
        </Empty>
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter certificates">
            <Seg
              label="Status"
              value={status}
              onChange={setStatus}
              options={[
                { value: 'all', label: 'All', count: d.certificates.length },
                ...(['active', 'expiring', 'expired', 'revoked'] as CertStatus[]).map((s) => ({ value: s, label: certLabel[s].replace(' soon', ''), count: counts(s) })),
              ]}
            />
            <div className="relative w-full sm:w-[240px]">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 f-ink-3" aria-hidden />
              <input className="f-input pl-9" placeholder="Serial, subject, user or device" value={table.query} onChange={(e) => table.setQuery(e.target.value)} aria-label="Search certificates" />
            </div>
            <FSelect label="Template" value={template} onChange={setTemplate} options={[{ value: 'any', label: 'Any template' }, ...d.templates.map((t) => ({ value: t.id, label: t.name }))]} />
            <span className="f-small f-ink-3 ml-auto" aria-live="polite">{table.rows.length} shown</span>
          </div>

          <div className={paneOpen ? 'grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_440px] 2xl:grid-cols-[minmax(0,1fr)_480px]' : ''}>
            <div className="min-w-0 overflow-x-auto">
              {table.rows.length === 0 ? (
                <Empty title="No certificates match" action={<Btn onClick={() => { setStatus('all'); setTemplate('any'); table.setQuery('') }}>Clear filters</Btn>}>Search matches serial, subject, user and device name.</Empty>
              ) : (
                <table className="f-table">
                  <caption className="sr-only">Certificates, sortable. Select a row to inspect it.</caption>
                  <thead>
                    <tr>
                      <SortTh label="Serial" sortKey="serial" table={table} />
                      <SortTh label="Holder and device" sortKey="holder" table={table} />
                      {!paneOpen && <th>Issuing CA</th>}
                      {!paneOpen && <SortTh label="Issued" sortKey="issued" table={table} />}
                      <SortTh label="Status" sortKey="status" table={table} />
                      <SortTh label="Validity left" sortKey="expires" table={table} right />
                    </tr>
                  </thead>
                  <tbody>
                    {table.rows.map((c) => {
                      const h = holder(c)
                      const dev = device(c)
                      const sel = c.id === selectedId
                      return (
                        <tr key={c.id} data-clickable="true" aria-selected={sel} onClick={() => select(c.id)}>
                          <td className="whitespace-nowrap">
                            <button type="button" className="f-rowlink f-mono text-[12.5px] hover:underline" onClick={(e) => { e.stopPropagation(); select(c.id) }} aria-label={`Inspect certificate ${c.serial}`}>{formatSerial(c.serial).slice(0, paneOpen ? 9 : 14)}…</button>
                          </td>
                          <td className={paneOpen ? 'min-w-[170px]' : 'min-w-[200px]'}>
                            <span className="flex items-center gap-2.5">
                              <PlatformIcon platform={dev?.platform ?? null} />
                              <span className="min-w-0">
                                <span className="block truncate font-medium">{h?.displayName ?? c.commonName}</span>
                                <span className="block truncate text-[12px] f-ink-3">{dev?.name ?? 'RADIUS server'}{!paneOpen && <> · {c.subject}</>}</span>
                              </span>
                            </span>
                          </td>
                          {!paneOpen && <td className="f-ink-2 whitespace-nowrap">{d.cas.find((x) => x.id === c.issuerCaId)?.commonName}</td>}
                          {!paneOpen && <td className="f-num f-ink-2 whitespace-nowrap">{formatDate(c.notBefore)}</td>}
                          <td className="whitespace-nowrap">
                            <CertChip status={c.status} />
                            {c.status === 'revoked' && !paneOpen && <span className="f-small f-ink-3 ml-2">{c.revocationReason ? revocationReasonLabels[c.revocationReason] : ''}{c.revokedAt ? ` · ${formatDate(c.revokedAt)}` : ''}</span>}
                          </td>
                          <td className="f-right whitespace-nowrap">
                            <Remaining cert={c} className="block" />
                            <span className="f-num block text-[12px] f-ink-3">{c.status === 'revoked' ? `was to ${formatDate(c.notAfter)}` : `to ${formatDate(c.notAfter)}`}</span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
            {paneOpen && <aside className="sticky top-8 min-w-0" aria-label="Certificate inspector">{detail}</aside>}
          </div>
        </>
      )}

      {!wide && selected && (
        <Dialog.Root open onOpenChange={(o) => !o && closePane()}>
          <Dialog.Portal container={container}>
            <Dialog.Overlay className="f-backdrop" />
            <Dialog.Content className="f-sheet p-4">
              <Dialog.Title className="sr-only">Certificate {selected.serial}</Dialog.Title>
              <Dialog.Description className="sr-only">Certificate details and revocation</Dialog.Description>
              {detail}
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      )}
      {selected && revoking && <RevokeDialog cert={selected} subject={device(selected)?.name ?? selected.commonName} open={revoking} onOpenChange={setRevoking} onRevoked={() => navigate('certificates', selected.id)} />}
    </div>
  )
}

function CertDetail({ cert, ctx, onRevoke, navigate, onClose }: { cert: Certificate; ctx: CertContext; onRevoke: () => void; navigate: Navigate; onClose: () => void }) {
  const d = useTenantData()
  // Audit rows name a certificate by serial or by "Holder · device type"
  const deviceShort = ctx.device?.name.split("'s ").pop()
  const audit = d.audit.filter(
    (a) => a.detail.includes(cert.serial) || (!!ctx.holder && !!deviceShort && a.target === `${ctx.holder.displayName} · ${deviceShort}`),
  )
  const events = d.authEvents.filter((e) => e.certSerial === cert.serial)
  const accepted = events.filter((e) => e.result === 'accept').length
  const isServer = !cert.identityId
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-2">
        <p className="f-small f-ink-3">Inspector</p>
        <Btn size="sm" variant="ghost" icon aria-label="Close inspector" onClick={onClose}><X aria-hidden /></Btn>
      </div>
      <CertificateDataPage
        cert={cert}
        ctx={ctx}
        size="sm"
        actions={
          <>
            {ctx.holder && <Btn size="sm" onClick={() => navigate('user', ctx.holder!.id)}><UserRound aria-hidden />Open {ctx.holder.displayName.split(' ')[0]}’s record</Btn>}
            {cert.status !== 'revoked' && !isServer && <Btn size="sm" variant="danger" onClick={onRevoke}><Ban aria-hidden />Revoke</Btn>}
          </>
        }
      />
      {cert.status === 'revoked' && (
        <section aria-labelledby="f-rev-h">
          <SectionHeader id="f-rev-h" title="Revocation" level={3} />
          <Dl
            items={[
              ['Revoked', <span className="f-num">{cert.revokedAt ? formatDateTime(cert.revokedAt) : '—'}</span>],
              ['Reason', cert.revocationReason ? revocationReasonLabels[cert.revocationReason] : '—'],
              ['By', cert.revokedBy ?? '—'],
              ['Effect', 'New authentications are rejected. Connected devices drop at their next reauthentication or CoA disconnect.'],
            ]}
          />
        </section>
      )}
      <section aria-labelledby="f-use-h">
        <SectionHeader id="f-use-h" title="Use in the last 24 hours" level={3} />
        <p className="text-[13px] f-ink-2">{events.length === 0 ? 'Not presented to RADIUS in the last 24 hours.' : <><span className="f-num font-semibold text-[var(--f-ink)]">{events.length}</span> authentications · <span className="f-num">{accepted}</span> accepted · <span className="f-num">{events.length - accepted}</span> rejected · last {ago(events[0].at)}</>}</p>
      </section>
      <section aria-labelledby="f-san-h">
        <SectionHeader id="f-san-h" title="Subject alternative names" level={3} />
        <ul className="space-y-1">{cert.sans.map((s) => <li key={s} className="f-mono break-all text-[12.5px] f-ink-2">{s}</li>)}</ul>
      </section>
      <section aria-labelledby="f-cert-audit-h">
        <SectionHeader id="f-cert-audit-h" title="Audit trail" level={3} />
        {audit.length === 0 ? (
          <p className="f-small f-ink-3">No audit entries in this window.</p>
        ) : (
          <ul className="f-divide border-y border-[var(--f-line)]">
            {audit.map((a) => (
              <li key={a.id} className="py-2.5 text-[13px]">
                <p className="flex justify-between gap-3"><span className="font-medium">{auditLabels[a.action] ?? a.action}</span><span className="f-num f-ink-3">{ago(a.at)}</span></p>
                <p className="f-small f-ink-2 mt-0.5">{a.detail}</p>
                <p className="f-small f-ink-3">{a.actor}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
