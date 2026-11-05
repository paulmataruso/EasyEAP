// Client certificates issued in the tenant. GET /api/tenants/{tid}/certificates (routers/certificates.py):
// q, status (active | expiring | expired | revoked), purpose, identity_id, page. Intents: ?status=… and ?revoke=<id>.
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { FileKey, ShieldX, X } from 'lucide-react'
import { ApiError } from '../api/client'
import { useTenant } from '../api/tenant'
import { useCertificate, useCertificates, usePki, type Certificate, type CertStatusValue } from '../api/people'
import { paths } from '../routes'
import { Btn, CertChip, Empty, ErrorState, ESelect, PageHeader, Panel, PlatformIcon, platformLabels, Seg, Tip, toast } from '../ui'
import { fmtDate, fmtDateTime, fmtSerial, remaining } from '../lib/format'
import { useNow } from '../lib/useNow'
import { RevokeDialog } from './people/RevokeDialog'
import { keyOrigin, Pager, reasonLabel, SearchBox, TableSkeleton, useUrlState } from './people/shared'

const PAGE_SIZE = 50
type StatusFilter = 'all' | CertStatusValue
const STATUSES: CertStatusValue[] = ['active', 'expiring', 'expired', 'revoked']
const STATUS_LABEL: Record<CertStatusValue, string> = { active: 'Active', expiring: 'Expiring', expired: 'Expired', revoked: 'Revoked' }

export default function Certificates() {
  const { tid, tenant, can } = useTenant()
  const navigate = useNavigate()
  const now = useNow()
  const { values, page, set, params, setParams } = useUrlState(['q', 'status', 'purpose'] as const)
  const status: StatusFilter = (STATUSES as string[]).includes(values.status) ? (values.status as CertStatusValue) : 'all'
  const list = useCertificates(tid, { q: values.q || undefined, status: status === 'all' ? undefined : status, purpose: values.purpose || undefined, page, page_size: PAGE_SIZE })
  const pki = usePki(tid)
  const data = list.data
  const filtered = !!(values.q || status !== 'all' || values.purpose)
  const clear = () => set({ q: null, status: null, purpose: null })
  const issuing = pki.data?.authorities.find((a) => a.role === 'issuing' && a.status === 'active')
  const allCount = data ? STATUSES.reduce((n, s) => n + data.counts[s], 0) : undefined

  // Revoke: from a row, or from the ?revoke=<id> intent (command palette, dashboard).
  const [revoking, setRevoking] = useState<Certificate | null>(null)
  // Each certificate has a link in the table (wide) and in the stacked list (narrow); focus returns to the visible one.
  const rowRefs = useRef<Record<string, HTMLAnchorElement | null>>({})
  const stackRefs = useRef<Record<string, HTMLAnchorElement | null>>({})
  const focusAfter = useRef<HTMLElement | null>(null)
  const intentId = params.get('revoke')
  const intent = useCertificate(tid, intentId)
  useEffect(() => {
    if (!intentId || intent.isLoading) return
    const clearIntent = () => setParams((p) => { const n = new URLSearchParams(p); n.delete('revoke'); return n }, { replace: true })
    if (intent.error) {
      toast('Certificate not found', intent.error instanceof ApiError && intent.error.status === 404 ? 'It may belong to another tenant, or the link is wrong.' : String(intent.error), 'warn')
    } else if (intent.data) {
      if (!can('certificates:revoke')) toast('You can’t revoke certificates', 'Your role doesn’t include revoking certificates. Ask a Tenant, PKI or Wi-Fi Administrator.', 'warn')
      else if (intent.data.status === 'revoked') toast('Already revoked', `Certificate ${fmtSerial(intent.data.serial).slice(0, 14)}… was revoked on ${fmtDate(intent.data.revoked_at)}.`, 'gold')
      else openRevoke(intent.data)
    }
    clearIntent()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intentId, intent.isLoading, intent.data, intent.error])

  function openRevoke(c: Certificate) {
    const visible = [rowRefs.current[c.id], stackRefs.current[c.id]].find((el) => el && el.offsetParent !== null)
    focusAfter.current = visible ?? document.querySelector<HTMLElement>('[data-page-heading]')
    setRevoking(c)
  }

  const statusOptions = [{ value: 'all', label: 'All', count: allCount }, ...STATUSES.map((s) => ({ value: s, label: STATUS_LABEL[s], count: data?.counts[s] }))]
  const onStatus = (v: string) => set({ status: v === 'all' ? null : v })
  const canRevoke = can('certificates:revoke')
  const open = (c: Certificate) => navigate(paths.certificate(tid, c.id))

  return (
    <div>
      <PageHeader
        title="Certificates"
        lede={<>Wi-Fi client certificates in {tenant.name}{issuing ? <>, issued by {issuing.common_name}</> : null}.{data ? <> Expiring means within {data.warning_days} days.</> : null}</>}
        actions={<Link to={paths.users(tid)} className="ee-btn">Issue from a user’s page</Link>}
      />

      <div className="mb-4 flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter certificates">
        {/* Segments on wider screens; a select on phones, where five segments with counts don't fit. */}
        <div className="hidden max-w-full overflow-x-auto sm:block">
          <Seg label="Status" value={status} onChange={onStatus} options={statusOptions} />
        </div>
        <SearchBox className="order-first w-full sm:order-none sm:w-[280px]" value={values.q} onChange={(v) => set({ q: v.trim() || null })} label="Search certificates" placeholder="Serial, user, device or subject" />
        <ESelect label="Status" className="min-w-0 flex-1 sm:hidden" value={status} onChange={onStatus}
          options={statusOptions.map((o) => ({ value: o.value, label: <>{o.label}{o.count !== undefined && <span className="ee-ink-3 ml-1.5 tabular-nums">{o.count}</span>}</> }))} />
        <ESelect label="Purpose" className="min-w-0 flex-1 sm:min-w-[160px] sm:flex-none" value={values.purpose || 'any'} onChange={(v) => set({ purpose: v === 'any' ? null : v })}
          options={[{ value: 'any', label: 'User and device' }, { value: 'user', label: 'User certificates' }, { value: 'device', label: 'Device certificates' }]} />
        {filtered && <Btn size="sm" variant="ghost" onClick={clear}><X aria-hidden />Clear filters</Btn>}
      </div>

      {list.error ? (
        <ErrorState error={list.error} onRetry={() => list.refetch()} title="Certificates couldn’t be loaded" />
      ) : data && data.total === 0 ? (
        filtered ? (
          <Empty icon={<FileKey aria-hidden />} title="No certificates match these filters" action={<Btn onClick={clear}>Clear filters</Btn>}>
            Search matches the serial, the user’s name or username, the device name and the subject.
          </Empty>
        ) : (
          <Empty icon={<FileKey aria-hidden />} title={`No certificates issued in ${tenant.name} yet`} action={<Link to={paths.users(tid)} className="ee-btn ee-btn-primary">Choose a user</Link>}>
            {pki.data && !pki.data.initialized ? 'Initialize the tenant’s PKI first, then issue certificates from each user’s page.' : 'Open a user’s page and issue a certificate for each of their devices.'}
          </Empty>
        )
      ) : (
        <Panel className="px-4 py-3 sm:px-5" aria-label="Certificates">
          <div className="hidden overflow-x-auto lg:block">
            <table className="ee-table" aria-busy={list.isFetching || undefined}>
              <caption className="sr-only">Certificates. Select a row to open it.</caption>
              <thead>
                <tr>
                  <th className="pt-1.5">User</th>
                  <th className="pt-1.5">Device</th>
                  <th className="pt-1.5">Serial</th>
                  <th className="pt-1.5">Status</th>
                  <th className="pt-1.5 text-right">Remaining</th>
                  <th className="pt-1.5">Key</th>
                  <th className="pt-1.5 text-right">Issued</th>
                  {canRevoke && <th className="pt-1.5"><span className="sr-only">Actions</span></th>}
                </tr>
              </thead>
              {!data ? <TableSkeleton cols={canRevoke ? 8 : 7} /> : (
                <tbody className={list.isPlaceholderData ? 'opacity-60' : undefined}>
                  {data.items.map((c) => (
                    <tr key={c.id} data-clickable="true" onClick={(e) => { if (!(e.target as HTMLElement).closest('a,button')) open(c) }}>
                      <td className="min-w-[150px]">
                        {c.identity ? <Link to={paths.user(tid, c.identity.id)} className="font-medium hover:underline">{c.identity.display_name}</Link> : <span className="ee-ink-3">No user</span>}
                        {c.identity && <span className="ee-small ee-ink-3 block truncate max-w-[180px]">{c.identity.username}</span>}
                      </td>
                      <td className="min-w-[130px]">
                        <span className="flex items-center gap-2">
                          <PlatformIcon platform={c.device?.platform} />
                          <span className="min-w-0">
                            <span className="block truncate max-w-[180px]">{c.device?.name ?? <span className="ee-ink-3">No device</span>}</span>
                            {c.device && <span className="ee-small ee-ink-3 block">{platformLabels[c.device.platform] ?? c.device.platform}</span>}
                          </span>
                        </span>
                      </td>
                      <td className="whitespace-nowrap">
                        <Link ref={(el) => { rowRefs.current[c.id] = el }} to={paths.certificate(tid, c.id)} className="ee-mono text-[12.5px] underline decoration-[var(--ee-line-3)] underline-offset-2 hover:text-[var(--ee-gold)]" aria-label={`Open certificate ${fmtSerial(c.serial)}`}>
                          {fmtSerial(c.serial).slice(0, 14)}…
                        </Link>
                      </td>
                      <td className="whitespace-nowrap">
                        <CertChip status={c.status} />
                        {c.status === 'revoked' && <span className="ee-small ee-ink-3 block mt-0.5" title={`Revoked ${fmtDateTime(c.revoked_at)}`}>{reasonLabel(c.revocation_reason)}</span>}
                      </td>
                      <td className="ee-remaining">
                        {c.status === 'revoked' ? <span className="ee-ink-3">—<span className="sr-only">not valid</span></span> : <span className="font-semibold">{remaining(c.not_after, now)}</span>}
                        <span className="ee-small ee-ink-3 block">{c.status === 'revoked' ? 'was to ' : 'to '}{fmtDate(c.not_after)}</span>
                      </td>
                      <td className="ee-ink-2" title={keyOrigin(c.key_origin).long}>{keyOrigin(c.key_origin).short}</td>
                      <td className="text-right whitespace-nowrap ee-num ee-ink-2" title={fmtDateTime(c.not_before)}>{fmtDate(c.not_before)}</td>
                      {canRevoke && (
                        <td className="text-right">
                          {c.status !== 'revoked' && c.purpose !== 'radius-server' && (
                            <Tip content="Revoke">
                              <Btn size="sm" variant="danger" icon className="w-7" onClick={() => openRevoke(c)} aria-label={`Revoke certificate ${fmtSerial(c.serial).slice(0, 14)} for ${c.device?.name ?? c.identity?.display_name ?? c.common_name}`}>
                                <ShieldX aria-hidden />
                              </Btn>
                            </Tip>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              )}
            </table>
          </div>

          <ul className="ee-divide lg:hidden" aria-label="Certificates">
            {!data && Array.from({ length: 5 }, (_, i) => <li key={i} className="py-3"><span className="ee-skeleton block h-4 w-2/3" /><span className="ee-skeleton mt-2 block h-4 w-1/3" /></li>)}
            {data?.items.map((c) => (
              <li key={c.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1 py-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <PlatformIcon platform={c.device?.platform} />
                    <Link ref={(el) => { stackRefs.current[c.id] = el }} to={paths.certificate(tid, c.id)} className="text-[14px] font-semibold hover:underline">{c.device?.name ?? c.common_name}</Link>
                    <CertChip status={c.status} />
                  </div>
                  <p className="ee-small ee-ink-3 mt-0.5 break-words">{c.identity?.display_name ?? 'No user'} · <span className="ee-mono">{fmtSerial(c.serial).slice(0, 14)}…</span></p>
                  <p className="ee-small ee-ink-3">Key: {keyOrigin(c.key_origin).short} · issued {fmtDate(c.not_before)}</p>
                  {c.status === 'revoked' && <p className="ee-small ee-ink-2">{reasonLabel(c.revocation_reason)} · revoked {fmtDate(c.revoked_at)}</p>}
                </div>
                <div className="flex flex-col items-end gap-2">
                  <span className="ee-remaining text-[13.5px] font-semibold">{c.status === 'revoked' ? <span className="ee-ink-3 font-normal">Not valid</span> : remaining(c.not_after, now)}</span>
                  {canRevoke && c.status !== 'revoked' && c.purpose !== 'radius-server' && <Btn size="sm" variant="danger" onClick={() => openRevoke(c)} aria-label={`Revoke certificate for ${c.device?.name ?? c.common_name}`}><ShieldX aria-hidden />Revoke</Btn>}
                </div>
              </li>
            ))}
          </ul>
          {data && <Pager page={page} pageSize={PAGE_SIZE} total={data.total} onPage={(p) => set({ page: p > 1 ? String(p) : null })} noun={['certificate', 'certificates']} />}
        </Panel>
      )}

      <RevokeDialog cert={revoking} open={!!revoking} onOpenChange={(o) => { if (!o) setRevoking(null) }} returnFocus={focusAfter} />
    </div>
  )
}
