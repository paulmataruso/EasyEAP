// Pieces shared by the Users, User, Certificates and Certificate screens.
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { Ban, Check, ChevronDown, ChevronLeft, ChevronRight, Lock, Search, Trash2, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import type { AccountState, AuthEvent, DirectoryGroup, RevocationReason } from '../../api/people'
import { paths } from '../../routes'
import { Btn, Chip, OutcomeChip, SourceTag, Tip, VlanTag, type Tone } from '../../ui'
import { ago, fmtDateTime, fmtSerial, plural } from '../../lib/format'

// ── Revocation reasons (exactly the backend's five) ─────────────────────
export const REASON_META: Record<RevocationReason, { label: string; explain: string; code: number }> = {
  keyCompromise: { label: 'Key compromise', code: 1, explain: 'The device was lost or stolen, or its private key may have been copied.' },
  affiliationChanged: { label: 'Affiliation changed', code: 3, explain: 'The person left the organisation or no longer needs Wi-Fi access.' },
  superseded: { label: 'Superseded', code: 4, explain: 'A replacement certificate has been issued for this device.' },
  cessationOfOperation: { label: 'Cessation of operation', code: 5, explain: 'The device is retired, wiped or no longer used.' },
  unspecified: { label: 'Unspecified', code: 0, explain: 'None of the above applies. Recorded without a specific reason.' },
}
export const reasonLabel = (r: string | null | undefined) => (r && r in REASON_META ? REASON_META[r as RevocationReason].label : r ?? '—')

// ── Key origin ──────────────────────────────────────────────────────────
const KEY_ORIGIN: Record<string, { short: string; long: string }> = {
  device: { short: 'On device', long: 'The private key was generated on the device and never left it.' },
  browser: { short: 'On device, in browser', long: 'The private key was generated in the browser on the device and never left it.' },
  csr: { short: 'On device, CSR', long: 'The private key was generated on the device; EasyEAP signed its certificate request.' },
  server: { short: 'Server-generated', long: 'EasyEAP generated the private key and delivered it once as an encrypted PKCS#12 package. Less secure than a key made on the device.' },
}
export const keyOrigin = (o: string) => KEY_ORIGIN[o] ?? { short: o, long: o }

export const keyAlgorithm = (a: string) =>
  a.startsWith('ecdsa-p') ? `ECDSA P-${a.slice(7)}` : a.startsWith('rsa-') ? `RSA ${a.slice(4)}` : a

// ── Account state ───────────────────────────────────────────────────────
export function AccountChip({ state }: { state: AccountState | string }) {
  if (state === 'enabled') return <Chip tone="valid" icon={<Check aria-hidden />}>Enabled</Chip>
  if (state === 'locked') return <Chip tone="warn" icon={<Lock aria-hidden />}>Locked</Chip>
  if (state === 'deleted') return <Chip tone="crit" icon={<Trash2 aria-hidden />}>Deleted</Chip>
  return <Chip tone="crit" icon={<Ban aria-hidden />}>{state === 'disabled' ? 'Disabled' : state}</Chip>
}

/** Short reason for a denial, from the backend reason code. */
export const denyReason: Record<string, string> = {
  account_disabled: 'Account disabled, locked or deleted',
  policy_deny: 'A deny rule matches',
  identity_unauthorized: 'No rule grants access',
  cert_revoked: 'Certificate revoked',
  cert_expired: 'Certificate expired',
  cert_unknown: 'Certificate not known to EasyEAP',
}

// ── URL-synced list state ───────────────────────────────────────────────
/** Read and write list filters in the URL (replace, so Back leaves the list). Changing a filter resets the page. */
export function useUrlState<K extends string>(keys: readonly K[]) {
  const [params, setParams] = useSearchParams()
  const get = (k: K) => params.get(k) ?? ''
  const set = (patch: Partial<Record<K | 'page', string | null>>) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev)
      for (const [k, v] of Object.entries(patch) as Array<[string, string | null | undefined]>) {
        if (v === null || v === undefined || v === '') next.delete(k)
        else next.set(k, v)
      }
      if (!('page' in patch)) next.delete('page')
      return next
    }, { replace: true })
  }
  const values = Object.fromEntries(keys.map((k) => [k, get(k)])) as Record<K, string>
  const page = Math.max(1, Number(params.get('page')) || 1)
  return { values, page, set, params, setParams }
}

/** Search input that writes to the URL after a short pause. */
export function SearchBox({ value, onChange, label, placeholder, className }: { value: string; onChange: (v: string) => void; label: string; placeholder: string; className?: string }) {
  const [text, setText] = useState(value)
  const last = useRef(value)
  const cb = useRef(onChange)
  useEffect(() => { cb.current = onChange })
  // Follow outside changes (Back/forward, "Clear filters").
  useEffect(() => { if (value !== last.current) { last.current = value; setText(value) } }, [value])
  useEffect(() => {
    if (text === last.current) return
    const id = setTimeout(() => { last.current = text; cb.current(text) }, 250)
    return () => clearTimeout(id)
  }, [text])
  return (
    <div className={cn('relative', className)}>
      <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 ee-ink-3" aria-hidden />
      <input type="search" className="ee-input pl-9" placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} aria-label={label} autoComplete="off" spellCheck={false} />
    </div>
  )
}

// ── Pagination ──────────────────────────────────────────────────────────
export function Pager({ page, pageSize, total, onPage, noun }: { page: number; pageSize: number; total: number; onPage: (p: number) => void; noun: [string, string] }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)
  return (
    <nav className="flex flex-wrap items-center justify-between gap-3 pt-3" aria-label="Pagination">
      <p className="ee-small ee-ink-3 ee-num" aria-live="polite">
        {total === 0 ? `No ${noun[1]}` : `${from.toLocaleString('en-GB')}–${to.toLocaleString('en-GB')} of ${plural(total, noun[0], noun[1])}`}
      </p>
      {pages > 1 && (
        <div className="flex items-center gap-2">
          <Btn size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}><ChevronLeft aria-hidden />Previous</Btn>
          <span className="ee-small ee-ink-2 ee-num">Page {page} of {pages}</span>
          <Btn size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next<ChevronRight aria-hidden /></Btn>
        </div>
      )}
    </nav>
  )
}

/** Skeleton rows for a table while the first page loads. */
export function TableSkeleton({ rows = 6, cols }: { rows?: number; cols: number }) {
  return (
    <tbody aria-hidden>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r}>
          {Array.from({ length: cols }, (_, c) => (
            <td key={c}><span className={cn('ee-skeleton block h-4', c === 0 ? 'w-40' : 'w-20')} /></td>
          ))}
        </tr>
      ))}
    </tbody>
  )
}

// ── Group picker (local users) ──────────────────────────────────────────
export function GroupPicker({ groups, value, onChange, loading }: { groups: DirectoryGroup[]; value: string[]; onChange: (ids: string[]) => void; loading?: boolean }) {
  const [q, setQ] = useState('')
  const selected = new Set(value)
  const s = q.trim().toLowerCase()
  const list = groups.filter((g) => !s || g.name.toLowerCase().includes(s)).slice(0, 200)
  const toggle = (id: string) => onChange(selected.has(id) ? value.filter((x) => x !== id) : [...value, id])
  return (
    <fieldset className="min-w-0">
      <legend className="mb-1.5 text-[13px] font-semibold">Groups <span className="ml-1 font-normal ee-ink-3">optional</span></legend>
      <p className="ee-small ee-ink-3 mb-2">Access rules match on groups. A user in no group gets the tenant default.</p>
      {value.length > 0 && (
        <ul className="mb-2 flex flex-wrap gap-1.5" aria-label="Selected groups">
          {value.map((id) => {
            const g = groups.find((x) => x.id === id)
            return (
              <li key={id}>
                <button type="button" className="ee-tag gap-1 hover:border-[var(--ee-line-3)]" onClick={() => toggle(id)} aria-label={`Remove ${g?.name ?? 'group'}`}>
                  {g?.name ?? 'Unknown group'}<X className="size-3" aria-hidden />
                </button>
              </li>
            )
          })}
        </ul>
      )}
      <div className="rounded-[8px] border border-[var(--ee-line-2)]">
        <div className="relative border-b border-[var(--ee-line)]">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 ee-ink-3" aria-hidden />
          <input className="h-9 w-full bg-transparent pl-9 pr-3 text-[13px] outline-none placeholder:text-[var(--ee-ink-3)] focus-visible:shadow-[inset_0_0_0_2px_var(--ee-gold)]" placeholder="Filter groups" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter groups" autoComplete="off" />
        </div>
        <ul className="max-h-[200px] overflow-y-auto py-1" aria-label="Groups">
          {loading && <li className="px-3 py-2 ee-small ee-ink-3">Loading groups…</li>}
          {!loading && list.length === 0 && <li className="px-3 py-2 ee-small ee-ink-2">{groups.length === 0 ? 'This tenant has no groups yet. Create local groups on the Directory page.' : `No group matches “${q}”.`}</li>}
          {list.map((g) => (
            <li key={g.id}>
              <label className="flex cursor-pointer items-center gap-2.5 px-3 py-1.5 text-[13px] hover:bg-[var(--ee-hover)]">
                <input type="checkbox" className="ee-check" checked={selected.has(g.id)} onChange={() => toggle(g.id)} />
                <span className="min-w-0 flex-1 truncate">{g.name}</span>
                <span className="ee-small ee-ink-3 ee-num">{g.members}</span>
                <SourceTag source={g.source} />
              </label>
            </li>
          ))}
        </ul>
      </div>
    </fieldset>
  )
}

// ── Authentication events ───────────────────────────────────────────────
export function EventList({ tid, events, deviceName, now, emptyText, vlans = [] }: { tid: string; events: AuthEvent[]; deviceName?: (id: string | null) => string | null; now: Date; emptyText: string; vlans?: Array<{ vlan_id: number; name: string; color: string }> }) {
  const [open, setOpen] = useState<string | null>(null)
  if (events.length === 0) return <p className="ee-small ee-ink-2 py-1">{emptyText}</p>
  return (
    <ol className="ee-divide">
      {events.map((e) => {
        const isOpen = open === e.id
        const dev = deviceName?.(e.device_id)
        return (
          <li key={e.id} className="grid gap-x-4 gap-y-1 py-3 first:pt-0 last:pb-0 sm:grid-cols-[minmax(0,1fr)_auto]">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <OutcomeChip outcome={e.result} />
                {e.result === 'accept'
                  ? <span className="inline-flex items-center gap-1.5 text-[13.5px] font-medium">Placed on VLAN {e.vlan_id !== null ? <VlanTag vlanId={e.vlan_id} name={vlans.find((v) => v.vlan_id === e.vlan_id)?.name} color={vlans.find((v) => v.vlan_id === e.vlan_id)?.color} /> : <span className="ee-ink-3">none (controller default)</span>}</span>
                  : <span className="text-[13.5px] font-medium">{e.explanation?.title ?? e.reason_code ?? 'Rejected'}</span>}
              </div>
              <p className="ee-small ee-ink-3 mt-1 break-words">
                {[dev ?? (e.device_id ? 'Unknown device' : null), e.ssid && `SSID ${e.ssid}`, e.nas_ip && `controller ${e.nas_ip}`, e.calling_station_id && `MAC ${e.calling_station_id}`].filter(Boolean).join(' · ') || 'No device details recorded'}
              </p>
              {e.result === 'reject' && e.explanation && (
                <p className="ee-small ee-ink-2 mt-1.5 max-w-[75ch]">{e.explanation.explanation} <span className="text-[var(--ee-ink)]">Fix: {e.explanation.fix}</span></p>
              )}
              <button type="button" className="ee-small ee-ink-3 mt-1.5 inline-flex items-center gap-1 rounded hover:text-[var(--ee-ink)]" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : e.id)}>
                <ChevronDown className={cn('size-3.5 transition-transform', isOpen && 'rotate-180')} aria-hidden />Technical details
              </button>
              {isOpen && (
                <dl className="ee-mono mt-2 grid gap-x-4 gap-y-1 rounded-[7px] bg-[rgba(6,9,17,0.5)] px-3 py-2 text-[12px] sm:grid-cols-[150px_minmax(0,1fr)]">
                  <dt className="ee-ink-3">RADIUS message</dt><dd className="break-words">{e.raw_message ?? (e.result === 'accept' ? 'Access-Accept' : '—')}</dd>
                  <dt className="ee-ink-3">User-Name</dt><dd className="break-all">{e.username ?? '—'}</dd>
                  <dt className="ee-ink-3">Calling-Station-Id</dt><dd className="break-all">{e.calling_station_id ?? '—'}</dd>
                  <dt className="ee-ink-3">Called-Station-Id</dt><dd className="break-all">{e.called_station_id ?? '—'}</dd>
                  <dt className="ee-ink-3">Certificate serial</dt><dd className="break-all">{e.cert_serial ? fmtSerial(e.cert_serial) : 'none presented'}</dd>
                  <dt className="ee-ink-3">Issuer</dt><dd className="break-all">{e.cert_issuer ?? '—'}</dd>
                </dl>
              )}
            </div>
            <p className="ee-small ee-num ee-ink-2 order-first sm:order-none sm:text-right">
              <time dateTime={e.at}>{fmtDateTime(e.at)}</time>
              <span className="ee-ink-3 sm:block"><span className="sm:hidden"> · </span>{ago(e.at, now)}</span>
            </p>
          </li>
        )
      })}
      <li className="pt-3"><Link to={paths.events(tid)} className="ee-small ee-ink-2 underline hover:text-[var(--ee-ink)]">Open Events for every attempt in this tenant</Link></li>
    </ol>
  )
}

/** "A", "A and B", "A, B and C". */
export function joinNames(list: Array<{ name: string }>): string {
  const n = list.map((c) => c.name)
  return n.length <= 1 ? n.join('') : `${n.slice(0, -1).join(', ')} and ${n[n.length - 1]}`
}

/** A label/value line inside a panel ("Synced 4 minutes ago"). */
export function Meta({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('ee-small ee-ink-3', className)}>{children}</span>
}

/** Tone for a certificate status (panels, edges). */
export const certTone = (status: string): Tone => (status === 'active' ? 'valid' : status === 'expiring' ? 'warn' : status === 'revoked' || status === 'expired' ? 'crit' : 'neutral')

export function Hint({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Tip content={children}>
      <button type="button" className="ee-small ee-ink-3 underline decoration-dotted underline-offset-2" aria-label={label}>{label}</button>
    </Tip>
  )
}
