// The needs-action queue (direction D): what breaks next, ranked by the backend by severity, time to impact and
// people affected. Every item carries one action that names a real destination, who is affected, when, and the age
// of the data behind it.
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { ArrowRight, CalendarClock, CircleCheck, History, UsersRound } from 'lucide-react'
import { cn } from '@/ui/lib'
import type { QueueItem, Severity } from '../../api/types'
import { ago, fmtDate, fmtDateTime, plural, relative } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { targetPath } from '../../routes'
import { SeverityChip, type Tone } from '../../ui'

export const worstSeverity = (items: QueueItem[]): Severity | null =>
  items.some((i) => i.severity === 'critical') ? 'critical' : items.some((i) => i.severity === 'warning') ? 'warning' : items.length ? 'info' : null

export const queueRisk = (items: QueueItem[]): Tone => {
  const w = worstSeverity(items)
  return w === 'critical' ? 'crit' : w === 'warning' ? 'warn' : w === 'info' ? 'neutral' : 'valid'
}

export function affectedText(item: QueueItem): string {
  const devices = item.code.startsWith('rejects:')
  if (item.affected === 0) return devices ? 'No devices identified' : 'No one affected yet'
  return `Affects ${devices ? plural(item.affected, 'device') : plural(item.affected, 'person', 'people')}`
}

/** "in 18 hours · 6 Nov 2026, 10:12 UTC" (future) or "since 3 Nov 2026, 10:12 UTC · 2 days ago" (past). */
export function impactText(iso: string, now: Date): string {
  const future = new Date(iso).getTime() > now.getTime()
  return future ? `Users affected ${relative(iso, now)} · ${fmtDateTime(iso)}` : `Users affected since ${fmtDateTime(iso)} · ${relative(iso, now)}`
}

/** The age of the data behind an item, named for what that data is. */
export function sourceText(item: QueueItem, now: Date): string | null {
  const at = item.source_at
  const c = item.code
  if (c === 'radius_offline' || c === 'radius_config' || c === 'snapshot_pending' || c === 'radius_stopped' || c === 'radius_not_serving') return at ? `Last RADIUS heartbeat ${ago(at, now)}` : 'No RADIUS heartbeat received yet'
  if (c === 'worker_offline') return at ? `Last worker heartbeat ${ago(at, now)}` : 'No worker heartbeat received yet'
  // Items whose impact time is the whole story (a list's expiry, a suspension) carry no separate source time.
  if (!at) return null
  if (c === 'snapshot_overdue' || c === 'snapshot_expired') return `Snapshot built ${ago(at, now)}`
  if (c === 'directory_stale') return `Last successful sync ${ago(at, now)}`
  if (c.startsWith('rejects:') || c === 'server_cert_rejected') return `Last attempt ${ago(at, now)}`
  if (c === 'directory_failed') return `Last sync attempt ${ago(at, now)}`
  if (c === 'server_cert_expiring' || c === 'issuing_ca_expiring' || c === 'issuing_ca_expired' || c === 'issuing_ca_cap') return `Certificate issued ${fmtDate(at)}`
  return `Checked ${ago(at, now)}`
}

function Meta({ icon, children, title }: { icon: ReactNode; children: ReactNode; title?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 [&_svg]:size-3.5 [&_svg]:shrink-0 [&_svg]:text-[var(--ee-ink-3)]" title={title}>
      {icon}
      <span>{children}</span>
    </span>
  )
}

export function ActionLink({ to, label, primary, size = 'md' }: { to: string; label: string; primary?: boolean; size?: 'sm' | 'md' }) {
  return (
    <Link to={to} className={cn('ee-btn', primary && 'ee-btn-primary', size === 'sm' && 'ee-btn-sm')}>
      {label}
      <ArrowRight aria-hidden />
    </Link>
  )
}

export function QueueRow({ item, tid, primary, canOpen, unavailable }: { item: QueueItem; tid: string; primary?: boolean; canOpen: boolean; unavailable?: string }) {
  const now = useNow()
  return (
    <li className="grid gap-x-6 gap-y-3 py-4 first:pt-1 last:pb-1 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
          <SeverityChip severity={item.severity} />
          <h3 className="ee-h3 min-w-0">{item.title}</h3>
        </div>
        <p className="ee-small ee-ink-2 mt-1.5 max-w-[75ch]">{item.detail}</p>
        <p className="ee-small mt-2.5 flex flex-wrap gap-x-4 gap-y-1.5">
          <Meta icon={<UsersRound aria-hidden />}>{affectedText(item)}</Meta>
          {item.impact_at && <Meta icon={<CalendarClock aria-hidden />}>{impactText(item.impact_at, now)}</Meta>}
          {sourceText(item, now) !== null && <Meta icon={<History aria-hidden />} title={item.source_at ? fmtDateTime(item.source_at) : undefined}><span className="ee-ink-2">{sourceText(item, now)}</span></Meta>}
        </p>
      </div>
      <div className="sm:pt-0.5">
        {canOpen
          ? <ActionLink to={targetPath(tid, item.action.target)} label={item.action.label} primary={primary} />
          : <p className="ee-small ee-ink-3 max-w-[30ch]">{unavailable}</p>}
      </div>
    </li>
  )
}

export function QueueEmpty({ freshness, caveat }: { freshness: ReactNode; caveat?: string }) {
  return (
    <div className="flex items-start gap-3 py-1">
      <CircleCheck className={cn('mt-0.5 size-5 shrink-0', caveat ? 'text-[var(--ee-neutral)]' : 'text-[var(--ee-valid)]')} aria-hidden />
      <div className="min-w-0">
        <p className="ee-h3">{caveat ? 'No queued issues' : 'Nothing needs action'}</p>
        {caveat && <p className="ee-small mt-1">{caveat}</p>}
        <p className="ee-small ee-ink-2 mt-1">{freshness}</p>
      </div>
    </div>
  )
}
