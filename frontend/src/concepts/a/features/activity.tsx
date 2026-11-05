import type { ComponentType } from 'react'
import { Ban, ChevronRight, FileBadge, FolderSync, KeyRound, Network, Router, ShieldCheck, SlidersHorizontal, TriangleAlert, UserCog } from 'lucide-react'
import type { AuditEvent, AuthEvent } from '@/domain/types'
import { failureExplanations } from '@/domain/explain'
import { cn } from '@/ui/lib'
import { ResultPill, VlanChip } from '../ui/badges'
import { Mono } from '../ui/primitives'
import { useLookups } from '../lib/model'
import { ago, at, hhmm } from '../lib/time'
import { useNav } from '../shell/nav'

// ── Audit ───────────────────────────────────────────────────────────────────

const AUDIT: Record<string, { label: string; icon: ComponentType<{ className?: string; 'aria-hidden'?: boolean }>; tone?: 'danger' | 'warn' }> = {
  'certificate.issue': { label: 'Certificate issued', icon: FileBadge },
  'certificate.revoke': { label: 'Certificate revoked', icon: Ban, tone: 'danger' },
  'directory.sync': { label: 'Directory synced', icon: FolderSync },
  'directory.sync.failed': { label: 'Directory sync failed', icon: TriangleAlert, tone: 'warn' },
  'pki.crl.publish': { label: 'CRL published', icon: ShieldCheck },
  'policy.rule.update': { label: 'Access rule changed', icon: SlidersHorizontal },
  'policy.rule.reorder': { label: 'Rule order changed', icon: SlidersHorizontal },
  'radius.client.rotate_secret': { label: 'Shared secret rotated', icon: KeyRound },
  'radius.client.create': { label: 'Controller added', icon: Router },
  'tenant.create': { label: 'Tenant created', icon: Network },
  'admin.role.grant': { label: 'Admin role granted', icon: UserCog },
}

export function auditLabel(action: string) {
  return AUDIT[action]?.label ?? action
}

/** Audit timeline. Platform-scope rows (no tenant) wear the platform glass so scope is visible. */
export function AuditTimeline({ events, limit = 8 }: { events: AuditEvent[]; limit?: number }) {
  return (
    <ol className="flex flex-col" aria-label="Audit activity">
      {events.slice(0, limit).map((e, i, arr) => {
        const meta = AUDIT[e.action] ?? { label: e.action, icon: ShieldCheck }
        const Icon = meta.icon
        const platform = e.tenantId === null
        return (
          <li key={e.id} className="relative flex gap-3 pb-4 last:pb-0">
            {i < arr.length - 1 && <span className="absolute top-8 bottom-0 left-[15px] w-px bg-white/[0.08]" aria-hidden />}
            <span
              className={cn(
                'relative grid size-8 shrink-0 place-items-center rounded-full border',
                platform ? 'border-[var(--a-d0-border)] bg-[var(--a-d0-fill)] text-[#a5b4fc]' : 'border-white/10 bg-white/[0.04] text-[var(--a-text-2)]',
                meta.tone === 'danger' && 'text-[var(--a-danger-text)]',
                meta.tone === 'warn' && 'text-[var(--a-warn-text)]',
              )}
            >
              <Icon className="size-4" aria-hidden />
            </span>
            <div className="min-w-0 flex-1 pt-0.5">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                <p className="text-[14px] font-medium text-[var(--a-text)]">
                  {meta.label}
                  <span className="font-normal text-[var(--a-text-2)]"> · {e.target}</span>
                </p>
                <time dateTime={e.at} title={at(e.at)} className="a-num shrink-0 text-[12px] text-[var(--a-text-3)]">
                  {ago(e.at)}
                </time>
              </div>
              <p className="mt-0.5 text-[13px] text-[var(--a-text-3)]">{e.detail}</p>
              <p className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-[var(--a-text-3)]">
                <Mono>{e.actor}</Mono>
                {platform && <span className="a-scope a-scope-platform !h-5 !rounded-md !px-1.5 !text-[11px]">Platform</span>}
              </p>
            </div>
          </li>
        )
      })}
    </ol>
  )
}

// ── Authentication events ───────────────────────────────────────────────────

/** Compact recent-authentications table for the dashboard. */
export function RecentAuthTable({ events, limit = 8 }: { events: AuthEvent[]; limit?: number }) {
  const { identityById, nasById, vlanById } = useLookups()
  const { navigate } = useNav()
  return (
    <div className="a-table-wrap">
      <table className="a-table">
        <caption className="sr-only">Most recent authentication attempts</caption>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">User</th>
            <th scope="col">Result</th>
            <th scope="col" className="hidden sm:table-cell">
              VLAN or reason
            </th>
          </tr>
        </thead>
        <tbody>
          {events.slice(0, limit).map((e) => {
            const user = e.identityId ? identityById.get(e.identityId) : undefined
            const nas = e.nasClientId ? nasById.get(e.nasClientId) : undefined
            return (
              <tr key={e.id} data-clickable={user ? 'true' : undefined} onClick={() => user && navigate('user', user.id)}>
                <td className="a-num whitespace-nowrap">
                  <time dateTime={e.at} title={at(e.at)}>
                    {hhmm(e.at)}
                  </time>
                </td>
                <td className="max-w-[220px]">
                  {user ? (
                    <a
                      href={`#/c/a/user/${encodeURIComponent(user.id)}`}
                      onClick={(ev) => {
                        ev.preventDefault()
                        navigate('user', user.id)
                      }}
                      className="block truncate font-medium text-[var(--a-text)] no-underline hover:underline"
                    >
                      {user.displayName}
                    </a>
                  ) : (
                    <Mono>{e.username ?? 'Unknown'}</Mono>
                  )}
                  <span className="block truncate text-[12px] text-[var(--a-text-3)]">{nas?.name ?? 'Unknown controller'}</span>
                </td>
                <td>
                  <ResultPill result={e.result} />
                </td>
                <td className="hidden max-w-[260px] sm:table-cell">{e.result === 'accept' ? <VlanChip vlan={e.vlanId ? vlanById.get(e.vlanId) : null} /> : <span className="line-clamp-2 text-[13px] leading-snug text-[var(--a-text-2)]">{e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'}</span>}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** Detailed event list with plain-language explanations (user detail). */
export function AuthEventList({ events, limit = 10 }: { events: AuthEvent[]; limit?: number }) {
  const { nasById, vlanById, deviceById } = useLookups()
  return (
    <ul className="flex flex-col divide-y divide-white/[0.07]">
      {events.slice(0, limit).map((e) => {
        const nas = e.nasClientId ? nasById.get(e.nasClientId) : undefined
        const device = e.deviceId ? deviceById.get(e.deviceId) : undefined
        const f = e.failureCode ? failureExplanations[e.failureCode] : null
        return (
          <li key={e.id} className="px-[18px] py-3">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
              <ResultPill result={e.result} />
              <span className="text-[14px] font-medium text-[var(--a-text)]">{f ? f.title : 'Connected'}</span>
              {e.result === 'accept' && e.vlanId && <VlanChip vlan={vlanById.get(e.vlanId)} />}
              <time dateTime={e.at} title={at(e.at)} className="a-num ml-auto text-[12px] text-[var(--a-text-3)]">
                {ago(e.at)}
              </time>
            </div>
            <p className="mt-1 text-[12px] text-[var(--a-text-3)]">
              {device?.name ?? 'Unknown device'}
              {e.callingStationId && (
                <>
                  {' · '}
                  <Mono>{e.callingStationId}</Mono>
                </>
              )}
              {' · '}
              {nas?.name ?? 'Unknown controller'}
              {e.ssid && ` · ${e.ssid}`}
            </p>
            {f && (
              <div className="mt-2 rounded-[10px] border border-white/[0.08] bg-black/15 p-3 text-[13px]">
                <p className="text-[var(--a-text-2)]">{f.explanation}</p>
                <p className="mt-1.5 text-[var(--a-text)]">
                  <span className="font-semibold">Fix: </span>
                  {f.fix}
                </p>
                {e.rawMessage && (
                  <details className="group mt-2">
                    <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded text-[12px] font-medium text-[var(--a-info-text)] [&::-webkit-details-marker]:hidden">
                      <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" aria-hidden />
                      Technical details
                    </summary>
                    <div className="mt-2 flex flex-col gap-1">
                      <Mono className="block rounded-md bg-black/35 px-2.5 py-2 text-[12px] break-all text-[var(--a-text-2)]">{e.rawMessage}</Mono>
                      {e.certSerial && (
                        <span className="text-[12px] text-[var(--a-text-3)]">
                          Certificate serial <Mono>{e.certSerial}</Mono>
                        </span>
                      )}
                    </div>
                  </details>
                )}
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
