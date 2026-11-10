// Authentication attempts as a table (md+) or stacked rows (phones). Shared by the dashboard's recent list and the
// Authentication log. Rows open the detail sheet; the user cell links to the user record when it is known.
import { Fragment, type MouseEvent } from 'react'
import { Link } from 'react-router'
import { ChevronRight } from 'lucide-react'
import { cn } from '@/ui/lib'
import type { AuthEvent, ClientLite, RuleLite, VlanLite } from '../../api/events'
import { controllerFor } from '../../api/events'
import { ago, fmtDate, fmtDateTime, fmtStamp, fmtTime, timeZoneName } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { OutcomeChip, VlanTag } from '../../ui'

export interface Lookups {
  clients?: ClientLite[]
  rules?: RuleLite[]
  vlans?: VlanLite[]
  canUsers: boolean
}

/** Plain-language reason for a row: the failure title for rejects, the allowing rule for accepts. */
export function reasonLine(e: AuthEvent, rules?: Lookups['rules']): string {
  if (e.result === 'reject') return e.explanation?.title ?? (e.reason_code ? `Rejected (${e.reason_code})` : 'Rejected, no reason recorded')
  const r = e.rule_id ? rules?.find((x) => x.id === e.rule_id) : undefined
  if (r) return `Allowed by “${r.name}”`
  return e.rule_id ? 'Allowed by a rule that no longer exists' : 'Allowed'
}

export function UserCell({ e, tid, canUsers }: { e: AuthEvent; tid: string; canUsers: boolean }) {
  const name = e.username || 'Unknown user'
  if (e.identity_id && canUsers) {
    return <Link to={paths.user(tid, e.identity_id)} className="font-medium underline-offset-2 hover:underline" onClick={(ev) => ev.stopPropagation()}>{name}</Link>
  }
  return <span className={cn('font-medium', !e.username && 'ee-ink-3')}>{name}</span>
}

function controllerText(e: AuthEvent, clients?: Lookups['clients']) {
  const c = controllerFor(clients, e)
  return c?.name ?? e.nas_ip ?? (e.network === 'wired' ? 'Unknown switch' : 'Unknown controller')
}

/** Where on the network: the switch port for wired attempts, the SSID for Wi-Fi. Events from before wired 802.1X
 * have no network and show the SSID as before. */
export function networkLine(e: AuthEvent): string {
  if (e.network === 'wired') return e.nas_port_id ? `Wired · ${e.nas_port_id}` : 'Wired · port not reported'
  if (e.network === 'wireless') return e.ssid ? `Wi-Fi · ${e.ssid}` : 'Wi-Fi · SSID not reported'
  return e.ssid ?? 'SSID not reported'
}

/** In monitor mode the VLAN is the one EasyEAP would have assigned; it sent none. */
export const MONITOR_VLAN_NOTE = 'Not sent: monitor mode'

function VlanCell({ e, vlan }: { e: AuthEvent; vlan?: VlanLite }) {
  if (e.vlan_id === null) return <span className="ee-ink-3">{e.monitor && e.result === 'accept' ? 'None' : '—'}</span>
  return (
    <>
      <VlanTag vlanId={e.vlan_id} name={vlan?.name} color={vlan?.color} />
      {e.monitor && <span className="mt-0.5 block whitespace-nowrap text-[12px] ee-ink-3" title="The switch is in monitor mode: EasyEAP decided but sent no VLAN, so the device stayed on its port’s VLAN.">{MONITOR_VLAN_NOTE}</span>}
    </>
  )
}

export function EventTable({ tid, events, lookups, onOpen, compact, selectedId, groupByDay }: {
  tid: string
  events: AuthEvent[]
  lookups: Lookups
  onOpen: (e: AuthEvent, opener: HTMLElement) => void
  compact?: boolean
  selectedId?: string | null
  groupByDay?: boolean
}) {
  const now = useNow()
  const vlan = (id: number | null) => lookups.vlans?.find((v) => v.vlan_id === id)
  const open = (e: AuthEvent) => (ev: MouseEvent<HTMLElement>) => {
    if ((ev.target as HTMLElement).closest('a')) return
    const btn = (ev.currentTarget as HTMLElement).querySelector<HTMLElement>('[data-open]') ?? (ev.currentTarget as HTMLElement)
    onOpen(e, btn)
  }
  const dayOf = (iso: string) => fmtDate(iso)
  const cols = compact ? 4 : 7

  return (
    <>
      <div className="hidden overflow-x-auto md:block">
        <table className="ee-table">
          <caption className="sr-only">Authentication attempts, newest first</caption>
          <thead>
            <tr>
              <th>{compact ? 'Time' : `Time (${timeZoneName})`}</th>
              <th>User</th>
              {!compact && <th>Device MAC</th>}
              {!compact && <th>Controller / network</th>}
              <th>Result</th>
              {!compact && <th>VLAN</th>}
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => {
              const newDay = groupByDay && (i === 0 || dayOf(events[i - 1].at) !== dayOf(e.at))
              return (
                <Fragment key={e.id}>
                  {newDay && (
                    <tr>
                      <th colSpan={cols} scope="colgroup" className="bg-[rgba(6,9,17,0.35)] pt-3 text-[12px] font-semibold ee-ink-2">{dayOf(e.at)}</th>
                    </tr>
                  )}
                  <tr data-clickable="true" aria-selected={selectedId === e.id || undefined} onClick={open(e)}>
                    <td className="whitespace-nowrap">
                      <button type="button" data-open className="ee-rowlink ee-num text-left" title={fmtDateTime(e.at)} aria-label={`Details for the ${e.result === 'accept' ? 'accepted' : 'rejected'} attempt by ${e.username ?? 'unknown user'} at ${fmtDateTime(e.at)}`}>
                        {compact ? ago(e.at, now) : groupByDay ? fmtTime(e.at, true) : fmtStamp(e.at)}
                      </button>
                    </td>
                    <td className="max-w-[240px]">
                      <span className="block truncate"><UserCell e={e} tid={tid} canUsers={lookups.canUsers} /></span>
                      {compact && (e.calling_station_id ? <span className="ee-mono block truncate text-[12px] ee-ink-3">{e.calling_station_id}</span> : <span className="block text-[12px] ee-ink-3">No MAC reported</span>)}
                    </td>
                    {!compact && <td className="ee-mono whitespace-nowrap text-[12.5px] ee-ink-2">{e.calling_station_id ?? '—'}</td>}
                    {!compact && (
                      <td className="max-w-[200px]">
                        <span className="block truncate">{controllerText(e, lookups.clients)}</span>
                        <span className="block truncate text-[12px] ee-ink-3">{networkLine(e)}</span>
                      </td>
                    )}
                    <td><OutcomeChip outcome={e.result} /></td>
                    {!compact && <td><VlanCell e={e} vlan={vlan(e.vlan_id)} /></td>}
                    <td className={cn(compact ? 'max-w-[260px]' : 'max-w-[300px]')}>
                      <span className="flex items-center gap-2">
                        <span className={cn('min-w-0 flex-1 truncate', e.result === 'accept' && 'ee-ink-2')}>{reasonLine(e, lookups.rules)}</span>
                        <ChevronRight className="size-4 shrink-0 ee-ink-3" aria-hidden />
                      </span>
                    </td>
                  </tr>
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      <ul className="ee-divide md:hidden" aria-label="Authentication attempts, newest first">
        {events.map((e, i) => {
          const newDay = groupByDay && (i === 0 || dayOf(events[i - 1].at) !== dayOf(e.at))
          return (
            <li key={e.id}>
              {newDay && <p className="pb-1 pt-3 text-[12px] font-semibold ee-ink-2">{dayOf(e.at)} <span className="font-normal ee-ink-3">· {timeZoneName}</span></p>}
              <div className={cn('flex cursor-pointer items-start gap-3 py-3', selectedId === e.id && 'bg-[var(--ee-select)]')} onClick={open(e)}>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <OutcomeChip outcome={e.result} />
                    <span className="min-w-0 truncate"><UserCell e={e} tid={tid} canUsers={lookups.canUsers} /></span>
                  </div>
                  <p className={cn('mt-1.5 text-[13px]', e.result === 'accept' && 'ee-ink-2')}>{reasonLine(e, lookups.rules)}</p>
                  <p className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[12px] ee-ink-3">
                    <span className="ee-num">{groupByDay ? fmtTime(e.at, true) : compact ? ago(e.at, now) : fmtStamp(e.at)}</span>
                    {e.calling_station_id && <span className="ee-mono">{e.calling_station_id}</span>}
                    {!compact && <span>{controllerText(e, lookups.clients)} · {networkLine(e)}</span>}
                    {!compact && e.vlan_id !== null && <span>VLAN {e.vlan_id}{e.monitor ? ` (${MONITOR_VLAN_NOTE.toLowerCase()})` : ''}</span>}
                  </p>
                </div>
                <button type="button" data-open className="ee-btn ee-btn-ghost ee-btn-sm ee-btn-icon shrink-0" aria-label={`Details for the attempt by ${e.username ?? 'unknown user'} at ${fmtDateTime(e.at)}`}>
                  <ChevronRight aria-hidden />
                </button>
              </div>
            </li>
          )
        })}
      </ul>
    </>
  )
}
