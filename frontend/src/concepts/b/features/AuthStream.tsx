import { useMemo, useState } from 'react'
import { CircleCheck, CircleX, Pause, Play, RadioTower, X } from 'lucide-react'
import { useTenantData } from '@/prototype/store'
import { failureExplanations } from '@/domain/explain'
import type { AuthEvent, FailureCode } from '@/domain/types'
import { cn, formatTime } from '@/ui/lib'
import { Button } from '../ui/Button'
import { VlanChip } from '../ui/Badge'
import { EmptyState } from '../ui/Panel'
import { Segmented } from '../ui/Field'
import { formatAge, secondsSince } from '../lib/format'
import { useInspector } from '../shell/Inspectors'
import { useShell } from '../shell/context'

type ResultFilter = 'all' | 'accept' | 'reject'
const PAGE = 60

/**
 * Live authentication stream, newest first. Pause freezes the list (new events are counted, not
 * inserted); the result filter and an optional failure-cause filter scope it.
 */
export function AuthStream({ failure, onClearFailure }: { failure: FailureCode | null; onClearFailure: () => void }) {
  const d = useTenantData()
  const { openEvent, active } = useInspector()
  const { go } = useShell()
  const [result, setResult] = useState<ResultFilter>('all')
  const [frozen, setFrozen] = useState<AuthEvent[] | null>(null)
  const [limit, setLimit] = useState(PAGE)
  const paused = frozen !== null
  const events = frozen ?? d.authEvents
  const newSincePause = frozen ? d.authEvents.length - frozen.length : 0

  const lookup = useMemo(
    () => ({
      identity: new Map(d.identities.map((i) => [i.id, i])),
      device: new Map(d.devices.map((x) => [x.id, x])),
      nas: new Map(d.radiusClients.map((n) => [n.id, n])),
      vlan: new Map(d.vlans.map((v) => [v.id, v])),
    }),
    [d.identities, d.devices, d.radiusClients, d.vlans],
  )

  const effectiveResult: ResultFilter = failure ? 'reject' : result
  const filtered = events.filter((e) => (effectiveResult === 'all' || e.result === effectiveResult) && (!failure || e.failureCode === failure))
  const accepts = events.filter((e) => e.result === 'accept').length
  const last = d.authEvents[0]

  return (
    <section id="b-sec-stream" aria-labelledby="stream-title" className="b-panel flex h-full min-h-0 flex-col">
      <header className="b-panel-head flex-wrap">
        <h2 id="stream-title" className="b-panel-title">
          Live authentications
        </h2>
        <span className="b-t2 text-[12px]">{paused ? 'Paused' : last ? `Last event ${formatAge(secondsSince(last.at))} ago` : 'Waiting for requests'}</span>
        {d.authEvents.length > 0 && (
          <Button size="sm" variant="secondary" icon={paused ? Play : Pause} className="ml-auto" aria-pressed={paused} onClick={() => setFrozen(paused ? null : d.authEvents)}>
            {paused ? 'Resume' : 'Pause'}
          </Button>
        )}
      </header>
      {d.authEvents.length === 0 ? (
        <EmptyState
          icon={RadioTower}
          title="No authentications yet"
          action={
            <Button size="sm" variant="primary" onClick={() => go('radius', { section: 'controllers' })}>
              Register a controller
            </Button>
          }
        >
          RADIUS has not received a request for this tenant. Register a wireless controller and point its secure SSID at EasyEAP; requests appear here as they arrive.
        </EmptyState>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 border-b border-[var(--b-line)] px-3 py-2">
            <Segmented
              label="Result"
              value={effectiveResult}
              onChange={(v) => {
                if (failure) onClearFailure()
                setResult(v)
              }}
              options={[
                { value: 'all', label: 'All', count: events.length },
                { value: 'accept', label: 'Accepted', count: accepts },
                { value: 'reject', label: 'Rejected', count: events.length - accepts },
              ]}
            />
            {failure && (
              <span className="b-chip max-w-full gap-1 pr-0.5 text-[var(--b-text)]">
                <span className="truncate">{failureExplanations[failure].title}</span>
                <button type="button" className="grid size-4 place-items-center rounded hover:bg-white/10" aria-label="Clear cause filter" onClick={onClearFailure}>
                  <X className="size-3" aria-hidden />
                </button>
              </span>
            )}
            {paused && newSincePause > 0 && (
              <button type="button" className="b-link text-[12px]" onClick={() => setFrozen(null)}>
                {newSincePause} new
              </button>
            )}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto" aria-live={paused ? 'off' : 'polite'} aria-relevant="additions">
            {filtered.length === 0 && <p className="b-t2 px-3 py-6 text-[12.5px]">No events match this filter in the last 24 hours.</p>}
            <ul>
              {filtered.slice(0, limit).map((e) => {
                const who = e.identityId ? lookup.identity.get(e.identityId) : undefined
                const device = e.deviceId ? lookup.device.get(e.deviceId) : undefined
                const nas = e.nasClientId ? lookup.nas.get(e.nasClientId) : undefined
                const ok = e.result === 'accept'
                const isOpen = active?.kind === 'event' && active.id === e.id
                return (
                  <li key={e.id}>
                    <button type="button" className={cn('b-stream-row', isOpen && '!bg-[#12222e]')} onClick={() => openEvent(e.id)} aria-label={`${ok ? 'Accepted' : 'Rejected'} ${who?.displayName ?? e.username ?? 'unknown'} at ${formatTime(e.at)} UTC`}>
                      <span className="row-span-2 flex flex-col">
                        <span className="b-mono text-[12px] text-[var(--b-text)]">{formatTime(e.at)}</span>
                        <span className="b-num text-[11.5px] text-[var(--b-text-3)]">{formatAge(secondsSince(e.at))} ago</span>
                      </span>
                      <span className="flex min-w-0 items-center gap-1.5">
                        {ok ? <CircleCheck className="b-ink-ok size-3.5 shrink-0" aria-hidden /> : <CircleX className="b-ink-crit size-3.5 shrink-0" aria-hidden />}
                        <span className="truncate font-medium text-[var(--b-text)]">{who?.displayName ?? e.username ?? 'Unknown identity'}</span>
                      </span>
                      <span className="justify-self-end">{ok ? <VlanChip vlan={e.vlanId ? lookup.vlan.get(e.vlanId) : undefined} showName={false} /> : <span className="b-ink-crit text-[12px] font-medium">Rejected</span>}</span>
                      <span className="col-span-2 col-start-2 truncate text-[12px] text-[var(--b-text-2)]">
                        {ok ? `${device?.name ?? 'Unknown device'} · ${nas?.site ?? 'unknown site'}` : e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
            {filtered.length > limit && (
              <div className="p-3">
                <Button size="sm" variant="ghost" className="w-full" onClick={() => setLimit((l) => l + PAGE)}>
                  Show {Math.min(PAGE, filtered.length - limit)} older events
                </Button>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  )
}
