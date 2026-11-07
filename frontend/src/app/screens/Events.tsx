// Authentication log: every RADIUS decision for the tenant with the reason in plain language. Filters by result,
// reason, network (Wi-Fi or wired), text and time window; pages backwards with the API's before_id cursor. Honours
// ?reason=, ?result=, ?network= and ?event= (opens that attempt's detail sheet), then clears them.
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useQueries, useQueryClient } from '@tanstack/react-query'
import { Tabs } from 'radix-ui'
import { RefreshCw, ScrollText, Search, X } from 'lucide-react'
import { api } from '../api/client'
import { eventsKey, eventsUrl, useControllers, usePolicyLite, type AuthEvent, type EventFilters, type EventsResponse, type Network } from '../api/events'
import { qk } from '../api/keys'
import { useTenant } from '../api/tenant'
import { fmtDateTime, plural, relative } from '../lib/format'
import { useNow } from '../lib/useNow'
import { Btn, Empty, ErrorState, ESelect, LoadingBlock, PageHeader, Panel, Seg } from '../ui'
import { EventSheet } from './events/EventSheet'
import { EventTable } from './events/EventTable'
import { SessionsView } from './events/Sessions'

const RANGES = [
  { value: '24', label: 'Last 24 hours' },
  { value: '168', label: 'Last 7 days' },
  { value: '720', label: 'Last 30 days' },
  { value: '2160', label: 'Last 90 days' },
]
const rangeText = (h: number) => RANGES.find((r) => Number(r.value) === h)?.label.toLowerCase() ?? `last ${h} hours`

const tabCls = 'ee-seg-item data-[state=active]:bg-[var(--ee-raised-solid)] data-[state=active]:text-[var(--ee-ink)] data-[state=active]:shadow-[inset_0_0_0_1px_var(--ee-line-2)]'

function AttemptsView({ initial, initialEvent }: { initial: Partial<EventFilters>; initialEvent: string | null }) {
  const { tid, can } = useTenant()
  const qc = useQueryClient()
  const now = useNow()
  const [filters, setFilters] = useState<EventFilters>({ result: initial.result ?? (initial.reason ? 'reject' : ''), reason: initial.reason ?? '', q: '', hours: 24, network: initial.network ?? '' })
  const [text, setText] = useState('')
  const [openId, setOpenId] = useState<string | null>(initialEvent)
  const [sheetOpen, setSheetOpen] = useState(!!initialEvent)
  const opener = useRef<HTMLElement | null>(null)
  const radius = useControllers(tid, can('radius:read'))
  const policy = usePolicyLite(tid, can('policy:read'))

  // Debounce the free-text filter.
  useEffect(() => {
    const id = setTimeout(() => setFilters((f) => (f.q === text ? f : { ...f, q: text })), 300)
    return () => clearTimeout(id)
  }, [text])
  const update = (patch: Partial<EventFilters>) => setFilters((f) => ({ ...f, ...patch }))
  // Loaded pages belong to one filter set; any filter change starts again from the newest page.
  const fkey = JSON.stringify(filters)
  const [pager, setPager] = useState<{ key: string; cursors: Array<number | undefined> }>({ key: fkey, cursors: [undefined] })
  const cursors = pager.key === fkey ? pager.cursors : [undefined]

  const pages = useQueries({
    queries: cursors.map((c, i) => ({
      queryKey: eventsKey(tid, filters, c),
      queryFn: ({ signal }: { signal: AbortSignal }) => api.get<EventsResponse>(eventsUrl(tid, filters, c), signal),
      // Only the newest page refreshes on its own; refreshing it under older pages would leave a gap between them.
      refetchInterval: cursors.length === 1 && i === 0 ? 30_000 : (false as const),
      placeholderData: (prev: EventsResponse | undefined) => prev,
    })),
  })
  const first = pages[0]
  const items = useMemo(() => pages.flatMap((p) => p.data?.items ?? []), [pages])
  const last = pages[pages.length - 1]
  const next = last?.data?.next_before_id ?? null
  const firstData = first?.data
  const reasons = useMemo(() => firstData?.reasons ?? [], [firstData])
  const filtered = !!(filters.result || filters.reason || filters.q || filters.network)
  const seed = items.find((e) => e.id === openId)

  const reasonOptions = useMemo(() => {
    const opts = [{ value: 'all', label: 'All reasons' as string }]
    const known = new Set<string>()
    for (const r of [...reasons].sort((a, b) => b.count - a.count)) {
      if (!r.reason_code) continue
      known.add(r.reason_code)
      opts.push({ value: r.reason_code, label: `${r.title} (${r.count})` })
    }
    if (filters.reason && !known.has(filters.reason)) opts.push({ value: filters.reason, label: `${filters.reason} (none in this window)` })
    return opts
  }, [reasons, filters.reason])

  const openEvent = (e: AuthEvent, el: HTMLElement) => { opener.current = el; setOpenId(e.id); setSheetOpen(true) }

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end gap-3" role="group" aria-label="Filter authentication attempts">
        <Seg<'all' | 'accept' | 'reject'>
          label="Result"
          value={filters.result || 'all'}
          onChange={(v) => update({ result: v === 'all' ? '' : v, reason: v === 'accept' ? '' : filters.reason })}
          options={[{ value: 'all', label: 'All' }, { value: 'accept', label: 'Accepted' }, { value: 'reject', label: 'Rejected' }]}
        />
        <ESelect
          label="Reason"
          className="min-w-[220px] max-w-full"
          value={filters.reason || 'all'}
          disabled={filters.result === 'accept'}
          onChange={(v) => update({ reason: v === 'all' ? '' : v, result: v === 'all' ? filters.result : 'reject' })}
          options={reasonOptions}
        />
        <Seg<'all' | Network>
          label="Network"
          value={filters.network || 'all'}
          onChange={(v) => update({ network: v === 'all' ? '' : v })}
          options={[{ value: 'all', label: 'All' }, { value: 'wireless', label: 'Wi-Fi' }, { value: 'wired', label: 'Wired' }]}
        />
        <ESelect label="Time window" className="min-w-[160px]" value={String(filters.hours)} onChange={(v) => update({ hours: Number(v) })} options={RANGES} />
        <div className="relative min-w-[220px] flex-1 sm:max-w-[340px]">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 ee-ink-3" aria-hidden />
          <input
            className="ee-input pl-8 pr-8"
            type="search"
            aria-label="Search by user, MAC address, certificate serial, NAS address or switch port"
            placeholder="User, MAC, serial, NAS or port"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          {text && (
            <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 rounded ee-ink-3 hover:text-[var(--ee-ink)]" aria-label="Clear search" onClick={() => setText('')}>
              <X className="size-4" aria-hidden />
            </button>
          )}
        </div>
        {filtered && <Btn variant="ghost" size="sm" onClick={() => { setText(''); update({ result: '', reason: '', q: '', network: '' }) }}>Clear filters</Btn>}
      </div>

      <Panel className="p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="ee-small ee-ink-2" aria-live="polite">
            {first?.isLoading ? 'Loading…' : first?.data ? <>{plural(items.length, 'attempt')}{next ? ' so far' : ''} from the {rangeText(filters.hours)}{items[0] && <> · newest <span title={fmtDateTime(items[0].at)}>{relative(items[0].at, now)}</span></>}</> : null}
          </p>
          <Btn variant="ghost" size="sm" onClick={() => { setPager({ key: fkey, cursors: [undefined] }); qc.invalidateQueries({ queryKey: qk.events(tid) }) }} busy={first?.isFetching && !first?.isLoading}>
            {!(first?.isFetching && !first?.isLoading) && <RefreshCw aria-hidden />}Refresh
          </Btn>
        </div>
        {first?.isLoading ? <LoadingBlock rows={8} label="Loading attempts" />
          : first?.error ? <ErrorState error={first.error} onRetry={() => first.refetch()} title="The authentication log couldn’t be loaded" />
          : items.length === 0 ? (
            <Empty icon={<ScrollText aria-hidden />} title={filtered ? 'No attempts match these filters' : `No authentication attempts in the ${rangeText(filters.hours)}`}
              action={filtered ? <Btn size="sm" onClick={() => { setText(''); update({ result: '', reason: '', q: '', network: '' }) }}>Clear filters</Btn> : filters.hours < 2160 ? <Btn size="sm" onClick={() => update({ hours: 2160 })}>Show the last 90 days</Btn> : undefined}>
              {filtered ? `Nothing in the ${rangeText(filters.hours)} matches. Try a longer time window or fewer filters.` : 'RADIUS hasn’t reported any attempts for this tenant in this window.'}
            </Empty>
          ) : (
            <div className={first?.isPlaceholderData ? 'opacity-60 transition-opacity' : undefined}>
              <EventTable
                tid={tid}
                events={items}
                groupByDay
                selectedId={sheetOpen ? openId : null}
                lookups={{ clients: radius.data?.clients, rules: policy.data?.rules, vlans: policy.data?.vlans, canUsers: can('identities:read') }}
                onOpen={openEvent}
              />
              <div className="mt-4 flex flex-wrap items-center gap-3">
                {next ? (
                  <Btn onClick={() => setPager({ key: fkey, cursors: [...cursors, next] })} busy={last?.isFetching}>Load older attempts</Btn>
                ) : (
                  <p className="ee-small ee-ink-3">That’s every matching attempt in the {rangeText(filters.hours)}.{filters.hours < 2160 && ' Choose a longer time window to see older ones.'}</p>
                )}
                {last?.error && <p className="ee-field-error">Older attempts couldn’t be loaded. Try again.</p>}
              </div>
            </div>
          )}
      </Panel>

      <EventSheet
        tid={tid}
        eventId={openId}
        seed={seed}
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        returnFocus={opener}
        lookups={{ clients: radius.data?.clients, rules: policy.data?.rules, vlans: policy.data?.vlans }}
        can={can}
      />
    </div>
  )
}

export default function Events() {
  const { tenant } = useTenant()
  const [params, setParams] = useSearchParams()
  // Intents (?reason=, ?result=, ?event=) are applied whenever they appear, even while this screen is open, then
  // cleared from the URL. Each new intent remounts the attempts view with those filters.
  const readIntent = (p: URLSearchParams, n: number) => {
    const result = p.get('result')
    const network = p.get('network')
    return {
      n,
      reason: p.get('reason') ?? undefined,
      result: (result === 'accept' || result === 'reject' ? result : undefined) as EventFilters['result'] | undefined,
      network: (network === 'wireless' || network === 'wired' ? network : undefined) as Network | undefined,
      event: p.get('event'),
    }
  }
  const [intent, setIntent] = useState(() => readIntent(params, 0))
  const [tab, setTab] = useState('attempts')
  useEffect(() => {
    if (params.has('reason') || params.has('result') || params.has('event') || params.has('network')) {
      setIntent((cur) => (cur.n === 0 && cur.reason === (params.get('reason') ?? undefined) && cur.event === params.get('event') && cur.result === (params.get('result') ?? undefined)
        && cur.network === (params.get('network') ?? undefined)
        ? cur
        : readIntent(params, cur.n + 1)))
      setTab('attempts')
      const p = new URLSearchParams(params)
      p.delete('reason'); p.delete('result'); p.delete('event'); p.delete('network')
      setParams(p, { replace: true })
    }
  }, [params, setParams])

  return (
    <div>
      <PageHeader title="Authentication log" lede={`Every RADIUS decision for ${tenant.name}, newest first, with the reason in plain language.`} />
      <Tabs.Root value={tab} onValueChange={setTab}>
        <Tabs.List className="ee-seg mb-5" aria-label="Authentication log views">
          <Tabs.Trigger value="attempts" className={tabCls}>Attempts</Tabs.Trigger>
          <Tabs.Trigger value="sessions" className={tabCls}>Sessions</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content value="attempts" forceMount hidden={tab !== 'attempts'} className="outline-none">
          <AttemptsView key={intent.n} initial={{ reason: intent.reason, result: intent.result, network: intent.network }} initialEvent={intent.event} />
        </Tabs.Content>
        <Tabs.Content value="sessions" className="outline-none">
          <SessionsView />
        </Tabs.Content>
      </Tabs.Root>
    </div>
  )
}
