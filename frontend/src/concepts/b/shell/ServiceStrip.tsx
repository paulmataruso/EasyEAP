import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Popover } from 'radix-ui'
import { ArrowRight, Pause, Play, RefreshCw } from 'lucide-react'
import type { ScreenId } from '@/concepts/contract'
import { now, useTenantData, useTenants } from '@/prototype/store'
import { cn } from '@/ui/lib'
import { classify, CONTROLLER_BUDGET, DIRECTORY_BUDGET, freshnessLabel, remaining, snapshotBudget, type Freshness, type FreshnessBudget } from '../lib/freshness'
import { clockUTC, formatAge } from '../lib/format'
import { healthLabel, healthTone, toneIcon, worstTone, type Tone } from '../lib/status'
import { usePageVisible, useReducedMotion, useStoredState } from '../lib/hooks'
import { usePortal } from '../ui/portal'
import { SelectBox } from '../ui/Field'
import { IconButton } from '../ui/Button'
import { useShell } from './context'

/**
 * The signature move: a persistent strip of live service telemetry for the current tenant.
 * Every number carries its age. Values drain a freshness bar between polls and go visibly stale
 * (hatched, struck, red age) when the console stops hearing from the source or the source itself is old.
 *
 * The demo clock is fixed, so "live" time is the demo clock plus real time elapsed since the page
 * opened. Under reduced motion the strip renders a static snapshot with a manual refresh.
 */

interface Cell {
  id: string
  name: string
  tone: Tone
  value: string
  unit: string
  /** Seconds since the console last refreshed this value (the age chip) */
  pollAge: number
  /** Freshness of the underlying source itself, e.g. time since the last AD sync */
  source: { freshness: Freshness; age: number | null; bar?: number; rule?: string }
  details: Array<[string, ReactNode]>
  screen: ScreenId
  screenLabel: string
  section?: string
  unconfigured?: boolean
}

const RANK: Record<Freshness, number> = { none: 0, fresh: 1, aging: 2, stale: 3 }
const worstFresh = (a: Freshness, b: Freshness) => (RANK[a] >= RANK[b] ? a : b)

export function ServiceStrip() {
  const { current } = useTenants()
  const d = useTenantData()
  const { go } = useShell()
  const reduced = useReducedMotion()
  const visible = usePageVisible()
  const [intervalSec, setIntervalSec] = useStoredState<number>('easyeap.b.pollInterval', 15)
  const [paused, setPaused] = useState(false)

  // Ops clock = demo clock + real elapsed time. Ticks once a second while visible and motion is allowed.
  const mount = useRef(performance.now())
  const [elapsed, setElapsed] = useState(0)
  const [lastPoll, setLastPoll] = useState(() => now().getTime() - 3000)
  const live = useRef({ paused, intervalSec })
  useEffect(() => {
    live.current = { paused, intervalSec }
  }, [paused, intervalSec])

  useEffect(() => {
    if (reduced || !visible) return
    const tick = () => {
      const e = performance.now() - mount.current
      setElapsed(e)
      if (!live.current.paused) setLastPoll((prev) => (now().getTime() + e - prev >= live.current.intervalSec * 1000 ? now().getTime() + e : prev))
    }
    tick()
    const id = window.setInterval(tick, 1000)
    return () => window.clearInterval(id)
  }, [reduced, visible])

  // A tenant switch is a fresh fetch.
  const firstTenant = useRef(current.id)
  useEffect(() => {
    if (firstTenant.current === current.id) return
    firstTenant.current = current.id
    setLastPoll(now().getTime() + (performance.now() - mount.current))
  }, [current.id])

  const refresh = () => {
    const e = performance.now() - mount.current
    setElapsed(e)
    setLastPoll(now().getTime() + e)
  }

  const opsNow = now().getTime() + elapsed
  const pollAge = Math.max(0, (opsNow - lastPoll) / 1000)
  const sinceDemo = elapsed / 1000

  const cells = useMemo<Cell[]>(() => {
    const t0 = now().getTime()
    const within = (min: number) => d.authEvents.filter((e) => t0 - new Date(e.at).getTime() <= min * 60_000)
    const last15 = within(15)
    const last60 = within(60)
    const rejects60 = last60.filter((e) => e.result === 'reject').length
    const radiusUnconfigured = current.health.radius === 'unconfigured' || d.radiusClients.length === 0
    const okNas = d.radiusClients.filter((n) => n.status === 'ok')
    const badNas = d.radiusClients.filter((n) => n.status !== 'ok')
    const issuing = d.cas.find((c) => c.role === 'issuing')
    const crl = issuing?.crl
    const ocspOn = issuing?.ocsp?.enabled
    const snapshotAge = current.health.authzSnapshotAgeSeconds
    const maxSnap = d.defaults.maxSnapshotAgeSeconds
    const syncAge = current.health.lastDirectorySync ? (t0 - new Date(current.health.lastDirectorySync).getTime()) / 1000 : null
    const rejectRate = last60.length ? rejects60 / last60.length : null
    const lastReq = d.radiusClients.reduce<number | null>((m, n) => (n.lastRequestAt ? Math.max(m ?? 0, new Date(n.lastRequestAt).getTime()) : m), null)
    const failingSync = d.audit.find((a) => a.action === 'directory.sync.failed')
    const silence = (iso: string | null) => (iso ? (t0 - new Date(iso).getTime()) / 1000 + sinceDemo : null)

    const out: Cell[] = [
      {
        id: 'radius',
        name: 'RADIUS',
        tone: radiusUnconfigured ? 'neutral' : healthTone[current.health.radius],
        value: radiusUnconfigured ? 'Not set up' : (last15.length / 15).toFixed(1),
        unit: radiusUnconfigured ? 'no controllers' : `req/min · ${last15.length} in 15 min`,
        pollAge,
        source: { freshness: 'none', age: lastReq === null ? null : (t0 - lastReq) / 1000 },
        details: [
          ['Server', d.radiusSettings?.serverHostname ?? '—'],
          ['State', healthLabel[current.health.radius]],
          ['Last request', lastReq ? `${clockUTC(new Date(lastReq))} UTC` : 'None received'],
          ['Window', 'Requests in the last 15 minutes'],
        ],
        screen: 'radius',
        screenLabel: 'RADIUS server',
        section: 'server',
        unconfigured: radiusUnconfigured,
      },
      {
        id: 'reject',
        name: 'Reject rate',
        tone: rejectRate === null ? 'neutral' : rejectRate > 0.25 ? 'crit' : rejectRate > 0.1 ? 'warn' : 'ok',
        value: rejectRate === null ? '—' : `${(rejectRate * 100).toFixed(1)}%`,
        unit: rejectRate === null ? 'no requests in 60 min' : `${rejects60} of ${last60.length} in 60 min`,
        pollAge,
        source: { freshness: 'none', age: null },
        details: [
          ['Window', 'Last 60 minutes'],
          ['Thresholds', 'Amber above 10 %, red above 25 %'],
        ],
        screen: 'dashboard',
        screenLabel: 'Failure reasons',
        section: 'failures',
        unconfigured: rejectRate === null && radiusUnconfigured,
      },
      {
        id: 'controllers',
        name: 'Controllers',
        tone: d.radiusClients.length === 0 ? 'neutral' : worstTone(d.radiusClients.map((n) => healthTone[n.status])),
        value: d.radiusClients.length ? `${okNas.length}/${d.radiusClients.length}` : 'None',
        unit: d.radiusClients.length ? (badNas.length ? `up · ${badNas[0].site} silent ${formatAge(silence(badNas[0].lastRequestAt))}` : 'up') : 'registered',
        pollAge,
        source: badNas.length
          ? { freshness: badNas.some((n) => classify(silence(n.lastRequestAt), CONTROLLER_BUDGET) === 'stale') ? 'aging' : 'fresh', age: silence(badNas[0].lastRequestAt), bar: okNas.length / d.radiusClients.length, rule: 'Amber while any controller is silent for more than 15 min' }
          : { freshness: 'none', age: null },
        details: d.radiusClients.length
          ? d.radiusClients.map((n) => [n.name, `${healthLabel[n.status]} · last request ${n.lastRequestAt ? formatAge((t0 - new Date(n.lastRequestAt).getTime()) / 1000 + sinceDemo) + ' ago' : 'never'}`] as [string, ReactNode])
          : [['Controllers', 'None registered yet']],
        screen: 'radius',
        screenLabel: 'Wireless controllers',
        section: 'controllers',
        unconfigured: d.radiusClients.length === 0,
      },
      {
        id: 'crl',
        name: 'PKI · CRL',
        tone: crl?.nextUpdate ? healthTone[current.health.pki] : 'neutral',
        value: crl?.nextUpdate ? formatAge((new Date(crl.nextUpdate).getTime() - opsNow) / 1000) : '—',
        unit: crl?.nextUpdate ? `to next CRL · OCSP ${ocspOn ? 'on' : 'off'}` : 'no CRL yet',
        pollAge,
        source: {
          freshness: crl?.nextUpdate ? (new Date(crl.nextUpdate).getTime() <= opsNow ? 'stale' : new Date(crl.nextUpdate).getTime() - opsNow < 2 * 3600_000 ? 'aging' : 'fresh') : 'none',
          age: crl?.lastIssued ? (opsNow - new Date(crl.lastIssued).getTime()) / 1000 : null,
          bar: crl?.lastIssued && crl.nextUpdate ? Math.max(0, Math.min(1, (new Date(crl.nextUpdate).getTime() - opsNow) / (new Date(crl.nextUpdate).getTime() - new Date(crl.lastIssued).getTime()))) : undefined,
          rule: 'Amber within 2 h of the next CRL, stale once it passes',
        },
        details: [
          ['Issuing CA', issuing?.commonName ?? '—'],
          ['CRL number', crl ? `#${crl.number}` : '—'],
          ['Last issued', crl?.lastIssued ? `${formatAge((opsNow - new Date(crl.lastIssued).getTime()) / 1000)} ago` : '—'],
          ['OCSP', ocspOn ? 'Responder enabled' : 'Not enabled'],
        ],
        screen: 'certificates',
        screenLabel: 'Certificate authorities',
        section: 'authorities',
      },
      {
        id: 'directory',
        name: 'Directory',
        tone: healthTone[current.health.directory],
        value: syncAge === null ? 'Not connected' : formatAge(syncAge + sinceDemo),
        unit: syncAge === null ? 'AD not configured' : current.health.directory === 'ok' ? 'since AD sync' : 'since last good sync',
        pollAge,
        source: syncAge === null ? { freshness: 'none', age: null } : { freshness: classify(syncAge + sinceDemo, DIRECTORY_BUDGET), age: syncAge + sinceDemo, bar: remaining(syncAge + sinceDemo, DIRECTORY_BUDGET), rule: 'Amber after 30 min without a sync, stale after 2 h' },
        details: [
          ['Domain', current.domain],
          ['State', healthLabel[current.health.directory]],
          ['Last good sync', current.health.lastDirectorySync ? `${current.health.lastDirectorySync.slice(11, 16)} UTC` : 'Never'],
          ...(failingSync && current.health.directory !== 'ok' ? ([['Last error', failingSync.detail]] as Array<[string, ReactNode]>) : []),
        ],
        screen: 'users',
        screenLabel: 'Directory users',
        unconfigured: syncAge === null,
      },
      {
        id: 'snapshot',
        name: 'Authz snapshot',
        tone: snapshotAge === null ? 'neutral' : snapshotAge > maxSnap ? 'crit' : 'ok',
        value: snapshotAge === null ? '—' : formatAge(snapshotAge + sinceDemo),
        unit: snapshotAge === null ? 'RADIUS not set up' : `old · fails safe at ${formatAge(maxSnap)}`,
        pollAge,
        source:
          snapshotAge === null
            ? { freshness: 'none', age: null }
            : { freshness: classify(snapshotAge + sinceDemo, snapshotBudget(maxSnap)), age: snapshotAge + sinceDemo, bar: remaining(snapshotAge + sinceDemo, snapshotBudget(maxSnap)), rule: `Amber after ${formatAge(snapshotBudget(maxSnap).warnAfter)}, stale at ${formatAge(maxSnap)}` },
        details: [
          ['What it is', 'The authorization data RADIUS loads: users, groups, rules, revoked serials'],
          ['Fail-safe', `RADIUS denies everyone when older than ${formatAge(maxSnap)}`],
        ],
        screen: 'policies',
        screenLabel: 'Access rules',
        section: 'rules',
        unconfigured: snapshotAge === null,
      },
    ]
    return out
  }, [d, current, pollAge, opsNow, sinceDemo])

  const pollBudget: FreshnessBudget = { warnAfter: intervalSec * 2, staleAfter: intervalSec * 4 }
  const isLive = !paused && !reduced && visible
  const staleCount = cells.filter((c) => cellFreshness(c, pollBudget) === 'stale').length

  return (
    <div className="b-strip" role="region" aria-label={`Live service status for ${current.name}`}>
      <div className="b-strip-cells">
        {cells.map((c) => (
          <StripCell key={c.id} cell={c} pollBudget={pollBudget} reduced={reduced} onOpen={() => go(c.screen, { section: c.section })} />
        ))}
      </div>
      <div className="flex shrink-0 items-center gap-2 border-l border-[var(--b-line)] px-3">
        <div className="flex min-w-[118px] flex-col gap-1">
          <span className="flex items-center gap-1.5 text-[12px] font-medium text-[var(--b-text)]">
            <span className="b-live-dot" data-live={isLive ? 'true' : 'false'} aria-hidden />
            {reduced ? 'Snapshot' : paused ? 'Paused' : 'Live'}
            <span className="b-mono font-normal text-[var(--b-text-2)]">{clockUTC(new Date(opsNow))}</span>
          </span>
          <span className="text-[11.5px] text-[var(--b-text-2)]" aria-live="polite">
            {staleCount ? <span className="b-ink-crit">{staleCount} stale</span> : reduced ? 'Static (reduced motion)' : paused ? 'Values are aging' : `Every ${intervalSec}s`}
          </span>
        </div>
        {!reduced && (
          <div className="hidden w-[68px] xl:block">
            <SelectBox
              size="sm"
              ariaLabel="Update interval"
              value={String(intervalSec)}
              onChange={(v) => setIntervalSec(Number(v))}
              options={[
                { value: '5', label: '5 s' },
                { value: '15', label: '15 s' },
                { value: '60', label: '60 s' },
              ]}
            />
          </div>
        )}
        {reduced ? (
          <IconButton icon={RefreshCw} label="Refresh now" variant="secondary" onClick={refresh} />
        ) : (
          <IconButton
            icon={paused ? Play : Pause}
            label={paused ? 'Resume live updates' : 'Pause live updates'}
            variant="secondary"
            aria-pressed={paused}
            onClick={() => {
              if (paused) refresh()
              setPaused(!paused)
            }}
          />
        )}
      </div>
    </div>
  )
}

function cellFreshness(c: Cell, pollBudget: FreshnessBudget): Freshness {
  if (c.unconfigured) return 'none'
  return worstFresh(classify(c.pollAge, pollBudget), c.source.freshness)
}

function StripCell({ cell: c, pollBudget, reduced, onOpen }: { cell: Cell; pollBudget: FreshnessBudget; reduced: boolean; onOpen: () => void }) {
  const container = usePortal()
  const fresh = cellFreshness(c, pollBudget)
  const pollFresh = classify(c.pollAge, pollBudget)
  const bar = c.unconfigured ? 0 : Math.min(c.source.bar ?? 1, remaining(c.pollAge, pollBudget))
  const Icon = toneIcon[c.tone]
  const ageText = formatAge(c.pollAge)
  return (
    <Popover.Root>
      <Popover.Trigger
        className="b-cell"
        data-fresh={fresh}
        aria-label={`${c.name}: ${c.value} ${c.unit}. ${freshnessLabel[fresh]}, updated ${ageText} ago.`}
      >
        <span className="b-cell-top">
          <Icon className={`b-ink-${c.tone}`} aria-hidden />
          <span className="b-cell-name">{c.name}</span>
          <span className="b-cell-age" data-poll={pollFresh} aria-hidden>
            {ageText}
          </span>
        </span>
        <span className="b-cell-value">
          <strong className={cn(c.unconfigured && '!text-[15px] !font-medium !text-[var(--b-text-2)]')}>{c.value}</strong>
          <span>{c.unit}</span>
        </span>
        <span className="b-fresh" aria-hidden>
          <i style={{ transform: `scaleX(${bar})`, transition: reduced ? 'none' : undefined }} />
        </span>
      </Popover.Trigger>
      <Popover.Portal container={container}>
        <Popover.Content side="bottom" align="start" sideOffset={6} className="b-pop w-[300px] p-3">
          <div className="flex items-center gap-2">
            <Icon className={`size-4 b-ink-${c.tone}`} aria-hidden />
            <p className="text-[13.5px] font-semibold">{c.name}</p>
            <span className={cn('b-badge ml-auto', fresh === 'stale' ? 'b-tone-crit' : fresh === 'aging' ? 'b-tone-warn' : fresh === 'fresh' ? 'b-tone-ok' : 'b-tone-neutral')}>{freshnessLabel[fresh]}</span>
          </div>
          <p className="mt-2 flex items-baseline gap-1.5">
            <span className="b-figure text-[22px]">{c.value}</span>
            <span className="text-[12.5px] text-[var(--b-text-2)]">{c.unit}</span>
          </p>
          <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
            <dt className="text-[var(--b-text-2)]">Updated</dt>
            <dd className="b-num">
              {ageText} ago{pollFresh !== 'fresh' && <span className={pollFresh === 'stale' ? 'b-ink-crit' : 'b-ink-warn'}> · console not refreshing</span>}
            </dd>
            {c.source.age !== null && c.source.freshness !== 'none' && (
              <>
                <dt className="text-[var(--b-text-2)]">Source</dt>
                <dd className="b-num">
                  {formatAge(c.source.age)} old · <span className={c.source.freshness === 'stale' ? 'b-ink-crit' : c.source.freshness === 'aging' ? 'b-ink-warn' : 'b-ink-ok'}>{freshnessLabel[c.source.freshness].toLowerCase()}</span>
                </dd>
              </>
            )}
            {c.details.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-[var(--b-text-2)]">{k}</dt>
                <dd className="min-w-0 break-words">{v}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-2 text-[12px] text-[var(--b-text-2)]">
            Stale after {formatAge(pollBudget.staleAfter)} without an update.{c.source.rule ? ` ${c.source.rule}.` : ''}
          </p>
          <Popover.Close asChild>
            <button type="button" className="b-btn b-btn-secondary b-btn-sm mt-3 w-full" onClick={onOpen}>
              Open {c.screenLabel}
              <ArrowRight aria-hidden />
            </button>
          </Popover.Close>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
