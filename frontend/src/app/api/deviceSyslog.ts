// Device syslog (docs/plans/syslog-full.md): the live view of everything switches and controllers send, and each
// device's syslog panel (how to send, today's counters, what it said, the sessions it logged). Shapes mirror
// backend/app/routers/device_syslog.py and app/switchaudit/devicelog.py.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, qs } from './client'
import { qk } from './keys'
import type { SyslogLine } from './switchAudit'

/** One stored message. A repeat within the minute updates its row (count, last_at) and gives it a new `seq`. */
export interface LiveMessage extends SyslogLine {
  seq: number
  facility: string
  mnemonic: string | null
  /** About access (802.1X, MAB, RADIUS, clients, ports, configuration): kept 14 days; the rest 3. */
  notable: boolean
  /** The address it came from, when that's not the device's RADIUS address. */
  source: string | null
  client_id: string
  device: string | null
}
export interface DeviceStats { day?: string; received?: number; kept?: number; quota?: number; last_at?: string | null; last_tag?: string | null }
export interface Receiver {
  /** This server publishes its syslog port (EASYEAP_SYSLOG_BIND). */
  receiving: boolean
  /** The receiver's heartbeat is recent. */
  listening: boolean
  address: string | null
  port: number | null
  /** UDP 514 is published too (deploy/docker-compose.syslog514.yml): AireOS controllers can send. */
  port_514: boolean
}
export interface LiveDevice { id: string; name: string; vendor: string; address: string; sends: boolean; via_audit: boolean; addresses: string[]; stats: DeviceStats }
/** Platform operators only: syslog from addresses that aren't a device with syslog on, in any tenant. */
export interface UnknownSources {
  at: string | null
  unknown: number
  ambiguous: number
  disabled: number
  kernel_drops: number | null
  top: Array<{ address: string; count: number; why: 'unknown' | 'ambiguous' | 'disabled' | string; sample: string }>
}
export interface LiveResponse {
  messages: LiveMessage[]
  /** Pass as `after` next. null after a `before` page. */
  cursor: number | null
  /** The table was replaced (a restore): start over. */
  reset: boolean
  /** A full page: there's more. */
  more: boolean
  earliest: number | null
  receiver?: Receiver
  devices?: LiveDevice[]
  unknown?: UnknownSources
}

/** A session or wireless client, put together from what the device logged in the last 24 hours. */
export interface LoggedSession {
  port: string | null
  mac: string | null
  state: string
  method: string | null
  vlan: number | null
  ip: string | null
  session_id: string | null
  reason: string | null
  ssid: string | null
  ap: string | null
  first_at: string
  last_at: string
  ended_at: string | null
  ended: string | null
  active: boolean
}
export interface SyslogGuide {
  steps: string[]
  config: string | null
  removal: string | null
  notes: string[]
  /** This server can receive from this device (AireOS needs UDP 514). */
  can_send: boolean
  port: number
}
export interface DeviceSyslogResponse {
  settings: { enabled: boolean; addresses: string[] }
  /** A Cisco switch with the switch audit set up: it sends from its SNMP address without the switch below. */
  via_audit: boolean
  receiver: Receiver
  guide: SyslogGuide
  stats: DeviceStats
  recent: LiveMessage[]
  sessions: LoggedSession[]
}

const base = (tid: string) => `/api/tenants/${tid}`
export const deviceSyslogKey = (tid: string, clientId: string) => [...qk.radius(tid), 'syslog', clientId] as const

export function useDeviceSyslog(tid: string, clientId: string) {
  return useQuery({
    queryKey: deviceSyslogKey(tid, clientId),
    queryFn: ({ signal }) => api.get<DeviceSyslogResponse>(`${base(tid)}/radius/clients/${clientId}/syslog`, signal),
    refetchInterval: 30_000,
  })
}

export function useSetDeviceSyslog(tid: string, clientId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { enabled: boolean; addresses: string[] }) => api.put<{ settings: DeviceSyslogResponse['settings'] }>(`${base(tid)}/radius/clients/${clientId}/syslog`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: deviceSyslogKey(tid, clientId) }),
  })
}

export const liveUrl = (tid: string, p: { after?: number | null; before?: number | null; client_id?: string | null; limit?: number; meta?: boolean }) =>
  `${base(tid)}/syslog/live${qs({ after: p.after ?? undefined, before: p.before ?? undefined, client_id: p.client_id || undefined, limit: p.limit, meta: p.meta ? 'true' : undefined })}`

/** At most this many messages are held; older ones drop off the bottom. */
export const MAX_HELD = 2000
const POLL_MS = 1000
const META_MS = 15_000
const PAGE = 500

/** Newest first. A message already held (same id: a repeat updated its row) moves to the top with its new count. */
export function merge(held: LiveMessage[], incoming: LiveMessage[], max = MAX_HELD): LiveMessage[] {
  if (!incoming.length) return held
  const fresh = new Map<string, LiveMessage>()
  for (const m of incoming) fresh.set(m.id, m)          // oldest first: a later version wins
  const top = [...fresh.values()].sort((a, b) => b.seq - a.seq)
  const rest = held.filter((m) => !fresh.has(m.id))
  return [...top, ...rest].slice(0, max)
}

/** Older messages, below what's held; a message held already (a newer version of it) stays as it is. */
export function appendOlder(held: LiveMessage[], older: LiveMessage[], max = MAX_HELD): LiveMessage[] {
  const ids = new Set(held.map((m) => m.id))
  const below = older.filter((m) => !ids.has(m.id)).sort((a, b) => b.seq - a.seq)
  return [...held, ...below].slice(0, max)
}

export interface LiveState {
  messages: LiveMessage[]
  meta: Pick<LiveResponse, 'receiver' | 'devices' | 'unknown'> | null
  error: unknown
  loading: boolean
  /** The oldest message on the server not yet loaded (for "Load earlier"), or null when there's nothing before. */
  canLoadEarlier: boolean
  loadingEarlier: boolean
  lastPollAt: Date | null
  /** The cursor when the view opened: messages above it arrived while watching. */
  liveFrom: number | null
}

const EMPTY: LiveState = { messages: [], meta: null, error: null, loading: true, canLoadEarlier: false, loadingEarlier: false, lastPollAt: null, liveFrom: null }

/** Polls every second while the page is visible and not paused, from a cursor, so nothing is missed or repeated. */
export function useLiveSyslog(tid: string, clientId: string | null, paused: boolean) {
  const [state, setState] = useState<LiveState>(EMPTY)
  const cursor = useRef<number | null>(null)
  const metaAt = useRef(0)
  const generation = useRef(0)
  const pausedRef = useRef(paused)
  useEffect(() => { pausedRef.current = paused }, [paused])

  useEffect(() => {
    const gen = ++generation.current
    const ctl = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    cursor.current = null
    metaAt.current = 0
    setState(EMPTY)

    const schedule = (ms: number) => { if (gen === generation.current) timer = setTimeout(tick, ms) }
    async function tick() {
      if (gen !== generation.current) return
      const hidden = typeof document !== 'undefined' && document.visibilityState === 'hidden'
      if ((pausedRef.current || hidden) && cursor.current !== null) { schedule(POLL_MS); return }
      const wantMeta = Date.now() - metaAt.current >= META_MS
      try {
        const first = cursor.current === null
        const r = await api.poll<LiveResponse>(liveUrl(tid, { after: first ? null : cursor.current, client_id: clientId, limit: first ? 200 : PAGE, meta: wantMeta }), ctl.signal)
        if (gen !== generation.current) return
        if (wantMeta) metaAt.current = Date.now()
        if (r.reset) {
          cursor.current = null
          setState((s) => ({ ...s, messages: [], canLoadEarlier: false }))
          schedule(0)
          return
        }
        cursor.current = r.cursor
        setState((s) => ({
          ...s,
          messages: first ? [...r.messages].reverse() : merge(s.messages, r.messages),
          meta: wantMeta ? { receiver: r.receiver, devices: r.devices, unknown: r.unknown } : s.meta,
          error: null,
          loading: false,
          canLoadEarlier: first ? r.more : s.canLoadEarlier,
          liveFrom: first ? r.cursor : s.liveFrom,
          lastPollAt: new Date(),
        }))
        schedule(!first && r.more ? 0 : POLL_MS)   // catching up after a pause: keep reading until there's no more
      } catch (e) {
        if ((e as Error).name === 'AbortError' || gen !== generation.current) return
        setState((s) => ({ ...s, error: e, loading: false }))
        schedule(5000)
      }
    }
    void tick()
    return () => { ctl.abort(); if (timer) clearTimeout(timer) }
  }, [tid, clientId])

  const loadEarlier = useCallback(async () => {
    const gen = generation.current
    const oldest = state.messages.reduce<number | null>((min, m) => (min === null || m.seq < min ? m.seq : min), null)
    if (oldest === null) return
    setState((s) => ({ ...s, loadingEarlier: true }))
    try {
      const r = await api.poll<LiveResponse>(liveUrl(tid, { before: oldest, client_id: clientId, limit: PAGE }))
      if (gen !== generation.current) return
      setState((s) => ({ ...s, messages: appendOlder(s.messages, r.messages), canLoadEarlier: r.more && s.messages.length + r.messages.length < MAX_HELD, loadingEarlier: false }))
    } catch (e) {
      if (gen !== generation.current) return
      setState((s) => ({ ...s, error: e, loadingEarlier: false }))
    }
  }, [tid, clientId, state.messages])

  /** Forget what's shown; new messages keep arriving. */
  const clear = useCallback(() => setState((s) => ({ ...s, messages: [], canLoadEarlier: false })), [])

  return { ...state, loadEarlier, clear }
}
