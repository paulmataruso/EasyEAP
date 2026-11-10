// System → Time (backend/app/routers/timesync.py, app/timesync/): the NTP servers the host's chronyd uses, and how well
// the clock is kept. The time service (easyeap-time) applies a change within seconds and reports every 30 seconds.
import { useQuery } from '@tanstack/react-query'
import { api } from './client'

export interface TimeServer {
  address: string
  kind: 'server' | 'pool'
  iburst: boolean
  nts: boolean
  prefer: boolean
}

export interface TimeSettings {
  servers: TimeServer[]
  /** The host's own servers stay configured but aren't used. */
  only_these: boolean
  revision: number
  updated_at: string | null
  updated_by: string | null
}

export type SourceSelect =
  | 'best' | 'combined' | 'not_combined' | 'noselect' | 'unsynchronised' | 'missing_samples' | 'large_distance' | 'jittery'
  | 'waits_for_others' | 'stale' | 'orphan' | 'not_trusted' | 'not_preferred' | 'waits_for_update' | 'falseticker' | string

export interface TimeSource {
  /** null: a name chronyd hasn't resolved yet. */
  address: string | null
  /** As configured, when it differs from the address (a pool's name for each of its servers). */
  name: string | null
  /** One of EasyEAP's servers, or from one of its pools. */
  ours: boolean
  mode: 'server' | 'peer' | 'refclock' | string
  select: SourceSelect | null
  reachable: boolean
  stratum: number | null
  /** Seconds; positive: this clock is ahead of the source. */
  offset: number | null
  error: number | null
  last_rx: number | null
  authenticated: boolean
  nts: boolean
  noselect: boolean
  prefer: boolean
  resolved: boolean
  switched_off_by_easyeap: boolean
}

export interface NtpCheck {
  server: string
  address: string | null
  /** Seconds; positive: this clock is ahead of the server. */
  offset: number | null
  delay: number | null
  stratum: number | null
  error: string | null
}

export interface TimeStatus {
  at: string
  /** chrony: EasyEAP manages the host's chronyd. sntp: no chronyd to manage, the clock is only measured. */
  mode: 'chrony' | 'sntp'
  synchronised: boolean
  /** Seconds; positive: this server's clock is ahead of true time. */
  offset: number | null
  stratum: number | null
  reference: string | null
  reference_time: string | null
  leap: string | null
  rms_offset: number | null
  frequency_ppm: number | null
  root_delay: number | null
  root_dispersion: number | null
  update_interval: number | null
  sources: TimeSource[]
  checks: NtpCheck[]
  /** The settings revision chronyd runs with, and why the latest one couldn't be applied. */
  applied_revision: number | null
  apply_error: string | null
  select_error: string | null
  /** Why EasyEAP can't manage the host's chronyd (with mode sntp). */
  problem: string | null
  kernel_synchronised: boolean | null
}

export interface TimeConfig {
  settings: TimeSettings
  status: TimeStatus | null
  /** The status is older than three minutes (or missing): the time service isn't reporting. */
  stale: boolean
  /** How the clock is doing, as the health check says it (null while stale). */
  assessment: { tone: 'valid' | 'warn' | 'crit'; line: string } | null
  max_servers: number
  /** The API's clock when it answered: compared with the browser's. */
  now: string
  warn_offset: number
  crit_offset: number
}

export const timeKey = ['system-time'] as const

export function useTime(enabled = true) {
  return useQuery({
    queryKey: timeKey,
    queryFn: ({ signal }) => api.get<TimeConfig>('/api/system/time', signal),
    enabled,
    refetchInterval: 15_000,
  })
}

export const timeApi = {
  save: (s: { servers: TimeServer[]; only_these: boolean }) => api.put<{ settings: TimeSettings }>('/api/system/time', s),
  test: (address: string) => api.post<{ address: string; offset: number; delay: number; stratum: number; leap: number }>('/api/system/time/test', { address }),
}

/** "0.3 ms", "12 ms", "1.24 s", "3 min 2 s". */
export function fmtSeconds(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || Number.isNaN(sec)) return '—'
  const a = Math.abs(sec)
  if (a < 0.001) return `${(a * 1e6).toFixed(0)} µs`
  if (a < 0.01) return `${(a * 1e3).toFixed(1)} ms`
  if (a < 1) return `${(a * 1e3).toFixed(0)} ms`
  if (a < 60) return `${a.toFixed(2)} s`
  const m = Math.floor(a / 60)
  return `${m} min ${Math.round(a - m * 60)} s`
}

/** "2.1 ms fast", "40 ms slow", "exact". */
export function fmtOffset(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || Number.isNaN(sec)) return '—'
  if (Math.abs(sec) < 0.000_000_5) return 'exact'
  return `${fmtSeconds(sec)} ${sec > 0 ? 'fast' : 'slow'}`
}
