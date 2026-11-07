// System log and remote syslog (backend/app/routers/logs.py, app/logs/syslog.py).
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { api, qs } from './client'

export type LogLevel = 'debug' | 'info' | 'warning' | 'error' | 'critical'
export type LogSource = 'api' | 'worker' | 'collector' | 'radius-agent' | 'freeradius'

export interface SystemLogEntry { id: number; at: string; level: LogLevel; source: LogSource; logger: string; message: string }
export interface SystemLogPage { logs: SystemLogEntry[]; next_before: number | null; sources: LogSource[] }

export const sourceLabels: Record<LogSource, string> = { api: 'API', worker: 'Worker', collector: 'Switch collector', 'radius-agent': 'RADIUS agent', freeradius: 'FreeRADIUS' }

export function useSystemLogs(filters: { level: LogLevel; source: string; q: string }) {
  return useInfiniteQuery({
    queryKey: ['system-logs', filters],
    queryFn: ({ pageParam, signal }) =>
      api.get<SystemLogPage>(`/api/system/logs${qs({ level: filters.level, source: filters.source || undefined, q: filters.q || undefined, before: pageParam ?? undefined, limit: 100 })}`, signal),
    initialPageParam: null as number | null,
    getNextPageParam: (last) => last.next_before,
    refetchInterval: 15_000,
  })
}

export type SyslogCategory = 'audit' | 'auth' | 'system'
export type SyslogTransport = 'udp' | 'tcp' | 'tls'

export interface SyslogDestinationInput {
  name: string
  host: string
  port: number
  transport: SyslogTransport
  format: 'rfc5424' | 'rfc3164'
  body: 'text' | 'json'
  framing: 'octet' | 'newline'
  facility: string
  categories: SyslogCategory[]
  system_level: 'info' | 'warning' | 'error'
  ca_pem: string | null
  enabled: boolean
}

export interface SyslogDestination extends SyslogDestinationInput {
  id: string
  created_at: string | null
  status: {
    state: 'delivering' | 'failing' | 'waiting' | 'disabled'
    error: string | null
    error_at: string | null
    last_sent_at: string | null
    sent: number
    /** Messages not yet sent (approximate; computed every ~15 s by the forwarder). */
    backlog: number | null
  }
}

export interface SyslogConfig {
  destinations: SyslogDestination[]
  max_destinations: number
  facilities: string[]
  /** HOSTNAME field in every message. */
  hostname: string
  worker_seen_at: string | null
}

export const syslogKey = ['syslog'] as const

export function useSyslog(enabled = true) {
  return useQuery({
    queryKey: syslogKey,
    queryFn: ({ signal }) => api.get<SyslogConfig>('/api/system/syslog', signal),
    enabled,
    refetchInterval: 15_000,
  })
}

export const syslogApi = {
  add: (d: SyslogDestinationInput) => api.post<SyslogDestination>('/api/system/syslog', d),
  update: (id: string, d: SyslogDestinationInput) => api.put<SyslogDestination>(`/api/system/syslog/${id}`, d),
  remove: (id: string) => api.del<{ ok: true }>(`/api/system/syslog/${id}`),
  test: (d: SyslogDestinationInput) => api.post<{ ok: true; detail: string }>('/api/system/syslog/test', d),
}

export const categoryLabels: Record<SyslogCategory, string> = { audit: 'Audit trail', auth: 'Authentication events', system: 'System log' }
export const transportLabels: Record<SyslogTransport, string> = { tls: 'TLS', tcp: 'TCP', udp: 'UDP' }
export const defaultPort = (t: SyslogTransport) => (t === 'tls' ? 6514 : 514)
