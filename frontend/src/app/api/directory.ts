// Directory (Active Directory over LDAPS): connection, test, sync, groups. Shapes match backend/app/routers/directory.py.
import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { qk } from './keys'

export type Transport = 'ldaps' | 'starttls' | 'plain'

export interface SyncStats {
  users: number
  groups: number
  created: number
  updated: number
  deleted: number
  decisions: number
  duration_ms: number
}

export interface DirectoryConfig {
  enabled: boolean
  hosts: string[]
  port: number
  transport: Transport
  verify_certificate: boolean
  has_ca_bundle: boolean
  domain: string
  base_dn: string
  user_search_base: string
  group_search_base: string
  user_filter: string
  group_filter: string
  bind_dn: string
  /** The bind password is write-only; this only says whether one is stored. */
  password_set: boolean
  sync_interval_minutes: number
  last_sync_at: string | null
  last_sync_status: 'ok' | 'failed' | null
  last_sync_error: string | null
  last_sync_stats: SyncStats | null
}

export interface DirectoryResponse { config: DirectoryConfig | null; group_count: number }

export interface DirectoryBody {
  hosts: string[]
  port: number
  transport: Transport
  verify_certificate: boolean
  /** null keeps the saved bundle. */
  ca_bundle_pem: string | null
  clear_ca_bundle: boolean
  domain: string
  base_dn: string
  user_search_base: string
  group_search_base: string
  user_filter: string
  group_filter: string
  bind_dn: string
  /** null keeps the saved password. */
  bind_password: string | null
  sync_interval_minutes: number
  enabled: boolean
}

export interface TestStep { step: 'connect' | 'search' | string; ok: boolean; message: string; hint?: string; detail?: string }
export interface TestResult {
  ok: boolean
  steps: TestStep[]
  /** The directory's own base DN and domain, read from its RootDSE once signed in. */
  discovered?: { base_dn: string; domain: string } | null
  /** The entered base DN isn't the directory's base DN or below it. */
  base_dn_outside?: boolean
}

/** Connection details for reading the RootDSE. No base DN needed; the service account is optional. */
export type DiscoverBody = Pick<DirectoryBody, 'hosts' | 'port' | 'transport' | 'verify_certificate' | 'ca_bundle_pem' | 'clear_ca_bundle' | 'bind_dn' | 'bind_password'>
export type DiscoverResult =
  | { ok: true; base_dn: string; domain: string; dc_hostname: string; signed_in: boolean }
  | { ok: false; message: string; hint?: string; detail?: string }

export type SyncResult = ({ ok: true } & SyncStats) | { ok: false; error: string } | { skipped: true }

export interface DirectoryGroup { id: string; name: string; dn: string; source: 'ad' | 'local' | string; members: number }

const base = (tid: string) => `/api/tenants/${tid}/directory`

export function useDirectory(tid: string) {
  return useQuery({ queryKey: qk.directory(tid), queryFn: ({ signal }) => api.get<DirectoryResponse>(base(tid), signal) })
}

/** GET /directory/groups (no filter): up to 500 groups that still exist, with member counts. */
export function useDirectoryGroups(tid: string, enabled = true) {
  return useQuery({
    queryKey: qk.directoryGroups(tid),
    queryFn: ({ signal }) => api.get<{ groups: DirectoryGroup[] }>(`${base(tid)}/groups`, signal),
    enabled,
    staleTime: 60_000,
  })
}

export const GROUP_LIST_LIMIT = 500

export const directoryApi = {
  save: (tid: string, body: DirectoryBody) => api.put<{ config: DirectoryConfig }>(base(tid), body),
  test: (tid: string, body: DirectoryBody) => api.post<TestResult>(`${base(tid)}/test`, body),
  discover: (tid: string, body: DiscoverBody) => api.post<DiscoverResult>(`${base(tid)}/discover`, body),
  sync: (tid: string, force = false) => api.post<SyncResult>(`${base(tid)}/sync`, { force }),
  createLocalGroup: (tid: string, name: string) => api.post<DirectoryGroup>(`${base(tid)}/groups`, { name }),
  searchGroups: (tid: string, q: string, signal?: AbortSignal) => api.get<{ groups: DirectoryGroup[] }>(`${base(tid)}/groups?q=${encodeURIComponent(q)}`, signal),
}

/** GET /pki carries the server's lab_mode flag, which decides whether plain LDAP is accepted at all. */
export function useLabMode(tid: string) {
  return useQuery({
    queryKey: qk.pki(tid),
    queryFn: ({ signal }) => api.get<{ lab_mode: boolean }>(`/api/tenants/${tid}/pki`, signal),
    select: (d) => d.lab_mode,
    staleTime: 5 * 60_000,
  })
}
