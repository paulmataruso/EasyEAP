// Group Policy autoenrollment (docs/plans/gpo-autoenrollment.md): Windows PCs and users get certificates from EasyEAP
// through Group Policy, as from AD CS. Shapes mirror backend/app/routers/autoenroll.py exactly.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, qs } from './client'
import { qk } from './keys'

export type ReadinessLevel = 'ok' | 'warning' | 'error'
export type ReadinessKey = 'host' | 'directory' | 'pki' | 'keytab' | 'keytab_test' | 'binding' | 'policy' | 'quota'
export interface ReadinessItem { key: ReadinessKey | string; level: ReadinessLevel; message: string }

export interface KeytabInfo {
  principal: string | null
  realm: string | null
  kvno: number
  enctypes: string[]
  problems: string[]
  entries: number
  sha256: string
  uploaded_at: string | null
  /** console: EasyEAP made the account with an administrator's credentials; upload: a keytab file. */
  source?: 'console' | 'upload'
  account_dn?: string
  /** The administrator account that made or reset it (never its password). */
  created_by?: string
  /** The SPN was checked in the whole forest (global catalog), not only this domain. */
  forest_checked?: boolean
}

export interface KeytabTest { ok: boolean; step: string; message: string; at: string; uploaded_at: string }

export type ResponseFormat = 'unsigned' | 'signed' | 'pkcs7'

export interface AutoenrollTemplate {
  id: string
  kind: 'computer' | 'user'
  name: string
  /** The template's name Windows shows (certmgr, event log). */
  common_name: string | null
  oid: string | null
  /** major.minor */
  revision: string
  validity_days: number
  renew_before_days: number
}

export type EventOutcome = 'ok' | 'denied' | 'error'
export interface AutoenrollEvent {
  id: number
  at: string
  /** cep: which templates (policy); ces: issuing (enrollment). */
  service: 'cep' | 'ces'
  caller: string
  kind: 'computer' | 'user' | null
  outcome: EventOutcome
  code: string
  message: string
  template: string | null
  machine: string | null
  certificate_id: string | null
  ip: string | null
}

export interface AutoenrollStatus {
  config: {
    enabled: boolean
    computers: boolean
    users: boolean
    computer_group: { id: string; name: string } | null
    require_channel_binding: boolean
    response_format: ResponseFormat
    service_account: string
    policy_id: string
    keytab: KeytabInfo | null
    keytab_test: KeytabTest | null
    machine_account_quota: number | null
    last_success_at: string | null
    last_error_at: string | null
    last_error: string | null
  }
  /** The host name PCs use; the SPN is HTTP/<host>. */
  host: string
  realm: string | null
  /** The directory connection checks the domain controller's certificate. */
  directory_verified?: boolean
  urls: { policy: string; enrollment: string }
  templates: AutoenrollTemplate[]
  readiness: ReadinessItem[]
  /** No readiness item is an error. */
  ready: boolean
  counts: { computers: number; certificates: number }
  events: AutoenrollEvent[]
}

export interface AutoenrollSettings {
  enabled: boolean
  computers: boolean
  users: boolean
  computer_group_id: string | null
  require_channel_binding: boolean
  response_format: ResponseFormat
  computer_validity_days?: number | null
  computer_renew_before_days?: number | null
  user_validity_days?: number | null
  user_renew_before_days?: number | null
}

const base = (tid: string) => `/api/tenants/${tid}/autoenroll`
const key = (tid: string) => [...qk.tenantScope(tid), 'autoenroll'] as const

export function useAutoenroll(tid: string, enabled = true) {
  return useQuery({ queryKey: key(tid), queryFn: ({ signal }) => api.get<AutoenrollStatus>(base(tid), signal), refetchInterval: 30_000, enabled })
}

function useStatusMutation<V>(tid: string, fn: (v: V) => Promise<AutoenrollStatus>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (data) => {
      qc.setQueryData(key(tid), data)
      void qc.invalidateQueries({ queryKey: [...key(tid), 'events'] })
    },
  })
}

export const useSaveAutoenroll = (tid: string) => useStatusMutation(tid, (body: AutoenrollSettings) => api.put<AutoenrollStatus>(base(tid), body))
export const useUploadKeytab = (tid: string) => useStatusMutation(tid, (keytab_b64: string) => api.put<AutoenrollStatus>(`${base(tid)}/keytab`, { keytab_b64 }))
export const useDeleteKeytab = (tid: string) => useStatusMutation(tid, () => api.del<AutoenrollStatus>(`${base(tid)}/keytab`))
export const useTestKeytab = (tid: string) => useStatusMutation(tid, () => api.post<AutoenrollStatus>(`${base(tid)}/keytab/test`))

export interface ServiceAccountInput { username: string; password: string; container?: string; accept_unverified?: boolean }
export type ServiceAccountResult = AutoenrollStatus & { service_account: { dn: string; created: boolean; forest_checked: boolean } }
/** Creates (or resets) the service account with an administrator's credentials. They're sent once and not kept:
 * the mutation keeps no variables in the cache (gcTime 0) and the dialog clears its fields. */
export function useCreateServiceAccount(tid: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: ServiceAccountInput) => api.post<ServiceAccountResult>(`${base(tid)}/service-account`, body),
    gcTime: 0,
    onSuccess: (data) => {
      qc.setQueryData(key(tid), data)
      void qc.invalidateQueries({ queryKey: [...key(tid), 'events'] })
    },
  })
}
export const useReenroll = (tid: string) => useStatusMutation(tid, (kind: 'computer' | 'user') => api.post<AutoenrollStatus>(`${base(tid)}/reenroll`, { kind }))

export const fetchScript = (tid: string, flavor: 'windows' | 'samba') =>
  api.get<{ filename: string; content: string }>(`${base(tid)}/script${qs({ flavor })}`)

export function useAutoenrollEvents(tid: string, outcome: '' | EventOutcome) {
  return useQuery({
    queryKey: [...key(tid), 'events', outcome] as const,
    queryFn: ({ signal }) => api.get<{ events: AutoenrollEvent[]; more: boolean }>(`${base(tid)}/events${qs({ outcome, limit: 200 })}`, signal),
    refetchInterval: 30_000,
  })
}

/** Plain words for the request log's codes (backend: Denied codes in app/autoenroll/service.py, KerberosError codes). */
export const codeLabels: Record<string, string> = {
  ntlm: 'NTLM, not Kerberos',
  invalid: 'Kerberos refused',
  keytab: 'Keytab problem',
  realm: 'Other realm',
  not_kerberos: 'Not Kerberos',
  binding: 'Channel binding',
  no_directory: 'No directory',
  directory: 'AD unreachable',
  not_computer: 'Not a computer in AD',
  not_workstation: 'Not a workstation',
  account_state: 'Account disabled',
  not_in_group: 'Not in the group',
  unknown_user: 'User not synced',
  request_type: 'Unsupported request',
  bad_request: 'Unreadable request',
  key: 'Key refused',
  template: 'Template not allowed',
  no_dns_name: 'No DNS name',
  dns_name: 'DNS name not its own',
  name_taken: 'Name taken locally',
  limit: 'Too many today',
  ca_expiring: 'CA expiring',
  pki: 'CA not ready',
  internal: 'EasyEAP error',
  none: 'Nothing offered',
}
