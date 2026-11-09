// Certificate renewal (backend app/routers/renewal.py, docs/plans/cert-renewal.md §15a, §15b): what renews by itself, at
// what share of each certificate's life, the templates' days that follow from it, how the certificates stand, and the
// CA schedule.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './client'
import { qk } from './keys'
import type { ServerCertificateRenewal } from './radius'

export interface RenewalSettings {
  user_certs: boolean
  machine_certs: boolean
  server_cert: boolean
  renew_at_percent: number
  /** Revoke a renewed certificate once its device uses the newer one and the old one has been quiet a week. */
  retire_superseded: boolean
  updated_at: string | null
  updated_by: string | null
}

export interface RenewalTemplate { id: string; name: string; purpose: string; validity_days: number; renew_before_days: number; group_policy: boolean }

export interface CaSchedule {
  issuing: { common_name: string; expires: string; prepare_by: string; switch_by: string; shortens_from: string; shortening: boolean }
  root: { common_name: string; expires: string; crl_next_update: string | null } | null
  longest_validity_days: number
}

export interface RenewalOverview {
  settings: RenewalSettings
  limits: { min_percent: number; max_percent: number; rollback_days: number; silent_days: number; quiet_days: number }
  /** Valid client certificates by how they renew. */
  counts: { auto: number; silent: number; overdue: number; manual: number }
  templates: RenewalTemplate[]
  server_certificate: ServerCertificateRenewal | null
  ca_schedule: CaSchedule | null
}

export type RenewalIn = Pick<RenewalSettings, 'user_certs' | 'machine_certs' | 'server_cert' | 'renew_at_percent' | 'retire_superseded'>

const base = (tid: string) => `/api/tenants/${tid}/renewal`

export function useRenewal(tid: string, enabled = true) {
  return useQuery({ queryKey: qk.renewal(tid), queryFn: ({ signal }) => api.get<RenewalOverview>(base(tid), signal), enabled })
}

export function useSaveRenewal(tid: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: RenewalIn) => api.put<RenewalOverview>(base(tid), body),
    onSuccess: (data) => {
      qc.setQueryData(qk.renewal(tid), data)
      return Promise.all([qc.invalidateQueries({ queryKey: qk.pki(tid) }), qc.invalidateQueries({ queryKey: qk.radius(tid) }),
        qc.invalidateQueries({ queryKey: qk.dashboard(tid) })])
    },
  })
}

/** The day renewal starts for a certificate of `days` validity at `percent`: what the panel's worked example shows. */
export const renewAfterDays = (days: number, percent: number) => Math.floor((days * percent) / 100)
/** A template's renewal period in days, as the backend derives it (renewal.derived_days). */
export const derivedDays = (days: number, percent: number) => Math.max(1, Math.ceil((days * (100 - percent)) / 100))
