// Tenant PKI: the root/issuing CA ceremony, CA details, chain, CRL and certificate templates.
// Shapes mirror backend/app/routers/pki.py. The ceremony response carries the encrypted offline root key exactly once;
// it is never cached (callers hold it in component state until the administrator has downloaded it).
import { useCallback } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './client'
import { useOneTimeCall } from './oneTime'
import { qk } from './keys'

export interface CertificateAuthority {
  id: string
  role: 'root' | 'issuing' | string
  common_name: string
  subject: string
  key_algorithm: string
  serial: string
  fingerprint_sha256: string
  not_before: string
  not_after: string
  offline: boolean
  status: string
  crl_next_update: string | null
}

export interface CertificateTemplate {
  id: string
  name: string
  purpose: 'user' | 'device' | 'radius-server' | string
  key_algorithm: string
  validity_days: number
  renew_before_days: number
  extended_key_usage: string[]
  subject_pattern: string
  san_patterns: string[]
  allow_client_keygen: boolean
  allow_server_keygen: boolean
}

export interface PkiUrls { ca: string; crl: string; ocsp: string; root_ca: string; root_crl: string }

/** The issuing CA's current CRL as OpenBao publishes it (the one RADIUS checks). */
export interface IssuingCrl { available: boolean; this_update: string | null; next_update: string | null; revoked_count: number | null }

export interface PkiOverview { initialized: boolean; authorities: CertificateAuthority[]; templates: CertificateTemplate[]; urls: PkiUrls; lab_mode: boolean; crl: IssuingCrl | null }

export interface CeremonyIn {
  organization: string
  country: string
  state: string
  locality: string
  root_common_name: string
  issuing_common_name: string
  key_algorithm: string
  root_validity_years: number
  issuing_validity_years: number
  root_passphrase: string | null
  keep_root_online: boolean
}

export interface FileOut { filename: string; content_b64: string }
export interface CeremonyOut { root: CertificateAuthority; issuing: CertificateAuthority; root_key_file?: FileOut; root_cert_file?: FileOut }

export interface TemplateIn {
  name: string
  purpose: 'user' | 'device'
  key_algorithm: string
  validity_days: number
  renew_before_days: number
  subject_pattern: string
  san_patterns: string[]
  allow_client_keygen: boolean
  allow_server_keygen: boolean
}

/** Key algorithms the backend accepts (pki/service.py KEY_PARAMS). */
export const KEY_ALGORITHMS = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'] as const
export const keyAlgorithmLabels: Record<string, string> = {
  'ecdsa-p256': 'ECDSA P-256',
  'ecdsa-p384': 'ECDSA P-384',
  'rsa-2048': 'RSA 2048',
  'rsa-3072': 'RSA 3072',
  'rsa-4096': 'RSA 4096',
}
/** Fields a template pattern may use (routers/pki.py _check_patterns). */
export const TEMPLATE_FIELDS = ['upn', 'username', 'email', 'display_name', 'device', 'domain', 'tenant'] as const
export const purposeLabels: Record<string, string> = { user: 'User', device: 'Device', 'radius-server': 'RADIUS server' }

const base = (tid: string) => `/api/tenants/${tid}/pki`

export function usePki(tid: string, enabled = true) {
  return useQuery({ queryKey: qk.pki(tid), queryFn: ({ signal }) => api.get<PkiOverview>(base(tid), signal), enabled })
}

/** Refresh everything the PKI state feeds: the PKI view, dashboard posture and tenant health. */
export function useInvalidatePki(tid: string) {
  const qc = useQueryClient()
  return () => Promise.all([
    qc.invalidateQueries({ queryKey: qk.pki(tid) }),
    qc.invalidateQueries({ queryKey: qk.dashboard(tid) }),
    qc.invalidateQueries({ queryKey: qk.tenant(tid) }),
    qc.invalidateQueries({ queryKey: qk.tenants() }),
  ])
}

/**
 * Run the ceremony. Deliberately does not refresh the PKI query on success: screens swap the ceremony form for the CA
 * details when `initialized` flips, which would unmount the one-time result. Call useInvalidatePki() when the
 * administrator has downloaded the root key and closed the result.
 */
export function useInitializePki(tid: string) {
  // The request carries the root passphrase and the response the encrypted root key: kept out of the mutation cache.
  const fn = useCallback((body: CeremonyIn) => api.post<CeremonyOut>(`${base(tid)}/initialize`, body), [tid])
  return useOneTimeCall(fn)
}

export function useRotateCrl(tid: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post<{ ok: boolean }>(`${base(tid)}/crl/rotate`),
    onSuccess: () => Promise.all([qc.invalidateQueries({ queryKey: qk.pki(tid) }), qc.invalidateQueries({ queryKey: qk.radius(tid) }), qc.invalidateQueries({ queryKey: ['t', tid, 'audit'] })]),
  })
}

export function useSaveTemplate(tid: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: TemplateIn }) =>
      id ? api.put<CertificateTemplate>(`${base(tid)}/templates/${id}`, body) : api.post<CertificateTemplate>(`${base(tid)}/templates`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.pki(tid) }),
  })
}

export const chainUrl = (tid: string) => `${base(tid)}/chain.pem`

/** Decode a base64 file from the API into a Blob (the ceremony's root key and root certificate). */
export function fileBlob(f: FileOut, type = 'application/x-pem-file'): Blob {
  const bin = atob(f.content_b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new Blob([bytes], { type })
}

/**
 * A strong passphrase generated in this browser for the offline root key: 6 groups of 5 characters from an unambiguous
 * alphabet (~170 bits). It is sent once with the ceremony request and shown once afterwards.
 */
export function generatePassphrase(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
  const out: string[] = []
  const buf = new Uint32Array(30)
  crypto.getRandomValues(buf)
  for (let g = 0; g < 6; g++) {
    let s = ''
    for (let i = 0; i < 5; i++) s += alphabet[buf[g * 5 + i] % alphabet.length]
    out.push(s)
  }
  return out.join('-')
}
