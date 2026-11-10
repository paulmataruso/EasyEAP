// People: identities (directory and local users), certificates, enrollments, plus the read-only tenant config the
// people screens need (policy rules/VLANs for the decision ledger, PKI authorities/templates, RADIUS CoA settings).
// Field names match backend/app/routers/{identities,certificates,enrollments,policy,pki,radius,directory}.py exactly.
import { keepPreviousData, useQuery, type QueryClient } from '@tanstack/react-query'
import { api, qs, saveBlob } from './client'
import { qk } from './keys'
import type { AccessStatus, EnforcementGap, EnforcementStatus, Outcome, Page } from './types'

// ── Identities ──────────────────────────────────────────────────────────
export type AccountState = 'enabled' | 'disabled' | 'locked' | 'deleted'
export interface GroupRef { id: string; name: string }

export interface Identity {
  id: string
  source: 'ad' | 'local'
  /** computer: a domain PC that enrolled through Group Policy autoenrollment (username NAME$). */
  kind?: 'user' | 'computer'
  dns_name?: string | null
  username: string
  upn: string | null
  email: string | null
  display_name: string
  department: string | null
  title: string | null
  account_state: AccountState
  enrolled: boolean
  last_auth_at: string | null
  last_synced_at: string | null
  groups: GroupRef[]
}

export interface IdentityAccess { status: AccessStatus; vlan_id: number | null; reason_code: string | null }
export interface IdentityListItem extends Identity { certificates: number; active_certificates: number; access: IdentityAccess; waiting: WaitingEnrollment[] }
export interface IdentityPage extends Page<IdentityListItem> { enforceable: boolean; enforcement_missing: EnforcementGap[]; enforcement_status?: EnforcementStatus }

export interface Device { id: string; name: string; platform: string; last_seen_mac: string | null; created_at: string | null }

export type EnrollmentStatus = 'pending' | 'completed' | 'cancelled' | 'expired'
export interface IdentityEnrollment {
  id: string
  device_name: string
  platform: string
  /** windows-setup: one code of a Windows setup file (screens/people/WindowsSetupDialog.tsx). */
  method: 'link' | 'server' | 'windows-setup'
  status: EnrollmentStatus
  /** The certificate it issues: device = the PC's own certificate in a Windows setup. Identity detail only. */
  purpose?: 'user' | 'device' | null
  created_by: string
  created_at: string | null
  expires_at: string
  completed_at: string | null
  /** EasyEAP kept its one-time code, so it can be given again: Show link (a link) or Download setup file (Windows
   *  setup). False for links and setup files made before EasyEAP kept them, and once used, cancelled or expired. */
  link_available?: boolean
  /** A Windows setup file's two codes share it. Identity detail only. */
  device_id?: string | null
}
/** A link, Windows setup file or package still waiting for a device (Users list). A setup file is one entry. */
export interface WaitingEnrollment {
  id: string
  method: IdentityEnrollment['method']
  device_name: string
  platform: string
  expires_at: string
  /** Show link or Download setup file works (see IdentityEnrollment.link_available). */
  available: boolean
  device_id: string | null
}

export interface EventExplanation { title: string; explanation: string; fix: string }
export interface AuthEvent {
  id: string
  at: string
  result: 'accept' | 'reject'
  reason_code: string | null
  explanation: EventExplanation | null
  username: string | null
  identity_id: string | null
  device_id: string | null
  cert_serial: string | null
  cert_issuer: string | null
  calling_station_id: string | null
  called_station_id: string | null
  ssid: string | null
  nas_ip: string | null
  nas_client_id: string | null
  vlan_id: number | null
  rule_id: string | null
  raw_message: string | null
}

export interface IdentityDetail extends Identity {
  object_guid: string | null
  devices: Device[]
  certificates: Certificate[]
  enrollments: IdentityEnrollment[]
  access: { user: Outcome; device: Outcome }
  events: AuthEvent[]
}

export interface IdentityListParams { q?: string; state?: string; group_id?: string; enrolled?: boolean; waiting?: boolean; page?: number; page_size?: number; kind?: 'user' | 'computer' }

export function useIdentities(tid: string, params: IdentityListParams, enabled = true) {
  return useQuery({
    queryKey: qk.identities(tid, params),
    queryFn: ({ signal }) => api.get<IdentityPage>(`/api/tenants/${tid}/identities${qs({ ...params })}`, signal),
    placeholderData: keepPreviousData,
    enabled,
  })
}

export function useIdentity(tid: string, id: string, enabled = true) {
  return useQuery({ queryKey: qk.identity(tid, id), queryFn: ({ signal }) => api.get<IdentityDetail>(`/api/tenants/${tid}/identities/${id}`, signal), enabled: enabled && !!id })
}

export interface LocalIdentityIn { username: string; display_name: string; email?: string | null; group_ids: string[] }
export interface IdentityPatch { account_state?: 'enabled' | 'disabled'; group_ids?: string[]; display_name?: string }
export interface DisconnectResult { sessions: number; queued: number; without_coa: number }

export const createIdentity = (tid: string, body: LocalIdentityIn) => api.post<Identity>(`/api/tenants/${tid}/identities`, body)
export const updateIdentity = (tid: string, id: string, body: IdentityPatch) => api.patch<Identity>(`/api/tenants/${tid}/identities/${id}`, body)
export const disconnectIdentity = (tid: string, id: string) => api.post<DisconnectResult>(`/api/tenants/${tid}/identities/${id}/disconnect`)

// ── Certificates ────────────────────────────────────────────────────────
/** Effective status, as the chip shows it. superseded: renewed; still accepted until it expires, needs no renewal. */
export type CertStatusValue = 'active' | 'expiring' | 'superseded' | 'expired' | 'revoked'
export const REVOCATION_REASONS = ['keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'unspecified'] as const
export type RevocationReason = (typeof REVOCATION_REASONS)[number]

export interface Certificate {
  id: string
  serial: string
  common_name: string
  subject: string
  sans: string[]
  purpose: 'user' | 'device' | 'computer' | 'radius-server'
  not_before: string
  not_after: string
  key_algorithm: string
  key_origin: string
  fingerprint_sha256: string
  /** Effective status (revoked, expired, expiring within the tenant's warning window, active). */
  status: CertStatusValue
  /** Stored status: active | revoked | superseded. */
  stored_status: string
  revoked_at: string | null
  revocation_reason: RevocationReason | null
  revoked_by: string | null
  template_id: string | null
  identity: { id: string; username: string; display_name: string } | null
  device: { id: string; name: string; platform: string } | null
  created_at: string | null
  /** Where Windows keeps the key: tpm | software (a PC without a TPM) | null (not reported). */
  key_storage?: 'tpm' | 'software' | null
  /** The certificate this one renewed, and when this one was renewed (renewal by its own key). */
  renewal_of?: string | null
  renewed_at?: string | null
  /** What renews it (docs/plans/cert-renewal.md §15b): null means the user needs a new link. */
  renewer?: Renewer | null
  /** "1": an older renewal task that asks only when due; "2…": checks in daily. */
  renewer_version?: string | null
  /** The renewer's last check-in signed with this certificate's key (v2 renewers). */
  renewal_checked_at?: string | null
  /** When EasyEAP retired it (revoked as superseded: its device uses the newer certificate). */
  retired_at?: string | null
}

export type Renewer = 'windows-setup' | 'windows-helper' | 'linux' | 'gpo' | 'renewed'
/** auto: renews by itself; silent: its renewer stopped checking in while due; overdue: should have renewed; manual: needs the user. */
export type RenewalState = 'auto' | 'silent' | 'overdue' | 'manual'
export interface CertificateSuccessor {
  id: string
  serial: string
  status: CertStatusValue
  not_after: string
  revoked_by: string | null
  /** Revoked by EasyEAP because the device never received it and asked again (a lost renewal answer). */
  replaced?: boolean
  /** A renewal of this certificate (same template and device), not a certificate that replaced it. */
  renewal?: boolean
}

export interface CertificatePage extends Page<Certificate> { counts: Record<CertStatusValue, number>; warning_days: number }
export interface CertificateDecision extends Outcome { computed_at: string }
export interface CertificateDetail extends Certificate {
  decision: CertificateDecision | null
  issuer: string | null
  /** Client certificates only: when renewal starts, whether it's on for this kind, and how it stands (null unless active). */
  renewal?: { renew_from: string; enabled: boolean; state: RenewalState | null } | null
  /** Certificates that superseded this one, newest first (including ones revoked since). */
  successors?: CertificateSuccessor[]
  /** What revoking this one revokes too: the unrevoked chain renewed from it. */
  revoke_also?: { id: string; serial: string }[]
}

export interface CertificateListParams { q?: string; status?: string; purpose?: string; identity_id?: string; page?: number; page_size?: number }

export function useCertificates(tid: string, params: CertificateListParams) {
  return useQuery({
    queryKey: qk.certificates(tid, params),
    queryFn: ({ signal }) => api.get<CertificatePage>(`/api/tenants/${tid}/certificates${qs({ ...params })}`, signal),
    placeholderData: keepPreviousData,
  })
}

export function useCertificate(tid: string, id: string | null | undefined) {
  return useQuery({
    queryKey: qk.certificate(tid, id ?? ''),
    queryFn: ({ signal }) => api.get<CertificateDetail>(`/api/tenants/${tid}/certificates/${id}`, signal),
    enabled: !!id,
  })
}

export interface RevokeResult { ok: boolean; disconnect: DisconnectResult; session_timeout_seconds: number | null; note: string; successors?: string[] }
/** `successors`: also revoke the certificates renewed from this one (the backend's default). */
export const revokeCertificate = (tid: string, id: string, reason: RevocationReason, disconnect: boolean, successors = true) =>
  api.post<RevokeResult>(`/api/tenants/${tid}/certificates/${id}/revoke`, { reason, disconnect, successors })
export const fetchPem = (tid: string, id: string) => api.get<string>(`/api/tenants/${tid}/certificates/${id}/pem`)

/** Authentications that presented this certificate (events search matches the serial). */
export function useCertificateEvents(tid: string, serial: string | undefined, enabled: boolean) {
  const params = { q: serial ?? '', hours: 24 * 30, page_size: 10 }
  return useQuery({
    queryKey: qk.events(tid, params),
    queryFn: ({ signal }) => api.get<{ items: AuthEvent[] }>(`/api/tenants/${tid}/events${qs(params)}`, signal),
    enabled: enabled && !!serial,
  })
}

// ── Enrollments ─────────────────────────────────────────────────────────
export type Platform = 'windows' | 'macos' | 'ios' | 'android' | 'linux'
export interface EnrollIn {
  identity_id: string
  template_id?: string | null
  device_name: string
  platform: Platform
  method: 'link' | 'server'
  legacy_p12?: boolean
  ttl_hours?: number
  /** Certificate this link renews (link method only); it is marked superseded when the device enrolls. */
  renewal_of?: string | null
}
export interface EnrollmentOut extends IdentityEnrollment {
  identity_id: string
  identity: { display_name: string; username: string } | null
  certificate_id: string | null
}
export type EnrollResult =
  | { enrollment: EnrollmentOut; link: string }
  | { enrollment: EnrollmentOut; download_url: string; pkcs12_password: string; note: string }

/** Called directly, not through useMutation, so the one-time link and PKCS#12 password never enter a query cache. */
export const createEnrollment = (tid: string, body: EnrollIn) => api.post<EnrollResult>(`/api/tenants/${tid}/enrollments`, body)
/** The Windows 11 setup for one user (routers/enrollments.py windows_setup): a .cmd file with one-time codes. */
export interface WindowsSetupIn {
  identity_id: string
  user_certificate: boolean
  computer_certificate: boolean
  wifi: boolean
  wired: boolean
  shared_pc: boolean
  ttl_hours: number
}
export interface WindowsSetupResult {
  filename: string
  content: string
  /** The program users double-click, carrying the same file (null when the server was built without it). */
  exe_filename: string | null
  exe_b64: string | null
  expires_at: string
  sign_in_mode: 'user' | 'machine' | 'machineOrUser'
  enrollments: unknown[]
}

/** Saves a Windows setup file to the browser's downloads: the .exe when the server made one, otherwise (or with
 *  `asCmd`) the .cmd, which does the same and can be read first. Returns the file name saved. */
export function saveSetupFile(res: WindowsSetupResult, asCmd = false): string {
  if (res.exe_b64 && res.exe_filename && !asCmd) {
    const bin = atob(res.exe_b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    saveBlob(new Blob([bytes], { type: 'application/vnd.microsoft.portable-executable' }), res.exe_filename)
    return res.exe_filename
  }
  saveBlob(new Blob([res.content], { type: 'application/octet-stream' }), res.filename)
  return res.filename
}
export const createWindowsSetup = (tid: string, body: WindowsSetupIn) => api.post<WindowsSetupResult>(`/api/tenants/${tid}/enrollments/windows-setup`, body)
export const cancelEnrollment = (tid: string, id: string) => api.post<{ ok: boolean }>(`/api/tenants/${tid}/enrollments/${id}/cancel`)
/** A pending enrollment's link, again (recorded in the audit log). */
export const showEnrollmentLink = (tid: string, id: string) => api.post<{ link: string; expires_at: string }>(`/api/tenants/${tid}/enrollments/${id}/link`)
/** A waiting Windows setup file again, with the same one-time codes (recorded in the audit log). Not cached. */
export const downloadSetupAgain = (tid: string, id: string) => api.post<WindowsSetupResult>(`/api/tenants/${tid}/enrollments/${id}/windows-setup`)
/** A waiting Linux link's setup script, the one its page gives (recorded in the audit log). Not cached. */
export const downloadLinuxScript = (tid: string, id: string) => api.post<{ filename: string; content: string; expires_at: string }>(`/api/tenants/${tid}/enrollments/${id}/linux-script`)
/** Takes the one-time PKCS#12 package (consumes it). */
export const downloadPackage = (tid: string, id: string) => api.postRaw(`/api/tenants/${tid}/enrollments/${id}/download`)

// ── Tenant configuration read by these screens (raw responses, shared keys) ──
export interface PolicyVlan { id: string; vlan_id: number; name: string; description: string; color: string; certificates: number }
export interface PolicyRule {
  id: string
  name: string
  description: string
  priority: number
  enabled: boolean
  action: 'allow' | 'deny'
  vlan_ref: string | null
  purposes: string[]
  extra_attributes: Array<{ name: string; value: string }>
  groups: Array<{ id: string; name: string; deleted: boolean }>
}
export interface PolicySettings { default_action: 'allow' | 'deny'; default_vlan_ref: string | null; max_snapshot_age_seconds: number; allow_server_keygen: boolean; expiry_warning_days: number }
export interface PolicyResponse { vlans: PolicyVlan[]; rules: PolicyRule[]; settings: PolicySettings; allowed_extra_attributes: string[]; revision: string }

export function usePolicy(tid: string, enabled = true) {
  return useQuery({ queryKey: qk.policy(tid), queryFn: ({ signal }) => api.get<PolicyResponse>(`/api/tenants/${tid}/policy`, signal), staleTime: 60_000, enabled })
}

export interface Authority {
  id: string
  role: 'root' | 'issuing'
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
export interface Template {
  id: string
  name: string
  purpose: 'user' | 'device' | 'computer' | 'radius-server'
  key_algorithm: string
  validity_days: number
  renew_before_days: number
  extended_key_usage: string[]
  subject_pattern: string
  san_patterns: string[]
  allow_client_keygen: boolean
  allow_server_keygen: boolean
}
export interface PkiOverview { initialized: boolean; authorities: Authority[]; templates: Template[]; urls: Record<string, string>; lab_mode: boolean }

export function usePki(tid: string, enabled = true) {
  return useQuery({ queryKey: qk.pki(tid), queryFn: ({ signal }) => api.get<PkiOverview>(`/api/tenants/${tid}/pki`, signal), staleTime: 60_000, enabled })
}

export interface RadiusClientLite { id: string; name: string; vendor: string; address: string; site: string; coa_enabled: boolean; coa_port: number }
export interface RadiusOverview {
  settings: { session_timeout_seconds: number | null; ssid: string; server_hostname: string; wired_enabled?: boolean } | null
  clients: RadiusClientLite[]
}

export function useRadius(tid: string, enabled = true) {
  return useQuery({ queryKey: qk.radius(tid), queryFn: ({ signal }) => api.get<RadiusOverview>(`/api/tenants/${tid}/radius`, signal), staleTime: 60_000, enabled })
}

export interface DirectoryGroup { id: string; name: string; dn: string | null; source: string; members: number }
export function useDirectoryGroups(tid: string, enabled = true) {
  return useQuery({
    queryKey: qk.directoryGroups(tid),
    queryFn: ({ signal }) => api.get<{ groups: DirectoryGroup[] }>(`/api/tenants/${tid}/directory/groups`, signal),
    staleTime: 60_000,
    enabled,
  })
}

export interface DirectoryConfigLite { config: { enabled: boolean; sync_interval_minutes: number; last_sync_at: string | null; last_sync_status: string | null } | null; group_count: number }
export function useDirectory(tid: string, enabled = true) {
  return useQuery({ queryKey: qk.directory(tid), queryFn: ({ signal }) => api.get<DirectoryConfigLite>(`/api/tenants/${tid}/directory`, signal), staleTime: 60_000, enabled })
}

// ── Invalidation ────────────────────────────────────────────────────────
/**
 * After any people mutation: user and certificate lists and records, enrollments, search, the dashboard (queue and
 * counts), the tenant health and the policy (VLAN usage counts). Only queries on screen refetch.
 */
export function invalidatePeople(qc: QueryClient, tid: string) {
  const keys: ReadonlyArray<readonly unknown[]> = [
    ['t', tid, 'identities'],
    ['t', tid, 'identity'],
    ['t', tid, 'certificates'],
    ['t', tid, 'certificate'],
    ['t', tid, 'enrollments'],
    ['t', tid, 'search'],
    qk.dashboard(tid),
    qk.tenant(tid),
    qk.policy(tid),
  ]
  return Promise.all(keys.map((queryKey) => qc.invalidateQueries({ queryKey })))
}
