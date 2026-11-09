// Device administration (docs/plans/device-admin.md §6): admin logins to switches and controllers over TACACS+ with
// AD or local accounts. Shapes mirror backend/app/routers/device_admin.py exactly.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, qs } from './client'
import { qk } from './keys'

export interface AdminDevice {
  id: string
  name: string
  vendor: string
  address: string
  site: string
  admin_enabled: boolean
  /** EasyEAP generates the configuration for this vendor (Cisco IOS / IOS-XE). */
  supported: boolean
  /** Why not, for other vendors. */
  not_supported: string | null
  key_set_at: string | null
  /** The key before the last rotation still works until then. */
  previous_key_until: string | null
  /** Its port plan says classic IOS. */
  classic: boolean
  /** Offer the "older IOS" (`tacacs-server host`) choice: the release doesn't decide the form (classic IOS or IOS-XE, release unknown). */
  legacy_choice?: boolean
  /** The configuration form EasyEAP generates: named, legacy, nxos, sx, sx-old or cbs220; null without TACACS+. */
  form?: string | null
  /** What the TACACS+ service answers it as: ios, nxos or nxos-n7k. */
  os?: string
  last_login_at: string | null
}

export type AccountStatus = 'active' | 'disabled' | 'expired' | 'locked' | 'no_password'

export interface AdminAccount {
  id: string
  username: string
  display_name: string
  email: string
  role_id: string
  role: string | null
  priv_lvl: number | null
  sites: string[]
  enabled: boolean
  expires_at: string | null
  has_password: boolean
  password_set_at: string | null
  totp_enabled: boolean
  last_login_at: string | null
  locked_until: string | null
  status: AccountStatus
  /** A directory user that a mapping admits has the same name: the local account wins. */
  clashes_with_directory: boolean
  created_at: string | null
  created_by: string
}

export interface AdminRole { id: string; name: string; priv_lvl: number; description: string; builtin: boolean; used: number }

export interface GroupMap {
  id: string
  group_id: string
  group: string | null
  group_deleted: boolean
  role_id: string
  role: string | null
  priv_lvl: number | null
  sites: string[]
  position: number
  /** Synced directory users this mapping admits (first match). */
  admits: number
}

export interface Admitted { id: string; username: string; upn: string | null; display_name: string; role: string | null; priv_lvl: number | null; group: string; sites: string[] }

export interface DeviceAdminOverview {
  devices: AdminDevice[]
  users: AdminAccount[]
  roles: AdminRole[]
  maps: GroupMap[]
  admits: Admitted[]
  directory: {
    connected: boolean; usable: boolean; problem: string | null; domain: string | null
    /** The domain's lockout threshold (0: accounts never lock; null: not read yet), and EasyEAP's cap below it. */
    lockout_threshold: number | null; lockout_window_minutes: number; bind_cap: number
  }
  settings: { local_only_usernames: string[]; retention_days: number }
  /** supported: the RADIUS agent runs the TACACS+ service; in_sync: it has this tenant's latest admin data. */
  agent: { supported: boolean; online: boolean; in_sync: boolean | null; running: boolean | null }
  server: { radius_address: string; radius_address_problem: string | null; port: number }
  radius_configured: boolean
}

export interface ConfigGuide {
  server: string
  port: number
  server_name: string
  preflight: Array<{ command: string; look_for: string }>
  steps: string[]
  config: string
  rollback: string
  key_placeholder: string
  verified: boolean
  notes: string[]
}

export type AdminEventKind = 'login' | 'enable' | 'authz' | 'session' | 'command'
export type AdminEventResult = 'pass' | 'fail' | 'error' | 'start' | 'stop' | 'update'

export interface AdminEvent {
  id: number
  at: string
  client_id: string | null
  client: string | null
  nas_ip: string | null
  /** The account's name; names that match no account are logged as "unknown:<hash>". */
  username: string | null
  user_id: string | null
  source: 'local' | 'directory' | null
  kind: AdminEventKind
  result: AdminEventResult
  reason: string | null
  priv_lvl: number | null
  /** Masked: secrets in configuration commands are replaced with *****. */
  command: string | null
  rem_addr: string | null
  port: string | null
  task_id: string | null
  message: string | null
}

export interface AccountIn { username: string; display_name: string; email: string; role_id: string; sites: string[]; expires_at: string | null; password?: string }
export interface AccountUpdate { display_name?: string; email?: string; role_id?: string; sites?: string[]; enabled?: boolean; expires_at?: string | null }

const base = (tid: string) => `/api/tenants/${tid}/device-admin`
/** The device's current TACACS+ key again, to fill its configuration (needs admin:write; audited). */
export const showDeviceKey = (tid: string, id: string) => api.post<{ key: string }>(`${base(tid)}/devices/${id}/key`)

export function useDeviceAdmin(tid: string, enabled = true) {
  return useQuery({
    queryKey: qk.deviceAdmin(tid),
    queryFn: ({ signal }) => api.get<DeviceAdminOverview>(base(tid), signal),
    enabled,
    refetchInterval: 30_000,
  })
}

export function useDeviceConfig(tid: string, deviceId: string | null, legacy: boolean) {
  return useQuery({
    queryKey: [...qk.deviceAdmin(tid), 'config', deviceId, legacy] as const,
    queryFn: ({ signal }) => api.get<ConfigGuide>(`${base(tid)}/devices/${deviceId}/config${qs({ legacy: legacy ? 1 : undefined })}`, signal),
    enabled: !!deviceId,
  })
}

export function useAdminEvents(tid: string, params: { hours: number; kind?: string; result?: string; q?: string; client_id?: string; user_id?: string }) {
  return useQuery({
    queryKey: [...qk.deviceAdmin(tid), 'events', params] as const,
    queryFn: ({ signal }) => api.get<{ items: AdminEvent[]; next_before_id: number | null }>(`${base(tid)}/events${qs({ ...params, page_size: 200 })}`, signal),
    refetchInterval: 15_000,
  })
}

function useInv(tid: string) {
  const qc = useQueryClient()
  // The switch panel and readiness show admin logins too.
  return () => Promise.all([qc.invalidateQueries({ queryKey: qk.deviceAdmin(tid) }), qc.invalidateQueries({ queryKey: qk.radius(tid) })])
}

function useMut<A, R>(tid: string, fn: (a: A) => Promise<R>) {
  const inv = useInv(tid)
  return useMutation({ mutationFn: fn, onSuccess: inv })
}

export const useSetAdminEnabled = (tid: string) =>
  useMut(tid, ({ id, enabled }: { id: string; enabled: boolean }) => api.post<{ device: AdminDevice; key: string | null }>(`${base(tid)}/devices/${id}/enable`, { enabled }))
export const useRotateKey = (tid: string) => useMut(tid, (id: string) => api.post<{ device: AdminDevice; key: string }>(`${base(tid)}/devices/${id}/rotate-key`))
export const useCreateAccount = (tid: string) => useMut(tid, (body: AccountIn) => api.post<{ user: AdminAccount }>(`${base(tid)}/users`, body))
export const useUpdateAccount = (tid: string) =>
  useMut(tid, ({ id, body }: { id: string; body: AccountUpdate }) => api.patch<{ user: AdminAccount }>(`${base(tid)}/users/${id}`, body))
export const useSetAccountPassword = (tid: string) =>
  useMut(tid, ({ id, password }: { id: string; password: string }) => api.post<{ user: AdminAccount }>(`${base(tid)}/users/${id}/password`, { password }))
export const useTotpSetup = (tid: string) => useMut(tid, (id: string) => api.post<{ secret: string; otpauth_uri: string }>(`${base(tid)}/users/${id}/totp/setup`))
export const useTotpConfirm = (tid: string) =>
  useMut(tid, ({ id, code }: { id: string; code: string }) => api.post<{ user: AdminAccount }>(`${base(tid)}/users/${id}/totp/confirm`, { code }))
export const useTotpRemove = (tid: string) =>
  useMut(tid, ({ id, password }: { id: string; password: string }) => api.post<{ user: AdminAccount }>(`${base(tid)}/users/${id}/totp/remove`, { password }))
export const useUnlockAccount = (tid: string) => useMut(tid, (id: string) => api.post<{ user: AdminAccount }>(`${base(tid)}/users/${id}/unlock`))
export const useDeleteAccount = (tid: string) => useMut(tid, (id: string) => api.del<{ ok: boolean }>(`${base(tid)}/users/${id}`))
export const useCreateMap = (tid: string) =>
  useMut(tid, (body: { group_id: string; role_id: string; sites: string[] }) => api.post<{ id: string }>(`${base(tid)}/maps`, body))
export const useUpdateMap = (tid: string) =>
  useMut(tid, ({ id, body }: { id: string; body: { role_id?: string; sites?: string[] } }) => api.patch<{ ok: boolean }>(`${base(tid)}/maps/${id}`, body))
export const useOrderMaps = (tid: string) => useMut(tid, (ids: string[]) => api.post<{ ok: boolean }>(`${base(tid)}/maps/order`, { ids }))
export const useDeleteMap = (tid: string) => useMut(tid, (id: string) => api.del<{ ok: boolean }>(`${base(tid)}/maps/${id}`))
export const useSaveRole = (tid: string) =>
  useMut(tid, ({ id, body }: { id?: string; body: { name: string; priv_lvl: number; description: string } }) =>
    id ? api.put<{ role: AdminRole }>(`${base(tid)}/roles/${id}`, body) : api.post<{ role: AdminRole }>(`${base(tid)}/roles`, body))
export const useDeleteRole = (tid: string) => useMut(tid, (id: string) => api.del<{ ok: boolean }>(`${base(tid)}/roles/${id}`))
export const useSaveAdminSettings = (tid: string) =>
  useMut(tid, (body: { local_only_usernames: string[]; retention_days: number }) => api.put<{ settings: DeviceAdminOverview['settings'] }>(`${base(tid)}/settings`, body))

// ── Pure helpers (tested in deviceAdmin.test.ts) ────────────────────────

export const KEY_PLACEHOLDER = '<tacacs-key>'

/** Mirrors backend app/admin/passwords.py problems(): length, not composition. */
export function passwordProblem(password: string, username: string, totp: boolean): string | null {
  const need = totp ? 8 : 15
  if (password.length < need) return totp ? `Use at least ${need} characters.` : `Use at least ${need} characters (or 8 with an authenticator code).`
  if (password.length > 128) return 'Use at most 128 characters.'
  if (password !== password.trim()) return 'Don’t start or end the password with a space.'
  if (username.length >= 3 && password.toLowerCase().includes(username.toLowerCase())) return 'Don’t include the username.'
  return null
}

/** Mirrors backend USERNAME: lowercase letters, digits, dot, dash, underscore, up to 64. */
export const usernameProblem = (v: string) => (/^[a-z0-9._-]{1,64}$/.test(v) ? null : 'Use lowercase letters, digits, dot, dash and underscore (up to 64).')

export const parseSites = (v: string) => [...new Set(v.split(',').map((s) => s.trim()).filter(Boolean))]

export const statusLabels: Record<AccountStatus, string> = {
  active: 'Active', disabled: 'Disabled', expired: 'Expired', locked: 'Locked', no_password: 'No password yet',
}

/** One sentence on how EasyEAP keeps AD logins under the domain's lockout threshold. */
export function lockoutNote(d: DeviceAdminOverview['directory']): string {
  const cap = `at most ${d.bind_cap === 1 ? 'one wrong password' : `${d.bind_cap} wrong passwords`} per account to AD in ${d.lockout_window_minutes} minutes`
  if (d.lockout_threshold == null) return `EasyEAP hasn’t read the domain’s lockout policy yet (it does at each sync), so it sends ${cap}.`
  if (d.lockout_threshold === 0) return `The domain doesn’t lock accounts; EasyEAP still sends ${cap}.`
  return `The domain locks accounts after ${d.lockout_threshold} failures; EasyEAP sends ${cap}.`
}

/** What each reason code in the admin log means, for people. */
export const reasonLabels: Record<string, string> = {
  admin_bad_password: 'Wrong password',
  admin_bad_code: 'Wrong or reused authenticator code',
  admin_unknown_user: 'No EasyEAP or directory account with this name',
  admin_disabled: 'Account disabled',
  admin_expired: 'Account expired',
  admin_password_expired: 'AD password expired or must be changed',
  admin_ad_locked: 'Locked out in Active Directory',
  admin_locked: 'Locked after too many failures',
  admin_lockout: '10 failures: locked for 15 minutes',
  admin_throttled: 'Too many failures: slowed down',
  admin_wrong_site: 'Not allowed at this device’s site',
  admin_not_permitted: 'Not in a directory group that may log in',
  admin_priv_too_high: 'Enable level above the role’s',
  admin_unsupported_method: 'CHAP or MS-CHAP: set the device to ASCII or PAP',
  admin_local_only: 'Local-only name: the device used its own account',
  admin_enable_no_user: 'Enable without a user: the device’s enable secret decided',
  admin_data_expired: 'EasyEAP’s data on the RADIUS node is out of date: the device used its own accounts',
  admin_directory_down: 'Domain controllers unreachable: the device used its own accounts',
  admin_directory_timeout: 'Domain controllers too slow: the device used its own accounts',
  admin_directory_busy: 'Too many AD logins at once: the device used its own accounts',
  admin_directory_unusable: 'The directory can’t be used for admin logins (it needs LDAPS or StartTLS with verification): the device used its own accounts',
  admin_bad_key: 'The device’s TACACS+ key doesn’t match',
  admin_internal_error: 'Internal error: the device used its own accounts',
  admin_busy: 'EasyEAP couldn’t decide in time: the device used its own accounts',
  admin_not_easyeap_login: 'The session didn’t log in through EasyEAP: the device’s own accounts decide',
  admin_service_not_supported: 'Not a shell (exec) request',
  admin_command_denied: 'Command needs privilege 15',
}

export const kindLabels: Record<AdminEventKind, string> = { login: 'Login', enable: 'Enable', authz: 'Authorization', session: 'Session', command: 'Command' }

/** The configuration with the key (when just shown) and the address (when the server has none) filled in. */
export function fillConfig(text: string, key: string | null, address: string | null): string {
  let out = text
  if (key) out = out.split(KEY_PLACEHOLDER).join(key)
  if (address) out = out.split('<easyeap-radius-ip>').join(address)
  return out
}

export const privLabel = (n: number | null | undefined) => (n == null ? '—' : n === 15 ? '15 (full)' : n === 1 ? '1 (read-only)' : String(n))
