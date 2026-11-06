// Backup and restore (backend/app/routers/backup.py). Everything here is the Super Administrator's (platform:write),
// except the first-run restore, which the one-time setup token authorises instead. Passphrases live only in the
// component state of the dialog that asks for them and are sent once, in the request body.
import { useQuery } from '@tanstack/react-query'
import { api, ApiError, getCsrfToken, maintenanceFrom, messageFrom, notifyMaintenance, notifyUnauthorized } from './client'
import { qk } from './keys'

export interface ProgressStep { key: string; label: string; done: boolean; current: boolean }

export interface BackupRecord {
  id: string
  kind: 'backup'
  status: 'running' | 'done' | 'failed'
  step?: string | null
  steps?: ProgressStep[]
  error?: string | null
  created_at: string
  finished_at?: string | null
  created_by?: string
  file_name?: string
  size?: number
  sha256?: string
  /** The server copy is deleted then: the backup belongs off this host. */
  expires_at?: string
  downloaded_at?: string | null
  downloads?: number
  summary?: { tenants: string[]; counts: Record<string, number> }
  pki_access?: { recovery_keys: boolean; token_expires_at?: string | null; restore_before?: string | null }
}

export interface RestoreState {
  id: string
  status: 'running' | 'rolling_back' | 'done' | 'failed'
  step: string | null
  steps: ProgressStep[]
  error: string | null
  started_at: string | null
  finished_at: string | null
  source: 'console' | 'first-run' | 'cli' | string | null
  backup_created_at: string | null
  warnings: string[]
}

export interface BackupList {
  backups: BackupRecord[]
  /** The PKI container runs the EasyEAP supervisor (needed to snapshot and restore OpenBao). */
  supervisor: boolean
  /** OpenBao recovery keys are on file, so a restored backup can always regain PKI access. */
  recovery_keys: boolean
  last_backup: { at: string; file: string; size: number; downloaded_at?: string; sha256?: string } | null
  last_restore: RestoreState | null
  retention_hours: number
}

export interface UploadedBackup { id: string; size: number; created_at: string | null; product_version: string | null }

export interface BackupInspection {
  created_at: string | null
  created_by: string | null
  product_version: string | null
  source_host: string | null
  tenants: Array<{ name: string; slug: string; status: string }>
  counts: Partial<Record<'tenants' | 'administrators' | 'identities' | 'certificates' | 'active_certificates' | 'radius_clients' | 'audit_events', number>>
  size: number
  restorable: boolean
  problems: string[]
  warnings: string[]
}

export interface MaintenanceStatus { maintenance: RestoreState | null; last_restore: RestoreState | null }

export function useBackups(enabled = true) {
  return useQuery({
    queryKey: qk.backups(),
    queryFn: ({ signal }) => api.get<BackupList>('/api/system/backups', signal),
    enabled,
    refetchInterval: (q) => (q.state.data?.backups.some((b) => b.status === 'running') ? 1500 : false),
  })
}

export function useBackup(id: string | null) {
  return useQuery({
    queryKey: qk.backup(id ?? ''),
    queryFn: ({ signal }) => api.get<BackupRecord>(`/api/system/backups/${id}`, signal),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 1000 : false),
  })
}

export const backupDownloadUrl = (id: string) => `/api/system/backups/${id}/download`

export const backupApi = {
  create: (body: { passphrase: string; password: string; totp?: string }) => api.post<BackupRecord>('/api/system/backups', body),
  remove: (id: string) => api.del<{ ok: true }>(`/api/system/backups/${id}`),
  inspect: (rid: string, passphrase: string) => api.post<BackupInspection>(`/api/system/restore/${rid}/inspect`, { passphrase }),
  start: (rid: string, body: { passphrase: string; password: string; totp?: string; confirm: string }) =>
    api.post<RestoreState>(`/api/system/restore/${rid}/start`, body),
  discard: (rid: string) => api.del<{ ok: true }>(`/api/system/restore/${rid}`),
  maintenance: (signal?: AbortSignal) => api.get<MaintenanceStatus>('/api/system/maintenance', signal),
  setupInspect: (rid: string, body: { setup_token: string; passphrase: string }) => api.post<BackupInspection>(`/api/setup/restore/${rid}/inspect`, body),
  setupStart: (rid: string, body: { setup_token: string; passphrase: string }) => api.post<RestoreState>(`/api/setup/restore/${rid}/start`, body),
}

/**
 * Upload a backup file as the raw request body, with progress. fetch() can't report upload progress, so this is the
 * one XMLHttpRequest in the console. The file is streamed from disk by the browser; nothing is read into memory.
 */
export function uploadBackup(file: File, opts: { setupToken?: string; onProgress?: (sent: number, total: number) => void; signal?: AbortSignal }): Promise<UploadedBackup> {
  const url = opts.setupToken !== undefined ? '/api/setup/restore/upload' : '/api/system/restore/upload'
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', url)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.setRequestHeader('Accept', 'application/json')
    const csrf = getCsrfToken()
    if (csrf) xhr.setRequestHeader('X-CSRF-Token', csrf)
    if (opts.setupToken !== undefined) xhr.setRequestHeader('X-Setup-Token', opts.setupToken.trim())
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) opts.onProgress?.(e.loaded, e.total) }
    xhr.onload = () => {
      let body: unknown = null
      try { body = xhr.responseText ? JSON.parse(xhr.responseText) : null } catch { /* non-JSON (proxy error page) */ }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body as UploadedBackup)
      if (xhr.status === 401) notifyUnauthorized()
      const m = maintenanceFrom(xhr.status, body)
      if (m) notifyMaintenance(m)
      const message = xhr.status === 413 && !body ? 'That file is too large for this server to accept.' : messageFrom(body, xhr.status)
      reject(new ApiError(xhr.status, message, body))
    }
    xhr.onerror = () => reject(new ApiError(0, 'The upload failed: EasyEAP stopped answering. Check your connection and try again.'))
    xhr.onabort = () => reject(new DOMException('Upload cancelled', 'AbortError'))
    opts.signal?.addEventListener('abort', () => xhr.abort(), { once: true })
    xhr.send(file)
  })
}

/** "2026-11-06T10:42:00Z" → whole days from `now` until then (negative when past). */
export const daysLeft = (iso: string | null | undefined, now: Date) =>
  iso ? Math.floor((new Date(iso).getTime() - now.getTime()) / 864e5) : null
