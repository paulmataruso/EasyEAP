// HTTP client for the EasyEAP API. Same-origin only; the session is an HttpOnly cookie and every unsafe request
// carries the per-session CSRF token from /api/auth/me in the X-CSRF-Token header.

export class ApiError extends Error {
  status: number
  detail: unknown
  constructor(status: number, message: string, detail?: unknown) {
    super(message)
    this.status = status
    this.detail = detail
  }
}

let csrfToken: string | null = null
export const setCsrfToken = (t: string | null) => { csrfToken = t }
export const getCsrfToken = () => csrfToken

type Listener = () => void
const unauthorizedListeners = new Set<Listener>()
/** Called when any request returns 401 (session expired or signed out elsewhere). */
export const onUnauthorized = (fn: Listener) => { unauthorizedListeners.add(fn); return () => { unauthorizedListeners.delete(fn) } }
export const notifyUnauthorized = () => unauthorizedListeners.forEach((fn) => fn())

/** A restore is running: the API answers 503 with {"maintenance": {...}} to everything but the progress endpoint. */
const maintenanceListeners = new Set<(state: unknown) => void>()
export const onMaintenance = (fn: (state: unknown) => void) => { maintenanceListeners.add(fn); return () => { maintenanceListeners.delete(fn) } }
export const notifyMaintenance = (state: unknown) => maintenanceListeners.forEach((fn) => fn(state))
/** Whether an error body is the API's "a restore is running" answer. */
export const maintenanceFrom = (status: number, body: unknown): unknown =>
  status === 503 && body && typeof body === 'object' && 'maintenance' in body ? (body as { maintenance: unknown }).maintenance : null

/** FastAPI errors: {"detail": "text"}, {"detail": {"field": …, "message": …}} for one field of a form, or
 * {"detail": [{"msg": …, "loc": […]}]} for validation. */
export function messageFrom(body: unknown, status: number): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const d = (body as { detail: unknown }).detail
    if (typeof d === 'string') return d
    if (d && typeof d === 'object' && !Array.isArray(d) && typeof (d as { message?: unknown }).message === 'string') return (d as { message: string }).message
    if (Array.isArray(d) && d.length) {
      return d.map((e) => {
        const field = Array.isArray(e?.loc) ? e.loc.filter((x: unknown) => x !== 'body').join('.') : ''
        const msg = String(e?.msg ?? 'Invalid value').replace(/^Value error, /, '')
        return field ? `${field}: ${msg}` : msg
      }).join(' ')
    }
  }
  if (status === 0) return 'EasyEAP is unreachable. Check your connection; RADIUS keeps working while the console is offline.'
  if (status >= 500) return 'The server hit an error. Try again; if it persists, check System health.'
  return `Request failed (${status}).`
}

async function request<T>(method: string, path: string, body?: unknown, init?: { signal?: AbortSignal; raw?: boolean; headers?: Record<string, string> }): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...init?.headers }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && method !== 'HEAD' && csrfToken) headers['X-CSRF-Token'] = csrfToken
  let res: Response
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', signal: init?.signal })
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e
    throw new ApiError(0, messageFrom(null, 0))
  }
  if (res.status === 401 && !path.startsWith('/api/auth/login')) notifyUnauthorized()
  if (!res.ok) {
    let parsed: unknown = null
    try { parsed = await res.json() } catch { /* non-JSON error body */ }
    const maintenance = maintenanceFrom(res.status, parsed)
    if (maintenance) notifyMaintenance(maintenance)
    throw new ApiError(res.status, messageFrom(parsed, res.status), parsed)
  }
  if (init?.raw) return res as unknown as T
  if (res.status === 204) return undefined as T
  const type = res.headers.get('content-type') ?? ''
  return (type.includes('application/json') ? await res.json() : await res.text()) as T
}

/** The form field an error is about, when the API names one ({"detail": {"field": …}}). */
export function errorField(e: unknown): string | null {
  const body = e instanceof ApiError ? e.detail : null
  const d = body && typeof body === 'object' && 'detail' in body ? (body as { detail: unknown }).detail : null
  return d && typeof d === 'object' && !Array.isArray(d) && typeof (d as { field?: unknown }).field === 'string' ? (d as { field: string }).field : null
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>('GET', path, undefined, { signal }),
  /** GET that doesn't count as activity: a page polling on its own doesn't keep an idle session alive (deps.py). */
  poll: <T>(path: string, signal?: AbortSignal) => request<T>('GET', path, undefined, { signal, headers: { 'X-EasyEAP-Passive': '1' } }),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {}),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body),
  /** POST that returns the raw Response (file downloads). */
  postRaw: (path: string, body?: unknown) => request<Response>('POST', path, body ?? {}, { raw: true }),
}

/** Build a query string, dropping empty values. */
export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== '' && v !== null && v !== undefined) u.set(k, String(v))
  const s = u.toString()
  return s ? `?${s}` : ''
}

/** Save a Blob as a file (downloads of chains, profiles and packages). */
export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function filenameFrom(res: Response, fallback: string): string {
  const cd = res.headers.get('content-disposition') ?? ''
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd)
  return m ? decodeURIComponent(m[1]) : fallback
}
