// Enrollment portal API (routers/enroll_public.py). The one-time token in the URL is the only credential: no cookies,
// no CSRF, and nothing here is cached or stored. Every shape below mirrors the router exactly.

export type Platform = 'windows' | 'macos' | 'ios' | 'android' | 'linux'
export const PLATFORMS: Platform[] = ['ios', 'macos', 'android', 'windows', 'linux']

/** `wired`: the tenant turned on wired 802.1X, so packages also set up network ports (Macs, Linux). */
export interface NetworkInfo { ssid: string; server_name: string; wpa3: boolean; wired: boolean }

/** GET /api/enroll/{token} while the link is usable. */
export interface PendingInfo {
  status: 'pending'
  tenant: string
  user: { display_name: string; upn: string }
  device_name: string
  platform: Platform
  /** "link": the key is created on the device (CSR). "server": IT prepared a password-protected package. */
  method: 'link' | 'server'
  expires_at: string
  network: NetworkInfo
  instructions: string[]
}
/** GET /api/enroll/{token} for a link that has been spent. Unknown tokens get a 404 instead. */
export type ClosedStatus = 'completed' | 'cancelled' | 'expired'
export interface ClosedInfo { status: ClosedStatus | (string & {}); tenant: string }
export type LinkInfo = PendingInfo | ClosedInfo
export const isPending = (i: LinkInfo): i is PendingInfo => i.status === 'pending'

/** POST /api/enroll/{token}/csr */
export interface CsrResult {
  certificate_pem: string
  issuing_ca_pem: string
  root_ca_pem: string | null
  serial: string
  not_after: string
  network: NetworkInfo
  profiles: {
    windows_xml: string | null
    mobileconfig_template: string | null
    mobileconfig_marker: string
    networkmanager: string | null
    wpa_supplicant: string | null
    /** Wired 802.1X for Linux; null unless the tenant turned wired on. */
    networkmanager_wired: string | null
    wpa_supplicant_wired: string | null
  }
  identity: string
  instructions: string[]
}

/** What went wrong, in terms the page can explain to a non-technical person. */
export type FailureKind = 'gone' | 'network' | 'rate' | 'server' | 'rejected'
export class EnrollError extends Error {
  kind: FailureKind
  status: number
  constructor(kind: FailureKind, status: number, message: string) {
    super(message)
    this.kind = kind
    this.status = status
  }
}

async function detailOf(res: Response): Promise<string | null> {
  try {
    const body = await res.json()
    return typeof body?.detail === 'string' ? body.detail : null
  } catch {
    return null
  }
}

async function call(path: string, init?: RequestInit): Promise<Response> {
  let res: Response
  try {
    res = await fetch(path, { credentials: 'omit', cache: 'no-store', ...init })
  } catch {
    throw new EnrollError('network', 0, 'This device couldn’t reach the enrollment service.')
  }
  if (res.ok) return res
  const detail = await detailOf(res)
  // 404: unknown link. 410: the link was used, cancelled or expired (GET /{token} says which).
  if (res.status === 404 || res.status === 410) throw new EnrollError('gone', res.status, detail ?? 'This link can’t be used any more.')
  if (res.status === 429) throw new EnrollError('rate', 429, detail ?? 'Too many requests. Wait a minute and try again.')
  if (res.status >= 500) throw new EnrollError('server', res.status, 'The enrollment service hit a problem.')
  // 400 / 409 / 422: the API's own plain-language reason (e.g. "Your directory account is not enabled. Contact your IT team.").
  throw new EnrollError('rejected', res.status, detail ?? 'The enrollment service didn’t accept this request.')
}

const base = (token: string) => `/api/enroll/${encodeURIComponent(token)}`

export async function getLink(token: string): Promise<LinkInfo> {
  return (await call(base(token), { headers: { Accept: 'application/json' } })).json()
}

export async function submitCsr(token: string, csr: string, deviceHint: string): Promise<CsrResult> {
  const res = await call(`${base(token)}/csr`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ csr, key_origin: 'browser', device_hint: deviceHint.slice(0, 120) }),
  })
  return res.json()
}

/** The Windows helper: the program users double-click, or the PowerShell script it carries when the server has no
 *  program (501) or it can't be had. Doesn't consume the link; the helper itself posts the CSR. */
export async function getWindowsHelper(token: string): Promise<{ blob: Blob; file: string }> {
  const exe = await fetch(`${base(token)}/windows.exe`, { credentials: 'omit', cache: 'no-store' }).catch(() => null)
  if (exe?.ok) return { blob: await exe.blob(), file: 'EasyEAP-WiFi-Setup.exe' }
  return { blob: await getWindowsScript(token), file: WINDOWS_SCRIPT }
}

export const WINDOWS_SCRIPT = 'EasyEAP-WiFi-Setup.ps1'
/** The same helper as a PowerShell script, for PCs that don't run unknown programs. Through call(): an unknown, used or
 *  rate-limited link is reported as usual. */
export async function getWindowsScript(token: string): Promise<Blob> {
  return (await call(`${base(token)}/windows.ps1`)).blob()
}

/** The Linux setup script (NetworkManager, iwd or wpa_supplicant). Doesn't consume the link; the script itself posts the CSR. */
export async function getLinuxHelper(token: string): Promise<Blob> {
  return (await call(`${base(token)}/linux.sh`)).blob()
}

/** Windows WLAN profile (EAP-TLS, server name pinned). Nothing secret; only while the link is pending. */
export async function getWifiXml(token: string): Promise<string> {
  return (await call(`${base(token)}/wifi.xml`)).text()
}

/** Server-generated PKCS#12, as a plain file or wrapped in an Apple profile (with the CA chain and the network).
 *  One download in either format, then the escrow copy is deleted and the link is spent. */
export async function takePackage(token: string, format: 'p12' | 'mobileconfig'): Promise<{ data: Blob; filename: string | null }> {
  const res = await call(`${base(token)}/package?format=${format}`, { method: 'POST' })
  const cd = res.headers.get('content-disposition') ?? ''
  const m = /filename="?([^";]+)"?/i.exec(cd)
  return { data: await res.blob(), filename: m ? m[1] : null }
}

/** Issuing CA followed by Root CA (PEM). Works for any link that resolves, spent or not. */
export async function getCaChain(token: string): Promise<string> {
  return (await call(`${base(token)}/ca.pem`)).text()
}
