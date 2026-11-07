// Flow state shared by the steps. Results live only in React state (memory) and vanish when the page closes.
import { getLink, isPending, type CsrResult, type LinkInfo, type PendingInfo, type Platform } from './api'
import type { GuideCtx, Route } from './guides'
import { pemBlocks, toPem } from './pem'
import { safeName } from './files'

/** Key generated here; certificate signed; PKCS#12 sealed with `password`. */
export interface BrowserResult {
  kind: 'browser'
  csr: CsrResult
  p12: Uint8Array<ArrayBuffer>
  password: string
  generated: boolean
  /** Filled Apple profile, for iOS/macOS. */
  mobileconfig: string | null
  profileName: string | null
  /** Root CA common name, for the trust prompts. */
  rootCn: string | null
}
/** Windows helper downloaded; the helper itself creates the key and posts the CSR. */
export interface HelperResult { kind: 'helper'; script: Blob; caPem: string | null; rootCn: string | null; finished: boolean }
/** IT's server-generated package, taken once: a .p12, or (iPhone, iPad, Mac) an Apple profile wrapping it. */
export interface PackageResult {
  kind: 'package'
  format: 'p12' | 'mobileconfig'
  data: Blob
  filename: string
  /** Name iOS/macOS shows for the profile. */
  profileName: string | null
  /** Windows Wi-Fi profile, fetched before the package spent the link. */
  wifiXml: string | null
  caPem: string | null
  rootCn: string | null
}
export type FlowResult = BrowserResult | HelperResult | PackageResult

/** Why the link can't be used. */
export type GoneReason = 'invalid' | 'expired' | 'used' | 'cancelled' | 'closed' | 'used-meanwhile' | 'lost-response' | 'no-token'

/** Reason for a link GET /{token} reports as spent, when the page opens. */
export function closedReason(info: LinkInfo): GoneReason {
  return info.status === 'completed' ? 'used' : info.status === 'cancelled' ? 'cancelled' : info.status === 'expired' ? 'expired' : 'closed'
}

/** A request was refused because the link closed while this page was open. Ask the API why.
 *  `ours`: this page's own certificate request may have used it (the reply was lost). */
export async function closedMeanwhile(token: string, ours = false): Promise<GoneReason> {
  try {
    const info = await getLink(token)
    if (isPending(info) || info.status === 'completed') return ours ? 'lost-response' : 'used-meanwhile'
    return closedReason(info)
  } catch {
    return ours ? 'lost-response' : 'used-meanwhile'
  }
}

export const APPLE: Platform[] = ['ios', 'macos']

export function routeFor(info: PendingInfo, platform: Platform, windowsRoute: 'helper' | 'browser'): Route {
  if (info.method === 'server') return 'package'
  if (platform === 'windows' && windowsRoute === 'helper') return 'helper'
  return APPLE.includes(platform) ? 'profile' : 'p12'
}

export const fileNames = (ssid: string) => {
  const s = safeName(ssid)
  return { p12: `${s}-certificate.p12`, mobileconfig: `${s}.mobileconfig`, caPem: `${s}-CA.pem`, caCrt: `${s}-CA.crt`, xml: `${s}.xml`, clientPem: `${s}-client.pem` }
}

/** The root CA (last certificate of the chain the API returns: issuing first, then root). */
export function rootPemOf(chainPem: string | null | undefined): string | null {
  if (!chainPem) return null
  const blocks = pemBlocks(chainPem)
  const last = blocks[blocks.length - 1]
  return last ? toPem(last, 'CERTIFICATE') : null
}

export function guideCtx(info: PendingInfo, platform: Platform, result: FlowResult | null): GuideCtx {
  const n = fileNames(info.network.ssid)
  const csr = result?.kind === 'browser' ? result.csr : null
  return {
    tenant: info.tenant,
    ssid: csr?.network.ssid || info.network.ssid,
    serverName: csr?.network.server_name || info.network.server_name,
    wpa3: csr?.network.wpa3 ?? info.network.wpa3,
    wired: csr?.network.wired ?? info.network.wired ?? false,
    identity: csr?.identity ?? info.user.upn,
    deviceName: info.device_name,
    profileName: result?.kind === 'browser' || result?.kind === 'package' ? result.profileName : null,
    rootCn: result?.rootCn ?? null,
    files: {
      p12: result?.kind === 'package' ? (result.format === 'p12' ? result.filename : undefined) : n.p12,
      profile: result?.kind === 'package' ? (result.format === 'mobileconfig' ? result.filename : undefined)
        : APPLE.includes(platform) && result?.kind === 'browser' && result.mobileconfig ? n.mobileconfig : undefined,
      ca: platform === 'android' ? n.caCrt : n.caPem,
      xml: platform === 'windows' && ((result?.kind === 'browser' && result.csr.profiles.windows_xml) || (result?.kind === 'package' && result.wifiXml)) ? n.xml : undefined,
      helper: 'EasyEAP-WiFi-Setup.ps1',
    },
    androidCertName: info.network.ssid,
  }
}
