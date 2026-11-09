// Handing files to the device. Everything is built in memory; nothing touches storage APIs.

export const MIME = {
  mobileconfig: 'application/x-apple-aspen-config',
  p12: 'application/x-pkcs12',
  pem: 'application/x-pem-file',
  crt: 'application/x-x509-ca-cert',
  xml: 'application/xml',
  ps1: 'text/plain',
  exe: 'application/vnd.microsoft.portable-executable',
  sh: 'text/plain',
} as const

/** The type a setup helper is saved with, by its name. */
export const helperMime = (file: string): string => (file.endsWith('.exe') ? MIME.exe : file.endsWith('.sh') ? MIME.sh : MIME.ps1)

/** Set while handing a file to the browser by navigation, so the page's own "leave this page?" guard stays quiet. */
export const handoff = { until: 0 }

export const canDownload = () => typeof document !== 'undefined' && 'download' in HTMLAnchorElement.prototype

/**
 * Save `data` as `filename`. `open` hands the file to the browser without the download attribute, which is what
 * iOS Safari needs to offer a configuration profile for installation ("This website is trying to download a
 * configuration profile").
 */
export function saveFile(data: BlobPart, filename: string, type: string, opts: { open?: boolean } = {}): void {
  const blob = data instanceof Blob && data.type === type ? data : new Blob([data], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  if (!opts.open) a.download = filename
  else handoff.until = Date.now() + 3000
  a.rel = 'noopener'
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  a.remove()
  // Keep the URL alive long enough for slow handoffs (iOS profile review, Android download manager).
  setTimeout(() => URL.revokeObjectURL(url), 120_000)
}

/** File-name-safe version of an SSID or organisation name. */
export const safeName = (s: string) => s.replace(/[\\/:*?"<>|\s]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '') || 'wifi'
