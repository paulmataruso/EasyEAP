// Helpers that don't need pkijs, so the first screen loads without the PKI library (crypto.ts is loaded on demand).

/** WebCrypto (crypto.subtle) only exists in secure contexts: HTTPS, or localhost during development. */
export function webCryptoAvailable(): boolean {
  return typeof window !== 'undefined' && window.isSecureContext === true && !!globalThis.crypto?.subtle
}

const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789' // no 0/O, 1/l/I
/** "k7Qm-Wz3p-…": 16 characters from a 55-symbol alphabet (~92 bits), grouped so it can be read aloud or typed. */
export function generatePassword(groups = 4, size = 4): string {
  const out: string[] = []
  const limit = 256 - (256 % ALPHABET.length) // rejection sampling: no modulo bias
  const buf = new Uint8Array(1)
  for (let g = 0; g < groups; g++) {
    let s = ''
    while (s.length < size) {
      crypto.getRandomValues(buf)
      if (buf[0] < limit) s += ALPHABET[buf[0] % ALPHABET.length]
    }
    out.push(s)
  }
  return out.join('-')
}

// ── PEM helpers ──────────────────────────────────────────────────────────
const toB64 = (bytes: Uint8Array) => {
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(bin)
}
export const base64 = (bytes: ArrayBuffer | Uint8Array) => toB64(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))

export function toPem(der: ArrayBuffer, label: string): string {
  const b64 = base64(der).match(/.{1,64}/g)?.join('\n') ?? ''
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`
}

/** Every certificate block in a PEM string, as DER. */
export function pemBlocks(pem: string): ArrayBuffer[] {
  const re = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g
  const out: ArrayBuffer[] = []
  for (const m of pem.matchAll(re)) {
    const bin = atob(m[1].replace(/\s+/g, ''))
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    out.push(bytes.buffer)
  }
  return out
}

// ── Apple configuration profile ──────────────────────────────────────────
/**
 * The API's unsigned profile carries `marker` inside the identity payload's <data> element; replace it with the
 * base64 PKCS#12 built here. Refuses a template that doesn't contain the marker exactly once.
 */
export function fillMobileconfig(template: string, marker: string, p12: Uint8Array): string {
  const parts = template.split(marker)
  if (parts.length !== 2) throw new Error('The Wi-Fi profile from the server is not in the expected format.')
  const b64 = base64(p12).match(/.{1,68}/g)?.join('\n\t\t\t') ?? ''
  return parts[0] + b64 + parts[1]
}

/** Top-level PayloadDisplayName of a plist profile (what iOS shows as the profile's name). */
export function profileDisplayName(plistXml: string): string | null {
  try {
    const doc = new DOMParser().parseFromString(plistXml, 'application/xml')
    const dict = doc.querySelector('plist > dict')
    if (!dict) return null
    const kids = Array.from(dict.children)
    for (let i = 0; i < kids.length - 1; i++) {
      if (kids[i].tagName === 'key' && kids[i].textContent === 'PayloadDisplayName') return kids[i + 1].textContent
    }
    return null
  } catch {
    return null
  }
}
