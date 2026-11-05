// On-device key generation, the certificate request, and the password-protected PKCS#12 file.
//
// The private key exists only inside this module's function scopes. It is never sent anywhere, never written to
// localStorage/IndexedDB, and the exported PKCS#8 bytes are zeroed as soon as they are sealed inside the PKCS#12.
// Loaded on demand (dynamic import) by the create step: it carries pkijs.
// The RA ignores the CSR's subject and SANs (names come from the directory), so the request carries a neutral subject.
import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import { pemBlocks, toPem } from './pem'

/** Same parameters as the server-side packages (enrollment/service.py `build_pkcs12`, non-legacy). */
export const P12_PARAMS = { pbkdf2Iterations: 600_000, macIterations: 2048, cipher: 'AES-256-CBC', prf: 'HMAC-SHA-256', mac: 'SHA-256' } as const

const OID = {
  commonName: '2.5.4.3',
  keyBag: '1.2.840.113549.1.12.10.1.2', // pkcs8ShroudedKeyBag
  certBag: '1.2.840.113549.1.12.10.1.3',
  x509Certificate: '1.2.840.113549.1.9.22.1',
  friendlyName: '1.2.840.113549.1.9.20',
  localKeyId: '1.2.840.113549.1.9.21',
}

const parseCert = (der: ArrayBuffer) => pkijs.Certificate.fromBER(der)

/** Common name of the first certificate in a PEM string (e.g. "Harborview Logistics Root CA"), or null. */
export function commonNameOf(pem: string | null | undefined): string | null {
  if (!pem) return null
  try {
    const [der] = pemBlocks(pem)
    if (!der) return null
    const cn = parseCert(der).subject.typesAndValues.find((t) => t.type === OID.commonName)
    return cn ? String(cn.value.valueBlock.value) : null
  } catch {
    return null
  }
}

// ── Key + certificate request ────────────────────────────────────────────
export interface DeviceKey { privateKey: CryptoKey; publicKey: CryptoKey }

/**
 * ECDSA P-256. Extractable because every browser deliverable (.mobileconfig, .p12) needs the key sealed inside a
 * password-protected PKCS#12; the export happens once, in memory, in `buildPkcs12`.
 */
export async function generateDeviceKey(): Promise<DeviceKey> {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return { privateKey: kp.privateKey, publicKey: kp.publicKey }
}

/** PKCS#10 request signed by the device key. The subject is a neutral placeholder: EasyEAP replaces it with the directory's names. */
export async function buildCsr(key: DeviceKey): Promise<string> {
  const csr = new pkijs.CertificationRequest()
  csr.version = 0
  csr.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({ type: OID.commonName, value: new asn1js.Utf8String({ value: 'EasyEAP enrollment' }) }))
  await csr.subjectPublicKeyInfo.importKey(key.publicKey)
  csr.attributes = []
  await csr.sign(key.privateKey, 'SHA-256')
  return toPem(csr.toSchema(true).toBER(false), 'CERTIFICATE REQUEST')
}

// ── PKCS#12 ──────────────────────────────────────────────────────────────
const bmp = (s: string) => new asn1js.BmpString({ value: s })

function certBag(der: ArrayBuffer, attrs: pkijs.Attribute[]): pkijs.SafeBag {
  return new pkijs.SafeBag({
    bagId: OID.certBag,
    bagValue: new pkijs.CertBag({ certId: OID.x509Certificate, parsedValue: parseCert(der) }),
    bagAttributes: attrs.length ? attrs : undefined,
  })
}

/**
 * PFX with the device key (pkcs8ShroudedKeyBag) and the certificate plus its CA chain (password-encrypted safe),
 * protected by PBES2 (PBKDF2-HMAC-SHA-256, 600,000 iterations, AES-256-CBC) and an HMAC-SHA-256 MAC: the same
 * profile as EasyEAP's server-generated packages. `key` must be the pair that signed the CSR.
 */
export async function buildPkcs12(opts: { key: DeviceKey; certificatePem: string; chainPems: Array<string | null>; password: string; friendlyName: string }): Promise<Uint8Array<ArrayBuffer>> {
  const [leafDer] = pemBlocks(opts.certificatePem)
  if (!leafDer) throw new Error('The certificate returned by the server could not be read.')
  const caDers = opts.chainPems.flatMap((p) => (p ? pemBlocks(p) : []))
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', opts.key.privateKey))
  try {
    const localKeyId = new Uint8Array(await crypto.subtle.digest('SHA-1', leafDer)) // the usual choice: hash of the leaf
    const idAttrs = () => [
      new pkijs.Attribute({ type: OID.friendlyName, values: [bmp(opts.friendlyName.slice(0, 64))] }),
      new pkijs.Attribute({ type: OID.localKeyId, values: [new asn1js.OctetString({ valueHex: localKeyId.slice().buffer })] }),
    ]
    const keyBag = new pkijs.SafeBag({
      bagId: OID.keyBag,
      bagValue: new pkijs.PKCS8ShroudedKeyBag({ parsedValue: pkijs.PrivateKeyInfo.fromBER(pkcs8.slice().buffer) }),
      bagAttributes: idAttrs(),
    })
    const pwd = new TextEncoder().encode(opts.password).buffer as ArrayBuffer
    // pkijs types AES-CBC with an `iv`, but it generates the IV itself for every encryption; only name and length are used.
    const aes256cbc = { name: 'AES-CBC', length: 256 } as unknown as pkijs.ContentEncryptionAlgorithm
    const enc = { password: pwd, contentEncryptionAlgorithm: aes256cbc, hmacHashAlgorithm: 'SHA-256', iterationCount: P12_PARAMS.pbkdf2Iterations }
    await (keyBag.bagValue as pkijs.PKCS8ShroudedKeyBag).makeInternalValues(enc)

    const certs = new pkijs.SafeContents({ safeBags: [certBag(leafDer, idAttrs()), ...caDers.map((d) => certBag(d, []))] })
    const keys = new pkijs.SafeContents({ safeBags: [keyBag] })
    const pfx = new pkijs.PFX({
      parsedValue: {
        integrityMode: 0, // password-based MAC
        authenticatedSafe: new pkijs.AuthenticatedSafe({
          parsedValue: { safeContents: [{ privacyMode: 1, value: certs }, { privacyMode: 0, value: keys }] },
        }),
      },
    })
    await pfx.parsedValue!.authenticatedSafe!.makeInternalValues({ safeContents: [{ ...enc }, {}] })
    await pfx.makeInternalValues({ password: pwd, iterations: P12_PARAMS.macIterations, pbkdf2HashAlgorithm: 'SHA-256', hmacHashAlgorithm: 'SHA-256' })
    return new Uint8Array(pfx.toSchema().toBER(false))
  } finally {
    pkcs8.fill(0)
  }
}
