// Machine-readable zone for EasyEAP credentials.
// Layout follows ICAO Doc 9303 TD3 (two lines of 44 characters, 7-3-1 weighted check digits,
// filler "<") so the line is verifiable by anyone with the spec. Field meanings are EasyEAP's:
//
//   Line 1  [1]   E            EasyEAP credential
//           [2]   U|D|S|I      user certificate · device certificate · server certificate · identity record
//           [3-5] AAA          issuing authority (tenant code)
//           [6-44]             holder: SURNAME<<GIVEN<NAMES  (server certificates: common name)
//
//   Line 2  [1-9]   document number (certificate serial, or username for identity records)
//           [10]    check digit over 1-9
//           [11-13] platform (WIN MAC IOS AND LNX SRV) · directory source (ADS LOC)
//           [14-19] issued YYMMDD · last directory sync
//           [20]    check digit over 14-19
//           [21]    key origin (D device · B browser · C CSR · S server) · account state (E D L X)
//           [22-27] expires YYMMDD · last authentication
//           [28]    check digit over 22-27
//           [29-42] optional data: status + key algorithm · decision + VLAN/rule + group count
//           [43]    check digit over 29-42
//           [44]    composite check digit over 1-10, 14-20, 22-43

export const MRZ_LENGTH = 44

const charValue = (ch: string): number => {
  if (ch === '<') return 0
  if (ch >= '0' && ch <= '9') return ch.charCodeAt(0) - 48
  if (ch >= 'A' && ch <= 'Z') return ch.charCodeAt(0) - 55
  throw new Error(`Invalid MRZ character "${ch}"`)
}

/** ICAO 9303 check digit: weights 7, 3, 1 repeating; sum modulo 10. */
export function checkDigit(field: string): string {
  const weights = [7, 3, 1]
  let sum = 0
  for (let i = 0; i < field.length; i++) sum += charValue(field[i]) * weights[i % 3]
  return String(sum % 10)
}

/** Transliterate to the MRZ alphabet: A-Z, 0-9 and "<" (spaces, dots, hyphens become fillers). */
export function mrzText(input: string): string {
  return input
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toUpperCase()
    .replace(/['’]/g, '')
    .replace(/[^A-Z0-9]+/g, '<')
    .replace(/^<+|<+$/g, '')
}

export const pad = (s: string, n: number) => (s + '<'.repeat(n)).slice(0, n)

/** YYMMDD in UTC, or six fillers when unknown. */
export function yymmdd(iso: string | null): string {
  if (!iso) return '<<<<<<'
  const d = new Date(iso)
  return `${String(d.getUTCFullYear() % 100).padStart(2, '0')}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`
}

/** SURNAME<<GIVEN<NAMES from a display name ("Priya Natarajan" → NATARAJAN<<PRIYA). */
export function holderField(displayName: string): string {
  const parts = displayName.trim().split(/\s+/)
  if (parts.length < 2) return mrzText(displayName)
  const surname = parts[parts.length - 1]
  return `${mrzText(surname)}<<${mrzText(parts.slice(0, -1).join(' '))}`
}

export interface MrzSegment {
  key: string
  label: string
  text: string
  /** Value this segment encodes, in plain language */
  value: string
  /** Check digit segment: which field it verifies */
  check?: { of: string; valid: boolean }
}

export interface Mrz {
  lines: [MrzSegment[], MrzSegment[]]
  /** Plain strings, 44 characters each */
  text: [string, string]
}

interface Line2Input {
  number: { text: string; value: string; label: string }
  code3: { text: string; value: string; label: string }
  date1: { iso: string | null; value: string; label: string }
  code1: { text: string; value: string; label: string }
  date2: { iso: string | null; value: string; label: string }
  optional: { text: string; value: string; label: string }
}

function buildLine2(f: Line2Input): MrzSegment[] {
  const num = pad(f.number.text, 9)
  const numCd = checkDigit(num)
  const d1 = yymmdd(f.date1.iso)
  const d1Cd = checkDigit(d1)
  const d2 = yymmdd(f.date2.iso)
  const d2Cd = checkDigit(d2)
  const opt = pad(f.optional.text, 14)
  const optCd = checkDigit(opt)
  const composite = checkDigit(num + numCd + d1 + d1Cd + d2 + d2Cd + opt + optCd)
  return [
    { key: 'num', label: f.number.label, text: num, value: f.number.value },
    { key: 'num-cd', label: 'Check digit', text: numCd, value: numCd, check: { of: f.number.label, valid: true } },
    { key: 'code3', label: f.code3.label, text: pad(f.code3.text, 3), value: f.code3.value },
    { key: 'd1', label: f.date1.label, text: d1, value: f.date1.value },
    { key: 'd1-cd', label: 'Check digit', text: d1Cd, value: d1Cd, check: { of: f.date1.label, valid: true } },
    { key: 'code1', label: f.code1.label, text: pad(f.code1.text, 1), value: f.code1.value },
    { key: 'd2', label: f.date2.label, text: d2, value: f.date2.value },
    { key: 'd2-cd', label: 'Check digit', text: d2Cd, value: d2Cd, check: { of: f.date2.label, valid: true } },
    { key: 'opt', label: f.optional.label, text: opt, value: f.optional.value },
    { key: 'opt-cd', label: 'Check digit', text: optCd, value: optCd, check: { of: f.optional.label, valid: true } },
    { key: 'composite', label: 'Composite check digit', text: composite, value: composite, check: { of: 'the whole line', valid: true } },
  ]
}

function buildLine1(kind: string, kindLabel: string, authority: string, authorityName: string, holder: string, holderValue: string): MrzSegment[] {
  return [
    { key: 'doc', label: 'Document', text: `E${kind}`, value: kindLabel },
    { key: 'auth', label: 'Issuing authority', text: pad(authority, 3), value: authorityName },
    { key: 'holder', label: 'Holder', text: pad(holder, MRZ_LENGTH - 5), value: holderValue },
  ]
}

const join = (segs: MrzSegment[]) => segs.map((s) => s.text).join('')

function finish(l1: MrzSegment[], l2: MrzSegment[]): Mrz {
  const a = join(l1)
  const b = join(l2)
  if (a.length !== MRZ_LENGTH || b.length !== MRZ_LENGTH) throw new Error(`MRZ length ${a.length}/${b.length}`)
  return { lines: [l1, l2], text: [a, b] }
}

/** Verifies every check digit of a line 2 string (used by the decode view and tests). */
export function verifyLine2(line: string): boolean {
  if (line.length !== MRZ_LENGTH) return false
  const num = line.slice(0, 9), d1 = line.slice(13, 19), d2 = line.slice(21, 27), opt = line.slice(28, 42)
  return (
    checkDigit(num) === line[9] &&
    checkDigit(d1) === line[19] &&
    checkDigit(d2) === line[27] &&
    checkDigit(opt) === line[42] &&
    checkDigit(line.slice(0, 10) + line.slice(13, 20) + line.slice(21, 43)) === line[43]
  )
}

const PLATFORM_CODE: Record<string, string> = { windows: 'WIN', macos: 'MAC', ios: 'IOS', android: 'AND', linux: 'LNX' }
const ORIGIN_CODE: Record<string, string> = { device: 'D', browser: 'B', csr: 'C', server: 'S' }
const STATUS_CODE: Record<string, string> = { active: 'ACT', expiring: 'EXP', expired: 'XPD', revoked: 'REV', pending: 'PND' }
const ALG_CODE: Record<string, string> = { 'ecdsa-p256': 'EC256', 'ecdsa-p384': 'EC384', 'rsa-2048': 'RSA2K', 'rsa-3072': 'RSA3K', 'rsa-4096': 'RSA4K' }
const ACCOUNT_CODE: Record<string, string> = { enabled: 'E', disabled: 'D', locked: 'L', deleted: 'X' }

export interface CertMrzInput {
  serial: string
  kind: 'user' | 'device' | 'server'
  authority: string
  authorityName: string
  holderName: string | null
  commonName: string
  platform: string | null
  platformLabel: string
  notBefore: string
  notAfter: string
  keyOrigin: string
  keyOriginLabel: string
  status: string
  statusLabel: string
  keyAlgorithm: string
  dateLabel: (iso: string) => string
}

export function certificateMrz(c: CertMrzInput): Mrz {
  const kindCode = c.kind === 'server' ? 'S' : c.kind === 'device' ? 'D' : 'U'
  const kindLabel = c.kind === 'server' ? 'Server certificate' : c.kind === 'device' ? 'Device certificate' : 'User certificate'
  const holder = c.holderName ? holderField(c.holderName) : mrzText(c.commonName)
  const l1 = buildLine1(kindCode, kindLabel, c.authority, c.authorityName, holder, c.holderName ?? c.commonName)
  const status = STATUS_CODE[c.status] ?? 'UNK'
  const alg = ALG_CODE[c.keyAlgorithm] ?? 'UNKWN'
  const l2 = buildLine2({
    number: { text: mrzText(c.serial).slice(0, 9), value: `Serial ${c.serial.slice(0, 9)}…`, label: 'Serial number' },
    code3: { text: c.platform ? PLATFORM_CODE[c.platform] ?? 'UNK' : 'SRV', value: c.platformLabel, label: 'Platform' },
    date1: { iso: c.notBefore, value: c.dateLabel(c.notBefore), label: 'Valid from' },
    code1: { text: ORIGIN_CODE[c.keyOrigin] ?? '<', value: c.keyOriginLabel, label: 'Key origin' },
    date2: { iso: c.notAfter, value: c.dateLabel(c.notAfter), label: 'Valid to' },
    optional: { text: `${status}<${alg}`, value: `${c.statusLabel} · ${alg}`, label: 'Status and key' },
  })
  return finish(l1, l2)
}

export interface IdentityMrzInput {
  username: string
  displayName: string
  authority: string
  authorityName: string
  source: 'ad' | 'local'
  lastSyncedAt: string | null
  accountState: string
  lastAuthAt: string | null
  outcome: 'allow' | 'deny'
  vlanNumber: number | null
  rulePriority: number | null
  groupCount: number
  dateLabel: (iso: string | null) => string
}

export function identityMrz(i: IdentityMrzInput): Mrz {
  const l1 = buildLine1('I', 'Identity record', i.authority, i.authorityName, holderField(i.displayName), i.displayName)
  const decision = i.outcome === 'allow' ? 'ALW' : 'DNY'
  const target = i.outcome === 'allow' && i.vlanNumber !== null ? `V${String(i.vlanNumber).padStart(4, '0')}` : i.rulePriority !== null ? `R${String(i.rulePriority).padStart(4, '0')}` : '<<<<<'
  const groups = `G${String(Math.min(99, i.groupCount)).padStart(2, '0')}`
  const l2 = buildLine2({
    number: { text: mrzText(i.username).slice(0, 9), value: i.username, label: 'Username' },
    code3: { text: i.source === 'ad' ? 'ADS' : 'LOC', value: i.source === 'ad' ? 'Active Directory' : 'Local account', label: 'Source' },
    date1: { iso: i.lastSyncedAt, value: i.dateLabel(i.lastSyncedAt), label: 'Last directory sync' },
    code1: { text: ACCOUNT_CODE[i.accountState] ?? '<', value: `Account ${i.accountState}`, label: 'Account state' },
    date2: { iso: i.lastAuthAt, value: i.dateLabel(i.lastAuthAt), label: 'Last authentication' },
    optional: {
      text: `${decision}<${target}<${groups}`,
      value: `${i.outcome === 'allow' ? 'Allowed' : 'Denied'}${i.vlanNumber !== null && i.outcome === 'allow' ? ` · VLAN ${i.vlanNumber}` : ''} · ${i.groupCount} groups`,
      label: 'Access decision',
    },
  })
  return finish(l1, l2)
}
