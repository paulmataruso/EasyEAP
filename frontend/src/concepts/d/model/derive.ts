import type { AuditEvent, AuthEvent, Certificate, CertStatus, Identity, RadiusClient, Tenant } from '@/domain/types'
import { now } from '@/prototype/store'
import { daysUntil, relativeTime } from '@/ui/lib'

/**
 * The store stamps actions taken in this session with the real clock, while seed data is relative
 * to the fixed demo clock. Every write made through this concept records a short window, so its
 * stamps can be shown as "Just now" instead of a misleading offset from the demo clock.
 */
const sessionWindows: Array<[number, number]> = []
export function markSessionWrite() {
  const t = Date.now()
  sessionWindows.push([t - 50, t + 5000])
}
export function isSessionStamp(iso: string | null) {
  if (!iso) return false
  const t = new Date(iso).getTime()
  return sessionWindows.some(([a, b]) => t >= a && t <= b)
}

/** Relative time against the fixed demo clock; actions taken in this session read "Just now". */
export function relTime(iso: string | null): string {
  if (!iso) return 'Never'
  if (isSessionStamp(iso)) return 'Just now'
  const s = relativeTime(iso, now())
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export const utcClock = (iso: string) => new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })

export type RemainingTone = 'ok' | 'warn' | 'crit' | 'off'

/** Remaining lifetime, printed right-aligned in tabular figures on every certificate. */
export function remaining(cert: Pick<Certificate, 'notAfter' | 'status'>): { text: string; tone: RemainingTone; days: number } {
  const days = daysUntil(cert.notAfter, now())
  if (cert.status === 'revoked') return { text: 'revoked', tone: 'off', days }
  if (days <= 0) return { text: `${days === 0 ? '0' : `−${Math.abs(days)}`} d`, tone: 'crit', days }
  if (days > 730) return { text: `${(days / 365).toFixed(1)} y`, tone: 'ok', days }
  return { text: `${days} d`, tone: days <= 30 ? 'warn' : 'ok', days }
}

const STATUS_RANK: Record<CertStatus, number> = { active: 0, expiring: 1, pending: 2, expired: 3, revoked: 4 }

/** The certificate that best describes a user's Wi-Fi readiness (soonest-expiring usable one first). */
export function primaryCertificate(certs: Certificate[]): Certificate | null {
  if (!certs.length) return null
  return [...certs].sort((a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || a.notAfter.localeCompare(b.notAfter))[0]
}

export type UserCertState = CertStatus | 'none'
export const userCertState = (certs: Certificate[]): UserCertState => primaryCertificate(certs)?.status ?? 'none'

const ACTION_LABELS: Record<string, string> = {
  'certificate.issue': 'Certificate issued',
  'certificate.revoke': 'Certificate revoked',
  'directory.sync': 'Directory synchronised',
  'directory.sync.failed': 'Directory sync failed',
  'pki.crl.publish': 'CRL published',
  'policy.rule.update': 'Access rule changed',
  'policy.rule.reorder': 'Access rule moved',
  'radius.client.rotate_secret': 'Shared secret rotated',
  'radius.client.create': 'Controller registered',
  'tenant.create': 'Tenant created',
  'admin.role.grant': 'Administrator role granted',
  'enrollment.create': 'Enrollment link created',
}
export const auditLabel = (a: AuditEvent) => ACTION_LABELS[a.action] ?? a.action

export interface TenantSnapshot {
  users: number
  authorized: number
  certCount: number
  expiring: number
  expired: number
  authTotal: number
  authAccepts: number
  controllers: number
  controllersOk: number
  hasServerCert: boolean
}

export function snapshotFrom(input: {
  identities: Identity[]
  allowed: number
  certificates: Certificate[]
  authEvents: AuthEvent[]
  radiusClients: RadiusClient[]
  hasServerCert: boolean
}): TenantSnapshot {
  const userCerts = input.certificates.filter((c) => c.identityId)
  return {
    users: input.identities.length,
    authorized: input.allowed,
    certCount: userCerts.length,
    expiring: userCerts.filter((c) => c.status === 'expiring').length,
    expired: userCerts.filter((c) => c.status === 'expired').length,
    authTotal: input.authEvents.length,
    authAccepts: input.authEvents.filter((e) => e.result === 'accept').length,
    controllers: input.radiusClients.length,
    controllersOk: input.radiusClients.filter((n) => n.status === 'ok').length,
    hasServerCert: input.hasServerCert,
  }
}

export interface SetupStep { key: string; label: string; done: boolean; detail: string }

/** What a tenant still needs before devices can authenticate. */
export function setupSteps(t: Tenant, s: TenantSnapshot): SetupStep[] {
  return [
    { key: 'pki', label: 'Initialise PKI', done: t.health.pki !== 'unconfigured', detail: 'Offline root and issuing CA created' },
    { key: 'directory', label: 'Connect Active Directory', done: t.health.directory !== 'unconfigured', detail: `LDAPS bind to ${t.domain}` },
    { key: 'server-cert', label: 'Issue the RADIUS server certificate', done: s.hasServerCert, detail: 'Devices check this name before sending credentials' },
    { key: 'controller', label: 'Add a wireless controller', done: s.controllers > 0, detail: 'Register the WLC or UniFi controller and its shared secret' },
    { key: 'first-cert', label: 'Issue the first Wi-Fi certificate', done: s.certCount > 0, detail: 'Enroll one pilot device end to end' },
  ]
}
