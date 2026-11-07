// EasyEAP domain model shared by the design prototypes and the production console.
// Field names mirror the backend API schemas (backend/app/schemas). Dates are ISO-8601 strings.

export type ISODate = string

export type HealthState = 'ok' | 'degraded' | 'down' | 'unconfigured'

export interface Tenant {
  id: string
  slug: string
  name: string
  /** Primary AD DNS domain, e.g. corp.harborview.example */
  domain: string
  status: 'active' | 'setup' | 'suspended'
  createdAt: ISODate
  health: TenantHealth
}

export interface TenantHealth {
  radius: HealthState
  pki: HealthState
  directory: HealthState
  /** ISO timestamp of the last successful directory sync */
  lastDirectorySync: ISODate | null
  /** Age in seconds of the authorization snapshot loaded by RADIUS */
  authzSnapshotAgeSeconds: number | null
}

// ── Identity ────────────────────────────────────────────────────────────────

export type IdentitySource = 'ad' | 'local'
export type AccountState = 'enabled' | 'disabled' | 'locked' | 'deleted'

export interface Identity {
  id: string
  tenantId: string
  source: IdentitySource
  displayName: string
  username: string // sAMAccountName or local username
  upn: string | null
  email: string | null
  department: string | null
  title: string | null
  accountState: AccountState
  /** Directory group ids (transitive membership, including primary group) */
  groupIds: string[]
  lastAuthAt: ISODate | null
  lastSyncedAt: ISODate | null
  objectGuid: string | null
}

export interface DirectoryGroup {
  id: string
  tenantId: string
  name: string
  dn: string
  sid: string | null
  memberCount: number
}

export type Platform = 'windows' | 'macos' | 'ios' | 'android' | 'linux'

export interface Device {
  id: string
  tenantId: string
  identityId: string
  name: string
  platform: Platform
  createdAt: ISODate
  lastSeenMac: string | null
}

// ── PKI ─────────────────────────────────────────────────────────────────────

export type CaRole = 'root' | 'issuing'
export type KeyAlgorithm = 'ecdsa-p256' | 'ecdsa-p384' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096'

export interface CertificateAuthority {
  id: string
  tenantId: string
  role: CaRole
  commonName: string
  subject: string
  keyAlgorithm: KeyAlgorithm
  notBefore: ISODate
  notAfter: ISODate
  /** Root CAs are kept offline: the private key is not held by EasyEAP. */
  offline: boolean
  serial: string
  fingerprintSha256: string
  crl: { lastIssued: ISODate | null; nextUpdate: ISODate | null; number: number; url: string | null } | null
  ocsp: { enabled: boolean; url: string | null } | null
}

export type CertPurpose = 'user' | 'device' | 'radius-server' | 'admin'

export interface CertificateTemplate {
  id: string
  tenantId: string
  name: string
  purpose: CertPurpose
  keyAlgorithm: KeyAlgorithm
  validityDays: number
  renewBeforeDays: number
  extendedKeyUsage: string[] // e.g. ['clientAuth']
  keyUsage: string[] // e.g. ['digitalSignature']
  subjectPattern: string // e.g. 'CN={upn}'
  sanPattern: string[] // e.g. ['upn:{upn}', 'email:{email}']
  allowClientKeyGeneration: boolean
  allowServerKeyGeneration: boolean
}

export type CertStatus = 'active' | 'expiring' | 'expired' | 'revoked' | 'pending'

/** RFC 5280 CRLReason values exposed in the UI. certificateHold is deliberately absent: revocation is permanent. */
export type RevocationReason =
  | 'unspecified'
  | 'keyCompromise'
  | 'affiliationChanged'
  | 'superseded'
  | 'cessationOfOperation'

export type KeyOrigin = 'device' | 'browser' | 'csr' | 'server'

export interface Certificate {
  id: string
  tenantId: string
  serial: string // colon-free uppercase hex
  subject: string
  commonName: string
  sans: string[]
  templateId: string
  issuerCaId: string
  identityId: string | null
  deviceId: string | null
  notBefore: ISODate
  notAfter: ISODate
  status: CertStatus
  keyAlgorithm: KeyAlgorithm
  keyOrigin: KeyOrigin
  fingerprintSha256: string
  revokedAt: ISODate | null
  revocationReason: RevocationReason | null
  revokedBy: string | null
}

// ── Policy ──────────────────────────────────────────────────────────────────

export interface Vlan {
  id: string
  tenantId: string
  vlanId: number // 1-4094
  name: string
  description: string
  /** Display colour token key; colour-codes the VLAN everywhere in the UI */
  color: 'blue' | 'green' | 'orange' | 'violet' | 'teal' | 'rose' | 'amber' | 'slate'
}

export interface RadiusAttribute {
  name: string
  value: string
}

export type RuleAction = 'allow' | 'deny'

export interface AccessRule {
  id: string
  tenantId: string
  name: string
  priority: number // lower number evaluated first among allow rules
  enabled: boolean
  action: RuleAction
  /** Directory groups this rule matches (any-of) */
  groupIds: string[]
  /** Optional: restrict to certificate template purposes */
  purposes: CertPurpose[]
  vlanId: string | null
  extraAttributes: RadiusAttribute[]
  description: string
}

export interface PolicyDefaults {
  /** What happens when no rule matches */
  defaultAction: RuleAction
  defaultVlanId: string | null
  /** RADIUS rejects when authorization data is older than this (seconds) */
  maxSnapshotAgeSeconds: number
}

export type DecisionStep =
  | { kind: 'account'; ok: boolean; detail: string }
  | { kind: 'certificate'; ok: boolean; detail: string }
  | { kind: 'rule'; ruleId: string; matched: boolean; action: RuleAction; detail: string }
  | { kind: 'default'; action: RuleAction; detail: string }

export interface Decision {
  identityId: string
  outcome: RuleAction
  decidingRuleId: string | null
  vlanId: string | null
  attributes: RadiusAttribute[]
  steps: DecisionStep[]
  computedAt: ISODate
}

// ── RADIUS ──────────────────────────────────────────────────────────────────

export type NasVendor = 'cisco-9800' | 'cisco-aireos' | 'cisco-switch' | 'unifi' | 'other'

export interface RadiusClient {
  id: string
  tenantId: string
  name: string
  vendor: NasVendor
  address: string // IP or CIDR
  /** Secrets are write-only; only rotation metadata is ever returned */
  secretSetAt: ISODate
  coaEnabled: boolean
  coaPort: number
  site: string
  lastRequestAt: ISODate | null
  status: HealthState
}

export interface RadiusSettings {
  tenantId: string
  serverHostname: string // name in the RADIUS server certificate
  authPort: number
  acctPort: number
  dedicatedPorts: boolean
  tlsMinVersion: '1.2' | '1.3'
  sessionTimeoutSeconds: number
  tlsSessionCache: boolean
  requireMessageAuthenticator: boolean
  serverCertificateId: string | null
}

export type AuthResult = 'accept' | 'reject'

export type FailureCode =
  | 'unknown_ca'
  | 'cert_expired'
  | 'cert_revoked'
  | 'cert_unknown'
  | 'identity_unauthorized'
  | 'account_disabled'
  | 'policy_deny'
  | 'vlan_assignment'
  | 'snapshot_stale'
  | 'tls_handshake'
  | 'client_timeout'
  | 'network_not_enabled'
  | 'network_unknown'
  | 'mab_unsupported'
  | 'mab_not_enabled'
  | 'mab_mismatch'
  | 'mab_password'
  | 'mac_unknown'
  | 'mac_disabled'
  | 'mac_expired'
  | 'mac_group_disabled'

export interface AuthEvent {
  id: string
  tenantId: string
  at: ISODate
  result: AuthResult
  identityId: string | null
  username: string | null
  deviceId: string | null
  certSerial: string | null
  callingStationId: string | null // client MAC
  calledStationId: string | null // AP MAC:SSID
  nasClientId: string | null
  ssid: string | null
  vlanId: string | null
  ruleId: string | null
  failureCode: FailureCode | null
  /** Raw FreeRADIUS module message, shown under "technical details" */
  rawMessage: string | null
}

// ── Audit ───────────────────────────────────────────────────────────────────

export interface AuditEvent {
  id: string
  tenantId: string | null
  at: ISODate
  actor: string
  action: string // e.g. certificate.revoke
  target: string
  detail: string
}
