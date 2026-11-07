// SYNTHETIC DEMONSTRATION DATA for the design prototypes only.
// Every organisation, person, address and serial number below is fictional (.example domains).
// This module is imported only by the design.html entry and never by the production console.
import type {
  AccessRule,
  AuditEvent,
  AuthEvent,
  Certificate,
  CertificateAuthority,
  CertificateTemplate,
  Device,
  DirectoryGroup,
  FailureCode,
  Identity,
  Platform,
  PolicyDefaults,
  RadiusClient,
  RadiusSettings,
  Tenant,
  Vlan,
} from '@/domain/types'

/** Fixed demo clock so every concept and every screenshot shows identical data. */
export const DEMO_NOW = new Date('2026-11-05T10:42:00Z')

const HOUR = 3600_000
const DAY = 24 * HOUR
const iso = (ms: number) => new Date(ms).toISOString()
const ago = (ms: number) => iso(DEMO_NOW.getTime() - ms)
const ahead = (ms: number) => iso(DEMO_NOW.getTime() + ms)

function mulberry32(seed: number) {
  let a = seed
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const hex = (rnd: () => number, bytes: number) =>
  Array.from({ length: bytes }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join('').toUpperCase()

const mac = (rnd: () => number) =>
  Array.from({ length: 6 }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join(':').toUpperCase()

const FIRST = ['Ana', 'Marcus', 'Priya', 'Jonah', 'Leila', 'Tomás', 'Grace', 'Kenji', 'Amara', 'Owen', 'Sofia', 'Darnell', 'Mei', 'Felix', 'Nadia', 'Ruben', 'Hannah', 'Idris', 'Clara', 'Mateo', 'Yara', 'Elliot', 'Zoe', 'Rafael', 'Ingrid', 'Samir', 'Beatriz', 'Liam', 'Aiko', 'Gideon', 'Freya', 'Kwame', 'Lucia', 'Arjun', 'Maren', 'Dmitri', 'Tessa', 'Hugo', 'Noor', 'Callum', 'Esme', 'Viktor']
const LAST = ['Ruiz', 'Chen', 'Natarajan', 'Becker', 'Haddad', 'Silva', 'Okafor', 'Watanabe', 'Mensah', 'Doyle', 'Rossi', 'Freeman', 'Lin', 'Hartmann', 'Karimi', 'Alvarez', 'Novak', 'Bello', 'Lindqvist', 'Moreno', 'Saleh', 'Brooks', 'Park', 'Costa', 'Berg', 'Qureshi', 'Ferreira', 'Walsh', 'Sato', 'Levi', 'Nilsen', 'Asante', 'Romero', 'Iyer', 'Jansen', 'Petrov', 'Grant', 'Dubois', 'Hassan', 'Reid', 'Clarke', 'Horvat']

interface TenantSeed {
  id: string
  slug: string
  name: string
  domain: string
  status: Tenant['status']
  users: number
  events: number
  directory: Tenant['health']['directory']
  radius: Tenant['health']['radius']
  lastSyncAgo: number | null
}

const TENANT_SEEDS: TenantSeed[] = [
  { id: 't-harborview', slug: 'harborview', name: 'Harborview Logistics', domain: 'corp.harborview.example', status: 'active', users: 42, events: 260, directory: 'ok', radius: 'ok', lastSyncAgo: 11 * 60_000 },
  { id: 't-cedar', slug: 'cedar-ridge', name: 'Cedar Ridge Medical Group', domain: 'cedarridge.example', status: 'active', users: 18, events: 90, directory: 'ok', radius: 'ok', lastSyncAgo: 7 * 60_000 },
  { id: 't-northgate', slug: 'northgate', name: 'Northgate School District', domain: 'ad.northgate.example', status: 'active', users: 14, events: 70, directory: 'degraded', radius: 'ok', lastSyncAgo: 26 * HOUR },
  { id: 't-atlas', slug: 'atlas', name: 'Atlas Fabrication', domain: 'atlasfab.example', status: 'setup', users: 4, events: 0, directory: 'unconfigured', radius: 'unconfigured', lastSyncAgo: null },
]

export interface SampleData {
  tenants: Tenant[]
  groups: DirectoryGroup[]
  identities: Identity[]
  devices: Device[]
  cas: CertificateAuthority[]
  templates: CertificateTemplate[]
  certificates: Certificate[]
  vlans: Vlan[]
  rules: AccessRule[]
  defaults: Record<string, PolicyDefaults>
  radiusClients: RadiusClient[]
  radiusSettings: Record<string, RadiusSettings>
  authEvents: AuthEvent[]
  audit: AuditEvent[]
}

export function generateSampleData(): SampleData {
  const rnd = mulberry32(0xeaee)
  const pick = <T,>(arr: T[]) => arr[Math.floor(rnd() * arr.length)]
  const data: SampleData = {
    tenants: [], groups: [], identities: [], devices: [], cas: [], templates: [], certificates: [],
    vlans: [], rules: [], defaults: {}, radiusClients: [], radiusSettings: {}, authEvents: [], audit: [],
  }

  let nameCursor = 0
  for (const ts of TENANT_SEEDS) {
    const t = ts.id
    data.tenants.push({
      id: t, slug: ts.slug, name: ts.name, domain: ts.domain, status: ts.status,
      createdAt: ago((ts.status === 'setup' ? 3 : 200 + Math.floor(rnd() * 300)) * DAY),
      health: {
        radius: ts.radius,
        pki: 'ok',
        directory: ts.directory,
        lastDirectorySync: ts.lastSyncAgo === null ? null : ago(ts.lastSyncAgo),
        authzSnapshotAgeSeconds: ts.radius === 'unconfigured' ? null : Math.round((ts.lastSyncAgo ?? 0) / 1000 / 8) + 4,
      },
    })

    // Directory groups
    const g = (key: string, name: string) => ({ id: `${t}:g-${key}`, tenantId: t, name, dn: `CN=${name},OU=Groups,DC=${ts.domain.split('.').join(',DC=')}`, sid: `S-1-5-21-${Math.floor(rnd() * 1e9)}-${Math.floor(rnd() * 1e9)}-${1100 + Math.floor(rnd() * 900)}`, memberCount: 0 })
    const groups = [
      g('du', 'Domain Users'), g('mgmt', 'Management'), g('it', 'IT Department'), g('net', 'Network Team'),
      g('wh', 'Warehouse Staff'), g('guest', 'Guests'), g('contract', 'Contractors'), g('former', 'Former Employees'),
    ]
    data.groups.push(...groups)
    const G = Object.fromEntries(groups.map((x) => [x.id.split(':g-')[1], x.id])) as Record<string, string>

    // VLANs
    const vlan = (vid: number, name: string, color: Vlan['color'], description: string): Vlan => ({ id: `${t}:v${vid}`, tenantId: t, vlanId: vid, name, color, description })
    const vlans = [
      vlan(100, 'Corporate', 'blue', 'Standard staff network'),
      vlan(110, 'Management', 'violet', 'Leadership and finance systems'),
      vlan(120, 'IT Infrastructure', 'teal', 'Administrative access to network gear'),
      vlan(130, 'Warehouse Floor', 'orange', 'Scanners and floor terminals'),
      vlan(150, 'Guest & Contractor', 'amber', 'Internet only, isolated'),
    ]
    data.vlans.push(...vlans)

    // Rules
    const rule = (id: string, name: string, priority: number, action: AccessRule['action'], groupKeys: string[], vid: number | null, description: string, extra: AccessRule['extraAttributes'] = []): AccessRule => ({
      id: `${t}:r-${id}`, tenantId: t, name, priority, enabled: true, action, groupIds: groupKeys.map((k) => G[k]), purposes: [], vlanId: vid === null ? null : `${t}:v${vid}`, extraAttributes: extra, description,
    })
    data.rules.push(
      rule('former', 'Block former employees', 1, 'deny', ['former'], null, 'Offboarded staff keep no Wi-Fi access even while still in other groups.'),
      rule('it', 'IT staff to infrastructure VLAN', 10, 'allow', ['it', 'net'], 120, 'Includes the nested Network Team group.', [{ name: 'Session-Timeout', value: '28800' }]),
      rule('mgmt', 'Management VLAN', 20, 'allow', ['mgmt'], 110, ''),
      rule('wh', 'Warehouse floor devices', 30, 'allow', ['wh'], 130, ''),
      rule('guest', 'Guests and contractors', 40, 'allow', ['guest', 'contract'], 150, 'Internet-only VLAN.'),
      rule('du', 'All staff', 90, 'allow', ['du'], 100, 'Catch-all for every domain user.'),
    )
    data.defaults[t] = { defaultAction: 'deny', defaultVlanId: null, maxSnapshotAgeSeconds: 86_400 }

    // CAs
    const short = ts.name.split(' ')[0]
    const rootId = `${t}:ca-root`
    const issId = `${t}:ca-iss`
    data.cas.push(
      { id: rootId, tenantId: t, role: 'root', commonName: `${short} Root CA`, subject: `CN=${short} Root CA,O=${ts.name},C=US`, keyAlgorithm: 'ecdsa-p384', notBefore: ago(400 * DAY), notAfter: ahead((3650 - 400) * DAY), offline: true, serial: hex(rnd, 16), fingerprintSha256: hex(rnd, 32), crl: { lastIssued: ago(40 * DAY), nextUpdate: ahead(140 * DAY), number: 3, url: `http://pki.${ts.domain}/crl/root.crl` }, ocsp: null },
      { id: issId, tenantId: t, role: 'issuing', commonName: `${short} Issuing CA 1`, subject: `CN=${short} Issuing CA 1,O=${ts.name},C=US`, keyAlgorithm: 'ecdsa-p256', notBefore: ago(399 * DAY), notAfter: ahead((1825 - 399) * DAY), offline: false, serial: hex(rnd, 16), fingerprintSha256: hex(rnd, 32), crl: { lastIssued: ago(2 * HOUR + 14 * 60_000), nextUpdate: ahead(21 * HOUR), number: 412 + Math.floor(rnd() * 60), url: `http://pki.${ts.domain}/crl/issuing-1.crl` }, ocsp: { enabled: true, url: `http://pki.${ts.domain}/ocsp` } },
    )

    // Templates
    const tpl = (id: string, name: string, purpose: CertificateTemplate['purpose'], days: number, renew: number, eku: string[], subject: string, san: string[]): CertificateTemplate => ({ id: `${t}:tpl-${id}`, tenantId: t, name, purpose, keyAlgorithm: 'ecdsa-p256', validityDays: days, renewBeforeDays: renew, extendedKeyUsage: eku, keyUsage: ['digitalSignature'], subjectPattern: subject, sanPattern: san, allowClientKeyGeneration: true, allowServerKeyGeneration: purpose !== 'radius-server' })
    data.templates.push(
      tpl('user', 'User Wi-Fi', 'user', 365, 30, ['clientAuth'], 'CN={upn}', ['upn:{upn}', 'email:{email}']),
      tpl('device', 'Device Wi-Fi', 'device', 730, 45, ['clientAuth'], 'CN={device}.{domain}', ['dns:{device}.{domain}']),
      tpl('radius', 'RADIUS Server', 'radius-server', 397, 30, ['serverAuth'], 'CN=radius.{domain}', ['dns:radius.{domain}']),
    )

    // RADIUS
    data.radiusSettings[t] = { tenantId: t, serverHostname: `radius.${ts.domain}`, authPort: 1812, acctPort: 1813, dedicatedPorts: false, tlsMinVersion: '1.2', sessionTimeoutSeconds: 28_800, tlsSessionCache: false, requireMessageAuthenticator: true, serverCertificateId: null }
    const nasDefs: Array<[string, RadiusClient['vendor'], string, string, boolean, number, RadiusClient['status'], number | null]> =
      ts.status === 'setup' ? [] : t === 't-harborview'
        ? [
            ['HQ Catalyst 9800-40', 'cisco-9800', '10.20.0.10', 'Headquarters', true, 1700, 'ok', 14_000],
            ['Warehouse UniFi Network', 'unifi', '10.40.0.2', 'Distribution centre', false, 3799, 'ok', 52_000],
            ['Riverside branch WLC 5520', 'cisco-aireos', '10.30.0.5', 'Riverside branch', true, 3799, 'degraded', 3.2 * HOUR],
          ]
        : [[`${short} Catalyst 9800-L`, 'cisco-9800', `10.${50 + data.tenants.length}.0.10`, 'Main campus', true, 1700, 'ok', 40_000]]
    nasDefs.forEach(([name, vendor, address, site, coa, port, status, last], i) => {
      data.radiusClients.push({ id: `${t}:nas-${i}`, tenantId: t, name, vendor, address, secretSetAt: ago((30 + i * 47) * DAY), coaEnabled: coa, coaPort: port, site, lastRequestAt: last === null ? null : ago(last), status })
    })

    // Identities, devices and certificates
    const tenantIdentities: Identity[] = []
    for (let i = 0; i < ts.users; i++) {
      // First pass pairs FIRST[i] with LAST[i]; later passes shift the surname so every name is new.
      const first = FIRST[nameCursor % FIRST.length]
      const last = LAST[(nameCursor + Math.floor(nameCursor / LAST.length) * 5) % LAST.length]
      nameCursor++
      const baseUsername = `${first[0]}${last}`.toLowerCase().normalize('NFD').replace(/[^a-z]/g, '')
      let username = baseUsername
      for (let n = 2; tenantIdentities.some((u) => u.username === username); n++) username = `${baseUsername}${n}` // as AD would
      const roll = rnd()
      const groupIds = [G.du]
      let department = 'Operations'
      let title = 'Coordinator'
      if (i % 9 === 0) { groupIds.push(G.it, G.net); department = 'IT'; title = 'Network Engineer' }
      else if (i % 7 === 0) { groupIds.push(G.it); department = 'IT'; title = 'Systems Administrator' }
      else if (i % 6 === 0) { groupIds.push(G.mgmt); department = 'Leadership'; title = pick(['Director of Operations', 'Finance Manager', 'Regional Manager']) }
      else if (i % 4 === 0) { groupIds.push(G.wh); department = 'Warehouse'; title = 'Floor Supervisor' }
      else if (i % 11 === 5) { groupIds.splice(0, 1, G.contract); department = 'External'; title = 'Contractor' }
      if (i === 13 || i === 29) { groupIds.push(G.former) }
      const accountState: Identity['accountState'] = i === 13 ? 'disabled' : i === 22 ? 'locked' : i === 31 ? 'deleted' : 'enabled'
      const id = `${t}:u-${username}`
      const ident: Identity = {
        id, tenantId: t, source: i === ts.users - 1 && ts.users > 6 ? 'local' : 'ad', displayName: `${first} ${last}`, username,
        upn: `${username}@${ts.domain}`, email: `${first.toLowerCase().normalize('NFD').replace(/[^a-z]/g, '')}.${last.toLowerCase().normalize('NFD').replace(/[^a-z]/g, '')}@${ts.domain.replace(/^(corp|ad)\./, '')}`,
        department, title, accountState, groupIds,
        lastAuthAt: roll < 0.85 && ts.status !== 'setup' ? ago(Math.floor(rnd() * 30 * HOUR)) : null,
        lastSyncedAt: ts.lastSyncAgo === null ? null : ago(ts.lastSyncAgo), objectGuid: hex(rnd, 16),
      }
      tenantIdentities.push(ident)
      data.identities.push(ident)
      if (ts.status === 'setup') continue

      const deviceCount = i % 10 === 3 ? 0 : 1 + Math.floor(rnd() * (department === 'IT' ? 3 : 2.2))
      const platforms: Platform[] = department === 'Warehouse' ? ['android', 'windows', 'android'] : ['windows', 'ios', 'macos', 'android', 'linux']
      for (let d = 0; d < deviceCount; d++) {
        const platform = platforms[(i + d) % platforms.length]
        const devName = { windows: 'Laptop', macos: 'MacBook', ios: 'iPhone', android: platform === 'android' && department === 'Warehouse' ? 'Scanner' : 'Pixel', linux: 'Workstation' }[platform]
        const deviceId = `${id}:d${d}`
        data.devices.push({ id: deviceId, tenantId: t, identityId: id, name: `${first}'s ${devName}`, platform, createdAt: ago((20 + Math.floor(rnd() * 300)) * DAY), lastSeenMac: mac(rnd) })

        // Certificate lifecycle distribution
        const issuedAgo = (10 + Math.floor(rnd() * 340)) * DAY
        let notAfterMs = DEMO_NOW.getTime() - issuedAgo + 365 * DAY
        const r = rnd()
        let status: Certificate['status'] = 'active'
        let revokedAt: string | null = null
        let revocationReason: Certificate['revocationReason'] = null
        if (i === 13 || (r < 0.06 && d > 0)) { status = 'revoked'; revokedAt = ago(Math.floor(rnd() * 60) * DAY + 3 * HOUR); revocationReason = i === 13 ? 'affiliationChanged' : pick<NonNullable<Certificate["revocationReason"]>>(["keyCompromise", "superseded", "cessationOfOperation"]) }
        else if (r < 0.12) { notAfterMs = DEMO_NOW.getTime() - (2 + Math.floor(rnd() * 40)) * DAY; status = 'expired' }
        else if (r < 0.26) { notAfterMs = DEMO_NOW.getTime() + (1 + Math.floor(rnd() * 28)) * DAY; status = 'expiring' }
        const serial = hex(rnd, 16)
        const tplId = platform === 'android' && department === 'Warehouse' ? `${t}:tpl-device` : `${t}:tpl-user`
        data.certificates.push({
          id: `${t}:c-${serial.slice(0, 10)}`, tenantId: t, serial, subject: `CN=${ident.upn}`, commonName: ident.upn ?? username,
          sans: [`upn:${ident.upn}`, `email:${ident.email}`], templateId: tplId, issuerCaId: issId, identityId: id, deviceId,
          notBefore: iso(notAfterMs - 365 * DAY), notAfter: iso(notAfterMs), status, keyAlgorithm: 'ecdsa-p256',
          keyOrigin: platform === 'windows' ? 'device' : platform === 'ios' || platform === 'macos' ? 'browser' : platform === 'linux' ? 'csr' : rnd() < 0.5 ? 'browser' : 'server',
          fingerprintSha256: hex(rnd, 32), revokedAt, revocationReason, revokedBy: revokedAt ? 'm.okafor@brightline.example' : null,
        })
      }
    }
    for (const grp of groups) grp.memberCount = tenantIdentities.filter((u) => u.groupIds.includes(grp.id)).length

    // RADIUS server certificate
    if (ts.status !== 'setup') {
      const serial = hex(rnd, 16)
      const certId = `${t}:c-${serial.slice(0, 10)}`
      data.certificates.push({ id: certId, tenantId: t, serial, subject: `CN=radius.${ts.domain}`, commonName: `radius.${ts.domain}`, sans: [`dns:radius.${ts.domain}`], templateId: `${t}:tpl-radius`, issuerCaId: issId, identityId: null, deviceId: null, notBefore: ago(120 * DAY), notAfter: ahead(277 * DAY), status: 'active', keyAlgorithm: 'ecdsa-p256', keyOrigin: 'server', fingerprintSha256: hex(rnd, 32), revokedAt: null, revocationReason: null, revokedBy: null })
      data.radiusSettings[t].serverCertificateId = certId
    }

    // Authentication events over the last 24h, weighted to working hours
    const nas = data.radiusClients.filter((n) => n.tenantId === t)
    const certsByIdentity = new Map<string, Certificate[]>()
    for (const c of data.certificates.filter((c) => c.tenantId === t && c.identityId)) {
      certsByIdentity.set(c.identityId!, [...(certsByIdentity.get(c.identityId!) ?? []), c])
    }
    const ssids = t === 't-harborview' ? ['HV-Secure', 'HV-Secure', 'HV-Floor'] : [`${short}-Secure`]
    for (let e = 0; e < ts.events; e++) {
      let offset = Math.floor(rnd() * 24 * HOUR)
      const hourOfDay = new Date(DEMO_NOW.getTime() - offset).getUTCHours()
      if ((hourOfDay < 12 || hourOfDay > 23) && rnd() < 0.6) offset = Math.floor(rnd() * 6 * HOUR) // UTC 12-23 ≈ US working day
      const user = pick(tenantIdentities)
      const certs = certsByIdentity.get(user.id) ?? []
      const cert = certs.length ? pick(certs) : null
      const nasClient = nas.length ? (rnd() < 0.08 && nas[2] ? nas[2] : pick(nas.slice(0, 2).length ? nas.slice(0, 2) : nas)) : null
      let failure: FailureCode | null = null
      if (!cert) failure = rnd() < 0.5 ? 'unknown_ca' : 'client_timeout'
      else if (cert.status === 'revoked') failure = 'cert_revoked'
      else if (cert.status === 'expired') failure = 'cert_expired'
      else if (user.accountState !== 'enabled') failure = 'account_disabled'
      else if (user.groupIds.includes(G.former)) failure = 'policy_deny'
      else if (rnd() < 0.025) failure = 'vlan_assignment'
      else if (rnd() < 0.02) failure = 'tls_handshake'
      const vlanKey = user.groupIds.includes(G.it) || user.groupIds.includes(G.net) ? 120 : user.groupIds.includes(G.mgmt) ? 110 : user.groupIds.includes(G.wh) ? 130 : user.groupIds.includes(G.contract) ? 150 : 100
      const ruleKey = { 120: 'it', 110: 'mgmt', 130: 'wh', 150: 'guest', 100: 'du' }[vlanKey]
      const device = cert ? data.devices.find((d) => d.id === cert.deviceId) : null
      data.authEvents.push({
        id: `${t}:ev-${e}`, tenantId: t, at: ago(offset), result: failure && failure !== 'vlan_assignment' ? 'reject' : failure ? 'reject' : 'accept',
        identityId: user.id, username: user.upn, deviceId: device?.id ?? null, certSerial: cert?.serial ?? (failure === 'unknown_ca' ? hex(rnd, 12) : null),
        callingStationId: device?.lastSeenMac ?? mac(rnd), calledStationId: `${mac(rnd)}:${pick(ssids)}`, nasClientId: nasClient?.id ?? null, ssid: pick(ssids),
        vlanId: failure ? null : `${t}:v${vlanKey}`, ruleId: failure === 'policy_deny' ? `${t}:r-former` : failure ? null : `${t}:r-${ruleKey}`, failureCode: failure,
        rawMessage: failure ? RAW[failure] : null,
      })
    }
  }
  data.authEvents.sort((a, b) => b.at.localeCompare(a.at))
  // "Last authentication" always agrees with the RADIUS log.
  const latest = new Map<string, string>()
  for (const e of data.authEvents) if (e.identityId && !latest.has(e.identityId)) latest.set(e.identityId, e.at)
  for (const ident of data.identities) ident.lastAuthAt = latest.get(ident.id) ?? null

  // Audit trail (platform + Harborview)
  const auditRows: Array<[number, string | null, string, string, string, string]> = [
    [9 * 60_000, 't-harborview', 'm.okafor@brightline.example', 'certificate.issue', 'Priya Natarajan · iPhone', 'User Wi-Fi certificate issued; key generated on device'],
    [37 * 60_000, 't-harborview', 'system', 'directory.sync', 'corp.harborview.example', '42 users, 8 groups synchronised; 1 user marked deleted'],
    [2 * HOUR + 14 * 60_000, 't-harborview', 'system', 'pki.crl.publish', 'Harborview Issuing CA 1', 'CRL published after revocation'],
    [2 * HOUR + 15 * 60_000, 't-harborview', 'j.becker@brightline.example', 'certificate.revoke', 'Owen Doyle · Laptop', 'Revoked: key compromise (device reported stolen). CoA disconnect sent to HQ Catalyst 9800-40'],
    [5 * HOUR, 't-harborview', 'j.becker@brightline.example', 'policy.rule.update', 'IT staff to infrastructure VLAN', 'Added nested group Network Team'],
    [26 * HOUR, 't-northgate', 'system', 'directory.sync.failed', 'ad.northgate.example', 'LDAPS bind failed: certificate verify failed (unable to get local issuer certificate)'],
    [28 * HOUR, 't-harborview', 'm.okafor@brightline.example', 'radius.client.rotate_secret', 'Warehouse UniFi Network', 'Shared secret rotated'],
    [3 * DAY, 't-atlas', 'a.reid@brightline.example', 'tenant.create', 'Atlas Fabrication', 'Tenant created; PKI initialised with offline root'],
    [4 * DAY, null, 'a.reid@brightline.example', 'admin.role.grant', 's.costa@cedarridge.example', 'Granted Wi-Fi Administrator on Cedar Ridge Medical Group'],
  ]
  auditRows.forEach(([a, t, actor, action, target, detail], i) => data.audit.push({ id: `au-${i}`, tenantId: t, at: ago(a), actor, action, target, detail }))
  return data
}

const RAW: Record<FailureCode, string> = {
  unknown_ca: 'eap_tls: ERROR: TLS Alert read:fatal:unknown CA',
  cert_expired: 'eap_tls: ERROR: (TLS) OpenSSL says error 10 : certificate has expired',
  cert_revoked: 'eap_tls: ERROR: (TLS) OpenSSL says error 23 : certificate revoked',
  cert_unknown: 'easyeap_authz: serial not present in authorization snapshot',
  identity_unauthorized: 'easyeap_authz: no allow rule matched identity groups',
  account_disabled: 'easyeap_authz: identity account_state=disabled',
  policy_deny: 'easyeap_authz: deny rule matched (Block former employees)',
  vlan_assignment: 'Accounting: Tunnel-Private-Group-ID not applied by NAS (client placed on default interface)',
  snapshot_stale: 'easyeap_authz: snapshot age 91844s exceeds max 86400s',
  tls_handshake: 'eap_tls: ERROR: TLS Alert read:fatal:handshake failure',
  client_timeout: 'eap: ERROR: Client stopped responding mid-handshake (no EAP-Response for 30s)',
  network_not_enabled: 'easyeap: wired request from a client registered for wireless only',
  mab_unsupported: 'easyeap: MAC authentication bypass request (Service-Type = Call-Check)',
  network_unknown: 'easyeap: neither wired nor wireless could be determined from the request',
}
