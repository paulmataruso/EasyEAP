// Copy-ready controller configuration for each supported vendor.
import type { NasVendor, RadiusClient, RadiusSettings } from '@/domain/types'

export interface Snippet {
  /** "Catalyst 9800 CLI" */
  label: string
  kind: 'cli' | 'steps'
  /** CLI text, or one string per step (may contain **bold** markers) */
  body: string | string[]
}

const SECRET_PLACEHOLDER = '<shared-secret>'

export function snippetFor(
  vendor: NasVendor,
  settings: RadiusSettings,
  opts: { client?: Pick<RadiusClient, 'coaEnabled' | 'coaPort' | 'name'>; secret?: string; ssid?: string },
): Snippet {
  const host = settings.serverHostname
  const ip = `<IP of ${host}>`
  const secret = opts.secret ?? SECRET_PLACEHOLDER
  const ssid = opts.ssid ?? 'Corp-Secure'
  const coa = opts.client?.coaEnabled ?? true
  const coaPort = opts.client?.coaPort ?? (vendor === 'cisco-9800' ? 1700 : 3799)

  switch (vendor) {
    case 'cisco-9800':
      return {
        label: 'Catalyst 9800 CLI',
        kind: 'cli',
        body: [
          'radius server EASYEAP',
          ` address ipv4 ${ip} auth-port ${settings.authPort} acct-port ${settings.acctPort}`,
          ` key 0 ${secret}`,
          '!',
          'aaa group server radius EASYEAP-GROUP',
          ' server name EASYEAP',
          '!',
          'aaa authentication dot1x EASYEAP-DOT1X group EASYEAP-GROUP',
          'aaa authorization network EASYEAP-AUTHZ group EASYEAP-GROUP',
          'aaa accounting identity EASYEAP-ACCT start-stop group EASYEAP-GROUP',
          ...(coa ? ['!', 'aaa server radius dynamic-author', ` client ${ip} server-key 0 ${secret}`, ` port ${coaPort}`] : []),
          '!',
          'wireless profile policy EASYEAP-POLICY',
          ' aaa-override',
          ' accounting-list EASYEAP-ACCT',
          ' no shutdown',
          '!',
          `wlan ${ssid} 1 ${ssid}`,
          ' security dot1x authentication-list EASYEAP-DOT1X',
          ' no shutdown',
        ].join('\n'),
      }
    case 'cisco-aireos':
      return {
        label: 'AireOS CLI',
        kind: 'cli',
        body: [
          `config radius auth add 1 ${ip} ${settings.authPort} ascii ${secret}`,
          `config radius acct add 1 ${ip} ${settings.acctPort} ascii ${secret}`,
          coa ? 'config radius auth rfc3576 enable 1' : 'config radius auth rfc3576 disable 1',
          'config radius auth network 1 enable',
          'config radius auth management 1 disable',
          'config wlan disable 1',
          'config wlan radius_server auth add 1 1',
          'config wlan radius_server acct add 1 1',
          'config wlan security wpa akm 802.1x enable 1',
          'config wlan aaa-override enable 1',
          'config wlan enable 1',
        ].join('\n'),
      }
    case 'unifi':
      return {
        label: 'UniFi Network steps',
        kind: 'steps',
        body: [
          'In UniFi Network, open **Settings > Profiles > RADIUS** and choose **Create New**.',
          `Name it **EasyEAP**. Authentication server: **${ip}**, port **${settings.authPort}**, shared secret **${secret}**.`,
          `Turn on **Accounting** with the same address on port **${settings.acctPort}**.`,
          'Turn on **RADIUS assigned VLAN support** for wireless networks.',
          `Open **Settings > WiFi > ${ssid}**, set Security to **WPA2/WPA3 Enterprise** and choose the **EasyEAP** profile.`,
          coa
            ? `Leave CoA on port **${coaPort}** so EasyEAP can disconnect revoked devices.`
            : 'CoA is off for this controller: a revoked device stays online until it reauthenticates.',
        ],
      }
    default:
      return {
        label: 'Generic RADIUS client',
        kind: 'steps',
        body: [
          `Point 802.1X authentication at **${ip}**, UDP **${settings.authPort}**, and accounting at UDP **${settings.acctPort}**.`,
          `Use the shared secret **${secret}** and send Message-Authenticator on every request.`,
          'Accept RFC 3580 VLAN attributes (Tunnel-Type, Tunnel-Medium-Type, Tunnel-Private-Group-ID).',
        ],
      }
  }
}

/** Generates a 32-character shared secret (shown once, never stored in the UI). */
export function generateSecret(length = 32): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

export const defaultCoaPort = (vendor: NasVendor) => (vendor === 'cisco-9800' ? 1700 : 3799)
