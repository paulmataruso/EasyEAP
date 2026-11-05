// Copy-ready controller configuration. Shared secrets are write-only in EasyEAP, so snippets
// carry a placeholder the admin replaces with the secret they stored when adding the controller.
import type { NasVendor, RadiusClient, RadiusSettings } from '@/domain/types'

export type SnippetVendor = Exclude<NasVendor, 'other'>

export interface SnippetInput {
  vendor: SnippetVendor
  settings: RadiusSettings
  controller: RadiusClient | null
  serverAddress: string
  ssid: string
  tenantName: string
}

export const SECRET_TOKEN = '<shared-secret>'
export const ADDRESS_TOKEN = '<easyeap-address>'

export interface Snippet {
  kind: 'cli' | 'steps'
  text: string
  steps?: Array<{ title: string; detail: string }>
}

export function buildSnippet({ vendor, settings, controller, serverAddress, ssid, tenantName }: SnippetInput): Snippet {
  const ip = serverAddress.trim() || ADDRESS_TOKEN
  const coaPort = controller?.coaPort ?? (vendor === 'cisco-9800' ? 1700 : 3799)
  const coa = controller ? controller.coaEnabled : vendor !== 'unifi'
  const name = controller?.name ?? 'new controller'
  if (vendor === 'cisco-9800') {
    const lines = [
      `! EasyEAP RADIUS for ${tenantName} (${name})`,
      `radius server EASYEAP`,
      ` address ipv4 ${ip} auth-port ${settings.authPort} acct-port ${settings.acctPort}`,
      ` key 0 ${SECRET_TOKEN}`,
      `!`,
      `aaa group server radius EASYEAP-GRP`,
      ` server name EASYEAP`,
      `!`,
      `aaa new-model`,
      `aaa authentication dot1x EASYEAP-DOT1X group EASYEAP-GRP`,
      `aaa authorization network EASYEAP-AUTHZ group EASYEAP-GRP`,
      `aaa accounting identity EASYEAP-ACCT start-stop group EASYEAP-GRP`,
      ...(coa ? [`!`, `aaa server radius dynamic-author`, ` client ${ip} server-key 0 ${SECRET_TOKEN}`, ` port ${coaPort}`] : []),
      `!`,
      `wlan ${ssid} 1 ${ssid}`,
      ` security dot1x authentication-list EASYEAP-DOT1X`,
      ` no shutdown`,
      `!`,
      `wireless profile policy default-policy-profile`,
      ` aaa-override`,
      ` accounting-list EASYEAP-ACCT`,
    ]
    return { kind: 'cli', text: lines.join('\n') }
  }
  if (vendor === 'cisco-aireos') {
    const lines = [
      `# EasyEAP RADIUS for ${tenantName} (${name}); replace <wlan-id> with the SSID's WLAN ID`,
      `config radius auth add 1 ${ip} ${settings.authPort} ascii ${SECRET_TOKEN}`,
      `config radius acct add 1 ${ip} ${settings.acctPort} ascii ${SECRET_TOKEN}`,
      ...(coa ? [`config radius auth rfc3576 enable 1`] : []),
      `config wlan disable <wlan-id>`,
      `config wlan security wpa akm 802.1x enable <wlan-id>`,
      `config wlan radius_server auth add <wlan-id> 1`,
      `config wlan radius_server acct add <wlan-id> 1`,
      `config wlan aaa-override enable <wlan-id>`,
      `config wlan enable <wlan-id>`,
    ]
    return { kind: 'cli', text: lines.join('\n') }
  }
  const steps = [
    { title: 'Create a RADIUS profile', detail: `Settings → Profiles → RADIUS → Create New. Name it “EasyEAP”.` },
    { title: 'Authentication server', detail: `IP ${ip}, port ${settings.authPort}, shared secret ${SECRET_TOKEN}.` },
    { title: 'Accounting server', detail: `Enable RADIUS accounting: IP ${ip}, port ${settings.acctPort}, same shared secret.` },
    { title: 'Dynamic VLANs', detail: 'Turn on “RADIUS Assigned VLAN Support” for wireless networks in the profile.' },
    { title: 'Attach to the SSID', detail: `WiFi → ${ssid} → Security: WPA2/WPA3 Enterprise, RADIUS profile “EasyEAP”. Apply.` },
  ]
  return {
    kind: 'steps',
    steps,
    text: steps.map((s, i) => `${i + 1}. ${s.title}: ${s.detail}`).join('\n'),
  }
}
