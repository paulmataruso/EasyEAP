import { Tabs } from 'radix-ui'
import type { NasVendor, RadiusClient, RadiusSettings, Tenant } from '@/domain/types'
import { codeText, nasCode, siteCode } from '../model/codes'
import { CopyButton } from '../ui/Controls'

type SnippetVendor = 'cisco-9800' | 'cisco-aireos' | 'unifi'
const TAB_LABEL: Record<SnippetVendor, string> = { 'cisco-9800': 'Catalyst 9800 CLI', 'cisco-aireos': 'AireOS CLI', unifi: 'UniFi steps' }

function ssidFor(t: Tenant) {
  return t.id === 't-harborview' ? 'HV-Secure' : `${t.name.split(' ')[0]}-Secure`
}

function cat9800(t: Tenant, s: RadiusSettings, nas: RadiusClient | null, label: string) {
  const site = siteCode(t)
  return `! EasyEAP · ${t.name} · ${nas ? `${nas.name} (${label})` : 'new controller'}
radius server EASYEAP-${site}
 address ipv4 <RADIUS-IP> auth-port ${s.authPort} acct-port ${s.acctPort}
 key 0 <shared-secret>
!
aaa new-model
aaa group server radius EASYEAP
 server name EASYEAP-${site}
!
aaa authentication dot1x EASYEAP-DOT1X group EASYEAP
aaa authorization network EASYEAP-AUTHZ group EASYEAP
aaa accounting identity EASYEAP-ACCT start-stop group EASYEAP
!${nas?.coaEnabled !== false ? `
aaa server radius dynamic-author
 client <RADIUS-IP> server-key 0 <shared-secret>
 port ${nas?.coaPort ?? 1700}
!` : ''}
wlan ${ssidFor(t)} 1 ${ssidFor(t)}
 security dot1x authentication-list EASYEAP-DOT1X
 no shutdown
!
wireless profile policy EASYEAP-POLICY
 aaa-override
 accounting-list EASYEAP-ACCT
 no shutdown`
}

function aireos(t: Tenant, s: RadiusSettings, nas: RadiusClient | null, label: string) {
  return `# EasyEAP · ${t.name} · ${nas ? `${nas.name} (${label})` : 'new controller'}
config radius auth add 1 <RADIUS-IP> ${s.authPort} ascii <shared-secret>
config radius acct add 1 <RADIUS-IP> ${s.acctPort} ascii <shared-secret>${nas?.coaEnabled !== false ? `
config radius auth rfc3576 enable 1` : ''}
config wlan disable <wlan-id>
config wlan radius_server auth add <wlan-id> 1
config wlan radius_server acct add <wlan-id> 1
config wlan security wpa akm 802.1x enable <wlan-id>
config wlan aaa-override enable <wlan-id>
config wlan enable <wlan-id>
save config`
}

function unifiSteps(t: Tenant, s: RadiusSettings): string[] {
  return [
    `Settings → Profiles → RADIUS → Create New. Name it “EasyEAP ${siteCode(t)}”.`,
    `Authentication server: <RADIUS-IP>, port ${s.authPort}, shared secret <shared-secret>.`,
    `Enable RADIUS accounting: <RADIUS-IP>, port ${s.acctPort}, same secret.`,
    'Turn on “RADIUS assigned VLAN support” for wireless networks.',
    `WiFi → ${ssidFor(t)} → Security: WPA2/WPA3 Enterprise, RADIUS profile “EasyEAP ${siteCode(t)}”.`,
    'Apply, then join with an enrolled device and confirm the VLAN in the client list.',
  ]
}

/** Copy-ready configuration for the selected controller's vendor. Secrets are never printed. */
export function ConfigSnippet({ tenant, settings, nas, all, vendor, onVendor }: { tenant: Tenant; settings: RadiusSettings; nas: RadiusClient | null; all: RadiusClient[]; vendor: NasVendor; onVendor: (v: SnippetVendor) => void }) {
  const tab: SnippetVendor = vendor === 'other' ? 'cisco-9800' : vendor
  const label = nas ? codeText(nasCode(nas, all)) : ''
  const text = tab === 'cisco-9800' ? cat9800(tenant, settings, nas, label) : tab === 'cisco-aireos' ? aireos(tenant, settings, nas, label) : unifiSteps(tenant, settings).map((s, i) => `${i + 1}. ${s}`).join('\n')
  return (
    <Tabs.Root value={tab} onValueChange={(v) => onVendor(v as SnippetVendor)}>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <Tabs.List className="d-tabs-list" aria-label="Controller vendor">
          {(Object.keys(TAB_LABEL) as SnippetVendor[]).map((v) => <Tabs.Trigger key={v} value={v} className="d-tab">{TAB_LABEL[v]}</Tabs.Trigger>)}
        </Tabs.List>
        <CopyButton text={text} what={`${TAB_LABEL[tab]} configuration`} label="Copy configuration" small />
      </div>
      {(['cisco-9800', 'cisco-aireos'] as const).map((v) => (
        <Tabs.Content key={v} value={v} className="mt-3">
          <pre className="d-code" tabIndex={0} aria-label={`${TAB_LABEL[v]} configuration`}>{text}</pre>
        </Tabs.Content>
      ))}
      <Tabs.Content value="unifi" className="mt-3">
        <ol className="d-rows max-w-[75ch]">
          {unifiSteps(tenant, settings).map((s, i) => (
            <li key={i} className="grid grid-cols-[28px_minmax(0,1fr)] py-2 text-[13.5px]">
              <span className="tnum text-[var(--d-ink-3)]">{i + 1}</span>
              <span>{s}</span>
            </li>
          ))}
        </ol>
      </Tabs.Content>
      <p className="mt-3 text-[12.5px] text-[var(--d-ink-2)]">
        Replace <span className="mono text-[var(--d-ink)]">&lt;RADIUS-IP&gt;</span> with the address that serves <span className="mono">{settings.serverHostname}</span>, and <span className="mono text-[var(--d-ink)]">&lt;shared-secret&gt;</span> with the secret shown once when the controller was registered or rotated. EasyEAP never displays a stored secret.
      </p>
    </Tabs.Root>
  )
}
