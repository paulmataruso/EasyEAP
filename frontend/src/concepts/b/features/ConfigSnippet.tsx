import { useId, useState, type ReactNode } from 'react'
import { Tabs } from 'radix-ui'
import type { NasVendor, RadiusClient, RadiusSettings, Tenant } from '@/domain/types'
import { CopyButton } from '../ui/CopyButton'
import { Field, SelectBox } from '../ui/Field'
import { Notice } from '../ui/Panel'

type SnippetVendor = Exclude<NasVendor, 'other' | 'cisco-switch'>
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

interface Ctx {
  ip: string
  ssid: string
  tenant: Tenant
  settings: RadiusSettings
  coa: boolean
  coaPort: number
}

function catalyst(c: Ctx): string {
  return [
    `! EasyEAP: ${c.tenant.name} (Catalyst 9800, IOS-XE)`,
    `radius server EASYEAP`,
    ` address ipv4 ${c.ip} auth-port ${c.settings.authPort} acct-port ${c.settings.acctPort}`,
    ` key <shared-secret>`,
    `!`,
    `aaa group server radius EASYEAP-GRP`,
    ` server name EASYEAP`,
    `!`,
    `aaa authentication dot1x EASYEAP-DOT1X group EASYEAP-GRP`,
    `aaa authorization network EASYEAP-AUTHZ group EASYEAP-GRP`,
    `aaa accounting network EASYEAP-ACCT start-stop group EASYEAP-GRP`,
    ...(c.coa ? [`!`, `! CoA so revocations disconnect live sessions`, `aaa server radius dynamic-author`, ` client ${c.ip} server-key <shared-secret>`, ` port ${c.coaPort}`] : []),
    `!`,
    `wlan ${c.ssid} 1 ${c.ssid}`,
    ` security dot1x authentication-list EASYEAP-DOT1X`,
    ` no shutdown`,
    `!`,
    `wireless profile policy EASYEAP-POLICY`,
    ` aaa-override`,
    ` accounting-list EASYEAP-ACCT`,
    ` session-timeout ${c.settings.sessionTimeoutSeconds}`,
    ` no shutdown`,
  ].join('\n')
}

function aireos(c: Ctx): string {
  return [
    `# EasyEAP: ${c.tenant.name} (AireOS WLC). Server index 1, WLAN id 1.`,
    `config radius auth add 1 ${c.ip} ${c.settings.authPort} ascii <shared-secret>`,
    `config radius acct add 1 ${c.ip} ${c.settings.acctPort} ascii <shared-secret>`,
    ...(c.coa ? [`config radius auth rfc3576 enable 1`] : [`config radius auth rfc3576 disable 1`]),
    `config wlan disable 1`,
    `config wlan radius_server auth add 1 1`,
    `config wlan radius_server acct add 1 1`,
    `config wlan security wpa akm 802.1x enable 1`,
    `config wlan aaa-override enable 1`,
    `config wlan session-timeout 1 ${c.settings.sessionTimeoutSeconds}`,
    `config wlan enable 1`,
    `save config`,
  ].join('\n')
}

function unifi(c: Ctx): string {
  return [
    `# UniFi Network: ${c.tenant.name}`,
    `1. Settings › Profiles › RADIUS › Create New. Name: EasyEAP ${c.tenant.slug}`,
    `2. Authentication server: ${c.ip}  port ${c.settings.authPort}  secret <shared-secret>`,
    `3. Enable RADIUS accounting: ${c.ip}  port ${c.settings.acctPort}  secret <shared-secret>`,
    `4. Turn on "RADIUS assigned VLAN" for wireless networks.`,
    `5. WiFi › ${c.ssid} › Security: WPA2/WPA3 Enterprise, RADIUS profile: EasyEAP ${c.tenant.slug}`,
    `6. Apply. Clients verify the server as ${c.settings.serverHostname}.`,
    ...(c.coa ? [] : [`# CoA is off for this controller: revocations apply at the next reauthentication.`]),
  ].join('\n')
}

const BUILDERS: Record<SnippetVendor, (c: Ctx) => string> = { 'cisco-9800': catalyst, 'cisco-aireos': aireos, unifi }
const TAB_LABEL: Record<SnippetVendor, string> = { 'cisco-9800': 'Catalyst 9800 CLI', 'cisco-aireos': 'AireOS CLI', unifi: 'UniFi steps' }

/** Comments dimmed, placeholders highlighted, everything else as typed. */
function Highlighted({ text }: { text: string }) {
  return (
    <>
      {text.split('\n').map((line, i) => {
        const isComment = /^\s*[!#]/.test(line)
        const parts: ReactNode[] = line.split(/(<[a-z-]+>)/g).map((part, j) => (/^<[a-z-]+>$/.test(part) ? <span key={j} className="c-ph">{part}</span> : part))
        return (
          <span key={i} className={isComment ? 'c-comment' : undefined}>
            {parts}
            {'\n'}
          </span>
        )
      })}
    </>
  )
}

/** Copy-ready controller configuration for the selected vendor and controller. */
export function ConfigSnippet({ controllers, selectedId, onSelect, settings, tenant, ssid }: { controllers: RadiusClient[]; selectedId: string | null; onSelect: (id: string) => void; settings: RadiusSettings; tenant: Tenant; ssid: string }) {
  const ipId = useId()
  const ctlId = useId()
  const selected = controllers.find((c) => c.id === selectedId) ?? controllers[0]
  const [vendorOverride, setVendorOverride] = useState<SnippetVendor | null>(null)
  const [ip, setIp] = useState('')
  const vendor: SnippetVendor = vendorOverride ?? (selected && selected.vendor !== 'other' && selected.vendor !== 'cisco-switch' ? selected.vendor : 'cisco-9800')
  const ipValid = IPV4.test(ip.trim())
  const ctx: Ctx = { ip: ipValid ? ip.trim() : '<easyeap-ip>', ssid, tenant, settings, coa: selected?.coaEnabled ?? true, coaPort: selected?.coaPort ?? (vendor === 'cisco-9800' ? 1700 : 3799) }
  const text = BUILDERS[vendor](ctx)

  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Controller" htmlFor={ctlId}>
          <SelectBox
            id={ctlId}
            value={selected?.id ?? ''}
            placeholder="No controllers yet"
            disabled={!controllers.length}
            onChange={(v) => {
              setVendorOverride(null)
              onSelect(v)
            }}
            options={controllers.map((c) => ({ value: c.id, label: c.name, hint: c.address }))}
          />
        </Field>
        <Field label="EasyEAP RADIUS address" htmlFor={ipId} error={ip.trim() && !ipValid ? 'Enter the IPv4 address the controller reaches EasyEAP on, e.g. 10.20.0.25.' : null} hint={!ip.trim() ? 'Fills the address placeholder in the snippet.' : undefined}>
          <input id={ipId} className="b-input b-mono" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.20.0.25" inputMode="decimal" spellCheck={false} aria-invalid={ip.trim() && !ipValid ? true : undefined} />
        </Field>
      </div>
      <Tabs.Root value={vendor} onValueChange={(v) => setVendorOverride(v as SnippetVendor)}>
        <div className="flex flex-wrap items-center gap-2">
          <Tabs.List className="b-seg" aria-label="Vendor">
            {(Object.keys(BUILDERS) as SnippetVendor[]).map((v) => (
              <Tabs.Trigger key={v} value={v}>
                {TAB_LABEL[v]}
              </Tabs.Trigger>
            ))}
          </Tabs.List>
          <div className="ml-auto">
            <CopyButton text={text} label="Copy snippet" />
          </div>
        </div>
        {(Object.keys(BUILDERS) as SnippetVendor[]).map((v) => (
          <Tabs.Content key={v} value={v} className="mt-2">
            <pre className="b-code" tabIndex={0} aria-label={`${TAB_LABEL[v]} configuration`}>
              <Highlighted text={BUILDERS[v](ctx)} />
            </pre>
          </Tabs.Content>
        ))}
      </Tabs.Root>
      <Notice tone="neutral">
        <span className="b-mono text-[var(--b-warn)]">&lt;shared-secret&gt;</span> stays a placeholder: EasyEAP shows each secret once, when the controller is added or its secret is rotated.
      </Notice>
    </div>
  )
}
