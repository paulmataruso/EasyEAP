import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Tabs } from 'radix-ui'
import { Check, Plus, RotateCw, Router, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { vendorLabels } from '@/domain/explain'
import type { NasVendor, RadiusClient, RadiusSettings } from '@/domain/types'
import { CertificateDataPage } from '../credential'
import { AddControllerDialog, RotateSecretDialog } from '../dialogs'
import { ago, formatSeconds, pushRecent } from '../lib'
import type { Navigate } from '../shell'
import { Btn, Chip, CopyButton, Empty, HealthChip, PageHeader, SectionHeader } from '../ui'

const IP = '<easyeap-radius-ip>'
const KEY = '<shared-secret>'

type SnippetVendor = 'cisco-9800' | 'cisco-aireos' | 'unifi'

function snippet(vendor: SnippetVendor, s: RadiusSettings, client: RadiusClient | undefined, ssids: string[]): string {
  const ssid = ssids[0] ?? 'Corp-Secure'
  const coaPort = client?.coaPort ?? (vendor === 'cisco-9800' ? 1700 : 3799)
  const coa = client ? client.coaEnabled : vendor !== 'unifi'
  if (vendor === 'cisco-9800') {
    return [
      `! ${client?.name ?? 'Catalyst 9800'} → EasyEAP (${s.serverHostname})`,
      'radius server EASYEAP',
      ` address ipv4 ${IP} auth-port ${s.authPort} acct-port ${s.acctPort}`,
      ` key ${KEY}`,
      '!',
      'aaa group server radius EASYEAP-GRP',
      ' server name EASYEAP',
      '!',
      'aaa authentication dot1x EASYEAP-DOT1X group EASYEAP-GRP',
      'aaa authorization network EASYEAP-AUTHZ group EASYEAP-GRP',
      'aaa accounting identity EASYEAP-ACCT start-stop group EASYEAP-GRP',
      ...(coa ? ['!', 'aaa server radius dynamic-author', ` client ${IP} server-key ${KEY}`, ` port ${coaPort}`] : []),
      '!',
      `wlan ${ssid} 1 ${ssid}`,
      ' security dot1x authentication-list EASYEAP-DOT1X',
      ' no shutdown',
      '!',
      `wireless profile policy ${ssid}-POLICY`,
      ' aaa-override',
      ' accounting-list EASYEAP-ACCT',
      ` session-timeout ${s.sessionTimeoutSeconds}`,
      ' no shutdown',
    ].join('\n')
  }
  if (vendor === 'cisco-aireos') {
    return [
      `# ${client?.name ?? 'AireOS WLC'} → EasyEAP (${s.serverHostname})`,
      `config radius auth add 1 ${IP} ${s.authPort} ascii ${KEY}`,
      `config radius acct add 1 ${IP} ${s.acctPort} ascii ${KEY}`,
      ...(coa ? ['config radius auth rfc3576 enable 1'] : ['config radius auth rfc3576 disable 1']),
      'config wlan disable <wlan-id>',
      'config wlan security wpa akm 802.1x enable <wlan-id>',
      'config wlan radius_server auth add <wlan-id> 1',
      'config wlan radius_server acct add <wlan-id> 1',
      'config wlan aaa-override enable <wlan-id>',
      `config wlan session-timeout <wlan-id> ${s.sessionTimeoutSeconds}`,
      'config wlan enable <wlan-id>',
    ].join('\n')
  }
  return [
    `UniFi Network → EasyEAP (${s.serverHostname})`,
    '',
    '1. Settings → Profiles → RADIUS → Create New',
    '   Name: EasyEAP',
    `   Authentication server: ${IP}  port ${s.authPort}  secret ${KEY}`,
    `   Accounting server: ${IP}  port ${s.acctPort}  secret ${KEY}`,
    '   Enable “RADIUS assigned VLAN” for wireless networks',
    `2. Settings → WiFi → ${ssids[1] ?? ssid} → Security`,
    '   Security protocol: WPA2/WPA3 Enterprise',
    '   RADIUS profile: EasyEAP',
    '3. Apply changes, then join with an enrolled device.',
    '',
    'UniFi Network does not accept CoA disconnects from EasyEAP: after a',
    'revocation, clients there drop at their next reauthentication.',
  ].join('\n')
}

function Highlighted({ text }: { text: string }) {
  const parts = text.split(/(<easyeap-radius-ip>|<shared-secret>|<wlan-id>)/g)
  return <>{parts.map((p, i) => (p.startsWith('<') && p.endsWith('>') ? <mark key={i}>{p}</mark> : <span key={i}>{p}</span>))}</>
}

const Setting = ({ k, v, note }: { k: string; v: ReactNode; note?: string }) => (
  <div className="grid grid-cols-[minmax(0,1fr)_auto] items-baseline gap-x-4 py-2.5">
    <dt className="text-[13px] f-ink-2">{k}{note && <span className="f-small f-ink-3 block">{note}</span>}</dt>
    <dd className="text-right text-[13.5px]">{v}</dd>
  </div>
)
const On = ({ on, yes = 'On', no = 'Off' }: { on: boolean; yes?: string; no?: string }) => (on ? <span className="inline-flex items-center gap-1.5"><Check className="size-3.5 text-[var(--f-valid)]" aria-hidden />{yes}</span> : <span className="inline-flex items-center gap-1.5 f-ink-2"><X className="size-3.5" aria-hidden />{no}</span>)

export function RadiusScreen({ entityId, navigate }: { entityId?: string; navigate: Navigate }) {
  const { current } = useTenants()
  const d = useTenantData()
  const s = d.radiusSettings
  const [adding, setAdding] = useState(false)
  const [rotating, setRotating] = useState<RadiusClient | null>(null)
  const selected = d.radiusClients.find((n) => n.id === entityId) ?? d.radiusClients.find((n) => n.status !== 'ok') ?? d.radiusClients[0]
  const [vendorTab, setVendorTab] = useState<SnippetVendor>('cisco-9800')
  useEffect(() => {
    if (selected && selected.vendor !== 'other') setVendorTab(selected.vendor)
  }, [selected?.id, selected?.vendor]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const n = d.radiusClients.find((x) => x.id === entityId)
    if (n) pushRecent(current.id, { kind: 'controller', id: n.id, label: n.name, sub: `${n.address} · ${n.site}` })
  }, [entityId, current.id, d.radiusClients])

  const serverCert = d.certificates.find((c) => c.id === s?.serverCertificateId)
  const ssids = useMemo(() => [...new Set(d.authEvents.map((e) => e.ssid).filter(Boolean) as string[])], [d.authEvents])
  const eventsVia = (id: string) => d.authEvents.filter((e) => e.nasClientId === id)

  return (
    <div>
      <PageHeader
        title="RADIUS"
        lede={s ? <>FreeRADIUS 3.2 · {s.serverHostname} · authorization snapshot {formatSeconds(current.health.authzSnapshotAgeSeconds)} old</> : 'Not configured'}
        actions={<Btn variant="primary" onClick={() => setAdding(true)}><Plus aria-hidden />Add controller</Btn>}
      />

      <div className="grid gap-x-10 gap-y-9 xl:grid-cols-12">
        <section className="min-w-0 xl:col-span-5" aria-labelledby="f-srv-h">
          <SectionHeader id="f-srv-h" title="Server settings" meta={<span className="inline-flex items-center gap-2">{current.health.radius === 'unconfigured' ? <HealthChip state="unconfigured" /> : <HealthChip state={current.health.radius} label="Server running" />}</span>} />
          {s && (
            <dl className="f-divide border-y border-[var(--f-line)]">
              <Setting k="Server name" note="Must match the server certificate" v={<span className="f-mono text-[12.5px]">{s.serverHostname}</span>} />
              <Setting k="Authentication port" v={<span className="f-num">UDP {s.authPort}</span>} />
              <Setting k="Accounting port" v={<span className="f-num">UDP {s.acctPort}</span>} />
              <Setting k="Minimum TLS version" v={<span className="f-num">TLS {s.tlsMinVersion}</span>} />
              <Setting k="Message-Authenticator" note="Rejects requests without it (Blast-RADIUS)" v={<On on={s.requireMessageAuthenticator} yes="Required" no="Optional" />} />
              <Setting k="TLS session cache" note="Off: every connection does a full handshake, so revocation is checked each time" v={<On on={s.tlsSessionCache} />} />
              <Setting k="Session timeout" note="Clients reauthenticate at least this often" v={<span className="f-num">{formatSeconds(s.sessionTimeoutSeconds)}</span>} />
              <Setting k="Fail-safe" note="Deny when authorization data is older than this" v={<span className="f-num">{formatSeconds(d.defaults.maxSnapshotAgeSeconds)}</span>} />
            </dl>
          )}
        </section>

        <section className="min-w-0 xl:col-span-7" aria-labelledby="f-srvcert-h">
          <SectionHeader id="f-srvcert-h" title="Server certificate" meta="Presented to every device during EAP-TLS" />
          {serverCert ? (
            <CertificateDataPage
              cert={serverCert}
              size="sm"
              ctx={{ tenant: current, issuer: d.cas.find((x) => x.id === serverCert.issuerCaId), template: d.templates.find((t) => t.id === serverCert.templateId) }}
            />
          ) : (
            <Empty title="No server certificate yet">Issue the RADIUS server certificate for {s?.serverHostname ?? 'this tenant'} before devices can trust the network. Devices check this name against their Wi-Fi profile.</Empty>
          )}
        </section>
      </div>

      <section className="mt-10" aria-labelledby="f-nas-h">
        <SectionHeader id="f-nas-h" title="Wireless controllers" meta={d.radiusClients.length ? `${d.radiusClients.filter((n) => n.status === 'ok').length} of ${d.radiusClients.length} healthy` : undefined} actions={d.radiusClients.length > 0 && <Btn size="sm" onClick={() => setAdding(true)}><Plus aria-hidden />Add controller</Btn>} />
        {d.radiusClients.length === 0 ? (
          <Empty icon={<Router />} title="No wireless controllers registered" action={<Btn variant="primary" onClick={() => setAdding(true)}><Plus aria-hidden />Add your first controller</Btn>}>
            RADIUS ignores requests from unknown addresses. Register each Catalyst 9800, AireOS WLC or UniFi Network controller to start authenticating.
          </Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="f-table">
              <caption className="sr-only">RADIUS clients. Select one to see its configuration snippet.</caption>
              <thead>
                <tr><th>Controller</th><th>Vendor</th><th>Address</th><th>CoA</th><th>Shared secret</th><th>Last request</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr>
              </thead>
              <tbody>
                {d.radiusClients.map((n) => {
                  const ev = eventsVia(n.id)
                  return (
                    <tr key={n.id} data-clickable="true" aria-selected={selected?.id === n.id} onClick={() => navigate('radius', n.id)}>
                      <td className="min-w-[200px]">
                        <button type="button" className="f-rowlink font-semibold hover:underline" onClick={(e) => { e.stopPropagation(); navigate('radius', n.id) }}>{n.name}</button>
                        <span className="f-small f-ink-3 block">{n.site} · {ev.length} requests in 24 h</span>
                      </td>
                      <td className="f-ink-2 whitespace-nowrap">{vendorLabels[n.vendor]}</td>
                      <td className="f-mono whitespace-nowrap text-[12.5px]">{n.address}</td>
                      <td className="whitespace-nowrap">{n.coaEnabled ? <span className="f-num">On · {n.coaPort}</span> : <span className="f-ink-3">Off</span>}</td>
                      <td className="f-ink-2 whitespace-nowrap">Set {ago(n.secretSetAt)}</td>
                      <td className={cn('whitespace-nowrap', n.status === 'degraded' && 'text-[var(--f-warn-ink)]')}>{ago(n.lastRequestAt)}</td>
                      <td>{n.status === 'unconfigured' ? <Chip tone="neutral">Waiting for first request</Chip> : <HealthChip state={n.status} />}</td>
                      <td className="f-right">
                        <Btn size="sm" variant="ghost" onClick={(e) => { e.stopPropagation(); setRotating(n) }} aria-label={`Rotate shared secret for ${n.name}`}><RotateCw aria-hidden />Rotate secret</Btn>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {s && (
        <section className="mt-10 grid gap-x-10 gap-y-6 xl:grid-cols-12" aria-labelledby="f-snip-h">
          <div className="xl:col-span-4">
            <SectionHeader id="f-snip-h" title={selected ? `Configure ${selected.name}` : 'Controller configuration'} />
            {selected?.status === 'degraded' && (
              <div className="mb-4 space-y-1.5 text-[13px]">
                <p className="flex items-center gap-2 font-semibold text-[var(--f-warn-ink)]"><HealthChip state="degraded" /></p>
                <p className="f-ink-2">Last request {ago(selected.lastRequestAt)}, while the other controllers report every few minutes. Check that the WLC can reach {s.serverHostname} on UDP {s.authPort} and that its shared secret matches; a mismatch shows as silence, not as rejects.</p>
              </div>
            )}
            <p className="f-small f-ink-2">Values come from this tenant’s server settings. Replace the highlighted placeholders: the address your controllers use to reach EasyEAP, and the shared secret you saved when you registered the controller. EasyEAP never shows a secret again.</p>
          </div>
          <div className="min-w-0 xl:col-span-8">
            <Tabs.Root value={vendorTab} onValueChange={(v) => setVendorTab(v as SnippetVendor)}>
              <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
                <Tabs.List className="f-seg" aria-label="Controller vendor">
                  {(['cisco-9800', 'cisco-aireos', 'unifi'] as NasVendor[]).map((v) => (
                    <Tabs.Trigger key={v} value={v} className="f-seg-item data-[state=active]:bg-[var(--f-raised-solid)] data-[state=active]:text-[var(--f-ink)] data-[state=active]:shadow-[inset_0_0_0_1px_var(--f-line-2)]">
                      {v === 'cisco-9800' ? 'Catalyst 9800 CLI' : v === 'cisco-aireos' ? 'AireOS CLI' : 'UniFi steps'}
                    </Tabs.Trigger>
                  ))}
                </Tabs.List>
                <CopyButton text={snippet(vendorTab, s, selected?.vendor === vendorTab ? selected : undefined, ssids)} what="configuration snippet" label="Copy snippet" />
              </div>
              {(['cisco-9800', 'cisco-aireos', 'unifi'] as SnippetVendor[]).map((v) => (
                <Tabs.Content key={v} value={v} className="f-code" tabIndex={0}>
                  <Highlighted text={snippet(v, s, selected?.vendor === v ? selected : undefined, ssids)} />
                </Tabs.Content>
              ))}
            </Tabs.Root>
          </div>
        </section>
      )}

      <AddControllerDialog open={adding} onOpenChange={setAdding} onAdded={(v) => v !== 'other' && setVendorTab(v)} />
      {rotating && <RotateSecretDialog client={rotating} open={!!rotating} onOpenChange={(o) => !o && setRotating(null)} />}
    </div>
  )
}
