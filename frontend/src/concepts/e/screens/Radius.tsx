import { useEffect, useMemo, useState } from 'react'
import { Plus, RotateCw, Router } from 'lucide-react'
import { useTenantData, useTenants, now } from '@/prototype/store'
import type { NasVendor, RadiusClient } from '@/domain/types'
import { vendorLabels } from '@/domain/explain'
import { daysUntil, formatDate, formatDuration, formatSerial } from '@/ui/lib'
import { DataTable } from '../DataTable'
import { Inspector, InspectorSection } from '../Inspector'
import { AddControllerForm, ConfigBlock, RotateSecretDialog } from '../flows'
import { buildRouteData } from '../routes'
import { INK, STATUS, ago, isSession, isSessionClient } from '../theme'
import { Button, EmptyState, PageHeader, Panel, Segmented, StatusMark, VolumeGlyph, useE, useScrollIntent } from '../ui'

const SNIPPET_VENDORS: Array<{ value: NasVendor; label: string }> = [
  { value: 'cisco-9800', label: 'Catalyst 9800 CLI' },
  { value: 'cisco-aireos', label: 'AireOS CLI' },
  { value: 'unifi', label: 'UniFi steps' },
]

export function Radius({ entityId }: { entityId?: string }) {
  const d = useTenantData()
  const { current } = useTenants()
  const { navigate } = useE()
  const s = d.radiusSettings
  const cert = d.certificates.find((c) => c.id === s?.serverCertificateId)
  const route = useMemo(() => buildRouteData(d.radiusClients, d.vlans, d.authEvents), [d.radiusClients, d.vlans, d.authEvents])
  const [panel, setPanel] = useState<{ kind: 'add' } | { kind: 'client'; id: string } | null>(entityId === 'new' ? { kind: 'add' } : entityId ? { kind: 'client', id: entityId } : null)
  const [rotate, setRotate] = useState<RadiusClient | null>(null)
  const [snippetVendor, setSnippetVendor] = useState<NasVendor>(d.radiusClients[0]?.vendor === 'other' ? 'cisco-9800' : d.radiusClients[0]?.vendor ?? 'cisco-9800')
  useEffect(() => { if (entityId === 'new') setPanel({ kind: 'add' }); else if (entityId) setPanel({ kind: 'client', id: entityId }) }, [entityId])
  useScrollIntent()

  const closePanel = () => { setPanel(null); if (entityId) navigate('radius') }
  const selected = panel?.kind === 'client' ? d.radiusClients.find((c) => c.id === panel.id) : undefined
  const volume = (id: string) => route.stations.find((x) => x.id === id)

  return (
    <>
      <PageHeader title="RADIUS" meta={<><span className="mono">{s?.serverHostname}</span><span aria-hidden className="t3">·</span><span>FreeRADIUS 3.2, EAP-TLS only</span><span aria-hidden className="t3">·</span><span>Keeps authenticating if the console or API restarts</span></>}
        actions={<Button variant="primary" onClick={() => setPanel({ kind: 'add' })}><Plus />Register controller</Button>} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Server settings" desc="Applies to every controller in this tenant.">
          {s && (
            <dl className="e-dl px-4 pb-3">
              <dt>Hostname</dt><dd className="mono">{s.serverHostname}</dd>
              <dt>Authentication port</dt><dd className="num">UDP {s.authPort}</dd>
              <dt>Accounting port</dt><dd className="num">UDP {s.acctPort}</dd>
              <dt>TLS minimum</dt><dd>TLS {s.tlsMinVersion}</dd>
              <dt>Message-Authenticator</dt><dd>{s.requireMessageAuthenticator ? <StatusMark state="ok" label="Required on every request" /> : <StatusMark state="degraded" label="Not required" />}</dd>
              <dt>TLS session cache</dt><dd>{s.tlsSessionCache ? 'On: faster reconnects' : 'Off: every connection re-checks revocation'}</dd>
              <dt>Session timeout</dt><dd className="num">{formatDuration(s.sessionTimeoutSeconds)} ({s.sessionTimeoutSeconds.toLocaleString('en-US')} s), then devices reauthenticate</dd>
            </dl>
          )}
        </Panel>
        <Panel title="Server certificate" desc="Devices check this name before sending their certificate.">
          {cert ? (
            <dl className="e-dl px-4 pb-3">
              <dt>Subject</dt><dd className="mono">{cert.subject}</dd>
              <dt>Status</dt><dd><StatusMark state={daysUntil(cert.notAfter, now()) < 30 ? 'degraded' : 'ok'} label={`Valid, ${daysUntil(cert.notAfter, now())} days left`} /></dd>
              <dt>Expires</dt><dd className="num">{formatDate(cert.notAfter)}</dd>
              <dt>Issuer</dt><dd>{d.cas.find((c) => c.id === cert.issuerCaId)?.commonName}</dd>
              <dt>Serial</dt><dd className="mono text-[12px]">{formatSerial(cert.serial).slice(0, 29)}…</dd>
              <dt>SAN</dt><dd className="mono text-[12px]">{cert.sans.join(', ')}</dd>
            </dl>
          ) : (
            <EmptyState icon={<Router />} title="No server certificate yet" body={`Issue one for ${s?.serverHostname ?? 'the RADIUS hostname'} before controllers can authenticate devices. It is signed by this tenant’s issuing CA.`} />
          )}
        </Panel>
      </div>

      <Panel id="controllers" className="mt-4" title="Wireless controllers" desc="RADIUS clients allowed to send requests. Line weight shows 24-hour volume on the same ramp as the route map."
        actions={<Button size="sm" variant="secondary" onClick={() => setPanel({ kind: 'add' })}><Plus />Register controller</Button>}>
        <DataTable
          caption="Wireless controllers"
          rows={d.radiusClients}
          rowKey={(c) => c.id}
          selectedKey={selected?.id}
          onActivate={(c) => { setPanel({ kind: 'client', id: c.id }); if (c.vendor !== 'other') setSnippetVendor(c.vendor) }}
          empty={<EmptyState icon={<Router />} title={`No controllers registered for ${current.name}`} body="Register the Catalyst 9800, AireOS WLC or UniFi Network controller that serves this site. EasyEAP generates its shared secret." action={<Button variant="primary" onClick={() => setPanel({ kind: 'add' })}><Plus />Register controller</Button>} />}
          columns={[
            { key: 'name', header: 'Controller', cell: (c) => (
              <div className="min-w-0 py-1.5">
                <button type="button" data-row-primary className="e-rowlink block max-w-full truncate" onClick={() => setPanel({ kind: 'client', id: c.id })}>{c.name}</button>
                <span className="t2 block text-[12px]">{vendorLabels[c.vendor]}</span>
              </div>
            ) },
            { key: 'status', header: 'Status', cell: (c) => <StatusMark state={c.status} label={c.status === 'unconfigured' ? 'Waiting for first request' : undefined} /> },
            { key: 'addr', header: 'Address', cell: (c) => <span className="mono">{c.address}</span> },
            { key: 'site', header: 'Site', hideBelow: 'lg', cell: (c) => <span className="t2">{c.site}</span> },
            { key: 'coa', header: 'CoA', hideBelow: 'md', cell: (c) => c.coaEnabled ? <span className="num">UDP {c.coaPort}</span> : <span className="t2">Off</span> },
            { key: 'secret', header: 'Secret rotated', hideBelow: 'xl', cell: (c) => <span className="t2">{ago(c.secretSetAt, isSession(`rot:${c.id}`) || isSessionClient(c.id))}</span> },
            { key: 'last', header: 'Last request', hideBelow: 'lg', cell: (c) => <span className={c.status === 'degraded' ? '' : 't2'}>{ago(c.lastRequestAt)}</span> },
            { key: 'vol', header: '24h volume', align: 'right', cell: (c) => { const v = volume(c.id); return <span className="inline-flex items-center gap-2"><VolumeGlyph count={v?.total ?? 0} form={v?.form} color={INK.station} /><span className="num w-8 text-right">{v?.total ?? 0}</span></span> } },
            { key: 'act', header: <span className="sr-only">Actions</span>, align: 'right', cell: (c) => <Button size="sm" variant="ghost" onClick={() => setRotate(c)} aria-label={`Rotate shared secret for ${c.name}`}><RotateCw />Rotate secret</Button> },
          ]}
        />
      </Panel>

      <Panel className="mt-4" title="Controller configuration" desc="Copy-ready settings for the selected vendor. Replace the highlighted placeholders; the shared secret is the one shown when the controller was registered or last rotated."
        actions={<Segmented label="Vendor" value={snippetVendor} onValueChange={setSnippetVendor} options={SNIPPET_VENDORS} />}>
        <div className="px-4 pb-4">
          <ConfigBlock vendor={snippetVendor} name={selected?.name ?? d.radiusClients.find((c) => c.vendor === snippetVendor)?.name ?? 'new controller'} coa={snippetVendor !== 'unifi'} coaPort={snippetVendor === 'cisco-9800' ? 1700 : 3799} />
        </div>
      </Panel>

      <Inspector open={panel?.kind === 'add'} onClose={closePanel} title="Register a wireless controller" subtitle={`Adds a RADIUS client to ${current.name}`} label="Register controller">
        <AddControllerForm key={String(panel?.kind === 'add')} onClose={closePanel} />
      </Inspector>

      {selected && (
        <Inspector open onClose={closePanel} title={selected.name} subtitle={`${selected.site} · ${vendorLabels[selected.vendor]}`} label="Controller detail"
          footer={<Button variant="secondary" onClick={() => setRotate(selected)}><RotateCw />Rotate secret</Button>}>
          <div className="mb-4"><StatusMark state={selected.status} label={selected.status === 'unconfigured' ? 'Waiting for first request' : undefined} /></div>
          {selected.status === 'degraded' && (
            <div className="e-callout mb-4" data-tone="warn">
              <div>
                <p className="font-semibold">No request for {ago(selected.lastRequestAt).replace(' ago', '')}</p>
                <p className="t2 mt-0.5">Check UDP {s?.authPort}/{s?.acctPort} from {selected.address} to {s?.serverHostname}, and that the controller’s shared secret matches. Its route-map line is drawn faded until it reports again.</p>
              </div>
            </div>
          )}
          <dl className="e-dl">
            <dt>Address</dt><dd className="mono">{selected.address}</dd>
            <dt>Vendor</dt><dd>{vendorLabels[selected.vendor]}</dd>
            <dt>CoA</dt><dd>{selected.coaEnabled ? `Enabled on UDP ${selected.coaPort}` : 'Off: revoked devices stay connected until they reauthenticate'}</dd>
            <dt>Shared secret</dt><dd>Set {ago(selected.secretSetAt, isSession(`rot:${selected.id}`) || isSessionClient(selected.id))}. Never shown again; rotate to replace.</dd>
            <dt>Last request</dt><dd>{ago(selected.lastRequestAt)}</dd>
            <dt>24h volume</dt><dd className="num">{volume(selected.id)?.total ?? 0} authentications · {STATUS[selected.status].label}</dd>
          </dl>
          <InspectorSection title="Configuration">
            <ConfigBlock vendor={selected.vendor} name={selected.name} coa={selected.coaEnabled} coaPort={selected.coaPort} />
          </InspectorSection>
        </Inspector>
      )}
      <RotateSecretDialog client={rotate} open={!!rotate} onOpenChange={(o) => !o && setRotate(null)} />
    </>
  )
}
