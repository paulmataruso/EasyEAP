import { useEffect, useMemo, useState } from 'react'
import { FileKey, Plus, RotateCw, Router, ShieldCheck, TriangleAlert } from 'lucide-react'
import { useTenantData } from '@/prototype/store'
import { vendorLabels } from '@/domain/explain'
import type { RadiusClient } from '@/domain/types'
import { formatDate, formatDuration } from '@/ui/lib'
import type { Intent } from '../app/context'
import { Button } from '../ui/Button'
import { CopyButton, Host, SnippetBlock } from '../ui/Code'
import { Cell, DataTable, toggleInSet, type ColumnDef } from '../ui/DataTable'
import { DefList, Empty, Lede, Note, Section, Specs } from '../ui/Layout'
import { HealthMark, StatusMark } from '../ui/Status'
import { AddControllerFlow } from '../parts/AddControllerFlow'
import { RotateSecretSheet } from '../parts/RotateSecretSheet'
import { snippetFor } from '../lib/snippets'
import { ageOf, formatFingerprint, plural, since, until } from '../lib/format'

export function RadiusScreen({ intent }: { intent: Intent }) {
  const d = useTenantData()
  const settings = d.radiusSettings
  const firstDegraded = d.radiusClients.find((c) => c.status === 'degraded' || c.status === 'down')
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set([intent.radius?.expand ?? firstDegraded?.id].filter((x): x is string => Boolean(x))))
  const [adding, setAdding] = useState(Boolean(intent.radius?.add))
  const [rotating, setRotating] = useState<RadiusClient | null>(null)
  const serverCert = d.certificates.find((c) => c.id === settings?.serverCertificateId)
  const issuer = d.cas.find((c) => c.id === serverCert?.issuerCaId)
  const ssid = useMemo(() => {
    const counts = new Map<string, number>()
    for (const e of d.authEvents) if (e.ssid) counts.set(e.ssid, (counts.get(e.ssid) ?? 0) + 1)
    return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0]
  }, [d.authEvents])

  useEffect(() => {
    const target = intent.radius?.expand ? 'c-radius-controllers' : intent.radius?.focus === 'server' ? 'c-radius-server' : null
    if (target) document.getElementById(target)?.scrollIntoView({ block: 'start' })
  }, [intent])

  const reporting = d.radiusClients.filter((c) => c.status === 'ok').length
  const quiet = d.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down')
  const pending = d.radiusClients.filter((c) => c.status === 'unconfigured')

  const columns: ColumnDef<RadiusClient>[] = [
    { key: 'name', header: 'Controller', cell: (c) => <Cell primary={c.name} secondary={c.site} /> },
    { key: 'vendor', header: 'Type', hide: 'lg', cell: (c) => <span className="c-muted">{vendorLabels[c.vendor]}</span> },
    { key: 'address', header: 'Address', hide: 'sm', cell: (c) => <span className="c-mono">{c.address}</span> },
    { key: 'coa', header: 'Disconnects', hide: 'md', cell: (c) => (c.coaEnabled ? <span className="tnum">CoA on, UDP {c.coaPort}</span> : <span className="c-faint">CoA off</span>) },
    { key: 'last', header: 'Last request', hide: 'md', cell: (c) => <span className="c-muted tnum">{c.lastRequestAt ? since(c.lastRequestAt) : 'Waiting for first'}</span> },
    { key: 'status', header: 'Status', cell: (c) => <HealthMark state={c.status} label={c.status === 'unconfigured' ? 'Not set up' : c.status === 'ok' ? 'Reporting' : undefined} /> },
  ]

  return (
    <>
      <Lede
        page="RADIUS"
        state={
          d.radiusClients.length === 0 ? (
            'No wireless controllers are registered yet.'
          ) : (
            <>
              <strong>
                {reporting} of {d.radiusClients.length}
              </strong>{' '}
              controllers are reporting.
            </>
          )
        }
        rest={
          d.radiusClients.length === 0
            ? `RADIUS is ready on UDP ${settings?.authPort ?? 1812}.`
            : quiet.length
              ? `${quiet[0].name} has been quiet for ${ageOf(quiet[0].lastRequestAt)}.`
              : pending.length
                ? `${plural(pending.length, 'controller is', 'controllers are')} waiting for a first request.`
                : 'All are sending requests.'
        }
        detail={settings ? `${settings.serverHostname} answers on UDP ${settings.authPort} (authentication) and ${settings.acctPort} (accounting), TLS ${settings.tlsMinVersion} or newer.` : undefined}
        actions={
          <Button variant="primary" icon={<Plus size={16} aria-hidden="true" />} onClick={() => setAdding(true)}>
            Add controller
          </Button>
        }
      />

      <Section id="c-radius-controllers" title="Wireless controllers" description="Only these addresses may send RADIUS requests. Open a row for its secret and configuration.">
        <DataTable
          caption="Wireless controllers"
          columns={columns}
          rows={d.radiusClients}
          rowKey={(c) => c.id}
          expanded={expanded}
          onToggle={(k) => setExpanded((s) => toggleInSet(s, k))}
          expandLabel={(c) => c.name}
          renderExpanded={(c) => (settings ? <ControllerDetail client={c} onRotate={() => setRotating(c)} ssid={ssid} /> : null)}
          empty={
            <Empty icon={Router} title="No controllers yet" action={<Button variant="secondary" icon={<Plus size={16} aria-hidden="true" />} onClick={() => setAdding(true)}>Add your first controller</Button>}>
              Register the Catalyst 9800, AireOS or UniFi controller that serves this tenant’s Wi-Fi. EasyEAP generates its shared secret and the configuration to paste in.
            </Empty>
          }
        />
      </Section>

      {settings ? (
        <Section id="c-radius-server" title="Server settings" description="Hardened defaults. RADIUS keeps authenticating even while the web console restarts.">
          <Specs
            items={[
              { label: 'Server name', value: <Host name={settings.serverHostname} /> },
              { label: 'Authentication port', value: <span className="tnum">UDP {settings.authPort}</span> },
              { label: 'Accounting port', value: <span className="tnum">UDP {settings.acctPort}</span> },
              { label: 'Minimum TLS version', value: `TLS ${settings.tlsMinVersion}` },
              { label: 'Message-Authenticator', value: settings.requireMessageAuthenticator ? 'Required on every request' : 'Optional' },
              { label: 'TLS session cache', value: settings.tlsSessionCache ? 'On (faster reconnects)' : 'Off (full handshake every time)' },
              { label: 'Session timeout', value: `${formatDuration(settings.sessionTimeoutSeconds)}, then reauthenticate` },
              { label: 'Ports', value: settings.dedicatedPorts ? 'Dedicated to this tenant' : 'Shared, tenant chosen by client address' },
            ]}
          />
        </Section>
      ) : null}

      <Section title="Server certificate" description="Devices check this certificate before they send their own. Wi-Fi profiles name it so a rogue access point cannot impersonate RADIUS.">
        {serverCert ? (
          <div className="c-split">
            <DefList
              items={[
                { label: 'Name', value: <span className="c-mono">{serverCert.commonName}</span> },
                { label: 'Issued by', value: issuer?.commonName ?? '—' },
                { label: 'Valid until', value: <span className="tnum">{formatDate(serverCert.notAfter)} ({until(serverCert.notAfter)})</span> },
                { label: 'SHA-256', value: <span className="c-mono c-small">{formatFingerprint(serverCert.fingerprintSha256)}</span> },
              ]}
            />
            <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
              <StatusMark tone="ok" icon={ShieldCheck} label="In use by RADIUS" sub={`renews ${until(new Date(new Date(serverCert.notAfter).getTime() - 30 * 864e5).toISOString())}`} />
              <div>
                <CopyButton text={serverCert.fingerprintSha256} label="Copy fingerprint" variant="secondary" />
              </div>
            </div>
          </div>
        ) : (
          <Empty icon={FileKey} title="No server certificate yet">
            EasyEAP issues {settings?.serverHostname ?? 'the server certificate'} from the issuing CA as part of setup. Until then RADIUS cannot complete EAP-TLS.
          </Empty>
        )}
      </Section>

      <AddControllerFlow open={adding} onOpenChange={setAdding} ssid={ssid} />
      <RotateSecretSheet client={rotating} onClose={() => setRotating(null)} />
    </>
  )
}

function ControllerDetail({ client: c, onRotate, ssid }: { client: RadiusClient; onRotate: () => void; ssid?: string }) {
  const d = useTenantData()
  const settings = d.radiusSettings!
  return (
    <div style={{ display: 'grid', gap: 24 }}>
      {c.status === 'degraded' || c.status === 'down' ? (
        <Note icon={TriangleAlert} tone="warn">
          <strong>No requests for {ageOf(c.lastRequestAt)}.</strong> Check that {c.address} can reach {settings.serverHostname} on UDP {settings.authPort}, and that the shared secret on the controller matches. A mismatched secret shows on the controller as “RADIUS server not responding”.
        </Note>
      ) : null}
      <div className="c-split" style={{ gap: 40 }}>
        <SnippetBlock snippet={snippetFor(c.vendor, settings, { client: c, ssid })} />
        <div style={{ display: 'grid', gap: 18, alignContent: 'start' }}>
          <DefList
            stacked
            items={[
              { label: 'Type', value: vendorLabels[c.vendor] },
              { label: 'Shared secret', value: `Set ${since(c.secretSetAt)}; never shown again` },
              { label: 'Disconnects', value: c.coaEnabled ? `CoA on UDP ${c.coaPort}: revoked devices are disconnected at once` : 'CoA off: revoked devices stay online until they reauthenticate' },
            ]}
          />
          <div>
            <Button variant="secondary" icon={<RotateCw size={16} aria-hidden="true" />} onClick={onRotate}>
              Rotate secret
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
