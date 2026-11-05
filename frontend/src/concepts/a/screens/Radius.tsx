import { useMemo, useState } from 'react'
import { DropdownMenu } from 'radix-ui'
import { Ellipsis, FileBadge, Plus, RotateCw, Router, SquareTerminal, TriangleAlert } from 'lucide-react'
import type { RadiusClient } from '@/domain/types'
import { vendorLabels } from '@/domain/explain'
import { cn, formatDuration, formatSerial } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { HealthPill } from '../ui/badges'
import { DataTable, useDataTable, type TableColumn } from '../ui/DataTable'
import { Button, EmptyState, IconButton, KeyValues, Mono, PageHeader, Panel, Pill, SettingsGrid } from '../ui/primitives'
import { usePortalContainer } from '../ui/portal'
import { AddControllerDialog, RotateSecretDialog } from '../features/ControllerDialogs'
import { ConfigSnippet } from '../features/ConfigSnippet'
import { useLookups } from '../lib/model'
import { ago, day, expiryText } from '../lib/time'
import { useNav } from '../shell/nav'

function RowMenu({ c, onRotate, onConfigure }: { c: RadiusClient; onRotate: () => void; onConfigure: () => void }) {
  const container = usePortalContainer()
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="a-icon-btn" aria-label={`More actions for ${c.name}`}>
        <Ellipsis aria-hidden />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <DropdownMenu.Content align="end" sideOffset={4} className="a-menu a-overlay-glass">
          <DropdownMenu.Item className="a-menu-item" onSelect={onConfigure}>
            <SquareTerminal aria-hidden /> Show configuration
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="a-menu-sep" />
          <DropdownMenu.Item className="a-menu-item a-menu-item-danger" onSelect={onRotate}>
            <RotateCw aria-hidden /> Rotate shared secret
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

const Yes = ({ children }: { children: string }) => <Pill tone="ok">{children}</Pill>
const No = ({ children }: { children: string }) => <Pill tone="neutral">{children}</Pill>

export function Radius() {
  const d = useTenantData()
  const { current } = useTenants()
  const { entityId, navigate } = useNav()
  const { caById } = useLookups()
  const [addOpen, setAddOpen] = useState(false)
  const [rotateId, setRotateId] = useState<string | null>(null)
  const s = d.radiusSettings
  const serverCert = s?.serverCertificateId ? d.certificates.find((c) => c.id === s.serverCertificateId) : undefined
  const selected = d.radiusClients.find((c) => c.id === entityId) ?? d.radiusClients[0] ?? null
  const rotate = d.radiusClients.find((c) => c.id === rotateId) ?? null
  const select = (c: RadiusClient) => navigate('radius', c.id)

  const columns = useMemo<TableColumn<RadiusClient>[]>(
    () => [
      {
        key: 'name',
        header: 'Controller',
        sortValue: (c) => c.name,
        cell: (c) => (
          <div className="min-w-0">
            <button type="button" onClick={() => navigate('radius', c.id)} className="block max-w-[260px] truncate text-left text-[14px] font-medium text-[var(--a-text)] underline-offset-[3px] hover:underline">
              {c.name}
            </button>
            <span className="block text-[12px] text-[var(--a-text-3)]">{c.site}</span>
          </div>
        ),
      },
      { key: 'vendor', header: 'Vendor', sortValue: (c) => vendorLabels[c.vendor], className: 'hidden md:table-cell', cell: (c) => <span className="whitespace-nowrap">{vendorLabels[c.vendor]}</span> },
      { key: 'address', header: 'Address', sortValue: (c) => c.address, cell: (c) => <Mono className="whitespace-nowrap">{c.address}</Mono> },
      { key: 'coa', header: 'CoA', sortValue: (c) => (c.coaEnabled ? c.coaPort : -1), cell: (c) => (c.coaEnabled ? <span className="a-num whitespace-nowrap text-[var(--a-text-2)]">On · UDP {c.coaPort}</span> : <span className="text-[var(--a-text-3)]">Off</span>) },
      { key: 'secret', header: 'Shared secret', className: 'hidden lg:table-cell', sortValue: (c) => c.secretSetAt, cell: (c) => <span className="a-num whitespace-nowrap">Rotated {ago(c.secretSetAt)}</span> },
      { key: 'last', header: 'Last request', sortValue: (c) => c.lastRequestAt, cell: (c) => <span className={cn('a-num whitespace-nowrap', (c.status === 'degraded' || c.status === 'down') && 'text-[var(--a-warn-text)]')}>{c.lastRequestAt ? ago(c.lastRequestAt) : 'Waiting for first request'}</span> },
      { key: 'status', header: 'Status', sortValue: (c) => c.status, cell: (c) => <HealthPill state={c.status} label={c.status === 'unconfigured' ? 'Awaiting traffic' : undefined} /> },
      {
        key: 'actions',
        header: 'Actions',
        srHeader: true,
        align: 'right',
        cell: (c) => (
          <div className="a-row-actions">
            <span className="a-row-hover">
              <IconButton label={`Rotate shared secret for ${c.name}`} icon={RotateCw} onClick={() => setRotateId(c.id)} />
            </span>
            <RowMenu c={c} onRotate={() => setRotateId(c.id)} onConfigure={() => navigate('radius', c.id)} />
          </div>
        ),
      },
    ],
    [navigate],
  )
  const table = useDataTable(d.radiusClients, columns, { initialSort: { key: 'name', dir: 'asc' } })
  const degraded = d.radiusClients.filter((c) => c.status === 'degraded' || c.status === 'down')

  return (
    <>
      <PageHeader
        title="RADIUS"
        description={
          <>
            FreeRADIUS for {current.name} · {d.radiusClients.length} wireless {d.radiusClients.length === 1 ? 'controller' : 'controllers'}
            {degraded.length > 0 && <span className="text-[var(--a-warn-text)]"> · {degraded.length} degraded</span>}
          </>
        }
        actions={
          <Button variant="primary" icon={Plus} onClick={() => setAddOpen(true)}>
            Add controller
          </Button>
        }
      />

      <div className="grid gap-4 xl:grid-cols-12">
        <Panel className="xl:col-span-7" title="Server settings" description="Applied to every controller in this tenant. RADIUS keeps authenticating if the web console restarts.">
          {s ? (
            <div className="px-[18px] pb-[18px]">
              <SettingsGrid
                items={[
                  { label: 'Server name', value: <Mono>{s.serverHostname}</Mono> },
                  { label: 'Ports', value: <span className="a-num">UDP {s.authPort} auth · {s.acctPort} acct</span>, hint: s.dedicatedPorts ? 'Dedicated to this tenant' : 'Shared listener, tenant chosen by controller address' },
                  { label: 'Minimum TLS', value: <span className="a-num">TLS {s.tlsMinVersion}</span>, hint: s.tlsMinVersion === '1.2' ? 'TLS 1.3 clients negotiate 1.3' : 'Older clients cannot connect' },
                  { label: 'Message-Authenticator', value: s.requireMessageAuthenticator ? <Yes>Required</Yes> : <No>Optional</No>, hint: 'Blocks forged Access-Requests (BlastRADIUS)' },
                  { label: 'TLS session cache', value: s.tlsSessionCache ? <Yes>On</Yes> : <No>Off</No>, hint: s.tlsSessionCache ? 'Roaming clients resume quickly' : 'Every connection does a full handshake' },
                  { label: 'Session timeout', value: <span className="a-num">{formatDuration(s.sessionTimeoutSeconds)}</span>, hint: 'Clients reauthenticate at least this often' },
                ]}
              />
            </div>
          ) : (
            <EmptyState icon={Router} title="RADIUS not configured" />
          )}
        </Panel>

        <Panel className="xl:col-span-5" title="Server certificate" description="Devices check this name before sending their certificate.">
          {serverCert ? (
            <div className="px-[18px] pb-3">
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <HealthPill state={serverCert.status === 'active' ? 'ok' : 'degraded'} label={serverCert.status === 'active' ? 'Valid' : 'Renew soon'} />
                <span className="a-num text-[12px] text-[var(--a-text-3)]">{expiryText(serverCert.notAfter)}</span>
              </div>
              <KeyValues
                items={[
                  { label: 'Subject', value: <Mono className="break-all">{serverCert.subject}</Mono> },
                  { label: 'Issued by', value: caById.get(serverCert.issuerCaId)?.commonName ?? '—' },
                  { label: 'Expires', value: day(serverCert.notAfter) },
                  { label: 'Serial', value: <Mono className="text-[12px] break-all">{formatSerial(serverCert.serial)}</Mono> },
                ]}
              />
            </div>
          ) : (
            <EmptyState
              icon={FileBadge}
              title="No server certificate yet"
              action={
                <Button size="sm" onClick={() => navigate('certificates')}>
                  Open certificates
                </Button>
              }
            >
              Issue <Mono>radius.{current.domain}</Mono> from the issuing CA before controllers send traffic.
            </EmptyState>
          )}
        </Panel>
      </div>

      <section aria-label="Wireless controllers" className="a-panel a-depth-tenant mt-4">
        <header className="a-panel-head">
          <div>
            <h2 className="a-panel-title">Wireless controllers</h2>
            <p className="a-panel-desc">RADIUS clients allowed to send requests. Select one to see its configuration.</p>
          </div>
          {degraded.length > 0 && (
            <p className="flex items-center gap-1.5 text-[13px] text-[var(--a-warn-text)]">
              <TriangleAlert className="size-4" aria-hidden />
              {degraded.map((c) => c.name).join(', ')}: no requests for {ago(degraded[0].lastRequestAt).replace(' ago', '')}
            </p>
          )}
        </header>
        <DataTable
          caption="Wireless controllers"
          columns={columns}
          table={table}
          rowKey={(c) => c.id}
          selectedKey={selected?.id}
          onRowClick={select}
          empty={
            <EmptyState icon={Router} title="No wireless controllers yet" action={<Button variant="primary" icon={Plus} onClick={() => setAddOpen(true)}>Add controller</Button>}>
              Register a Catalyst 9800, AireOS WLC or UniFi Network controller. EasyEAP generates its shared secret and the configuration to paste.
            </EmptyState>
          }
        />
      </section>

      <Panel className="mt-4" title={selected ? `Configure ${selected.name}` : 'Controller configuration'} description={selected ? `${vendorLabels[selected.vendor]} · ${selected.address} · ${selected.site}` : 'Generic configuration for a new controller.'}>
        <div className="px-[18px] pb-5">
          <ConfigSnippet controller={selected} />
        </div>
      </Panel>

      <AddControllerDialog open={addOpen} onOpenChange={setAddOpen} />
      {rotate && <RotateSecretDialog key={rotate.id} controller={rotate} open={!!rotateId} onOpenChange={(o) => !o && setRotateId(null)} />}
    </>
  )
}
