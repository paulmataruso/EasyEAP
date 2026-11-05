import { useCallback, useMemo, useState } from 'react'
import { Code, Eye, KeyRound, Plus, RotateCw, Router, ShieldCheck } from 'lucide-react'
import { now, useActions, useTenantData, useTenants } from '@/prototype/store'
import { vendorLabels } from '@/domain/explain'
import type { RadiusClient } from '@/domain/types'
import { daysUntil, formatDate, formatDuration } from '@/ui/lib'
import { PageHeader } from '../ui/PageHeader'
import { EmptyState, KeyValue, Panel, PanelHead } from '../ui/Panel'
import { Button } from '../ui/Button'
import { StatusText } from '../ui/Badge'
import { Drawer } from '../ui/Drawer'
import { Confirm } from '../ui/Confirm'
import { DataTable, useDataTable, type ColumnDef } from '../ui/DataTable'
import { useToast } from '../ui/Toast'
import { AddControllerDrawer } from '../features/AddControllerDrawer'
import { ConfigSnippet } from '../features/ConfigSnippet'
import { generateSecret, SecretReveal } from '../features/SecretReveal'
import { useInspector } from '../shell/Inspectors'
import { useIntent } from '../shell/context'
import { formatAge, secondsSince } from '../lib/format'
import { healthLabel, healthTone } from '../lib/status'
import { keyAlgorithmLabels } from '../lib/labels'

export function RadiusScreen() {
  const { current } = useTenants()
  const d = useTenantData()
  const { rotateSecret } = useActions()
  const { openCertificate } = useInspector()
  const toast = useToast()
  const [adding, setAdding] = useState<{ open: boolean; seq: number }>({ open: false, seq: 0 })
  const [snippetId, setSnippetId] = useState<string | null>(null)
  const [rotateTarget, setRotateTarget] = useState<RadiusClient | null>(null)
  const [revealed, setRevealed] = useState<{ name: string; secret: string; open: boolean } | null>(null)
  useIntent('radius')

  const s = d.radiusSettings
  const serverCert = d.certificates.find((c) => c.id === s?.serverCertificateId)
  const issuer = serverCert ? d.cas.find((c) => c.id === serverCert.issuerCaId) : undefined
  const ssid = d.authEvents.find((e) => e.ssid)?.ssid ?? `${current.name.split(' ')[0]}-Secure`

  const showSnippet = useCallback((id: string) => {
    setSnippetId(id)
    requestAnimationFrame(() => document.getElementById('b-sec-snippet')?.scrollIntoView({ block: 'start' }))
  }, [])

  const columns = useMemo<ColumnDef<RadiusClient>[]>(
    () => [
      {
        id: 'name',
        header: 'Controller',
        sticky: true,
        sort: (n) => n.name,
        cell: (n) => (
          <span className="flex min-w-0 items-baseline gap-2">
            <span className="shrink-0 font-medium text-[var(--b-text)]">{n.name}</span>
            <span className="truncate text-[12px] text-[var(--b-text-3)]">{n.site}</span>
          </span>
        ),
      },
      { id: 'vendor', header: 'Vendor', sort: (n) => vendorLabels[n.vendor], cell: (n) => <span className="text-[var(--b-text-2)]">{vendorLabels[n.vendor]}</span> },
      { id: 'address', header: 'Address', sort: (n) => n.address, cell: (n) => <span className="b-mono text-[12px]">{n.address}</span> },
      {
        id: 'coa',
        header: 'CoA',
        sort: (n) => (n.coaEnabled ? 1 : 0),
        cell: (n) => (n.coaEnabled ? <span className="text-[var(--b-text)]">On <span className="b-num text-[var(--b-text-3)]">· UDP {n.coaPort}</span></span> : <span className="text-[var(--b-text-3)]">Off</span>),
      },
      {
        id: 'status',
        header: 'Status',
        sort: (n) => ['ok', 'degraded', 'down', 'unconfigured'].indexOf(n.status),
        cell: (n) => (
          <StatusText tone={healthTone[n.status]}>
            {n.status === 'unconfigured' ? 'Awaiting first request' : healthLabel[n.status]}
            {n.status === 'degraded' && n.lastRequestAt && <span className="text-[var(--b-text-2)]"> · silent {formatAge(secondsSince(n.lastRequestAt))}</span>}
          </StatusText>
        ),
      },
      { id: 'last', header: 'Last request', align: 'end', sort: (n) => n.lastRequestAt, cell: (n) => <span className="b-num text-[var(--b-text-2)]">{n.lastRequestAt ? `${formatAge(secondsSince(n.lastRequestAt))} ago` : 'Never'}</span> },
      {
        id: 'secret',
        header: 'Shared secret',
        align: 'end',
        sort: (n) => n.secretSetAt,
        cell: (n) => {
          const age = n.secretSetAt > now().toISOString() ? 0 : Math.floor((secondsSince(n.secretSetAt) ?? 0) / 86400)
          return <span className={`b-num ${age > 180 ? 'b-ink-warn' : 'text-[var(--b-text-2)]'}`}>{age === 0 ? 'set today' : `rotated ${age}d ago`}</span>
        },
      },
      {
        id: 'actions',
        header: '',
        width: 210,
        cell: (n) => (
          <span className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
            <Button size="sm" variant="ghost" icon={Code} onClick={() => showSnippet(n.id)}>
              Config
            </Button>
            <Button size="sm" variant="ghost" icon={RotateCw} onClick={() => setRotateTarget(n)}>
              Rotate secret
            </Button>
          </span>
        ),
      },
    ],
    [showSnippet],
  )
  const table = useDataTable(d.radiusClients, columns, { initialSort: { key: 'name', dir: 'asc' } })

  return (
    <>
      <PageHeader
        title="RADIUS"
        context={`FreeRADIUS 3.2 for ${current.name} · authenticates independently of this console`}
        actions={
          <Button variant="primary" icon={Plus} onClick={() => setAdding((a) => ({ open: true, seq: a.seq + 1 }))}>
            Add controller
          </Button>
        }
      />
      <div className="mb-3 grid gap-3 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <Panel id="b-sec-server" aria-labelledby="srv-title">
          <PanelHead id="srv-title" title="Server settings" meta={s?.serverHostname} />
          {s ? (
            <div className="grid gap-x-6 px-3 pt-1 pb-3 md:grid-cols-2">
              <KeyValue
                labelWidth="128px"
                rows={[
                  ['Server name', <span key="h" className="b-mono break-all">{s.serverHostname}</span>],
                  ['Authentication', <span key="a" className="b-num">UDP {s.authPort}</span>],
                  ['Accounting', <span key="ac" className="b-num">UDP {s.acctPort}</span>],
                  ['Port mode', s.dedicatedPorts ? 'Dedicated to this tenant' : 'Shared, routed by client address'],
                ]}
              />
              <KeyValue
                labelWidth="150px"
                rows={[
                  ['TLS minimum', `TLS ${s.tlsMinVersion}`],
                  ['Message-Authenticator', s.requireMessageAuthenticator ? <StatusText key="m" tone="ok">Required</StatusText> : <StatusText key="m" tone="warn">Not required</StatusText>],
                  ['TLS session cache', s.tlsSessionCache ? 'On (resumed sessions skip revocation checks)' : 'Off · full check on every connection'],
                  ['Session timeout', <span key="t" className="b-num">{formatDuration(s.sessionTimeoutSeconds)} ({s.sessionTimeoutSeconds.toLocaleString('en-US')} s)</span>],
                ]}
              />
              <p className="b-t3 mt-2 text-[12px] md:col-span-2">
                Message-Authenticator is required on every request, which blocks forged responses. Session timeout bounds how long a revoked device can stay connected on a controller without CoA.
              </p>
            </div>
          ) : (
            <p className="b-t2 p-3">RADIUS has not been initialised for this tenant.</p>
          )}
        </Panel>
        <Panel aria-labelledby="cert-title">
          <PanelHead
            id="cert-title"
            title="Server certificate"
            actions={
              serverCert && (
                <Button size="sm" variant="ghost" icon={Eye} onClick={() => openCertificate(serverCert.id)}>
                  Details
                </Button>
              )
            }
          />
          {serverCert ? (
            <div className="px-3 pt-1 pb-3">
              <KeyValue
                labelWidth="110px"
                rows={[
                  ['Subject', <span key="s" className="b-mono break-all">{serverCert.subject}</span>],
                  ['Issued by', issuer?.commonName ?? '—'],
                  ['Key', keyAlgorithmLabels[serverCert.keyAlgorithm]],
                  [
                    'Valid until',
                    <span key="v">
                      {formatDate(serverCert.notAfter)} <span className="b-t3">· {daysUntil(serverCert.notAfter, now())} days left</span>
                    </span>,
                  ],
                  ['SHA-256', <span key="f" className="b-mono text-[11.5px] break-all text-[var(--b-text-2)]">{serverCert.fingerprintSha256.slice(0, 32)}…</span>],
                ]}
              />
              <p className="mt-2 flex items-start gap-2 text-[12px] text-[var(--b-text-2)]">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-[var(--b-cyan)]" aria-hidden />
                Enrolled devices pin this name and the {d.cas.find((c) => c.role === 'root')?.commonName}; renewing keeps both, so devices reconnect without changes.
              </p>
            </div>
          ) : (
            <EmptyState icon={KeyRound} title="No server certificate yet">
              Devices verify the RADIUS server before sending their certificate. EasyEAP issues <span className="b-mono text-[var(--b-text)]">{s?.serverHostname ?? 'the server certificate'}</span> from the issuing CA when RADIUS setup is completed.
            </EmptyState>
          )}
        </Panel>
      </div>

      <Panel id="b-sec-controllers" aria-labelledby="ctl-title" className="mb-3">
        <PanelHead id="ctl-title" title="Wireless controllers" meta={d.radiusClients.length ? `${d.radiusClients.length} registered as RADIUS clients` : undefined} />
        {d.radiusClients.length === 0 ? (
          <EmptyState
            icon={Router}
            title="No controllers registered"
            action={
              <Button variant="primary" icon={Plus} onClick={() => setAdding((a) => ({ open: true, seq: a.seq + 1 }))}>
                Add controller
              </Button>
            }
          >
            Add the Catalyst 9800, AireOS WLC or UniFi controller that serves {current.name}’s secure SSID. EasyEAP generates its shared secret and the configuration to paste.
          </EmptyState>
        ) : (
          <DataTable table={table} label="Wireless controllers" noun="controllers" rowKey={(n) => n.id} rowLabel={(n) => n.name} isActive={(n) => n.id === (snippetId ?? d.radiusClients[0]?.id)} onActivate={(n) => showSnippet(n.id)} />
        )}
      </Panel>

      <Panel id="b-sec-snippet" aria-labelledby="snip-title">
        <PanelHead id="snip-title" title="Configuration snippet" meta="copy-ready for the selected controller" />
        <div className="p-3">
          {s && <ConfigSnippet controllers={d.radiusClients} selectedId={snippetId} onSelect={setSnippetId} settings={s} tenant={current} ssid={ssid} />}
        </div>
      </Panel>

      <AddControllerDrawer
        key={adding.seq}
        open={adding.open}
        onOpenChange={(open) => setAdding((a) => ({ ...a, open }))}
        onConfigure={(address) => {
          const found = d.radiusClients.find((c) => c.address === address)
          if (found) showSnippet(found.id)
          else requestAnimationFrame(() => document.getElementById('b-sec-snippet')?.scrollIntoView({ block: 'start' }))
        }}
      />
      <Confirm
        open={rotateTarget !== null}
        onOpenChange={(o) => !o && setRotateTarget(null)}
        title={`Rotate the shared secret for ${rotateTarget?.name ?? ''}?`}
        confirmLabel="Rotate secret"
        onConfirm={() => {
          if (!rotateTarget) return
          rotateSecret(rotateTarget.id)
          setRevealed({ name: rotateTarget.name, secret: generateSecret(), open: true })
          toast({ tone: 'ok', title: `Secret rotated for ${rotateTarget.name}`, description: 'Audit entry recorded (radius.client.rotate_secret).' })
          setRotateTarget(null)
        }}
      >
        <p>The old secret stops working immediately. Requests from this controller fail until you paste the new secret into its RADIUS server{rotateTarget?.coaEnabled ? ' and CoA client' : ''} entry.</p>
        <p>Do this when you can update the controller straight away.</p>
      </Confirm>
      {revealed && (
        <Drawer key={revealed.secret} open={revealed.open} onOpenChange={(open) => setRevealed((r) => (r ? { ...r, open } : r))} width={500} title="New shared secret" description={revealed.name} footer={<Button variant="primary" className="ml-auto" onClick={() => setRevealed((r) => (r ? { ...r, open: false } : r))}>Done, hide secret</Button>}>
          <SecretReveal secret={revealed.secret} controllerName={revealed.name} />
        </Drawer>
      )}
    </>
  )
}

