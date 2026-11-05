import { CircleAlert, KeyRound, Plus, RadioTower, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import type { NasVendor, RadiusClient } from '@/domain/types'
import { vendorLabels } from '@/domain/explain'
import { useTenantData, useTenants } from '@/prototype/store'
import { useConceptActions } from '../model/actions'
import { formatDate, formatDuration } from '@/ui/lib'
import type { ScreenId } from '../../contract'
import { codeText, nasCode, siteCode } from '../model/codes'
import { relTime } from '../model/derive'
import { useViewState } from '../model/state'
import { AddControllerForm, generateSecret } from '../flows/AddControllerForm'
import { ConfigSnippet } from '../flows/ConfigSnippet'
import { CopyButton } from '../ui/Controls'
import { EmptyState, KV, MetaSep, Notice, PageHeader, Section } from '../ui/Section'
import { HealthMark, Remaining, StatusMark } from '../ui/Status'
import { DataTable, type TableColumn } from '../ui/Table'
import { CertTape, NasTape, Tape } from '../ui/Tape'
import { useToast } from '../ui/Toast'

type Nav = (s: ScreenId, id?: string) => void

export function Radius({ navigate }: { navigate: Nav }) {
  const { current } = useTenants()
  const d = useTenantData()
  const { rotateSecret } = useConceptActions()
  const toast = useToast()
  const vs = useViewState()
  const s = d.radiusSettings
  const [adding, setAdding] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState<string | null>(null)
  const [secret, setSecret] = useState<{ name: string; label: string; value: string; kind: 'new' | 'rotated' } | null>(null)
  const [snippetVendor, setSnippetVendor] = useState<NasVendor | null>(null)

  const clients = d.radiusClients
  const selected = clients.find((n) => n.id === vs.radiusSelected) ?? clients.find((n) => n.status !== 'ok') ?? clients[0] ?? null
  const serverCert = d.certificates.find((c) => c.id === s?.serverCertificateId)
  const site = siteCode(current)

  const columns: TableColumn<RadiusClient>[] = [
    { key: 'label', header: 'Label', cell: (n) => <NasTape nas={n} all={clients} size="sm" /> },
    {
      key: 'name', header: 'Controller',
      cell: (n) => <><button type="button" className="d-rowlink" onClick={() => { vs.setRadiusSelected(n.id); setSnippetVendor(null) }}>{n.name}</button><span className="d-sub">{n.site} · {vendorLabels[n.vendor]}</span></>,
    },
    { key: 'address', header: 'Address', cell: (n) => <span className="mono">{n.address}</span> },
    { key: 'coa', header: 'CoA', hideSm: true, cell: (n) => (n.coaEnabled ? <span className="tnum">UDP {n.coaPort}</span> : <span className="ink-3">Off</span>) },
    {
      key: 'secret', header: 'Shared secret', hideSm: true,
      cell: (n) => confirmRotate === n.id ? (
        <span className="flex flex-wrap items-center gap-2" role="group" aria-label={`Confirm rotating the secret for ${n.name}`}>
          <span className="text-[12.5px] text-[var(--d-warn)]">Requests fail until the controller has the new secret.</span>
          <button type="button" className="d-btn d-btn--sm d-btn--primary" autoFocus onClick={() => {
            rotateSecret(n.id)
            setSecret({ name: n.name, label: codeText(nasCode(n, clients)), value: generateSecret(), kind: 'rotated' })
            setConfirmRotate(null)
            toast({ title: `Secret rotated for ${n.name}`, description: 'Copy it into the controller now. It is shown once.' })
          }}>Rotate</button>
          <button type="button" className="d-btn d-btn--sm d-btn--ghost" onClick={() => setConfirmRotate(null)}>Cancel</button>
        </span>
      ) : (
        <span className="flex items-center gap-2">
          <span className="ink-2 text-[12.5px]">Set {relTime(n.secretSetAt).toLowerCase()}</span>
          <button type="button" className="d-btn d-btn--sm" onClick={() => setConfirmRotate(n.id)} aria-label={`Rotate shared secret for ${n.name}`}>Rotate</button>
        </span>
      ),
    },
    { key: 'last', header: 'Last request', cell: (n) => <span className={n.status === 'ok' ? 'ink-2' : ''}>{relTime(n.lastRequestAt)}</span> },
    { key: 'status', header: 'Status', align: 'right', cell: (n) => <HealthMark state={n.status} label={n.status === 'unconfigured' ? 'Awaiting first request' : undefined} /> },
  ]

  if (!s) return <EmptyState title="RADIUS isn’t provisioned for this tenant" />

  return (
    <>
      <PageHeader
        title="RADIUS"
        meta={<><span className="mono">{s.serverHostname}</span><MetaSep /><span className="tnum">UDP {s.authPort} / {s.acctPort}</span><MetaSep /><HealthMark state={current.health.radius} label={current.health.radius === 'ok' ? 'Authenticating' : undefined} /></>}
        actions={<button type="button" className="d-btn d-btn--primary" onClick={() => { setAdding(true); window.setTimeout(() => document.getElementById('nas-name')?.focus(), 30) }}><Plus aria-hidden="true" />Add controller</button>}
      />

      <Section id="server" title="Server settings" description="FreeRADIUS keeps authenticating from its last snapshot if the web console restarts.">
        <div className="d-grid-even pt-1">
          <KV items={[
            ['Server hostname', <span key="h" className="flex items-center justify-between gap-2"><span className="mono">{s.serverHostname}</span><CopyButton text={s.serverHostname} what="hostname" small iconOnly /></span>],
            ['Authentication', <span key="a" className="tnum">UDP {s.authPort}</span>],
            ['Accounting', <span key="c" className="tnum">UDP {s.acctPort}</span>],
            ['Listener', s.dedicatedPorts ? 'Dedicated ports for this tenant' : 'Shared listener; tenant chosen by controller address'],
            ['TLS minimum', `TLS ${s.tlsMinVersion}`],
            ['Message-Authenticator', s.requireMessageAuthenticator ? <StatusMark key="m" tone="ok">Required on every request</StatusMark> : <StatusMark key="m" tone="warn">Not required</StatusMark>],
            ['TLS session cache', s.tlsSessionCache ? 'On · resumed sessions skip the full handshake' : 'Off · every connection does a full handshake'],
            ['Session timeout', `${formatDuration(s.sessionTimeoutSeconds)} · devices reauthenticate at least this often`],
          ]} />
          <div>
            <h3 className="d-h3 pt-2 pb-2">Server certificate</h3>
            {serverCert ? (
              <div className="grid gap-3">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--d-line)] pb-3">
                  <span className="flex items-center gap-2.5"><CertTape cert={serverCert} /><span className="mono">{serverCert.commonName}</span></span>
                  <span className="flex items-baseline gap-2 text-[12.5px] text-[var(--d-ink-2)]">Remaining <Remaining cert={serverCert} /></span>
                </div>
                <KV items={[
                  ['Issuer', d.cas.find((c) => c.id === serverCert.issuerCaId)?.commonName ?? '—'],
                  ['Valid until', formatDate(serverCert.notAfter)],
                  ['SAN', <span key="san" className="mono">{serverCert.sans.join(', ')}</span>],
                  ['Key', serverCert.keyAlgorithm.toUpperCase()],
                ]} />
                <p className="text-[12.5px] text-[var(--d-ink-2)]">Every Wi-Fi profile names this host. Renewing keeps the name, so devices don’t need new profiles.</p>
              </div>
            ) : (
              <Notice tone="crit" icon={<CircleAlert aria-hidden="true" />}>
                <strong>No server certificate issued.</strong> Devices verify the RADIUS server before they send their own certificate, so EAP-TLS can’t start. Issue one for <span className="mono">{s.serverHostname}</span> from the issuing CA.
                <div className="mt-2"><button type="button" className="d-btn d-btn--sm" onClick={() => navigate('certificates')}>Open certificate authorities</button></div>
              </Notice>
            )}
          </div>
        </div>
      </Section>

      <Section
        id="controllers"
        title="Wireless controllers"
        description={clients.length ? `${clients.filter((n) => n.status === 'ok').length} of ${clients.length} answering. Select one to see its configuration below.` : undefined}
      >
        {adding && (
          <AddControllerForm
            onCancel={() => setAdding(false)}
            onCreated={(name, value) => {
              setAdding(false)
              setSecret({ name, label: `${site}·NAS·${String(clients.length + 1).padStart(2, '0')}`, value, kind: 'new' })
              toast({ title: `${name} registered`, description: 'Copy the shared secret into the controller now. It is shown once.' })
            }}
          />
        )}
        {secret && (
          <div className="grid gap-3 border-b border-[var(--d-line)] py-4" role="region" aria-label="Shared secret, shown once">
            <div className="flex flex-wrap items-center gap-2.5">
              <KeyRound aria-hidden="true" className="size-4 text-[var(--d-signal)]" />
              <span className="font-semibold">{secret.kind === 'new' ? 'Shared secret' : 'New shared secret'} for {secret.name}</span>
              <Tape code={secret.label} size="sm" />
            </div>
            <div className="d-secret">
              <span className="min-w-0 flex-1">{secret.value}</span>
              <CopyButton text={secret.value} what="shared secret" small />
            </div>
            <p className="flex items-start gap-2 text-[13px] text-[var(--d-ink-2)]">
              <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-[var(--d-warn)]" />
              This is the only time the secret is shown. EasyEAP keeps only a hash; if it’s lost, rotate it.
            </p>
            <div><button type="button" className="d-btn d-btn--sm" onClick={() => setSecret(null)}>I’ve saved it in the controller</button></div>
          </div>
        )}
        <DataTable
          caption="Wireless controllers"
          columns={columns}
          rows={clients}
          rowKey={(n) => n.id}
          selectedKey={selected?.id ?? null}
          onRowClick={(n) => { vs.setRadiusSelected(n.id); setSnippetVendor(null) }}
          empty={!adding && (
            <EmptyState icon={<RadioTower className="d-empty-icon" aria-hidden="true" />} title="No wireless controllers yet" action={<button type="button" className="d-btn d-btn--sm" onClick={() => setAdding(true)}>Add controller</button>}>
              Register the WLC or UniFi controller that will send RADIUS requests for {current.name}. You’ll get its shared secret once.
            </EmptyState>
          )}
        />
        {selected?.status === 'degraded' && (
          <div className="mt-3">
            <Notice tone="warn" icon={<TriangleAlert aria-hidden="true" />}>
              <strong>{selected.name} hasn’t sent a request {relTime(selected.lastRequestAt).toLowerCase()}.</strong> Other controllers answer every few minutes. Check its route to <span className="mono">{s.serverHostname}</span> on UDP {s.authPort}, then rotate the secret if it was recently replaced.
            </Notice>
          </div>
        )}
      </Section>

      <Section id="snippet" title="Controller configuration" description={selected ? <>Copy-ready configuration for <span className="text-[var(--d-ink)]">{selected.name}</span> ({codeText(nasCode(selected, clients))}).</> : 'Copy-ready configuration for a new controller.'}>
        <div className="pt-4">
          <ConfigSnippet tenant={current} settings={s} nas={selected} all={clients} vendor={snippetVendor ?? selected?.vendor ?? 'cisco-9800'} onVendor={setSnippetVendor} />
        </div>
      </Section>
    </>
  )
}
