// RADIUS: server settings and certificate, wireless controllers and switches, agent status, CoA queue and guides.
// Intent parameters: ?add=1 opens "Add controller", ?add=switch "Add switch"; ?rotate=<clientId> opens "Rotate shared
// secret"; ?client=<clientId> selects a controller or switch. All are cleared.
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { DropdownMenu } from 'radix-ui'
import { BookOpen, ChevronDown, Ellipsis, EthernetPort, Logs, MonitorDown, Pencil, Plus, RotateCw, Router, Send, Trash2, Wifi } from 'lucide-react'
import { cn } from '@/ui/lib'
import { api } from '../api/client'
import { qk } from '../api/keys'
import { useCoa, useRadius, vendorLabels, type CoaRequest, type RadiusClient, type RadiusResponse, type Unattributed } from '../api/radius'
import { useTenant } from '../api/tenant'
import { radiusState, type Enforcement } from '../api/types'
import { ago, fmtDateTime } from '../lib/format'
import { pushRecent } from '../lib/recent'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Btn, Callout, Chip, Empty, ErrorState, HealthDot, LoadingBlock, PageHeader, Panel, SectionHeader, Skeleton, toast, type Tone } from '../ui'
import { AddControllerDialog, DeleteControllerDialog, EditControllerDialog, RotateSecretDialog } from './radius/Controllers'
import { DeviceSyslogPanel } from './radius/DeviceSyslog'
import { ControllerGuides } from './radius/Guide'
import { AddSwitchDialog, ModeChip, ServesChips, SwitchPanel, WiredKitDialog } from './radius/Switches'
import { GroupPolicyDialog } from './radius/GroupPolicy'
import { RadiusSettingsForm, ServerCertificateCard, SettingsSummary } from './radius/Settings'

export default function Radius() {
  const { tid, tenant, can } = useTenant()
  const q = useRadius(tid)
  const [params, setParams] = useSearchParams()
  const [adding, setAdding] = useState(false)
  const [addingSwitch, setAddingSwitch] = useState(false)
  const [kit, setKit] = useState(false)
  const [gpo, setGpo] = useState(false)
  const [rotating, setRotating] = useState<RadiusClient | null>(null)
  const [editing, setEditing] = useState<RadiusClient | null>(null)
  const [deleting, setDeleting] = useState<RadiusClient | null>(null)
  const [editSettings, setEditSettings] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [vendor, setVendor] = useState<string>('cisco-9800')
  const data = q.data
  // Where focus goes when a controller dialog closes: the changed row, or the list heading after a delete.
  const focusTo = useRef<HTMLElement | null>(null)
  const rowTarget = (id: string) => {
    const el = [...document.querySelectorAll<HTMLElement>(`[data-ctl="${id}"]`)].find((e) => e.offsetParent !== null)
    focusTo.current = el ?? null
  }
  const openRotate = (c: RadiusClient) => { rowTarget(c.id); setRotating(c) }
  const openEdit = (c: RadiusClient) => { rowTarget(c.id); setEditing(c) }
  const openDelete = (c: RadiusClient) => {
    const h = document.getElementById('rad-nas-h')
    h?.setAttribute('tabindex', '-1')
    focusTo.current = h
    setDeleting(c)
  }

  // Intent parameters from the command palette, the needs-action queue and the setup wizard.
  useEffect(() => {
    if (!data) return
    const add = params.get('add')
    const rot = params.get('rotate')
    const pick = params.get('client')
    if (!add && !rot && !pick) return
    if (add) {
      if (!can('radius:write')) toast('You can’t add controllers or switches', 'Your role can view RADIUS but not change it. A Wi-Fi Administrator or Tenant Administrator can.', 'warn')
      else if (!data.settings) toast('Save the RADIUS settings first', 'Controllers and switches need the RADIUS server settings and certificate to exist.', 'warn')
      else if (add === 'switch') setAddingSwitch(true)
      else setAdding(true)
    }
    if (pick) {
      const c = data.clients.find((x) => x.id === pick)
      if (c) { setSelectedId(c.id); if (c.vendor !== 'cisco-switch' && c.vendor !== 'meraki') setVendor(c.vendor) }
    }
    if (rot) {
      const c = data.clients.find((x) => x.id === rot)
      if (!can('radius:secrets')) toast('You can’t rotate shared secrets', 'Rotating secrets needs the Tenant Administrator role.', 'warn')
      else if (!c) toast('Controller not found', 'It may have been deleted. Choose it from the list below.', 'warn')
      else if (data.settings) { rowTarget(c.id); setRotating(c) }
    }
    const next = new URLSearchParams(params)
    next.delete('add')
    next.delete('rotate')
    next.delete('client')
    setParams(next, { replace: true })
  }, [params, data, can, setParams])

  const selected = data?.clients.find((c) => c.id === selectedId) ?? null
  const select = (c: RadiusClient) => {
    setSelectedId(c.id)
    if (c.vendor !== 'cisco-switch' && c.vendor !== 'meraki') setVendor(c.vendor)
    pushRecent(tid, { kind: 'controller', id: c.id, label: c.name, sub: [c.address, c.site].filter(Boolean).join(' · ') })
  }

  if (q.isLoading) return <><PageHeader title="RADIUS" /><LoadingBlock rows={8} label="Loading RADIUS" /></>
  if (q.error || !data) return <><PageHeader title="RADIUS" /><ErrorState error={q.error} onRetry={() => q.refetch()} /></>
  const s = data.settings

  return (
    <div>
      <PageHeader
        title="RADIUS"
        lede={s
          ? <>Devices validate <span className="ee-mono text-[13px]">{s.server_hostname}</span>. Controllers send requests to {s.radius_address ? <span className="ee-mono text-[13px]">{s.radius_address}</span> : 'this EasyEAP server’s address'} on UDP <span className="ee-num">{s.dedicated_ports ? s.auth_port : 1812}</span> and <span className="ee-num">{s.dedicated_ports ? s.acct_port : 1813}</span>.</>
          : <>Set up the RADIUS server for {tenant.name}, then register each wireless controller and switch that will send it requests.</>}
        actions={s && can('radius:write') ? <AddMenu primary onController={() => setAdding(true)} onSwitch={() => setAddingSwitch(true)} /> : undefined}
      />

      <div className="space-y-6">
        {s?.radius_address_problem && <Callout tone="warn" title="Controllers can’t reach the configured RADIUS address">{s.radius_address_problem} Until then the setup guides leave the address for you to fill in.</Callout>}
        <ServiceStatus data={data} />

        {!s ? (
          <Panel className="p-5 sm:p-6" risk="gold" aria-labelledby="rad-setup-h">
            <SectionHeader id="rad-setup-h" title="RADIUS server settings" meta="Not saved yet" />
            {can('radius:write')
              ? <RadiusSettingsForm current={null} />
              : <Empty title="RADIUS isn’t set up yet">A Wi-Fi Administrator or Tenant Administrator saves the settings and issues the server certificate.</Empty>}
          </Panel>
        ) : (
          <div className="grid gap-6 xl:grid-cols-12">
            <Panel className="min-w-0 p-5 sm:p-6 xl:col-span-7" aria-labelledby="rad-set-h">
              <SectionHeader id="rad-set-h" title="Server settings"
                meta={s.snapshot_built_at ? `Snapshot built ${ago(s.snapshot_built_at)}` : undefined}
                actions={can('radius:write') && !editSettings ? <Btn size="sm" onClick={() => setEditSettings(true)}><Pencil aria-hidden />Edit</Btn> : undefined} />
              {editSettings
                ? <RadiusSettingsForm current={s} onSaved={() => setEditSettings(false)} onCancel={() => setEditSettings(false)} />
                : <SettingsSummary s={s} />}
            </Panel>
            <Panel className="min-w-0 p-5 sm:p-6 xl:col-span-5" aria-labelledby="rad-cert-h">
              <SectionHeader id="rad-cert-h" title="Server certificate" meta="Presented to every device" />
              <ServerCertificateCard s={s} />
            </Panel>
          </div>
        )}

        <Panel className="p-5 sm:p-6" aria-labelledby="rad-nas-h">
          <SectionHeader id="rad-nas-h" title="Controllers and switches"
            meta={data.clients.length ? `${data.clients.length} registered` : undefined}
            actions={<>
              {s && data.clients.some((c) => c.networks.includes('wired')) && <Btn size="sm" variant="ghost" onClick={() => setKit(true)}><MonitorDown aria-hidden />Windows wired kit</Btn>}
              {s && <Btn size="sm" variant="ghost" onClick={() => setGpo(true)}><MonitorDown aria-hidden />Windows Group Policy</Btn>}
              {s && can('radius:write') && data.clients.length > 0 && <AddMenu onController={() => setAdding(true)} onSwitch={() => setAddingSwitch(true)} />}
            </>} />
          {data.clients.length === 0 ? (
            <Empty icon={<Router />} title="No controllers or switches registered"
              action={s && can('radius:write') ? <AddMenu primary onController={() => setAdding(true)} onSwitch={() => setAddingSwitch(true)} /> : undefined}>
              {s ? 'RADIUS ignores requests from addresses it doesn’t know. Register each Catalyst 9800, AireOS or UniFi controller, and each switch with 802.1X ports, to start authenticating.' : 'Save the RADIUS settings first. Controllers and switches are registered against this tenant’s RADIUS server.'}
            </Empty>
          ) : (
            <ControllerList clients={data.clients} selectedId={selectedId} onSelect={select} canWrite={can('radius:write')} canSecrets={can('radius:secrets') && !!s}
              onRotate={openRotate} onEdit={openEdit} onDelete={openDelete} unmatched={!!data.unattributed} />
          )}
          {s && selected && selected.networks.includes('wired') && (
            <section aria-labelledby="rad-sw-h" className="mt-5 border-t border-[var(--ee-line)] pt-4">
              <h3 id="rad-sw-h" className="ee-h3 mb-3 flex items-center gap-2"><EthernetPort className="size-4 ee-ink-3" aria-hidden />Wired 802.1X on {selected.name}</h3>
              <SwitchPanel client={selected} settings={s} />
            </section>
          )}
          {s && selected && !(selected.vendor === 'cisco-switch' && selected.monitoring?.set_up) && (
            <section aria-labelledby="rad-sl-h" className="mt-5 border-t border-[var(--ee-line)] pt-4">
              <h3 id="rad-sl-h" className="ee-h3 mb-3 flex items-center gap-2"><Logs className="size-4 ee-ink-3" aria-hidden />Syslog from {selected.name}</h3>
              <DeviceSyslogPanel key={selected.id} client={selected} />
            </section>
          )}
          {data.unattributed && <UnattributedNote u={data.unattributed} />}
          {data.clients.length > 0 && can('radius:write') && !can('radius:secrets') && (
            <p className="ee-small ee-ink-3 mt-3">Rotating shared secrets needs the Tenant Administrator role.</p>
          )}
        </Panel>

        {s && (
          <Panel className="p-5 sm:p-6" aria-labelledby="rad-guide-h">
            <SectionHeader id="rad-guide-h" title="Wireless controller setup guides" meta="Filled with this tenant’s RADIUS address, ports and SSID. A switch’s configuration is in its panel above." />
            <ControllerGuides settings={s} vendor={vendor} onVendor={(v) => { setVendor(v); if (selected && selected.vendor !== v) setSelectedId(null) }} forName={selected?.vendor === vendor ? selected.name : null} forClientId={selected?.vendor === vendor ? selected.id : null} />
          </Panel>
        )}

        <CoaQueue clients={data.clients} />
      </div>

      {s && <AddControllerDialog open={adding} onOpenChange={setAdding} settings={s} clients={data.clients} onAdded={(c) => { setSelectedId(c.id); setVendor(c.vendor) }} />}
      {s && <AddSwitchDialog open={addingSwitch} onOpenChange={setAddingSwitch} settings={s} clients={data.clients} onAdded={(c) => setSelectedId(c.id)} />}
      <WiredKitDialog open={kit} onOpenChange={setKit} />
      <GroupPolicyDialog open={gpo} onOpenChange={setGpo} />
      {s && <RotateSecretDialog client={rotating} onClose={() => setRotating(null)} settings={s} returnFocus={focusTo} />}
      <EditControllerDialog client={editing} onClose={() => setEditing(null)} clients={data.clients} returnFocus={focusTo} />
      <DeleteControllerDialog client={deleting} onClose={() => { if (deleting?.id === selectedId) setSelectedId(null); setDeleting(null) }} returnFocus={focusTo} />
    </div>
  )
}

/** "Add" menu: a wireless controller or a switch. */
function AddMenu({ primary, onController, onSwitch }: { primary?: boolean; onController: () => void; onSwitch: () => void }) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Btn variant={primary ? 'primary' : 'default'} size={primary ? 'md' : 'sm'}><Plus aria-hidden />Add<ChevronDown aria-hidden /></Btn>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="ee-menu" align="end" sideOffset={4}>
          <DropdownMenu.Item className="ee-menu-item" onSelect={onController}><Wifi className="size-4 ee-ink-3" aria-hidden />Wireless controller</DropdownMenu.Item>
          <DropdownMenu.Item className="ee-menu-item" onSelect={onSwitch}><EthernetPort className="size-4 ee-ink-3" aria-hidden />Switch (wired 802.1X)</DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

// ── Service status ──────────────────────────────────────────────────────
function StatusCell({ label, tone, value, sub }: { label: string; tone: Tone; value: string; sub?: ReactNode }) {
  return (
    <div className="min-w-0 px-5 py-4">
      <p className="ee-label mb-1.5">{label}</p>
      <HealthDot tone={tone} label={value} />
      {sub && <p className="ee-small ee-ink-3 mt-1">{sub}</p>}
    </div>
  )
}

function freeradiusCell(a: RadiusResponse['agent']): { tone: Tone; value: string; sub?: ReactNode } {
  if (!a) return { tone: 'neutral', value: 'Unknown' }
  switch (radiusState(a)) {
    case 'running': return { tone: 'valid', value: 'Running' }
    case 'idle': return { tone: 'neutral', value: 'Idle', sub: 'Starts when a tenant is activated. Until then there is nothing to serve.' }
    case 'starting': return { tone: 'neutral', value: 'Starting', sub: 'Loading the newly activated tenant. The agent checks every 15 seconds.' }
    default: return { tone: 'crit', value: 'Not running', sub: <>Check <Link className="underline" to={paths.system()}>System health</Link> and the Configuration status.</> }
  }
}

function ServiceStatus({ data }: { data: RadiusResponse }) {
  const { tid, tenant } = useTenant()
  const now = useNow()
  const a = data.agent
  const s = data.settings
  const dash = useQuery({
    queryKey: qk.dashboard(tid),
    queryFn: ({ signal }) => api.get<{ enforcement: Enforcement }>(`/api/tenants/${tid}/dashboard`, signal),
    enabled: tenant.status === 'active',
  })
  const enf = dash.data?.enforcement
  const seen = a ? <span title={fmtDateTime(a.last_seen_at)}>Last report {ago(a.last_seen_at, now)}</span> : undefined

  let tenantCell: { tone: Tone; value: string; sub?: ReactNode }
  if (tenant.status === 'suspended') tenantCell = { tone: 'crit', value: 'Not served: tenant suspended', sub: <Link className="underline" to={paths.settings(tid)}>Tenant settings</Link> }
  else if (tenant.status !== 'active') tenantCell = { tone: 'neutral', value: 'Not served yet', sub: <>RADIUS serves a tenant once it’s active. <Link className="underline" to={paths.setup(tid)}>Finish setup</Link></> }
  else if (!s?.server_certificate) tenantCell = { tone: 'warn', value: 'Not served', sub: 'Save the settings to issue the server certificate.' }
  else if (!a) tenantCell = { tone: 'crit', value: 'Unknown', sub: 'The RADIUS agent has never reported.' }
  else if (a.tenant_in_sync) tenantCell = { tone: 'valid', value: 'Latest snapshot applied', sub: s.snapshot_built_at ? `Built ${ago(s.snapshot_built_at, now)}` : undefined }
  else tenantCell = { tone: 'warn', value: 'Waiting to apply the latest snapshot', sub: `RADIUS has ${a.tenant_snapshot_applied ? 'an older snapshot' : 'no snapshot for this tenant'}; the latest was built ${ago(s.snapshot_built_at, now)}.` }

  return (
    <Panel aria-label="RADIUS service status" risk={!a || !a.online || !a.config_ok ? 'crit' : undefined}>
      <div className="grid divide-y divide-[var(--ee-line)] sm:grid-cols-2 sm:divide-y-0 xl:grid-cols-4 xl:divide-x">
        <StatusCell label="RADIUS agent" tone={!a ? 'crit' : a.online ? 'valid' : 'crit'} value={!a ? 'Never reported' : a.online ? 'Online' : 'Not reporting'} sub={seen ?? 'Check System health.'} />
        <StatusCell label="FreeRADIUS" {...freeradiusCell(a)} />
        <StatusCell label="Configuration" tone={!a ? 'neutral' : a.config_ok ? 'valid' : 'crit'} value={!a ? 'Unknown' : a.config_ok ? 'Loaded' : 'Rejected'} sub={a && !a.config_ok ? (a.config_error ?? 'The last configuration failed to load.') : a ? <>Reported {ago(a.last_seen_at, now)}</> : undefined} />
        <StatusCell label={`${tenant.name} on RADIUS`} {...tenantCell} />
      </div>
      {tenant.status === 'active' && enf?.deadline_at && (
        <p className="ee-small ee-ink-2 border-t border-[var(--ee-line)] px-5 py-3">
          {enf.auto_refresh
            ? <>The snapshot refreshes automatically. RADIUS denies everyone from {fmtDateTime(enf.deadline_at)} if refreshes stop.</>
            : <span className="text-[var(--ee-warn-ink)]">Refreshes have stopped because directory sync is failing; RADIUS denies everyone from {fmtDateTime(enf.deadline_at)}. <Link className="underline" to={paths.directory(tid)}>Directory</Link></span>}
        </p>
      )}
    </Panel>
  )
}

// ── Controllers ─────────────────────────────────────────────────────────
interface ListProps {
  clients: RadiusClient[]
  selectedId: string | null
  onSelect: (c: RadiusClient) => void
  canWrite: boolean
  canSecrets: boolean
  onRotate: (c: RadiusClient) => void
  onEdit: (c: RadiusClient) => void
  onDelete: (c: RadiusClient) => void
  unmatched?: boolean
}

function LastRequest({ at, now, unmatched }: { at: string | null; now: Date; unmatched?: boolean }) {
  // "No requests yet" only when that's true: if RADIUS answered requests EasyEAP couldn't attribute, say so instead.
  if (!at) return <span className="ee-ink-3">{unmatched ? 'None matched' : 'No requests yet'}</span>
  return <span title={fmtDateTime(at)}>{ago(at, now)}</span>
}

function UnattributedNote({ u }: { u: Unattributed }) {
  const now = useNow()
  const addrs = u.nas_addresses
  return (
    <Callout tone="warn" className="mt-4" title={`${u.count.toLocaleString()} ${u.count === 1 ? 'request wasn’t' : 'requests weren’t'} matched to a controller or switch`}>
      In the last {u.days} days RADIUS answered {u.count === 1 ? 'a request' : 'requests'} (latest {ago(u.last_at, now)}) that EasyEAP couldn’t tie to a registered controller.
      {addrs.length > 0 && <> {addrs.length === 1 ? 'It' : 'They'} reported NAS address{addrs.length === 1 ? '' : 'es'} {addrs.map((ip, i) => <span key={ip}>{i > 0 && ', '}<span className="ee-mono text-[12.5px]">{ip}</span></span>)}, which {addrs.length === 1 ? 'isn’t' : 'aren’t'} inside any controller’s source address.</>}
      {' '}If that’s one of your controllers, edit its source address to cover it. Until then EasyEAP can’t show when it last sent a request, or send it a CoA disconnect.
    </Callout>
  )
}

function RowActions({ c, ...p }: { c: RadiusClient } & Omit<ListProps, 'clients' | 'selectedId'>) {
  return (
    <div className="flex items-center justify-end gap-1">
      {p.canSecrets && <Btn size="sm" variant="ghost" onClick={(e) => { e.stopPropagation(); p.onRotate(c) }} aria-label={`Rotate shared secret for ${c.name}`}><RotateCw aria-hidden />Rotate secret</Btn>}
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <Btn size="sm" variant="ghost" icon aria-label={`More actions for ${c.name}`} onClick={(e) => e.stopPropagation()}><Ellipsis aria-hidden /></Btn>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content className="ee-menu" align="end" sideOffset={4} onClick={(e) => e.stopPropagation()}>
            <DropdownMenu.Item className="ee-menu-item" onSelect={() => p.onSelect(c)}><BookOpen className="size-4 ee-ink-3" aria-hidden />{c.networks.includes('wired') && !c.networks.includes('wireless') ? 'Show switch panel' : 'Show setup guide'}</DropdownMenu.Item>
            {p.canWrite && <DropdownMenu.Item className="ee-menu-item" onSelect={() => p.onEdit(c)}><Pencil className="size-4 ee-ink-3" aria-hidden />Edit</DropdownMenu.Item>}
            {p.canWrite && <DropdownMenu.Separator className="ee-menu-sep" />}
            {p.canWrite && <DropdownMenu.Item className="ee-menu-item text-[var(--ee-crit-ink)]" onSelect={() => p.onDelete(c)}><Trash2 className="size-4" aria-hidden />Delete</DropdownMenu.Item>}
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
    </div>
  )
}

function ControllerList(p: ListProps) {
  const now = useNow()
  const coa = (c: RadiusClient) => (c.coa_enabled ? <span className="ee-num">On · UDP {c.coa_port}</span> : <span className="ee-ink-3">Off</span>)
  return (
    <>
      <div className="hidden md:block">
        <table className="ee-table">
          <caption className="sr-only">Wireless controllers and switches. Select one to show its setup guide or switch panel.</caption>
          <thead>
            <tr>
              <th>Name</th><th>Type</th><th>Serves</th><th>Source address</th><th>CoA</th><th>Secret set</th><th>Last request</th><th><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {p.clients.map((c) => (
              <tr key={c.id} data-clickable="true" aria-selected={p.selectedId === c.id} onClick={() => p.onSelect(c)}>
                <td className="min-w-[180px]">
                  <button type="button" data-ctl={c.id} className="ee-rowlink font-semibold hover:underline" onClick={(e) => { e.stopPropagation(); p.onSelect(c) }}>{c.name}</button>
                  <span className="ee-small ee-ink-3 block">{c.site || 'No site'}</span>
                </td>
                <td className="whitespace-nowrap ee-ink-2">{vendorLabels[c.vendor] ?? c.vendor}</td>
                <td><span className="inline-flex flex-wrap items-center gap-1"><ServesChips c={c} /><ModeChip c={c} /></span></td>
                <td className="ee-mono whitespace-nowrap text-[12.5px]">{c.address}</td>
                <td className="whitespace-nowrap">{coa(c)}</td>
                <td className="whitespace-nowrap ee-ink-2" title={fmtDateTime(c.secret_set_at)}>{c.secret_set_at ? ago(c.secret_set_at, now) : '—'}</td>
                <td className="whitespace-nowrap"><LastRequest at={c.last_request_at} now={now} unmatched={p.unmatched} /></td>
                <td className="text-right"><RowActions c={c} {...p} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="md:hidden divide-y divide-[var(--ee-line)] border-y border-[var(--ee-line)]" aria-label="Wireless controllers and switches">
        {p.clients.map((c) => (
          <li key={c.id} className={cn('py-3', p.selectedId === c.id && 'bg-[var(--ee-select)]')}>
            <div className="flex items-start justify-between gap-3">
              <button type="button" data-ctl={c.id} className="ee-rowlink min-w-0 text-left" onClick={() => p.onSelect(c)}>
                <span className="block font-semibold">{c.name}</span>
                <span className="block ee-small ee-ink-3">{vendorLabels[c.vendor] ?? c.vendor}{c.site ? ` · ${c.site}` : ''}</span>
              </button>
              <RowActions c={c} {...p} />
            </div>
            <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1.5 text-[13px]">
              <div className="col-span-2"><dt className="ee-label">Serves</dt><dd className="mt-0.5 inline-flex flex-wrap gap-1"><ServesChips c={c} /><ModeChip c={c} /></dd></div>
              <div className="col-span-2"><dt className="ee-label">Source address</dt><dd className="ee-mono text-[12.5px] break-all">{c.address}</dd></div>
              <div><dt className="ee-label">CoA</dt><dd>{coa(c)}</dd></div>
              <div><dt className="ee-label">Last request</dt><dd><LastRequest at={c.last_request_at} now={now} unmatched={p.unmatched} /></dd></div>
            </dl>
          </li>
        ))}
      </ul>
    </>
  )
}

// ── CoA queue ───────────────────────────────────────────────────────────
const coaStatus: Record<string, { tone: Tone; label: string }> = {
  pending: { tone: 'neutral', label: 'Queued' },
  sent: { tone: 'gold', label: 'Sent, awaiting reply' },
  acked: { tone: 'valid', label: 'Session ended' },
  nak: { tone: 'warn', label: 'Refused by controller' },
  failed: { tone: 'crit', label: 'Failed' },
}

/** A request's status, aged: the agent sends within seconds and records the reply, so a request still queued or
 * waiting minutes later has stalled (agent down, or it stopped before recording the answer). */
function coaState(r: CoaRequest, now: Date): { tone: Tone; label: string } {
  const age = r.created_at ? now.getTime() - new Date(r.created_at).getTime() : 0
  if (r.status === 'pending' && age > 5 * 60_000) return { tone: 'warn', label: 'Not sent: check the RADIUS agent' }
  if (r.status === 'sent' && age > 2 * 60_000) return { tone: 'warn', label: 'No reply recorded' }
  return coaStatus[r.status] ?? { tone: 'neutral', label: r.status }
}

function CoaQueue({ clients }: { clients: RadiusClient[] }) {
  const { tid } = useTenant()
  const now = useNow()
  const q = useCoa(tid)
  const names = useMemo(() => new Map(clients.map((c) => [c.id, c.name])), [clients])
  const items = q.data?.items ?? []
  const anyCoa = clients.some((c) => c.coa_enabled)
  return (
    <Panel className="p-5 sm:p-6" aria-labelledby="rad-coa-h">
      <SectionHeader id="rad-coa-h" title="Disconnect requests (CoA)" meta={items.length ? `Latest ${items.length}` : undefined} />
      {q.isLoading ? <div className="space-y-2"><Skeleton className="w-2/3" /><Skeleton className="w-1/2" /></div>
        : q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} />
          : items.length === 0 ? (
            <p className="ee-small ee-ink-2 max-w-[75ch]">
              No disconnect requests yet. When you revoke a certificate or block a user with a live session, EasyEAP queues a disconnect for each controller that has CoA turned on, and the RADIUS agent sends it.
              {!anyCoa && clients.length > 0 && ' None of this tenant’s controllers has CoA on, so revoked devices stay connected until their session timeout.'}
            </p>
          ) : (
            <>
            <ul className="md:hidden divide-y divide-[var(--ee-line)] border-y border-[var(--ee-line)]" aria-label="Recent CoA disconnect requests">
              {items.map((r) => {
                const st = coaState(r, now)
                return (
                  <li key={r.id} className="space-y-1.5 py-3 text-[13px]">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span title={fmtDateTime(r.created_at)}>{ago(r.created_at, now)} · {names.get(r.nas_client_id) ?? 'Deleted controller'}</span>
                      <Chip tone={st.tone} icon={<Send aria-hidden />}>{st.label}</Chip>
                    </div>
                    <p className="ee-mono text-[12.5px] break-all">{r.attributes['User-Name'] || r.attributes['Calling-Station-Id'] || '—'}</p>
                    {r.reason && <p className="ee-ink-2 break-words">{r.reason}</p>}
                    {r.result_detail && <p className="ee-small ee-ink-3">{r.result_detail}</p>}
                  </li>
                )
              })}
            </ul>
            <div className="hidden md:block">
              <table className="ee-table">
                <caption className="sr-only">Recent CoA disconnect requests</caption>
                <thead><tr><th>Requested</th><th>Controller</th><th>Device</th><th>Reason</th><th>Status</th></tr></thead>
                <tbody>
                  {items.map((r: CoaRequest) => {
                    const st = coaState(r, now)
                    const who = r.attributes['User-Name'] || r.attributes['Calling-Station-Id'] || '—'
                    return (
                      <tr key={r.id}>
                        <td className="whitespace-nowrap" title={fmtDateTime(r.created_at)}>{ago(r.created_at, now)}</td>
                        <td className="whitespace-nowrap">{names.get(r.nas_client_id) ?? 'Deleted controller'}</td>
                        <td className="ee-mono text-[12.5px] break-all">{who}</td>
                        <td className="ee-ink-2 break-words">{r.reason || '—'}</td>
                        <td>
                          <Chip tone={st.tone} icon={<Send aria-hidden />}>{st.label}</Chip>
                          {(r.result_detail || r.completed_at) && <span className="ee-small ee-ink-3 block mt-1">{r.result_detail}{r.completed_at ? `${r.result_detail ? ' · ' : ''}${ago(r.completed_at, now)}` : ''}</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            </>
          )}
      {items.length > 0 && <Callout tone="neutral" className="mt-4">A disconnect ends a live session on the controller. Controllers without CoA keep the session until its timeout.</Callout>}
    </Panel>
  )
}
