// Device administration (docs/plans/device-admin.md): administrators log in to Cisco switches and controllers with
// their AD account or an EasyEAP account, over TACACS+ to the RADIUS node. Devices keep their own local accounts for
// when EasyEAP can't be reached.
// Intents: ?tab=accounts|directory|log|settings, ?account=<id> opens a local account, ?device=<id> its configuration.
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { FileCode, KeyRound, Plus, RefreshCw, SquareTerminal, UserPlus, X } from 'lucide-react'
import {
  kindLabels, privLabel, reasonLabels, statusLabels, useAdminEvents, useDeviceAdmin, useSetAdminEnabled,
  type AdminAccount, type AdminDevice, type AdminEvent, type AdminEventKind, type DeviceAdminOverview,
} from '../api/deviceAdmin'
import { vendorLabels } from '../api/radius'
import { useTenant } from '../api/tenant'
import { ago, fmtDateTime, fmtStamp, plural, timeZoneName } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Btn, Callout, Chip, ESelect, ESwitch, Empty, ErrorState, LoadingBlock, PageHeader, Panel, Seg, Tip, errorMessage, toast, type Tone } from '../ui'
import { AccountDialog, NewAccountDialog, statusTone } from './deviceadmin/AccountDialogs'
import { AdminSettings } from './deviceadmin/AdminSettings'
import { ConfigDialog, RotateKeyDialog } from './deviceadmin/DeviceDialogs'
import { DirectoryAccess } from './deviceadmin/DirectoryAccess'
import { errorCode } from './mac/dialogs'
import { SearchBox, useUrlState } from './people/shared'

type Tab = 'devices' | 'accounts' | 'directory' | 'log' | 'settings'
const TABS: Tab[] = ['devices', 'accounts', 'directory', 'log', 'settings']

export default function DeviceAdmin() {
  const { tid, tenant, can } = useTenant()
  const write = can('admin:write')
  const { values, set, params, setParams } = useUrlState(['tab'] as const)
  const tab: Tab = (TABS as string[]).includes(values.tab) ? (values.tab as Tab) : 'devices'
  const q = useDeviceAdmin(tid)
  const data = q.data
  const [config, setConfig] = useState<{ id: string; key: string | null } | null>(null)
  const [rotating, setRotating] = useState<AdminDevice | null>(null)
  const [accountId, setAccountId] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  // Intents from search, the command palette and the RADIUS page.
  useEffect(() => {
    const account = params.get('account')
    const device = params.get('device')
    if (!account && !device) return
    if (account) setAccountId(account)
    if (device) setConfig({ id: device, key: null })
    setParams((p) => { const n = new URLSearchParams(p); n.delete('account'); n.delete('device'); if (account) n.set('tab', 'accounts'); return n }, { replace: true })
  }, [params, setParams])

  const configDevice = data?.devices.find((d) => d.id === config?.id) ?? null
  const account = data?.users.find((u) => u.id === accountId) ?? null
  const enabledCount = data?.devices.filter((d) => d.admin_enabled).length ?? 0

  return (
    <div>
      <PageHeader
        title="Device administration"
        lede={<>Administrators log in to switches and controllers in {tenant.name} with their AD account or an EasyEAP account. Devices ask EasyEAP over TACACS+ and keep their own local accounts for when EasyEAP can’t be reached.</>}
        actions={write && data && tab === 'accounts' ? <Btn variant="primary" onClick={() => setCreating(true)}><UserPlus aria-hidden />New account</Btn> : undefined}
      />
      {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="Device administration couldn’t be loaded" /> : !data ? <LoadingBlock rows={6} label="Loading device administration" /> : (
        <>
          <StatusCallouts data={data} enabledCount={enabledCount} />
          <div className="mb-4 max-w-full overflow-x-auto">
            <Seg label="View" value={tab} onChange={(v) => set({ tab: v === 'devices' ? null : v })} options={[
              { value: 'devices', label: 'Devices', count: enabledCount || undefined },
              { value: 'accounts', label: 'EasyEAP accounts', count: data.users.length },
              { value: 'directory', label: 'Directory access', count: data.maps.length },
              { value: 'log', label: 'Admin log' },
              { value: 'settings', label: 'Settings' },
            ]} />
          </div>
          {tab === 'devices' && <DevicesTab data={data} write={write} onConfig={(d, key = null) => setConfig({ id: d.id, key })} onRotate={setRotating} />}
          {tab === 'accounts' && <AccountsTab users={data.users} write={write} onOpen={(a) => setAccountId(a.id)} onNew={() => setCreating(true)} />}
          {tab === 'directory' && <DirectoryAccess data={data} write={write} />}
          {tab === 'log' && <AdminLog data={data} />}
          {tab === 'settings' && <AdminSettings data={data} write={write} />}

          <ConfigDialog device={configDevice} secret={config?.key ?? null} server={data.server} onClose={() => setConfig(null)} />
          <RotateKeyDialog device={rotating} onClose={() => setRotating(null)} onRotated={(d, key) => { setRotating(null); setConfig({ id: d.id, key }) }} />
          <NewAccountDialog open={creating} roles={data.roles} onClose={() => setCreating(false)} onCreated={(a) => { setCreating(false); set({ tab: 'accounts' }); setAccountId(a.id) }} />
          <AccountDialog account={account} roles={data.roles} onClose={() => setAccountId(null)} />
        </>
      )}
    </div>
  )
}

function StatusCallouts({ data, enabledCount }: { data: DeviceAdminOverview; enabledCount: number }) {
  const { tid, can } = useTenant()
  const radiusLink = can('radius:read') ? <Link to={paths.radius(tid)} className="ee-btn ee-btn-sm">Open RADIUS</Link> : undefined
  if (!data.radius_configured) {
    return <Callout tone="neutral" className="mb-4" title="Set up RADIUS first" action={radiusLink}>Admin logins run on the RADIUS node. Save the RADIUS settings and add your switches there.</Callout>
  }
  const out = []
  if (!data.agent.supported) {
    out.push(<Callout key="old" tone="warn" title="RADIUS needs updating">The RADIUS node doesn’t run the TACACS+ service yet. Update EasyEAP on the RADIUS host (System health shows its version), then turn on admin logins.</Callout>)
  } else if (enabledCount > 0 && data.agent.online && data.agent.in_sync && data.agent.running === false) {
    out.push(<Callout key="down" tone="crit" title="The TACACS+ service isn’t running">Devices fall back to their own local accounts. Check the RADIUS container’s log for “tacacs”.</Callout>)
  } else if (enabledCount > 0 && !data.agent.online) {
    out.push(<Callout key="off" tone="crit" title="The RADIUS node is offline">Devices fall back to their own local accounts until it’s back.</Callout>)
  } else if (data.agent.in_sync === false) {
    out.push(<Callout key="sync" tone="neutral" title="Applying changes">The RADIUS node picks up the latest accounts and keys within about 15 seconds.</Callout>)
  }
  if (data.server.radius_address_problem) out.push(<Callout key="addr" tone="warn" title="Check EasyEAP’s address">{data.server.radius_address_problem}</Callout>)
  return out.length ? <div className="mb-4 space-y-3">{out}</div> : null
}

// ── Devices ─────────────────────────────────────────────────────────────

function DevicesTab({ data, write, onConfig, onRotate }: { data: DeviceAdminOverview; write: boolean; onConfig: (d: AdminDevice, key?: string | null) => void; onRotate: (d: AdminDevice) => void }) {
  const { tid, can } = useTenant()
  const now = useNow(60_000)
  const setEnabled = useSetAdminEnabled(tid)
  const [busy, setBusy] = useState<string | null>(null)
  if (data.devices.length === 0) {
    return (
      <Empty icon={<SquareTerminal aria-hidden />} title="No switches or controllers yet"
        action={can('radius:write') ? <Link to={paths.radius(tid, { add: 'switch' })} className="ee-btn ee-btn-sm">Add a switch</Link> : undefined}>
        Add your Cisco switches and controllers on the RADIUS page. Then turn on admin logins for them here.
      </Empty>
    )
  }
  const toggle = (d: AdminDevice, on: boolean) => {
    setBusy(d.id)
    setEnabled.mutate({ id: d.id, enabled: on }, {
      onSuccess: (r) => {
        if (r.key) onConfig(r.device, r.key)
        else toast(on ? 'Admin logins on' : 'Admin logins off', on ? `${d.name} keeps its TACACS+ key. Open its configuration to paste it.` : `EasyEAP stops answering ${d.name} within about 15 seconds, so it uses its local accounts. Paste the rollback from its configuration to remove the TACACS+ lines.`)
      },
      onError: (e) => toast('It wasn’t changed', errorCode(e) === 'agent_too_old' ? 'RADIUS needs updating first.' : errorMessage(e), 'crit'),
      onSettled: () => setBusy(null),
    })
  }
  return (
    <Panel className="px-4 py-3 sm:px-5" aria-label="Devices">
      <div className="overflow-x-auto">
        <table className="ee-table">
          <caption className="sr-only">Switches and controllers, and whether administrators log in to them with EasyEAP accounts</caption>
          <thead><tr><th className="pt-1.5">Device</th><th className="pt-1.5">Admin logins</th><th className="pt-1.5">TACACS+ key</th><th className="pt-1.5">Last admin login</th><th className="pt-1.5"><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {data.devices.map((d) => (
              <tr key={d.id}>
                <td className="min-w-[180px]">
                  <span className="block font-medium">{d.name}</span>
                  <span className="ee-small ee-ink-3">{[vendorLabels[d.vendor] ?? d.vendor, d.address, d.site].filter(Boolean).join(' · ')}</span>
                </td>
                <td className="whitespace-nowrap">
                  {d.supported ? (
                    <span className="flex items-center gap-2">
                      <ESwitch checked={d.admin_enabled} onChange={(v) => toggle(d, v)} label={`Admin logins on ${d.name}`} disabled={!write || busy === d.id || (!d.admin_enabled && !data.agent.supported)} />
                      <span className="text-[13px]">{d.admin_enabled ? 'On' : 'Off'}</span>
                    </span>
                  ) : (
                    <Tip content={d.not_supported ?? 'Not supported for this device.'}><span><Chip tone="neutral">Not supported</Chip></span></Tip>
                  )}
                </td>
                <td className="min-w-[140px]">
                  {d.key_set_at ? <span className="ee-small">Set {fmtDateTime(d.key_set_at)}</span> : <span className="ee-ink-3">—</span>}
                  {d.previous_key_until && <span className="ee-small block text-[var(--ee-warn-ink)]">Old key works until {fmtDateTime(d.previous_key_until)}</span>}
                </td>
                <td className="whitespace-nowrap">{d.last_login_at ? <span title={fmtDateTime(d.last_login_at)}>{ago(d.last_login_at, now)}</span> : <span className="ee-ink-3">{d.admin_enabled ? 'None yet' : '—'}</span>}</td>
                <td className="whitespace-nowrap text-right">
                  {d.supported && d.admin_enabled && (
                    <span className="inline-flex gap-2">
                      <Btn size="sm" onClick={() => onConfig(d)}><FileCode aria-hidden />Configuration</Btn>
                      {write && <Btn size="sm" variant="ghost" onClick={() => onRotate(d)}><RefreshCw aria-hidden />Rotate key</Btn>}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="ee-small ee-ink-3 pt-3">
        TACACS+ uses TCP {data.server.port} to {data.server.radius_address || 'EasyEAP’s RADIUS address'}. It only obfuscates its packets, so keep it on the management network. Each device gets its own key.
      </p>
    </Panel>
  )
}

// ── Accounts ────────────────────────────────────────────────────────────

function AccountsTab({ users, write, onOpen, onNew }: { users: AdminAccount[]; write: boolean; onOpen: (a: AdminAccount) => void; onNew: () => void }) {
  const now = useNow(60_000)
  const [q, setQ] = useState('')
  const focusAfter = useRef<HTMLElement | null>(null)
  const shown = useMemo(() => {
    const ql = q.trim().toLowerCase()
    return users.filter((u) => !ql || [u.username, u.display_name, u.email, u.role].some((x) => x?.toLowerCase().includes(ql)))
  }, [users, q])
  if (users.length === 0) {
    return (
      <Empty icon={<KeyRound aria-hidden />} title="No EasyEAP accounts yet" action={write ? <Btn variant="primary" onClick={onNew}><Plus aria-hidden />New account</Btn> : undefined}>
        Accounts for people who aren’t in the directory, such as contractors, or for a site without AD. People in AD log in with their AD account through Directory access.
      </Empty>
    )
  }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter accounts">
        <SearchBox className="w-full sm:w-[280px]" value={q} onChange={setQ} label="Search accounts" placeholder="Username, name or role" />
        {q && <Btn size="sm" variant="ghost" onClick={() => setQ('')}><X aria-hidden />Clear</Btn>}
      </div>
      <Panel className="px-4 py-3 sm:px-5" aria-label="EasyEAP accounts">
        <div className="overflow-x-auto">
          <table className="ee-table">
            <caption className="sr-only">Local device admin accounts. Select a row to open it.</caption>
            <thead><tr><th className="pt-1.5">Account</th><th className="pt-1.5">Role</th><th className="pt-1.5">Sites</th><th className="pt-1.5">Status</th><th className="pt-1.5">Last login</th></tr></thead>
            <tbody>
              {shown.map((u) => (
                <tr key={u.id} data-clickable="true" onClick={(e) => { if (!(e.target as HTMLElement).closest('a,button')) { focusAfter.current = e.currentTarget.querySelector('button'); onOpen(u) } }}>
                  <td className="min-w-[160px]">
                    <button type="button" className="ee-mono text-left font-medium hover:underline" onClick={() => onOpen(u)}>{u.username}</button>
                    {u.display_name && <span className="ee-small ee-ink-3 block">{u.display_name}</span>}
                  </td>
                  <td className="whitespace-nowrap">{u.role ?? '—'} <span className="ee-ink-3">· {privLabel(u.priv_lvl)}</span></td>
                  <td className="ee-small">{u.sites.length ? u.sites.join(', ') : <span className="ee-ink-3">Every site</span>}</td>
                  <td className="whitespace-nowrap">
                    <span className="flex flex-wrap gap-1">
                      <Chip tone={statusTone[u.status]}>{statusLabels[u.status]}</Chip>
                      {u.totp_enabled && <Chip tone="valid">Code</Chip>}
                      {u.clashes_with_directory && <Tip content="A directory user has the same name. This local account wins on devices."><span><Chip tone="warn">Same as AD</Chip></span></Tip>}
                    </span>
                    {u.expires_at && u.status !== 'expired' && <span className="ee-small ee-ink-3 block">Until {fmtDateTime(u.expires_at)}</span>}
                  </td>
                  <td className="whitespace-nowrap">{u.last_login_at ? <span title={fmtDateTime(u.last_login_at)}>{ago(u.last_login_at, now)}</span> : <span className="ee-ink-3">Never</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {shown.length === 0 && <p className="ee-small ee-ink-3 py-3">No account matches.</p>}
        <p className="ee-small ee-ink-3 pt-3">{plural(shown.length, 'account')}{shown.length !== users.length ? ` of ${users.length}` : ''}. Ten failed logins in 15 minutes lock an account for 15 minutes.</p>
      </Panel>
    </div>
  )
}

// ── Admin log ───────────────────────────────────────────────────────────

const resultTone = (e: AdminEvent): Tone => (e.result === 'pass' ? 'valid' : e.result === 'fail' ? 'crit' : e.result === 'error' ? 'warn' : 'neutral')
const resultLabel = (e: AdminEvent) => ({ pass: 'Allowed', fail: 'Refused', error: 'Fell back', start: 'Started', stop: 'Ended', update: 'Update' })[e.result] ?? e.result

function AdminLog({ data }: { data: DeviceAdminOverview }) {
  const { tid } = useTenant()
  const now = useNow(30_000)
  const [hours, setHours] = useState('24')
  const [kind, setKind] = useState('')
  const [result, setResult] = useState('')
  const [device, setDevice] = useState('')
  const [text, setText] = useState('')
  const q = useAdminEvents(tid, { hours: Number(hours), kind: kind || undefined, result: result || undefined, client_id: device || undefined, q: text.trim() || undefined })
  const items = q.data?.items ?? []
  const filtered = !!(kind || result || device || text)
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter the admin log">
        <Seg label="Period" value={hours} onChange={setHours} options={[{ value: '24', label: '24 hours' }, { value: '168', label: '7 days' }, { value: '720', label: '30 days' }]} />
        <ESelect label="What" className="min-w-[150px]" value={kind || 'all'} onChange={(v) => setKind(v === 'all' ? '' : v)}
          options={[{ value: 'all', label: 'Everything' }, ...(Object.keys(kindLabels) as AdminEventKind[]).map((k) => ({ value: k, label: kindLabels[k] }))]} />
        <ESelect label="Result" className="min-w-[140px]" value={result || 'all'} onChange={(v) => setResult(v === 'all' ? '' : v)}
          options={[{ value: 'all', label: 'Any result' }, { value: 'pass', label: 'Allowed' }, { value: 'fail', label: 'Refused' }, { value: 'error', label: 'Fell back' }]} />
        <ESelect label="Device" className="min-w-[160px]" value={device || 'all'} onChange={(v) => setDevice(v === 'all' ? '' : v)}
          options={[{ value: 'all', label: 'Every device' }, ...data.devices.filter((d) => d.admin_enabled).map((d) => ({ value: d.id, label: d.name }))]} />
        <SearchBox className="w-full sm:w-[240px]" value={text} onChange={setText} label="Search the admin log" placeholder="User, command or address" />
        {filtered && <Btn size="sm" variant="ghost" onClick={() => { setKind(''); setResult(''); setDevice(''); setText('') }}><X aria-hidden />Clear filters</Btn>}
      </div>
      {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : q.isLoading ? <LoadingBlock rows={5} label="Loading the admin log" /> : items.length === 0 ? (
        <Empty icon={<SquareTerminal aria-hidden />} title={filtered ? 'Nothing matches these filters' : 'No admin activity in this period'}>
          Logins, enable, sessions and the commands administrators run on devices with admin logins on appear here within a minute.
        </Empty>
      ) : (
        <Panel className="px-4 py-3 sm:px-5" aria-label="Admin log">
          <div className="overflow-x-auto">
            <table className="ee-table">
              <caption className="sr-only">Device administration activity, newest first</caption>
              <thead><tr><th className="pt-1.5">When ({timeZoneName})</th><th className="pt-1.5">Who</th><th className="pt-1.5">Device</th><th className="pt-1.5">What</th><th className="pt-1.5">Detail</th></tr></thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap"><span className="ee-num text-[12.5px]">{fmtStamp(e.at)}</span><span className="ee-small ee-ink-3 block">{ago(e.at, now)}</span></td>
                    <td className="min-w-[120px]">
                      <span className={e.username?.startsWith('unknown:') ? 'ee-ink-3' : 'ee-mono text-[12.5px]'}>{e.username?.startsWith('unknown:') ? 'Unknown name' : e.username ?? '—'}</span>
                      {e.source && <span className="ee-small ee-ink-3 block">{e.source === 'local' ? 'EasyEAP account' : 'Directory'}</span>}
                    </td>
                    <td className="min-w-[120px]">{e.client ?? e.nas_ip ?? '—'}{e.rem_addr && <span className="ee-small ee-ink-3 block">from {e.rem_addr}</span>}</td>
                    <td className="whitespace-nowrap">
                      <span className="flex flex-wrap items-center gap-1.5">{kindLabels[e.kind] ?? e.kind}<Chip tone={resultTone(e)}>{resultLabel(e)}</Chip></span>
                    </td>
                    <td className="min-w-[220px] ee-small">
                      {e.command ? <code className="ee-mono break-all text-[12px]">{e.command}</code> : null}
                      {e.reason && <span className={e.command ? 'ee-ink-3 block' : 'ee-ink-2'}>{reasonLabels[e.reason] ?? e.reason}</span>}
                      {!e.command && !e.reason && e.priv_lvl != null && <span className="ee-ink-2">Level {privLabel(e.priv_lvl)}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="ee-small ee-ink-3 pt-3">{q.data?.next_before_id ? 'The latest 200 entries: narrow the filters to see older ones. ' : ''}Secrets in configuration commands are replaced with *****. Kept {data.settings.retention_days} days.</p>
        </Panel>
      )}
    </div>
  )
}
