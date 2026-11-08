// The MAC allow list (docs/plans/mac-auth.md §7): devices without 802.1X that switches with MAC authentication admit,
// the MACs switches asked about that aren't listed ("Seen, not allowed"), and the groups that give them a VLAN.
// Intents: ?device=<id> opens an entry, ?allow=<MAC> opens "Allow a device" with it, ?tab=seen | groups.
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { Cable, Download, Eye, Plus, Trash2, Upload, X } from 'lucide-react'
import { api, saveBlob } from '../api/client'
import { exportUrl, statusLabels, useDeleteGroup, useDismissSighting, useMacOverview, useSightings, type DeviceGroup, type MacDevice, type MacStatus, type Sighting } from '../api/mac'
import { useTenant } from '../api/tenant'
import { failureExplanations } from '@/domain/explain'
import type { FailureCode } from '@/domain/types'
import { ago, fmtDateTime, plural } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Btn, Callout, Chip, EDialog, ESelect, Empty, ErrorState, LoadingBlock, PageHeader, Panel, Seg, Tip, errorMessage, toast } from '../ui'
import { AllowDeviceDialog, BulkAllowDialog, GroupDialog, ImportDialog, groupVlanLabel } from './mac/dialogs'
import { DeviceSheet, statusTone } from './mac/DeviceSheet'
import { SearchBox, useUrlState } from './people/shared'

type Tab = 'devices' | 'seen' | 'groups'

function matches(d: MacDevice, q: string) {
  if (!q) return true
  const ql = q.toLowerCase()
  const hex = q.replace(/[^0-9A-Fa-f]/g, '').toUpperCase()
  return d.name.toLowerCase().includes(ql) || (d.group_name ?? '').toLowerCase().includes(ql) || d.notes.toLowerCase().includes(ql)
    || (hex.length >= 2 && d.mac.replace(/:/g, '').includes(hex)) || (d.last_seen_port ?? '').toLowerCase().includes(ql)
}

export default function MacAllowList() {
  const { tid, tenant, can } = useTenant()
  const now = useNow(60_000)
  const { values, set, params, setParams } = useUrlState(['tab', 'q', 'status'] as const)
  const tab: Tab = values.tab === 'seen' || values.tab === 'groups' ? values.tab : 'devices'
  const q = useMacOverview(tid)
  const [days, setDays] = useState(30)
  const seen = useSightings(tid, days)
  const write = can('mac:write')

  const [allowing, setAllowing] = useState<{ mac?: string } | null>(null)
  const [importing, setImporting] = useState(false)
  const [group, setGroup] = useState<DeviceGroup | 'new' | null>(null)
  const [openId, setOpenId] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulk, setBulk] = useState(false)
  const [removeGroup, setRemoveGroup] = useState<DeviceGroup | null>(null)
  const focusAfter = useRef<HTMLElement | null>(null)
  const delGroup = useDeleteGroup(tid)
  const dismiss = useDismissSighting(tid)

  // Intents from the command palette, an authentication attempt or a switch's readiness.
  useEffect(() => {
    const device = params.get('device')
    const allow = params.get('allow')
    if (!device && !allow) return
    if (device) setOpenId(device)
    if (allow && write) setAllowing({ mac: allow })
    setParams((p) => { const n = new URLSearchParams(p); n.delete('device'); n.delete('allow'); return n }, { replace: true })
  }, [params, setParams, write])

  const data = q.data
  const groups = useMemo(() => data?.groups ?? [], [data])
  const status = (['allowed', 'blocked', 'expired', 'group_off'] as const).includes(values.status as MacStatus) ? (values.status as MacStatus) : null
  const devices = useMemo(() => (data?.devices ?? []).filter((d) => matches(d, values.q.trim()) && (!status || d.status === status)), [data, values.q, status])
  const sightings = seen.data?.sightings ?? []
  const open = (d: MacDevice, el: HTMLElement | null) => { focusAfter.current = el; setOpenId(d.id) }
  const exportCsv = async () => {
    try {
      const text = await api.get<string>(exportUrl(tid))
      saveBlob(new Blob([text], { type: 'text/csv' }), `${tenant.slug}-mac-allow-list.csv`)
    } catch (e) { toast('The list couldn’t be exported', errorMessage(e), 'crit') }
  }
  const allowFirst = groups.length === 0

  return (
    <div>
      <PageHeader
        title="MAC allow list"
        lede={<>Devices without 802.1X, such as printers, cameras and phones, that switches with MAC authentication admit in {tenant.name}. A MAC address is easy to copy, so give these devices a VLAN that reaches only what they need.</>}
        actions={write && data ? (
          <>
            <Btn onClick={exportCsv} disabled={data.devices.length === 0}><Download aria-hidden />Export</Btn>
            <Btn onClick={() => setImporting(true)} disabled={allowFirst}><Upload aria-hidden />Import</Btn>
            <Btn variant="primary" onClick={() => (allowFirst ? setGroup('new') : setAllowing({}))}><Plus aria-hidden />{allowFirst ? 'Create a group' : 'Allow a device'}</Btn>
          </>
        ) : data && data.devices.length > 0 ? <Btn onClick={exportCsv}><Download aria-hidden />Export</Btn> : undefined}
      />

      {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="The MAC allow list couldn’t be loaded" /> : !data ? <LoadingBlock rows={6} label="Loading the MAC allow list" /> : (
        <>
          {data.switches_with_mab.length === 0 ? (
            <Callout tone="neutral" className="mb-4" title="No switch checks this list yet"
              action={can('radius:read') ? <Link to={paths.radius(tid)} className="ee-btn ee-btn-sm">Open RADIUS</Link> : undefined}>
              Turn on MAC authentication for a Cisco, Meraki or UniFi switch (open it on the RADIUS page while it’s in monitor mode). Wi-Fi doesn’t use this list.
            </Callout>
          ) : (
            <p className="ee-small ee-ink-2 mb-4">
              Checked by {data.switches_with_mab.map((s, i) => (
                <span key={s.id}>{i > 0 && (i === data.switches_with_mab.length - 1 ? ' and ' : ', ')}{can('radius:read') ? <Link className="underline decoration-[var(--ee-line-3)] underline-offset-2" to={paths.radius(tid, { client: s.id })}>{s.name}</Link> : s.name}{s.mode === 'monitor' && <span className="ee-ink-3"> (monitor mode)</span>}</span>
              ))}. Devices that answer 802.1X never fall back to their MAC address.
            </p>
          )}

          <div className="mb-4 max-w-full overflow-x-auto">
            <Seg label="View" value={tab} onChange={(v) => set({ tab: v === 'devices' ? null : v })} options={[
              { value: 'devices', label: 'Devices', count: data.devices.length },
              { value: 'seen', label: 'Seen, not allowed', count: seen.data ? sightings.length : undefined },
              { value: 'groups', label: 'Groups', count: groups.length },
            ]} />
          </div>

          {tab === 'devices' && (allowFirst ? (
            <Empty icon={<Cable aria-hidden />} title="Create a group first" action={write ? <Btn variant="primary" onClick={() => setGroup('new')}><Plus aria-hidden />Create a group</Btn> : undefined}>
              Every device belongs to a group, and the group decides its VLAN on switch ports: for example Printers on the print VLAN, Cameras on the camera VLAN.
            </Empty>
          ) : data.devices.length === 0 ? (
            <Empty icon={<Cable aria-hidden />} title="No devices allowed yet" action={write ? <Btn variant="primary" onClick={() => setAllowing({})}><Plus aria-hidden />Allow a device</Btn> : undefined}>
              Allow devices one at a time, import a list, or turn on MAC authentication for a switch in monitor mode and allow what it sees from “Seen, not allowed”.
            </Empty>
          ) : (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter devices">
                <SearchBox className="w-full sm:w-[280px]" value={values.q} onChange={(v) => set({ q: v.trim() || null })} label="Search devices" placeholder="Name, MAC, group or port" />
                <ESelect label="Status" className="min-w-[150px]" value={status ?? 'all'} onChange={(v) => set({ status: v === 'all' ? null : v })}
                  options={[{ value: 'all', label: 'Any status' }, ...(Object.keys(statusLabels) as MacStatus[]).map((s) => ({ value: s, label: statusLabels[s] }))]} />
                {(values.q || status) && <Btn size="sm" variant="ghost" onClick={() => set({ q: null, status: null })}><X aria-hidden />Clear filters</Btn>}
              </div>
              {devices.length === 0 ? <Empty title="No devices match these filters">Search matches the name, MAC address, group, notes and the port it was last seen on.</Empty> : (
                <Panel className="px-4 py-3 sm:px-5" aria-label="Devices">
                  <div className="overflow-x-auto">
                    <table className="ee-table">
                      <caption className="sr-only">Allowed devices. Select a row to open it.</caption>
                      <thead><tr><th className="pt-1.5">Device</th><th className="pt-1.5">MAC address</th><th className="pt-1.5">Group</th><th className="pt-1.5">Status</th><th className="pt-1.5">Last seen</th></tr></thead>
                      <tbody>
                        {devices.map((d) => (
                          <tr key={d.id} data-clickable="true" onClick={(e) => { if (!(e.target as HTMLElement).closest('a,button')) open(d, e.currentTarget.querySelector('button')) }}>
                            <td className="min-w-[160px]">
                              <button type="button" className="text-left font-medium hover:underline" onClick={(e) => open(d, e.currentTarget)}>{d.name}</button>
                              {d.notes && <span className="ee-small ee-ink-3 block truncate max-w-[240px]">{d.notes}</span>}
                            </td>
                            <td className="whitespace-nowrap">
                              <span className="ee-mono text-[12.5px]">{d.mac}</span>
                              {d.randomized && <Tip content="A randomised address: the device may change it, and the entry stops matching."><span className="ml-1.5"><Chip tone="warn">Random</Chip></span></Tip>}
                            </td>
                            <td><span className="block">{d.group_name}</span><span className="ee-small ee-ink-3">{(() => { const g = groups.find((x) => x.id === d.group_id); return g ? groupVlanLabel(g) : null })()}</span></td>
                            <td className="whitespace-nowrap"><Chip tone={statusTone[d.status]}>{statusLabels[d.status]}</Chip></td>
                            <td className="min-w-[140px]">
                              {d.last_seen_at ? <><span title={fmtDateTime(d.last_seen_at)}>{ago(d.last_seen_at, now)}</span><span className="ee-small ee-ink-3 block">{[d.last_seen_client, d.last_seen_port].filter(Boolean).join(' · ')}</span></> : <span className="ee-ink-3">Not yet</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <p className="ee-small ee-ink-3 pt-3">{plural(devices.length, 'device')}{devices.length !== data.devices.length ? ` of ${data.devices.length}` : ''} · at most {data.limits.devices.toLocaleString('en-GB')} per tenant</p>
                </Panel>
              )}
            </>
          ))}

          {tab === 'seen' && (
            <SeenTab sightings={sightings} loading={seen.isLoading} error={seen.error} retry={() => seen.refetch()} days={days} setDays={setDays} now={now}
              write={write && !allowFirst} selected={selected} setSelected={setSelected}
              onAllow={(s) => setAllowing({ mac: s.mac })} onBulk={() => setBulk(true)}
              onDismiss={(s) => dismiss.mutate(s.id, { onError: (e) => toast('It wasn’t dismissed', errorMessage(e), 'crit') })}
              noGroups={allowFirst} onCreateGroup={() => setGroup('new')} />
          )}

          {tab === 'groups' && (groups.length === 0 ? (
            <Empty icon={<Cable aria-hidden />} title="No groups yet" action={write ? <Btn variant="primary" onClick={() => setGroup('new')}><Plus aria-hidden />Create a group</Btn> : undefined}>
              A group gives its devices a VLAN on switch ports.
            </Empty>
          ) : (
            <Panel className="px-4 py-3 sm:px-5" aria-label="Groups">
              {write && <div className="mb-2 flex justify-end"><Btn size="sm" onClick={() => setGroup('new')}><Plus aria-hidden />New group</Btn></div>}
              <ul className="ee-divide">
                {groups.map((g) => (
                  <li key={g.id} className="flex flex-wrap items-start justify-between gap-3 py-3">
                    <div className="min-w-0">
                      <p className="flex flex-wrap items-center gap-2 text-[14px] font-semibold">{g.name}{!g.enabled && <Chip tone="warn">Off</Chip>}</p>
                      <p className="ee-small ee-ink-2 mt-0.5">{groupVlanLabel(g)} · {plural(g.devices, 'device')}{g.description ? ` · ${g.description}` : ''}</p>
                      {g.shared_with_certificates && <p className="ee-small mt-1 text-[var(--ee-warn-ink)]">Certificate users are placed on this VLAN too: a device that copies a listed MAC lands next to them.</p>}
                    </div>
                    {write && (
                      <div className="flex gap-2">
                        <Btn size="sm" onClick={() => setGroup(g)}>Edit</Btn>
                        <Tip content={g.devices ? 'Move or remove its devices first' : 'Delete group'}>
                          <span><Btn size="sm" variant="danger" icon className="w-7" disabled={g.devices > 0} onClick={() => setRemoveGroup(g)} aria-label={`Delete group ${g.name}`}><Trash2 aria-hidden /></Btn></span>
                        </Tip>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </Panel>
          ))}
        </>
      )}

      <AllowDeviceDialog open={!!allowing} groups={groups} initialMac={allowing?.mac} onClose={() => setAllowing(null)} />
      {data && <ImportDialog open={importing} groups={groups} maxLines={data.limits.import_lines} onClose={() => setImporting(false)} />}
      <GroupDialog open={group !== null} group={group === 'new' ? null : group} onClose={() => setGroup(null)} />
      <BulkAllowDialog open={bulk} macs={[...selected]} groups={groups} onClose={() => setBulk(false)} onDone={() => setSelected(new Set())} />
      <DeviceSheet deviceId={openId} groups={groups} onClose={() => setOpenId(null)} returnFocus={focusAfter} />
      <EDialog open={!!removeGroup} onOpenChange={(o) => !o && setRemoveGroup(null)} risk="crit" title={`Delete ${removeGroup?.name}?`}
        footer={<><Btn variant="ghost" onClick={() => setRemoveGroup(null)}>Cancel</Btn>
          <Btn variant="danger" busy={delGroup.isPending} onClick={() => removeGroup && delGroup.mutate(removeGroup.id, {
            onSuccess: () => { toast('Group deleted'); setRemoveGroup(null) },
            onError: (e) => toast('The group wasn’t deleted', errorMessage(e), 'crit'),
          })}><Trash2 aria-hidden />Delete</Btn></>}>
        <p className="text-[13.5px] ee-ink-2">It has no devices. This can’t be undone.</p>
      </EDialog>
    </div>
  )
}

function SeenTab({ sightings, loading, error, retry, days, setDays, now, write, selected, setSelected, onAllow, onBulk, onDismiss, noGroups, onCreateGroup }: {
  sightings: Sighting[]; loading: boolean; error: unknown; retry: () => void; days: number; setDays: (d: number) => void; now: Date
  write: boolean; selected: Set<string>; setSelected: (s: Set<string>) => void
  onAllow: (s: Sighting) => void; onBulk: () => void; onDismiss: (s: Sighting) => void; noGroups: boolean; onCreateGroup: () => void
}) {
  if (error) return <ErrorState error={error} onRetry={retry} />
  if (loading) return <LoadingBlock rows={4} label="Loading what switches saw" />
  const selectable = sightings.filter((s) => !s.certificate_device)
  const macs = [...new Set(selectable.map((s) => s.mac))]
  const all = macs.length > 0 && macs.every((m) => selected.has(m))
  const toggle = (mac: string) => { const n = new Set(selected); if (n.has(mac)) n.delete(mac); else n.add(mac); setSelected(n) }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <Seg label="Seen in the last" value={String(days)} onChange={(v) => setDays(Number(v))} options={[{ value: '7', label: '7 days' }, { value: '30', label: '30 days' }, { value: '90', label: '90 days' }]} />
        {write && selected.size > 0 && <Btn variant="primary" size="sm" onClick={onBulk}><Plus aria-hidden />Allow {plural(selected.size, 'device')}…</Btn>}
      </div>
      {noGroups && <Callout tone="neutral" action={<Btn size="sm" onClick={onCreateGroup}>Create a group</Btn>}>Create a group before you allow devices: the group decides their VLAN.</Callout>}
      {sightings.length === 0 ? (
        <Empty icon={<Eye aria-hidden />} title="Nothing waiting">
          MAC addresses that switches with MAC authentication ask about, and that aren’t on the list, appear here. In monitor mode their ports stay open, so you can allow them before you enforce.
        </Empty>
      ) : (
        <Panel className="px-4 py-3 sm:px-5" aria-label="Seen, not allowed">
          <div className="overflow-x-auto">
            <table className="ee-table">
              <caption className="sr-only">MAC addresses switches asked about that aren’t on the allow list</caption>
              <thead><tr>
                {write && <th className="pt-1.5 w-8"><input type="checkbox" className="ee-check" aria-label="Select all" checked={all} onChange={() => setSelected(all ? new Set() : new Set(macs))} /></th>}
                <th className="pt-1.5">MAC address</th><th className="pt-1.5">Where</th><th className="pt-1.5 text-right">Attempts</th><th className="pt-1.5">Last seen</th>
                {write && <th className="pt-1.5"><span className="sr-only">Actions</span></th>}
              </tr></thead>
              <tbody>
                {sightings.map((s) => (
                  <tr key={s.id}>
                    {write && <td>{!s.certificate_device && <input type="checkbox" className="ee-check" aria-label={`Select ${s.mac}`} checked={selected.has(s.mac)} onChange={() => toggle(s.mac)} />}</td>}
                    <td className="whitespace-nowrap">
                      <span className="ee-mono text-[12.5px]">{s.mac}</span>
                      <span className="mt-0.5 flex flex-wrap gap-1">
                        {s.certificate_device && <Tip content="This MAC signs in with a certificate elsewhere: listing it would let anything that copies it skip the certificate."><span><Chip tone="crit">Uses a certificate</Chip></span></Tip>}
                        {s.randomized && <Tip content="A randomised address: the device may change it, and an entry stops matching."><span><Chip tone="warn">Random</Chip></span></Tip>}
                        {s.reason_code && s.reason_code !== 'mac_unknown' && <Chip tone="neutral">{failureExplanations[s.reason_code as FailureCode]?.title ?? s.reason_code}</Chip>}
                      </span>
                    </td>
                    <td><span className="block">{s.switch ?? 'A removed switch'}</span>{s.port && <span className="ee-mono ee-small ee-ink-3">{s.port}</span>}</td>
                    <td className="text-right ee-num">{s.attempts.toLocaleString('en-GB')}</td>
                    <td className="whitespace-nowrap" title={fmtDateTime(s.last_seen)}>{ago(s.last_seen, now)}<span className="ee-small ee-ink-3 block">first {ago(s.first_seen, now)}</span></td>
                    {write && (
                      <td className="text-right whitespace-nowrap">
                        <span className="inline-flex gap-1.5">
                          <Btn size="sm" onClick={() => onAllow(s)}>Allow…</Btn>
                          <Tip content="Dismiss (it reappears if the switch asks again)"><Btn size="sm" variant="ghost" icon className="w-7" aria-label={`Dismiss ${s.mac}`} onClick={() => onDismiss(s)}><X aria-hidden /></Btn></Tip>
                        </span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  )
}
