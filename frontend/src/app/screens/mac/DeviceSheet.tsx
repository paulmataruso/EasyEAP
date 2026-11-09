// One MAC allow-list entry: where it was last seen, its recent attempts, and edit / block / delete. Opens as a side
// sheet like an authentication attempt; focus returns to the row.
import { useEffect, useId, useState, type ReactNode, type RefObject } from 'react'
import { Link } from 'react-router'
import { Dialog } from 'radix-ui'
import { Ban, Check, Pencil, Trash2, X } from 'lucide-react'
import { errorField } from '../../api/client'
import { useTenant } from '../../api/tenant'
import { coaSummary, statusLabels, useDeleteDevice, useMacDevice, useUpdateDevice, type DeviceGroup, type MacDevice, type MacStatus } from '../../api/mac'
import { failureExplanations } from '@/domain/explain'
import type { FailureCode } from '@/domain/types'
import { ago, fmtDate, fmtDateTime } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { Btn, Callout, Chip, Dl, EDialog, ESelect, ErrorState, Field, LoadingBlock, OutcomeChip, errorMessage, toast, type Tone } from '../../ui'
import { groupVlanLabel } from './dialogs'

export const statusTone: Record<MacStatus, Tone> = { allowed: 'valid', blocked: 'crit', expired: 'warn', group_off: 'warn' }
const sourceLabels: Record<string, string> = { manual: 'Added by hand', import: 'Imported', learned: 'Allowed from “Seen, not allowed”' }
const linkCls = 'underline decoration-[var(--ee-line-3)] underline-offset-[3px] hover:decoration-[var(--ee-ink)]'

function EditForm({ device, groups, onDone }: { device: MacDevice; groups: DeviceGroup[]; onDone: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const update = useUpdateDevice(tid)
  const [name, setName] = useState(device.name)
  const [groupId, setGroupId] = useState(device.group_id)
  const [notes, setNotes] = useState(device.notes)
  const [expires, setExpires] = useState(device.expires_at ? device.expires_at.slice(0, 10) : '')
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  const moved = groupId !== device.group_id
  const submit = () => {
    if (!name.trim()) return setError({ field: 'name', message: 'Name the device.' })
    update.mutate({ id: device.id, body: {
      name: name.trim(), notes, group_id: groupId,
      ...(expires ? { expires_at: new Date(`${expires}T23:59:59`).toISOString() } : { clear_expiry: true }),
    } }, {
      onSuccess: (r) => { toast('Device saved', coaSummary(r.coa) ?? 'RADIUS uses the change within about 15 seconds.'); onDone() },
      onError: (e) => setError({ field: errorField(e) ?? '', message: errorMessage(e) }),
    })
  }
  return (
    <form noValidate className="space-y-4 rounded-[10px] border border-[var(--ee-line)] p-4" onSubmit={(e) => { e.preventDefault(); submit() }}>
      <Field label="Name" htmlFor={`${id}-n`} error={error?.field === 'name' ? error.message : null}>
        <input id={`${id}-n`} className="ee-input" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} autoComplete="off" />
      </Field>
      <Field label="Group" htmlFor={`${id}-g`} hint={moved ? 'A new VLAN takes effect when the device reconnects: Cisco switches with CoA restart its port now.' : undefined}>
        <ESelect id={`${id}-g`} label="Group" value={groupId} onChange={setGroupId} className="w-full"
          options={groups.map((g) => ({ value: g.id, label: <>{g.name}<span className="ee-ink-3 ml-1.5">{groupVlanLabel(g)}</span></> }))} />
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Expires" htmlFor={`${id}-x`} optional hint="Blank: never.">
          <input id={`${id}-x`} type="date" className="ee-input" value={expires} onChange={(e) => setExpires(e.target.value)} />
        </Field>
        <Field label="Notes" htmlFor={`${id}-o`} optional>
          <input id={`${id}-o`} className="ee-input" value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={500} autoComplete="off" />
        </Field>
      </div>
      {error && error.field !== 'name' && <Callout tone="crit">{error.message}</Callout>}
      <div className="flex justify-end gap-2">
        <Btn variant="ghost" size="sm" onClick={onDone}>Cancel</Btn>
        <Btn variant="primary" size="sm" type="submit" busy={update.isPending}>Save</Btn>
      </div>
    </form>
  )
}

export function DeviceSheet({ deviceId, groups, onClose, returnFocus }: {
  deviceId: string | null; groups: DeviceGroup[]; onClose: () => void; returnFocus: RefObject<HTMLElement | null>
}) {
  const { tid, can } = useTenant()
  const now = useNow()
  const q = useMacDevice(tid, deviceId)
  const update = useUpdateDevice(tid)
  const del = useDeleteDevice(tid)
  const [editing, setEditing] = useState(false)
  const [deleting, setDeleting] = useState(false)
  useEffect(() => { setEditing(false); setDeleting(false) }, [deviceId])
  const d = q.data
  const write = can('mac:write')
  const setEnabled = (enabled: boolean) => d && update.mutate({ id: d.id, body: { enabled } }, {
    onSuccess: (r) => toast(enabled ? `${r.name} unblocked` : `${r.name} blocked`, coaSummary(r.coa) ?? (enabled ? 'It’s admitted at its next attempt.' : 'It’s refused from its next attempt.')),
    onError: (e) => toast('The device wasn’t changed', errorMessage(e), 'crit'),
  })
  const remove = () => d && del.mutate(d.id, {
    onSuccess: (r) => { toast(`${d.name} removed`, coaSummary(r.coa) ?? 'Switches refuse it from its next attempt.'); setDeleting(false); onClose() },
    onError: (e) => toast('The device wasn’t removed', errorMessage(e), 'crit'),
  })
  return (
    <Dialog.Root open={!!deviceId} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="ee-backdrop" />
        <Dialog.Content className="ee-sheet" aria-describedby={undefined}
          onCloseAutoFocus={(ev) => { ev.preventDefault(); const t = returnFocus.current; (t && t.isConnected ? t : document.querySelector<HTMLElement>('[data-page-heading]'))?.focus() }}>
          <div className="sticky top-0 z-[1] flex items-start justify-between gap-4 border-b border-[var(--ee-line)] bg-[#10172a] px-5 py-4 sm:px-6">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                {d && <Chip tone={statusTone[d.status]}>{statusLabels[d.status]}</Chip>}
                <Dialog.Title className="ee-h2 text-[17px] break-words">{d?.name ?? 'Device'}</Dialog.Title>
              </div>
              {d && <p className="ee-mono ee-small ee-ink-2 mt-1.5">{d.mac}</p>}
            </div>
            <Dialog.Close asChild><Btn variant="ghost" size="sm" icon aria-label="Close"><X aria-hidden /></Btn></Dialog.Close>
          </div>
          <div className="px-5 py-5 sm:px-6">
            {!d ? (q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="This device couldn’t be loaded" /> : <LoadingBlock rows={6} label="Loading device" />) : (
              <div className="space-y-6">
                {d.certificate_device && (
                  <Callout tone="crit" title="This MAC also signs in with a certificate">Anything that copies this address gets on without one. Remove the entry unless the device can’t use its certificate on wired ports.</Callout>
                )}
                {d.answers_8021x && (
                  <Callout tone="warn" title="This device answers 802.1X">It tried 802.1X in the last week and failed, so switches never fall back to its MAC address. Turn 802.1X off on the device, or enroll it for a certificate.</Callout>
                )}
                {d.randomized && (
                  <Callout tone="warn" title="Randomised MAC address">Phones and laptops change these per network, so this entry stops matching when the device picks a new one. Turn off private addresses for this network on the device.</Callout>
                )}
                {d.status === 'group_off' && <Callout tone="warn">Its group, {d.group_name}, is turned off: every device in it is refused.</Callout>}
                {write && !editing && (
                  <div className="flex flex-wrap gap-2">
                    <Btn size="sm" onClick={() => setEditing(true)}><Pencil aria-hidden />Edit</Btn>
                    {d.enabled
                      ? <Btn size="sm" busy={update.isPending} onClick={() => setEnabled(false)}><Ban aria-hidden />Block</Btn>
                      : <Btn size="sm" busy={update.isPending} onClick={() => setEnabled(true)}><Check aria-hidden />Unblock</Btn>}
                    <Btn size="sm" variant="danger" onClick={() => setDeleting(true)}><Trash2 aria-hidden />Remove</Btn>
                  </div>
                )}
                {editing && <EditForm device={d} groups={groups} onDone={() => setEditing(false)} />}
                <section aria-labelledby="mac-details">
                  <h3 id="mac-details" className="ee-h3 mb-3">Details</h3>
                  <Dl items={[
                    ['Group', <span>{d.group_name ?? '—'}<span className="ee-small ee-ink-3 block">{(() => { const g = groups.find((x) => x.id === d.group_id); return g ? groupVlanLabel(g) : null })()}</span></span>],
                    ['Expires', d.expires_at ? <span className={d.status === 'expired' ? 'text-[var(--ee-warn-ink)]' : undefined}>{fmtDate(d.expires_at)}</span> : <span className="ee-ink-3">Never</span>],
                    ['Last seen', d.last_seen_at
                      ? <span>{ago(d.last_seen_at, now)}<span className="ee-small ee-ink-3 block">{[d.last_seen_client, d.last_seen_port].filter(Boolean).join(' · ') || fmtDateTime(d.last_seen_at)}</span></span>
                      : <span className="ee-ink-3">Not yet</span>],
                    ['Added', <span>{fmtDate(d.created_at)}<span className="ee-small ee-ink-3 block">{[sourceLabels[d.source] ?? d.source, d.created_by].filter(Boolean).join(' · ')}</span></span>],
                    ...(d.notes ? [['Notes', <span className="break-words">{d.notes}</span>, 'wide'] as [string, ReactNode, 'wide']] : []),
                  ]} />
                </section>
                <section aria-labelledby="mac-events">
                  <h3 id="mac-events" className="ee-h3 mb-3">Recent attempts</h3>
                  {d.events.length === 0 ? <p className="ee-small ee-ink-2">No attempts from this MAC address in the authentication log yet.</p> : (
                    <ul className="ee-divide">
                      {d.events.slice(0, 20).map((e) => (
                        <li key={e.id} className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 py-2 text-[13px]">
                          <span className="min-w-0">
                            <span className="flex flex-wrap items-center gap-2">
                              <OutcomeChip outcome={e.result} label={e.result === 'accept' ? (e.monitor ? 'Accepted (monitor)' : 'Accepted') : undefined} />
                              {e.result === 'reject' && <span>{failureExplanations[e.reason_code as FailureCode]?.title ?? e.reason_code ?? 'Rejected'}</span>}
                              {e.method && !e.method.startsWith('mab') && <Chip tone="neutral">802.1X</Chip>}
                            </span>
                            <span className="ee-small ee-ink-3 block mt-0.5">{[e.switch, e.port, e.vlan_id ? `VLAN ${e.vlan_id}` : null].filter(Boolean).join(' · ')}</span>
                          </span>
                          {can('events:read')
                            ? <Link to={paths.events(tid, { event: String(e.id) })} className={`ee-small ee-ink-2 whitespace-nowrap ${linkCls}`}>{ago(e.at, now)}</Link>
                            : <span className="ee-small ee-ink-2 whitespace-nowrap">{ago(e.at, now)}</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              </div>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
      <EDialog open={deleting} onOpenChange={setDeleting} risk="crit" title={`Remove ${d?.name}?`}
        description="Switches refuse it from its next attempt, and a connected session is disconnected where the switch supports CoA."
        footer={<><Btn variant="ghost" onClick={() => setDeleting(false)}>Cancel</Btn><Btn variant="danger" busy={del.isPending} onClick={remove}><Trash2 aria-hidden />Remove</Btn></>}>
        <p className="text-[13.5px] ee-ink-2">To keep the entry but stop admitting it, block it instead.</p>
      </EDialog>
    </Dialog.Root>
  )
}
