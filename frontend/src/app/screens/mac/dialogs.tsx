// MAC allow list dialogs: a group (its VLAN), allowing one device, importing a list, and allowing several from
// "Seen, not allowed". Listing the MAC of a device that signs in with a certificate needs an explicit confirmation:
// anything that copies that address would get on without one.
import { useEffect, useId, useState } from 'react'
import { ApiError, errorField } from '../../api/client'
import {
  checkMac, coaSummary, formatMac, isRandomized, useBulkAllow, useCreateDevice, useImportDevices, useSaveGroup,
  type DeviceGroup, type ImportError,
} from '../../api/mac'
import { usePolicy, wiredVlanOf } from '../../api/policy'
import { useTenant } from '../../api/tenant'
import { plural } from '../../lib/format'
import { Btn, Callout, EDialog, ESelect, ESwitch, Field, Seg, errorMessage, toast } from '../../ui'

/** The API's machine-readable reason for a refusal ({"detail": {"code": …}}). */
export function errorCode(e: unknown): string | null {
  const body = e instanceof ApiError ? e.detail : null
  const d = body && typeof body === 'object' && 'detail' in body ? (body as { detail: unknown }).detail : null
  return d && typeof d === 'object' && !Array.isArray(d) && typeof (d as { code?: unknown }).code === 'string' ? (d as { code: string }).code : null
}

export function groupVlanLabel(g: Pick<DeviceGroup, 'port_vlan' | 'vlan_id' | 'vlan_name' | 'switch_vlan'>): string {
  if (g.port_vlan || g.vlan_id === null) return 'The port’s own VLAN'
  const base = `VLAN ${g.vlan_id}${g.vlan_name ? ` · ${g.vlan_name}` : ''}`
  return g.switch_vlan !== g.vlan_id ? `${base} (${g.switch_vlan === null ? 'the port’s own VLAN' : `VLAN ${g.switch_vlan}`} on switch ports)` : base
}

function CertificateConfirm({ checked, onChange, count = 1 }: { checked: boolean; onChange: (v: boolean) => void; count?: number }) {
  return (
    <Callout tone="crit" title={count === 1 ? 'This MAC belongs to a device that signs in with a certificate' : `${count} of these MACs belong to devices that sign in with certificates`}>
      <p>Anything that copies {count === 1 ? 'this address' : 'these addresses'} would get on the network without a certificate. Only list {count === 1 ? 'it' : 'them'} if the device can’t use its certificate on wired ports.</p>
      <label className="mt-2.5 flex items-start gap-2.5 text-[13px]">
        <input type="checkbox" className="ee-check mt-0.5" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span>List {count === 1 ? 'it' : 'them'} anyway</span>
      </label>
    </Callout>
  )
}

function GroupSelect({ id, groups, value, onChange, error }: { id: string; groups: DeviceGroup[]; value: string; onChange: (v: string) => void; error?: string | null }) {
  return (
    <Field label="Group" htmlFor={id} error={error} hint="The group decides the VLAN. Manage groups on the Groups tab.">
      <ESelect id={id} label="Group" value={value} onChange={onChange} className="w-full" placeholder="Choose a group"
        options={groups.map((g) => ({ value: g.id, label: <>{g.name}<span className="ee-ink-3 ml-1.5">{groupVlanLabel(g)}{g.enabled ? '' : ' · off'}</span></> }))} />
    </Field>
  )
}

// ── Group ────────────────────────────────────────────────────────────────

export function GroupDialog({ open, group, onClose }: { open: boolean; group: DeviceGroup | null; onClose: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const save = useSaveGroup(tid)
  const policy = usePolicy(tid)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [portVlan, setPortVlan] = useState(false)
  const [vlanRef, setVlanRef] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  useEffect(() => {
    if (!open) return
    setName(group?.name ?? ''); setDescription(group?.description ?? ''); setPortVlan(group?.port_vlan ?? false)
    setVlanRef(group?.vlan_ref ?? ''); setEnabled(group?.enabled ?? true); setError(null)
  }, [open, group])
  const vlans = policy.data?.vlans ?? []
  const chosen = vlans.find((v) => v.id === vlanRef)
  const err = (f: string) => (error?.field === f ? error.message : null)
  const submit = () => {
    setError(null)
    if (!name.trim()) return setError({ field: 'name', message: 'Name the group, for example Printers.' })
    if (!portVlan && !vlanRef) return setError({ field: 'vlan_ref', message: 'Choose the VLAN for devices in this group.' })
    save.mutate({ id: group?.id, body: { name: name.trim(), description, port_vlan: portVlan, vlan_ref: portVlan ? null : vlanRef, enabled } }, {
      onSuccess: (r) => { toast(group ? 'Group saved' : 'Group created', coaSummary(r.coa) ?? (group ? 'RADIUS uses the change within about 15 seconds.' : 'Add devices to it from the Devices tab.')); onClose() },
      onError: (e) => setError({ field: errorField(e) ?? '', message: errorMessage(e) }),
    })
  }
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} title={group ? `Edit ${group.name}` : 'New group'}
      description="A group of devices that share a VLAN, such as printers or cameras."
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" type="submit" form={`${id}-f`} busy={save.isPending}>{group ? 'Save group' : 'Create group'}</Btn></>}>
      <form id={`${id}-f`} noValidate className="space-y-4" onSubmit={(e) => { e.preventDefault(); submit() }}>
        <Field label="Name" htmlFor={`${id}-n`} error={err('name')}>
          <input id={`${id}-n`} className="ee-input" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="Printers" autoComplete="off" />
        </Field>
        <Field label="Description" htmlFor={`${id}-d`} optional>
          <input id={`${id}-d`} className="ee-input" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={300} autoComplete="off" />
        </Field>
        <Field label="VLAN on switch ports" htmlFor={`${id}-v`} error={err('vlan_ref')}
          hint="A MAC address is easy to copy, so choose a VLAN that reaches only what these devices need (for printers: the print server).">
          <div className="space-y-2.5">
            <Seg label="VLAN on switch ports" value={portVlan ? 'port' : 'vlan'} onChange={(v) => setPortVlan(v === 'port')}
              options={[{ value: 'vlan', label: 'A VLAN' }, { value: 'port', label: 'The port’s own VLAN' }]} />
            {!portVlan && (vlans.length === 0 && !policy.isLoading
              ? <Callout tone="warn">There are no VLANs yet. Add one in Access policy, then come back.</Callout>
              : <ESelect id={`${id}-v`} label="VLAN" value={vlanRef} onChange={setVlanRef} className="w-full" placeholder="Choose a VLAN"
                options={vlans.map((v) => ({ value: v.id, label: <>VLAN {v.vlan_id}<span className="ee-ink-3 ml-1.5">{v.name}</span></> }))} />)}
            {!portVlan && chosen && wiredVlanOf(chosen) !== chosen.vlan_id && (
              <p className="ee-small ee-ink-2">On switch ports this VLAN is {wiredVlanOf(chosen) === null ? 'not sent: devices keep the port’s own VLAN' : `VLAN ${wiredVlanOf(chosen)}`} (its “On switch ports” setting in Access policy).</p>
            )}
            {!portVlan && chosen && chosen.certificates > 0 && (
              <Callout tone="warn">{plural(chosen.certificates, 'certificate')} {chosen.certificates === 1 ? 'is' : 'are'} also placed on this VLAN. A device that copies a listed MAC would land next to them: a separate VLAN is safer.</Callout>
            )}
          </div>
        </Field>
        {group && (
          <div className="flex items-start justify-between gap-6">
            <div className="min-w-0">
              <p className="text-[13px] font-semibold">On</p>
              <p className="ee-small ee-ink-3 mt-0.5">{enabled ? 'Devices in this group are admitted.' : 'Every device in this group is refused, and connected ones are disconnected.'}</p>
            </div>
            <ESwitch checked={enabled} onChange={setEnabled} label="Group on" />
          </div>
        )}
        {error && !['name', 'vlan_ref'].includes(error.field) && <Callout tone="crit" title="The group wasn’t saved">{error.message}</Callout>}
      </form>
    </EDialog>
  )
}

// ── Allow one device ─────────────────────────────────────────────────────

export function AllowDeviceDialog({ open, groups, initialMac, onClose, onAdded }: {
  open: boolean; groups: DeviceGroup[]; initialMac?: string; onClose: () => void; onAdded?: (id: string) => void
}) {
  const { tid } = useTenant()
  const id = useId()
  const create = useCreateDevice(tid)
  const [mac, setMac] = useState('')
  const [name, setName] = useState('')
  const [groupId, setGroupId] = useState('')
  const [notes, setNotes] = useState('')
  const [expires, setExpires] = useState('')
  const [certNeeded, setCertNeeded] = useState(false)
  const [certOk, setCertOk] = useState(false)
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  useEffect(() => {
    if (!open) return
    setMac(initialMac ?? ''); setName(''); setNotes(''); setExpires(''); setCertNeeded(false); setCertOk(false); setError(null)
    setGroupId(groups.length === 1 ? groups[0].id : '')
  }, [open, initialMac, groups])
  const parsed = checkMac(mac)
  const err = (f: string) => (error?.field === f ? error.message : null)
  const submit = () => {
    setError(null)
    if ('error' in parsed) return setError({ field: 'mac', message: parsed.error })
    if (!name.trim()) return setError({ field: 'name', message: 'Name the device so others recognise it, for example “Printer, 2nd floor”.' })
    if (!groupId) return setError({ field: 'group_id', message: 'Choose a group.' })
    if (certNeeded && !certOk) return
    create.mutate({ mac: parsed.mac, name: name.trim(), group_id: groupId, notes, enabled: true, expires_at: expires ? new Date(`${expires}T23:59:59`).toISOString() : null, confirm_certificate: certOk }, {
      onSuccess: (r) => { toast(`${r.name} allowed`, coaSummary(r.coa) ?? 'RADIUS admits it within about 15 seconds.'); onAdded?.(r.id); onClose() },
      onError: (e) => {
        if (errorCode(e) === 'certificate_device') { setCertNeeded(true); return }
        setError({ field: errorField(e) ?? '', message: errorMessage(e) })
      },
    })
  }
  const today = new Date().toISOString().slice(0, 10)
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} title="Allow a device"
      description="Switches with MAC authentication admit it when it doesn’t answer 802.1X."
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" type="submit" form={`${id}-f`} busy={create.isPending} disabled={certNeeded && !certOk}>Allow device</Btn></>}>
      <form id={`${id}-f`} noValidate className="space-y-4" onSubmit={(e) => { e.preventDefault(); submit() }}>
        <Field label="MAC address" htmlFor={`${id}-m`} error={err('mac')} hint={'mac' in parsed && isRandomized(parsed.mac)
          ? 'This looks like a randomised address (phones and laptops change these per network), so the entry may stop matching. Turn off private addresses on the device first.'
          : 'Any notation: AA:BB:CC:DD:EE:FF, aa-bb-…, aabb.ccdd.eeff. It’s on the device’s label or in its network settings.'}>
          <input id={`${id}-m`} className="ee-input ee-mono" value={mac} onChange={(e) => { setMac(e.target.value); setCertNeeded(false); setCertOk(false) }}
            placeholder="AA:BB:CC:DD:EE:FF" spellCheck={false} autoComplete="off" aria-invalid={!!err('mac') || undefined} />
        </Field>
        <Field label="Name" htmlFor={`${id}-n`} error={err('name')}>
          <input id={`${id}-n`} className="ee-input" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} placeholder="Printer, 2nd floor" autoComplete="off" />
        </Field>
        <GroupSelect id={`${id}-g`} groups={groups} value={groupId} onChange={setGroupId} error={err('group_id')} />
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Expires" htmlFor={`${id}-x`} optional hint="For a contractor’s or a loaned device. Refused, and disconnected, after this day.">
            <input id={`${id}-x`} type="date" className="ee-input" value={expires} min={today} onChange={(e) => setExpires(e.target.value)} />
          </Field>
          <Field label="Notes" htmlFor={`${id}-o`} optional>
            <input id={`${id}-o`} className="ee-input" value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={500} autoComplete="off" />
          </Field>
        </div>
        {certNeeded && <CertificateConfirm checked={certOk} onChange={setCertOk} />}
        {error && !['mac', 'name', 'group_id'].includes(error.field) && <Callout tone="crit" title="The device wasn’t allowed">{error.message}</Callout>}
      </form>
    </EDialog>
  )
}

// ── Import ───────────────────────────────────────────────────────────────

export function ImportDialog({ open, groups, maxLines, onClose }: { open: boolean; groups: DeviceGroup[]; maxLines: number; onClose: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const imp = useImportDevices(tid)
  const [text, setText] = useState('')
  const [groupId, setGroupId] = useState('')
  const [errors, setErrors] = useState<ImportError[]>([])
  const [certOk, setCertOk] = useState(false)
  useEffect(() => { if (open) { setText(''); setErrors([]); setCertOk(false); setGroupId(groups.length === 1 ? groups[0].id : '') } }, [open, groups])
  const lines = text.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length
  const certErrors = errors.filter((e) => e.code === 'certificate_device')
  const otherErrors = errors.filter((e) => e.code !== 'certificate_device')
  const submit = () => imp.mutate({ text, group_id: groupId, confirm_certificate: certOk }, {
    onSuccess: (r) => {
      if (r.errors.length) { setErrors(r.errors); return }
      toast(`${plural(r.added, 'device')} imported`, 'RADIUS admits them within about 15 seconds.')
      onClose()
    },
    onError: (e) => toast('The list wasn’t imported', errorMessage(e), 'crit'),
  })
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} wide title="Import devices"
      description="One device per line: MAC address, then optionally a name and a group. Nothing is added unless every line is valid."
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="primary" busy={imp.isPending} disabled={!text.trim() || !groupId || lines > maxLines || (certErrors.length > 0 && otherErrors.length === 0 && !certOk)} onClick={submit}>
          Import {lines ? plural(lines, 'line') : ''}
        </Btn></>}>
      <div className="space-y-4">
        <Field label="Devices" htmlFor={`${id}-t`} error={lines > maxLines ? `Import at most ${maxLines} lines at a time.` : null}
          hint={<>For example <span className="ee-mono">AA:BB:CC:DD:EE:01,Printer 2nd floor,Printers</span>. A header line, blank lines and lines starting with # are skipped. A CSV exported from here imports as is.</>}>
          <textarea id={`${id}-t`} className="ee-input ee-mono min-h-[180px] text-[12.5px]" value={text} spellCheck={false}
            onChange={(e) => { setText(e.target.value); setErrors([]); setCertOk(false) }} placeholder={'mac,name,group\nAA:BB:CC:DD:EE:01,Printer 2nd floor,Printers'} />
        </Field>
        <GroupSelect id={`${id}-g`} groups={groups} value={groupId} onChange={setGroupId} />
        {otherErrors.length > 0 && (
          <Callout tone="crit" title={`${plural(otherErrors.length, 'line')} need${otherErrors.length === 1 ? 's' : ''} fixing first`}>
            <ul className="mt-1 max-h-[180px] space-y-1 overflow-auto">
              {otherErrors.map((e, i) => <li key={i}><span className="ee-mono text-[12px]">{e.line ? `Line ${e.line}: ` : ''}{e.text}</span> · {e.message}</li>)}
            </ul>
          </Callout>
        )}
        {certErrors.length > 0 && (
          <>
            <CertificateConfirm checked={certOk} onChange={setCertOk} count={certErrors.length} />
            <p className="ee-small ee-ink-3 ee-mono break-words">{certErrors.map((e) => e.text).join(', ')}</p>
          </>
        )}
      </div>
    </EDialog>
  )
}

// ── Allow several from "Seen, not allowed" ───────────────────────────────

export function BulkAllowDialog({ open, macs, groups, onClose, onDone }: { open: boolean; macs: string[]; groups: DeviceGroup[]; onClose: () => void; onDone: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const bulk = useBulkAllow(tid)
  const [groupId, setGroupId] = useState('')
  const [certNeeded, setCertNeeded] = useState<string | null>(null)
  const [certOk, setCertOk] = useState(false)
  useEffect(() => { if (open) { setCertNeeded(null); setCertOk(false); setGroupId(groups.length === 1 ? groups[0].id : '') } }, [open, groups])
  const submit = () => bulk.mutate({ macs, group_id: groupId, confirm_certificate: certOk }, {
    onSuccess: (r) => {
      toast(`${plural(r.added, 'device')} allowed`, r.already_listed ? `${plural(r.already_listed, 'was', 'were')} already on the list.` : 'Each is named after where it was seen: rename them from the Devices tab.')
      onDone(); onClose()
    },
    onError: (e) => { if (errorCode(e) === 'certificate_device') setCertNeeded(errorMessage(e)); else toast('The devices weren’t allowed', errorMessage(e), 'crit') },
  })
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} title={`Allow ${plural(macs.length, 'device')}`}
      description="Each is named after the switch and port it was seen on."
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" busy={bulk.isPending} disabled={!groupId || (!!certNeeded && !certOk)} onClick={submit}>Allow</Btn></>}>
      <div className="space-y-4">
        <p className="ee-mono text-[12.5px] ee-ink-2 break-words">{macs.slice(0, 12).map((m) => formatMac(m.replace(/[^0-9A-Fa-f]/g, '').toUpperCase())).join(', ')}{macs.length > 12 ? ` and ${macs.length - 12} more` : ''}</p>
        <GroupSelect id={`${id}-g`} groups={groups} value={groupId} onChange={setGroupId} />
        {certNeeded && (
          <>
            <CertificateConfirm checked={certOk} onChange={setCertOk} count={2} />
            <p className="ee-small ee-ink-3">{certNeeded}</p>
          </>
        )}
      </div>
    </EDialog>
  )
}
