// VLANs. Unlike rules, VLAN changes are not staged: create, edit and delete apply immediately through the VLAN
// endpoints, and the dialogs say so. The API refuses to delete a VLAN a rule or the default still assigns (409).
// Each VLAN also says what a wired 802.1X switch port gets when a rule assigns it (docs/plans/wired-8021x.md §4).
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { RadioGroup } from 'radix-ui'
import { PencilLine, Plus, Trash2 } from 'lucide-react'
import { cn } from '@/ui/lib'
import { ApiError } from '../../api/client'
import { qk } from '../../api/keys'
import { policyApi, wiredVlanOf, type PolicyResponse, type Vlan, type VlanBody, type WiredMode } from '../../api/policy'
import { plural } from '../../lib/format'
import { Btn, Callout, EDialog, Empty, Field, Panel, SectionHeader, toast, VLAN_COLORS, VlanTag, vlanVar } from '../../ui'
import type { Draft } from './draft'

interface Usage { live: string[]; draft: string[]; liveDefault: boolean; draftDefault: boolean }

function usageOf(v: Vlan, live: PolicyResponse, draft: Draft | null): Usage {
  return {
    live: live.rules.filter((r) => r.action === 'allow' && r.vlan_ref === v.id).map((r) => r.name),
    draft: (draft?.rules ?? []).filter((r) => !r.removed && r.action === 'allow' && r.vlan_ref === v.id).map((r) => r.name),
    liveDefault: live.settings.default_action === 'allow' && live.settings.default_vlan_ref === v.id,
    draftDefault: !!draft && draft.default_action === 'allow' && draft.default_vlan_ref === v.id,
  }
}

const sameList = (a: string[], b: string[]) => a.join('\u0000') === b.join('\u0000')

function AssignedBy({ u, draft, inline }: { u: Usage; draft: Draft | null; inline?: boolean }) {
  const draftDiffers = !!draft && (!sameList(u.live, u.draft) || u.liveDefault !== u.draftDefault)
  return (
    <>
      {u.live.length || u.liveDefault ? (
        <span className="ee-ink-2">{[...u.live.map((n) => `“${n}”`), ...(u.liveDefault ? ['tenant default'] : [])].join(', ')}</span>
      ) : <span className="ee-ink-3">no rule</span>}
      {draftDiffers && (
        <span className={inline ? 'ee-small ml-1.5 text-[var(--ee-warn-ink)]' : 'ee-small mt-0.5 block text-[var(--ee-warn-ink)]'}>
          Draft: {[...u.draft.map((n) => `“${n}”`), ...(u.draftDefault ? ['tenant default'] : [])].join(', ') || 'no rule'}
        </span>
      )}
    </>
  )
}

/** What a switch port gets for this VLAN, compactly: "Same VLAN", "Port's own VLAN" or the other VLAN's tag. */
function SwitchPorts({ v, vlans }: { v: Vlan; vlans: Vlan[] }) {
  if (v.wired_mode === 'port') return <span className="ee-ink-2" title="No VLAN is assigned on switch ports: the device stays on the port’s own VLAN.">Port’s own VLAN</span>
  if (v.wired_mode === 'vlan' && v.wired_vlan_id !== null) {
    const other = vlans.find((x) => x.vlan_id === v.wired_vlan_id)
    return <VlanTag vlanId={v.wired_vlan_id} name={other?.name} color={other?.color} />
  }
  return <span className="ee-ink-3">Same VLAN</span>
}

const wiredText = (v: Pick<Vlan, 'vlan_id' | 'wired_mode' | 'wired_vlan_id'>) => {
  const w = wiredVlanOf(v)
  return w === null ? 'the port’s own VLAN' : `VLAN ${w}`
}

function VlanActions({ v, onEdit, onDelete }: { v: Vlan; onEdit: (v: Vlan) => void; onDelete: (v: Vlan) => void }) {
  return (
    <>
      <Btn size="sm" variant="ghost" onClick={() => onEdit(v)} aria-label={`Edit VLAN ${v.vlan_id} ${v.name}`}><PencilLine aria-hidden />Edit</Btn>
      <Btn size="sm" variant="ghost" icon className="w-7" onClick={() => onDelete(v)} aria-label={`Delete VLAN ${v.vlan_id} ${v.name}`}><Trash2 aria-hidden /></Btn>
    </>
  )
}

export function VlanSection({ tid, live, draft, canWrite }: { tid: string; live: PolicyResponse; draft: Draft | null; canWrite: boolean }) {
  const [editing, setEditing] = useState<Vlan | 'new' | null>(null)
  const [deleting, setDeleting] = useState<Vlan | null>(null)
  // A deleted VLAN's row (and its button) disappears: return focus to "Add VLAN" instead.
  const addRef = useRef<HTMLButtonElement>(null)
  // Colour is how a VLAN is recognised across EasyEAP; two VLANs sharing one breaks that, so name the clash.
  const clashes = VLAN_COLORS.map((c) => live.vlans.filter((v) => v.color === c)).filter((g) => g.length > 1)

  return (
    <section aria-labelledby="vlans-h">
      <SectionHeader id="vlans-h" title="VLANs" meta="Colour-coded the same everywhere in EasyEAP. Changes apply immediately."
        actions={canWrite ? <Btn ref={addRef} size="sm" onClick={() => setEditing('new')}><Plus aria-hidden />Add VLAN</Btn> : undefined} />
      {clashes.length > 0 && (
        <Callout tone="warn" className="mb-3" title="Some VLANs share a colour">
          {clashes.map((g) => `${g.map((v) => v.vlan_id).join(' and ')} are both ${g[0].color}`).join('; ')}, so they can’t be told apart at a glance.
          {canWrite ? ' Edit one and choose another colour.' : ''}
        </Callout>
      )}
      <Panel className="overflow-hidden">
        {live.vlans.length === 0 ? (
          <div className="p-4"><Empty title="No VLANs yet">Allow rules place people on a VLAN, so create at least one. Use the VLAN numbers your switches and controllers already carry.</Empty></div>
        ) : (
          <>
          <div className="hidden md:block">
            <table className="ee-table">
              <caption className="sr-only">VLANs, what switch ports get instead, the rules that assign them and how many certificates they currently receive</caption>
              <thead>
                <tr><th className="pt-3">VLAN</th><th className="pt-3">Description</th><th className="pt-3" title="What a wired 802.1X switch port gets when a rule assigns this VLAN">On switch ports</th><th className="pt-3">Assigned by</th><th className="pt-3 text-right">Certificates</th>{canWrite && <th className="pt-3"><span className="sr-only">Actions</span></th>}</tr>
              </thead>
              <tbody>
                {live.vlans.map((v) => (
                  <tr key={v.id}>
                    <td><VlanTag vlanId={v.vlan_id} name={v.name} color={v.color} /></td>
                    <td className="ee-ink-2 min-w-[160px]">{v.description || <span className="ee-ink-3">—</span>}</td>
                    <td className="whitespace-nowrap"><SwitchPorts v={v} vlans={live.vlans} /></td>
                    <td className="min-w-[180px]"><AssignedBy u={usageOf(v, live, draft)} draft={draft} /></td>
                    <td className="ee-num text-right">{v.certificates}</td>
                    {canWrite && <td className="whitespace-nowrap text-right"><VlanActions v={v} onEdit={setEditing} onDelete={setDeleting} /></td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <ul className="ee-divide list-none p-0 md:hidden" aria-label="VLANs">
            {live.vlans.map((v) => (
              <li key={v.id} className="px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <VlanTag vlanId={v.vlan_id} name={v.name} color={v.color} />
                  {canWrite && <span className="shrink-0"><VlanActions v={v} onEdit={setEditing} onDelete={setDeleting} /></span>}
                </div>
                {v.description && <p className="ee-small ee-ink-2 mt-1">{v.description}</p>}
                <p className="ee-small mt-1 flex flex-wrap items-center gap-1.5"><span className="ee-ink-3">On switch ports</span><SwitchPorts v={v} vlans={live.vlans} /></p>
                <p className="ee-small mt-1"><span className="ee-ink-3">Assigned by </span><AssignedBy u={usageOf(v, live, draft)} draft={draft} inline /></p>
                <p className="ee-small ee-ink-3 mt-0.5"><span className="ee-num text-[var(--ee-ink)]">{v.certificates}</span> certificates placed here</p>
              </li>
            ))}
          </ul>
          </>
        )}
      </Panel>
      <p className="ee-small ee-ink-3 mt-2">The certificate count is how many certificates the live policy currently places on each VLAN. “On switch ports” is what a wired 802.1X port gets instead; switches in monitor mode get no VLAN at all until they enforce.</p>

      <VlanDialog tid={tid} live={live} draft={draft} vlan={editing} onClose={() => setEditing(null)} />
      <DeleteVlanDialog tid={tid} live={live} draft={draft} vlan={deleting} onClose={() => setDeleting(null)} returnFocus={addRef} />
    </section>
  )
}

function VlanDialog({ tid, live, draft, vlan, onClose }: { tid: string; live: PolicyResponse; draft: Draft | null; vlan: Vlan | 'new' | null; onClose: () => void }) {
  const open = vlan !== null
  const existing = vlan && vlan !== 'new' ? vlan : null
  return (
    <EDialog open={open} onOpenChange={(o) => { if (!o) onClose() }} title={existing ? `Edit VLAN ${existing.vlan_id}` : 'Add a VLAN'}
      description="VLANs aren’t part of the rule draft. Saving applies immediately.">
      {open && <VlanForm key={existing?.id ?? 'new'} tid={tid} live={live} draft={draft} vlan={existing} onClose={onClose} />}
    </EDialog>
  )
}

function VlanForm({ tid, live, draft, vlan, onClose }: { tid: string; live: PolicyResponse; draft: Draft | null; vlan: Vlan | null; onClose: () => void }) {
  const qc = useQueryClient()
  const used = live.vlans.map((v) => v.color)
  const [num, setNum] = useState(vlan ? String(vlan.vlan_id) : '')
  const [name, setName] = useState(vlan?.name ?? '')
  const [description, setDescription] = useState(vlan?.description ?? '')
  const [color, setColor] = useState(vlan?.color ?? VLAN_COLORS.find((c) => !used.includes(c)) ?? 'blue')
  const [wiredMode, setWiredMode] = useState<WiredMode>(vlan?.wired_mode ?? 'same')
  const [wiredNum, setWiredNum] = useState(vlan?.wired_vlan_id ? String(vlan.wired_vlan_id) : '')
  const sharedWith = live.vlans.filter((v) => v.color === color && v.id !== vlan?.id)
  const [tried, setTried] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const n = Number(num)
  const numErr = !/^\d+$/.test(num.trim()) || n < 1 || n > 4094 ? 'Enter a VLAN number from 1 to 4094.'
    : live.vlans.some((v) => v.vlan_id === n && v.id !== vlan?.id) ? `VLAN ${n} already exists.` : null
  const nameErr = !name.trim() ? 'Give the VLAN a name, such as Corporate or Guest.' : null
  const w = Number(wiredNum)
  const wiredErr = wiredMode === 'vlan' && (!/^\d+$/.test(wiredNum.trim()) || w < 1 || w > 4094) ? 'Enter the VLAN number switch ports get, from 1 to 4094.' : null
  const wiredNext = { vlan_id: numErr ? (vlan?.vlan_id ?? 0) : n, wired_mode: wiredMode, wired_vlan_id: wiredMode === 'vlan' && !wiredErr ? w : null }
  const wiredChanged = !!vlan && !wiredErr && wiredText(vlan) !== wiredText(wiredNext)
  const u = vlan ? usageOf(vlan, live, draft) : null
  const save = useMutation({
    mutationFn: (body: VlanBody) => (vlan ? policyApi.updateVlan(tid, vlan.id, body) : policyApi.createVlan(tid, body)),
    onSuccess: (v) => {
      qc.invalidateQueries({ queryKey: qk.tenantScope(tid) })
      toast(vlan ? `VLAN ${v.vlan_id} saved` : `VLAN ${v.vlan_id} created`, vlan && vlan.vlan_id !== v.vlan_id ? 'Rules that use it now assign the new number. RADIUS applies it within seconds.'
        : vlan && wiredText(vlan) !== wiredText(v) ? `Switch ports now get ${wiredText(v)} from their next authentication.` : vlan ? 'Applied immediately.' : 'Applied immediately. You can now use it in a rule.')
      onClose()
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'The VLAN couldn’t be saved.'),
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTried(true)
    setError(null)
    if (numErr || nameErr || wiredErr) return
    save.mutate({ vlan_id: n, name: name.trim(), description: description.trim(), color, wired_mode: wiredMode, wired_vlan_id: wiredMode === 'vlan' ? w : null })
  }
  const renumber = vlan && num.trim() && n !== vlan.vlan_id && !numErr
  return (
    <form onSubmit={submit} noValidate className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-[140px_minmax(0,1fr)]">
        <Field label="VLAN number" htmlFor="vlan-num" error={tried ? numErr : null}>
          <input id="vlan-num" className="ee-input ee-num" inputMode="numeric" value={num} onChange={(e) => setNum(e.target.value)} aria-invalid={(tried && !!numErr) || undefined} autoComplete="off" />
        </Field>
        <Field label="Name" htmlFor="vlan-name" error={tried ? nameErr : null}>
          <input id="vlan-name" className="ee-input" value={name} maxLength={80} onChange={(e) => setName(e.target.value)} aria-invalid={(tried && !!nameErr) || undefined} autoComplete="off" />
        </Field>
      </div>
      <Field label="Description" htmlFor="vlan-desc" optional>
        <input id="vlan-desc" className="ee-input" value={description} maxLength={300} onChange={(e) => setDescription(e.target.value)} placeholder="Who lands here and what it can reach" />
      </Field>
      <fieldset>
        <legend className="mb-1.5 text-[13px] font-semibold">Colour</legend>
        <RadioGroup.Root value={color} onValueChange={setColor} className="flex flex-wrap gap-1.5" aria-label="Colour">
          {VLAN_COLORS.map((c) => (
            <RadioGroup.Item key={c} value={c} aria-label={c} className={cn('inline-flex h-8 items-center gap-1.5 rounded-[7px] border px-2.5 text-[12.5px] capitalize', color === c ? 'border-[var(--ee-gold)] bg-[rgba(226,194,117,0.08)]' : 'border-[var(--ee-line-2)] ee-ink-2')}>
              <span className="size-3 rounded-[3px]" style={{ background: vlanVar(c) }} aria-hidden />{c}
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
        {sharedWith.length > 0 && (
          <p className="ee-small mt-1.5 text-[var(--ee-warn-ink)]">
            VLAN {sharedWith.map((v) => v.vlan_id).join(' and ')} already {sharedWith.length === 1 ? 'uses' : 'use'} {color}. Choose another so the two can be told apart.
          </p>
        )}
      </fieldset>
      <fieldset>
        <legend className="mb-1 text-[13px] font-semibold">On switch ports</legend>
        <p className="ee-small ee-ink-3 mb-2">What a wired 802.1X port gets when a rule assigns this VLAN. Wi-Fi always gets VLAN {numErr ? 'above' : n}. Switches in monitor mode get no VLAN until they enforce.</p>
        <RadioGroup.Root value={wiredMode} onValueChange={(m) => setWiredMode(m as WiredMode)} className="grid gap-1.5" aria-label="On switch ports">
          {([
            ['same', 'The same VLAN', `Switch ports get VLAN ${numErr ? 'above' : n} too. It must exist on every switch.`],
            ['port', 'The port’s own VLAN', 'EasyEAP assigns no VLAN on switch ports: the device stays on the VLAN the port is configured with.'],
            ['vlan', 'Another VLAN', 'Switch ports get a different VLAN, for example when wired and Wi-Fi use different numbers.'],
          ] as const).map(([value, label, hint]) => (
            <RadioGroup.Item key={value} value={value} className={cn('flex items-start gap-2.5 rounded-[8px] border px-3 py-2 text-left', wiredMode === value ? 'border-[var(--ee-gold)] bg-[rgba(226,194,117,0.08)]' : 'border-[var(--ee-line-2)]')}>
              <span className={cn('mt-[3px] grid size-[14px] shrink-0 place-items-center rounded-full border', wiredMode === value ? 'border-[var(--ee-gold)]' : 'border-[var(--ee-line-3)]')} aria-hidden>
                <RadioGroup.Indicator className="size-[6px] rounded-full bg-[var(--ee-gold)]" />
              </span>
              <span className="min-w-0">
                <span className="block text-[13px] font-medium">{label}</span>
                <span className="ee-small ee-ink-3 block">{hint}</span>
              </span>
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
        {wiredMode === 'vlan' && (
          <div className="mt-2 max-w-[200px]">
            <Field label="VLAN on switch ports" htmlFor="vlan-wired" error={tried ? wiredErr : null}>
              <input id="vlan-wired" className="ee-input ee-num" inputMode="numeric" value={wiredNum} onChange={(e) => setWiredNum(e.target.value)} aria-invalid={(tried && !!wiredErr) || undefined} autoComplete="off" />
            </Field>
          </div>
        )}
      </fieldset>
      {wiredChanged && u && (u.live.length > 0 || u.liveDefault) && (
        <Callout tone="warn" title="Switch ports change VLAN">Devices on enforcing switch ports placed here get {wiredText(wiredNext)} instead of {wiredText(vlan!)} from their next authentication, as soon as you save.{wiredMode !== 'port' ? ` Make sure the switches carry VLAN ${wiredVlanOf(wiredNext)}.` : ''}</Callout>
      )}
      {u && (
        <div className="ee-small rounded-[8px] border border-[var(--ee-line)] px-3 py-2.5">
          <p className="font-semibold">Used by</p>
          <p className="ee-ink-2 mt-0.5">
            {u.live.length || u.liveDefault ? [...u.live.map((x) => `“${x}”`), ...(u.liveDefault ? ['the tenant default'] : [])].join(', ') : 'No live rule.'}
            {' '}{plural(vlan!.certificates, 'certificate is', 'certificates are')} currently placed on it.
          </p>
          {draft && !sameList(u.live, u.draft) && <p className="mt-0.5 text-[var(--ee-warn-ink)]">Your draft: {u.draft.map((x) => `“${x}”`).join(', ') || 'no rule'}.</p>}
        </div>
      )}
      {renumber && (u!.live.length > 0 || u!.liveDefault) && (
        <Callout tone="warn" title={`Renumbering moves people to VLAN ${n}`}>Everyone placed on VLAN {vlan!.vlan_id} by these rules gets VLAN {n} from their next connection, as soon as you save. Make sure your switches and controllers carry VLAN {n}.</Callout>
      )}
      {error && <Callout tone="crit" title="Not saved">{error}</Callout>}
      <div className="-mx-6 -mb-5 flex flex-wrap items-center justify-end gap-2 border-t border-[var(--ee-line)] px-6 py-4">
        <Btn onClick={onClose} disabled={save.isPending}>Cancel</Btn>
        <Btn type="submit" variant="primary" busy={save.isPending}>{vlan ? 'Save now' : 'Create VLAN'}</Btn>
      </div>
    </form>
  )
}

function DeleteVlanDialog({ tid, live, draft, vlan, onClose, returnFocus }: { tid: string; live: PolicyResponse; draft: Draft | null; vlan: Vlan | null; onClose: () => void; returnFocus: React.RefObject<HTMLButtonElement | null> }) {
  const qc = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [deleted, setDeleted] = useState(false)
  useEffect(() => { if (vlan) setDeleted(false) }, [vlan])
  const del = useMutation({
    mutationFn: () => policyApi.deleteVlan(tid, vlan!.id),
    onSuccess: () => { setDeleted(true); qc.invalidateQueries({ queryKey: qk.tenantScope(tid) }); toast(`VLAN ${vlan!.vlan_id} deleted`); onClose() },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'The VLAN couldn’t be deleted.'),
  })
  const u = vlan ? usageOf(vlan, live, draft) : null
  const draftUses = !!u && (u.draft.length > 0 || u.draftDefault) && !!draft
  return (
    <EDialog open={!!vlan} onOpenChange={(o) => { if (!o) { setError(null); onClose() } }} risk="crit" returnFocus={deleted ? returnFocus : undefined} title={vlan ? `Delete VLAN ${vlan.vlan_id} ${vlan.name}?` : 'Delete VLAN'}
      description="This applies immediately; it isn’t part of the rule draft."
      footer={<>
        <Btn onClick={onClose} disabled={del.isPending}>Cancel</Btn>
        <Btn variant="danger-solid" busy={del.isPending} disabled={draftUses} onClick={() => { setError(null); del.mutate() }}><Trash2 aria-hidden />Delete VLAN</Btn>
      </>}
    >
      {u && (
        <div className="space-y-3">
          {u.live.length || u.liveDefault ? (
            <Callout tone="warn" title="Still assigned">
              {[...u.live.map((x) => `“${x}”`), ...(u.liveDefault ? ['the tenant default'] : [])].join(', ')} {u.live.length + (u.liveDefault ? 1 : 0) === 1 ? 'assigns' : 'assign'} this VLAN, so EasyEAP will refuse to delete it. Change {u.live.length + (u.liveDefault ? 1 : 0) === 1 ? 'it' : 'them'} and publish first.
            </Callout>
          ) : <p className="ee-small ee-ink-2">No live rule assigns this VLAN. {plural(vlan!.certificates, 'certificate is', 'certificates are')} currently placed on it.</p>}
          {draftUses && <Callout tone="crit" title="Your draft uses this VLAN">{u.draft.map((x) => `“${x}”`).join(', ') || 'The draft default'} in your unpublished draft {u.draft.length > 1 ? 'assign' : 'assigns'} it. Change the draft first, or the draft can’t be published.</Callout>}
          {error && <Callout tone="crit" title="Not deleted">{error}</Callout>}
        </div>
      )}
    </EDialog>
  )
}
