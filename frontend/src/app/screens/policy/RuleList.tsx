// The draft rules, grouped the way RADIUS evaluates them: Deny rules (always win, order irrelevant), Allow rules in
// order (first match decides the VLAN), then the tenant default. Every row carries its draft marker.
import { useRef, useState, type KeyboardEvent } from 'react'
import { ArrowDown, ArrowUp, GripVertical, PencilLine, Plus, RotateCcw, ShieldX, Trash2, Undo2 } from 'lucide-react'
import { cn } from '@/ui/lib'
import type { RuleAction, Vlan } from '../../api/policy'
import { Btn, Callout, Chip, ESelect, ESwitch, Empty, Seg, vlanVar } from '../../ui'
import type { Draft, DraftDiff, DraftRule } from './draft'
import { ActionChip, DiffChip, groupName, purposeLabel, VlanRef, type GroupSourceOf } from './shared'

interface Props {
  draft: Draft
  diff: DraftDiff
  vlans: Vlan[]
  groupSource: GroupSourceOf
  canWrite: boolean
  onAdd: () => void
  onEdit: (r: DraftRule) => void
  onToggle: (key: string, enabled: boolean) => void
  onRemove: (key: string) => void
  onRestore: (key: string) => void
  onRevert: (key: string) => void
  onMove: (key: string, dir: -1 | 1) => void
  onDefault: (action: RuleAction, vlanRef: string | null) => void
}

export function RuleList(p: Props) {
  const { draft, diff, canWrite } = p
  const [announce, setAnnounce] = useState('')
  const handles = useRef(new Map<string, HTMLButtonElement>())
  const deny = draft.rules.filter((r) => r.action === 'deny')
  const allow = draft.rules.filter((r) => r.action === 'allow')
  const allowLive = allow.filter((r) => !r.removed)

  // Keep keyboard focus on the row when the pressed button is replaced (remove → Restore, Restore/Revert → Edit).
  const focusInRow = (key: string, which: 'restore' | 'edit') => requestAnimationFrame(() => {
    const el = document.querySelector<HTMLElement>(`[data-rule-key="${CSS.escape(key)}"] [data-focus="${which}"]`)
    if (el) el.focus()
    else document.getElementById(draft.rules.find((x) => x.key === key)?.action === 'deny' ? 'deny-h' : 'allow-h')?.focus()
  })

  const move = (r: DraftRule, dir: -1 | 1) => {
    const pos = allowLive.findIndex((x) => x.key === r.key)
    const to = pos + dir
    if (to < 0 || to >= allowLive.length) return
    p.onMove(r.key, dir)
    setAnnounce(`“${r.name}” moved to Allow position ${to + 1} of ${allowLive.length}.`)
    // Keep focus on the moved rule when the pressed button becomes disabled at the end of the list.
    requestAnimationFrame(() => {
      const a = document.activeElement as HTMLButtonElement | null
      if (!a || a === document.body || a.disabled) handles.current.get(r.key)?.focus()
    })
  }

  const row = (r: DraftRule, pos: number | null) => {
    const d = diff.rules.get(r.key)
    const removed = !!r.removed
    const onHandleKey = (e: KeyboardEvent<HTMLButtonElement>) => {
      if (e.key === 'ArrowUp') { e.preventDefault(); move(r, -1) }
      else if (e.key === 'ArrowDown') { e.preventDefault(); move(r, 1) }
    }
    return (
      <li key={r.key} data-rule-key={r.key} className={cn('grid grid-cols-[24px_minmax(0,1fr)] gap-x-3 gap-y-2.5 py-3.5 md:grid-cols-[24px_minmax(0,1fr)_auto]', d && d.status !== 'same' && 'bg-[rgba(226,194,117,0.025)]')} data-draft={d?.status}>
        <span className="pt-[2px] text-center">
          {pos !== null ? <span className="ee-num text-[13px] font-semibold ee-ink-2" aria-label={`Allow position ${pos}`}>{pos}</span>
            : removed ? <Trash2 className="mx-auto size-4 ee-ink-3" aria-hidden /> : <ShieldX className="mx-auto size-4 text-[var(--ee-crit-ink)]" aria-hidden />}
        </span>
        <div className={cn('min-w-0', (removed || !r.enabled) && 'opacity-70')}>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
            <span className={cn('text-[14px] font-semibold', removed && 'line-through decoration-[var(--ee-ink-3)]')}>{r.name}</span>
            {r.action === 'allow' ? <span className="inline-flex items-center gap-1.5"><ActionChip action="allow" /><span className="ee-ink-3" aria-hidden>→</span><VlanRef vlans={p.vlans} vref={r.vlan_ref} /></span> : <ActionChip action="deny" />}
            {!r.enabled && !removed && <Chip tone="neutral">Disabled · skipped</Chip>}
            <DiffChip diff={d} enabled={r.enabled} />
          </div>
          {r.description && <p className="ee-small ee-ink-2 mt-1">{r.description}</p>}
          <p className="ee-small mt-1.5 flex flex-wrap items-center gap-1.5">
            <span className="ee-ink-3">Members of</span>
            {r.groups.map((g, i) => (
              <span key={g.id} className="inline-flex items-center gap-1">
                <span className={cn('ee-tag', g.deleted && 'border-[rgba(244,63,94,0.45)] text-[var(--ee-crit-ink)]')} title={g.deleted ? 'This group was deleted from the directory; it matches nobody' : undefined}>
                  {groupName(g.name, p.groupSource(g.id))}{g.deleted && ' · deleted'}
                </span>
                {i < r.groups.length - 1 && <span className="ee-ink-3">or</span>}
              </span>
            ))}
            <span className="ee-ink-3">· {purposeLabel(r.purposes)}</span>
          </p>
          {r.action === 'allow' && r.extra_attributes.length > 0 && (
            <p className="mt-1.5 flex flex-wrap gap-1.5">
              {r.extra_attributes.map((a, i) => <span key={i} className="ee-tag ee-mono text-[12px]">{a.name} = {a.value}</span>)}
            </p>
          )}
        </div>
        {canWrite && (
          <div className="col-start-2 flex flex-wrap items-center gap-1.5 md:col-start-3 md:row-start-1 md:justify-end">
            {removed ? (
              <Btn size="sm" data-focus="restore" onClick={() => { p.onRestore(r.key); setAnnounce(`“${r.name}” restored.`); focusInRow(r.key, 'edit') }}><Undo2 aria-hidden />Restore</Btn>
            ) : (
              <>
                <label className="mr-1 inline-flex items-center gap-2 text-[12.5px] ee-ink-2">
                  <ESwitch checked={r.enabled} onChange={(v) => { p.onToggle(r.key, v); setAnnounce(`“${r.name}” ${v ? 'enabled' : 'disabled'} in the draft.`) }} label={`${r.name}: enabled`} />
                  <span aria-hidden>{r.enabled ? 'On' : 'Off'}</span>
                </label>
                {d?.status === 'edited' && <Btn size="sm" variant="ghost" onClick={() => { p.onRevert(r.key); setAnnounce(`Changes to “${r.name}” reverted.`); focusInRow(r.key, 'edit') }} aria-label={`Revert changes to ${r.name}`}><RotateCcw aria-hidden />Revert</Btn>}
                <Btn size="sm" variant="ghost" data-focus="edit" onClick={() => p.onEdit(r)} aria-label={`Edit ${r.name}`}><PencilLine aria-hidden />Edit</Btn>
                <Btn size="sm" variant="ghost" icon className="w-7" aria-label={`Remove ${r.name}`} onClick={() => { p.onRemove(r.key); setAnnounce(`“${r.name}” ${r.id ? 'marked for removal' : 'removed from the draft'}.`); focusInRow(r.key, 'restore') }}><Trash2 aria-hidden /></Btn>
                {pos !== null && (
                  <span className="ml-1 inline-flex items-center gap-0.5 border-l border-[var(--ee-line)] pl-1.5">
                    <button
                      type="button"
                      ref={(el) => { if (el) handles.current.set(r.key, el); else handles.current.delete(r.key) }}
                      className="grid h-7 w-6 cursor-grab place-items-center rounded ee-ink-3 hover:text-[var(--ee-ink)]"
                      aria-label={`Reorder ${r.name}, Allow position ${pos} of ${allowLive.length}. Press Arrow Up or Arrow Down to move.`}
                      aria-keyshortcuts="ArrowUp ArrowDown"
                      onKeyDown={onHandleKey}
                    >
                      <GripVertical className="size-4" aria-hidden />
                    </button>
                    <Btn size="sm" variant="ghost" icon className="w-7" aria-label={`Move ${r.name} up`} disabled={pos === 1} onClick={() => move(r, -1)}><ArrowUp aria-hidden /></Btn>
                    <Btn size="sm" variant="ghost" icon className="w-7" aria-label={`Move ${r.name} down`} disabled={pos === allowLive.length} onClick={() => move(r, 1)}><ArrowDown aria-hidden /></Btn>
                  </span>
                )}
              </>
            )}
          </div>
        )}
      </li>
    )
  }

  let n = 0
  const defVlan = p.vlans.find((v) => v.id === draft.default_vlan_ref)
  return (
    <div>
      <p className="sr-only" aria-live="polite">{announce}</p>
      <p className="ee-small ee-ink-2 mb-4 max-w-[75ch]">
        Before any rule runs, RADIUS rejects disabled, locked and deleted accounts, and revoked or expired certificates. No rule can override that.
      </p>

      <section aria-labelledby="deny-h">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h3 id="deny-h" tabIndex={-1} className="ee-h3">Deny rules <span className="ee-num font-normal ee-ink-3">{deny.filter((r) => !r.removed).length}</span></h3>
          <p className="ee-small ee-ink-3">Deny rules always win; their order doesn’t matter.</p>
        </div>
        {deny.length === 0 ? (
          <p className="ee-small ee-ink-3 mt-2 border-y border-[var(--ee-line)] py-3">No Deny rules. Add one to keep a group off the network whatever the Allow rules say.</p>
        ) : (
          <ol className="ee-divide mt-2 list-none border-y border-[var(--ee-line)] p-0" aria-label="Deny rules">{deny.map((r) => row(r, null))}</ol>
        )}
      </section>

      <section aria-labelledby="allow-h" className="mt-6">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h3 id="allow-h" tabIndex={-1} className="ee-h3">Allow rules <span className="ee-num font-normal ee-ink-3">{allowLive.length}</span></h3>
          <p className="ee-small ee-ink-3">Checked top to bottom. The first match sets the VLAN.</p>
        </div>
        {allow.length === 0 ? (
          <div className="mt-2"><Empty title="No Allow rules">Nobody gets network access from a rule. Only the tenant default below applies.</Empty></div>
        ) : (
          <ol className="ee-divide mt-2 list-none border-y border-[var(--ee-line)] p-0" aria-label="Allow rules in order">{allow.map((r) => row(r, r.removed ? null : ++n))}</ol>
        )}
      </section>

      <section aria-labelledby="default-h" className={cn('mt-6 rounded-[8px] border border-[var(--ee-line)] px-4 py-3.5', diff.defaultChanged && 'border-[rgba(245,165,36,0.4)]')}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <h3 id="default-h" className="ee-h3 flex flex-wrap items-center gap-2">
              When no rule matches
              {diff.defaultChanged && <Chip tone="warn" icon={<PencilLine aria-hidden />}>Changed in draft</Chip>}
            </h3>
            <p className="ee-small ee-ink-2 mt-0.5">
              {draft.default_action === 'deny' ? 'RADIUS sends Access-Reject.' : <>RADIUS accepts anyone with a valid certificate and places them on {defVlan ? `VLAN ${defVlan.vlan_id} ${defVlan.name}` : 'the default VLAN'}.</>}
            </p>
          </div>
          {canWrite ? (
            <div className="flex flex-wrap items-center gap-2">
              <Seg label="Tenant default" value={draft.default_action} onChange={(v) => p.onDefault(v, v === 'allow' ? draft.default_vlan_ref ?? p.vlans[0]?.id ?? null : null)}
                options={[{ value: 'deny', label: 'Deny' }, { value: 'allow', label: 'Allow' }]} />
              {draft.default_action === 'allow' && (
                <ESelect label="Default VLAN" value={draft.default_vlan_ref ?? ''} onChange={(v) => p.onDefault('allow', v)} placeholder="Choose a VLAN" className="min-w-[180px]"
                  options={p.vlans.map((v) => ({ value: v.id, label: <span className="inline-flex items-center gap-2"><span className="ee-swatch" style={{ background: vlanVar(v.color) }} aria-hidden /><span className="ee-num font-semibold">{v.vlan_id}</span>{v.name}</span> }))} />
              )}
            </div>
          ) : (
            <ActionChip action={draft.default_action} />
          )}
        </div>
        {draft.default_action === 'allow' && (
          <Callout tone="warn" className="mt-3">A default of Allow lets anyone with a valid certificate who matches no rule onto the network. Most tenants keep Deny.</Callout>
        )}
        {draft.default_action === 'allow' && !draft.default_vlan_ref && <p className="ee-field-error mt-2">Choose the VLAN the default Allow assigns.</p>}
      </section>

      {canWrite && (
        <div className="mt-4">
          <Btn onClick={p.onAdd}><Plus aria-hidden />Add rule</Btn>
        </div>
      )}
    </div>
  )
}
