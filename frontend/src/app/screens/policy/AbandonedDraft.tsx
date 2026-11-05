// After a conflict (someone else published first) or an outdated saved draft: keep the user's unpublished changes
// visible, one line each, with "Apply again" so they can redo them on top of the latest policy.
import { useMemo, useState } from 'react'
import { Check, CornerDownRight, X } from 'lucide-react'
import type { PolicyResponse } from '../../api/policy'
import { Btn, Panel, toast } from '../../ui'
import { describeChanges, replayChange, type Draft } from './draft'
import { vlanText } from './shared'

export function AbandonedDraft({ old, oldBase, reason, current, vlansFrom, canWrite, onApply, onDismiss }: {
  old: Draft
  oldBase: PolicyResponse
  reason: 'conflict' | 'stored'
  current: Draft
  vlansFrom: PolicyResponse
  canWrite: boolean
  onApply: (d: Draft) => void
  onDismiss: () => void
}) {
  const lines = useMemo(() => describeChanges(oldBase, old, (ref) => vlanText(vlansFrom.vlans, ref)), [oldBase, old, vlansFrom])
  const [done, setDone] = useState<Set<string>>(new Set())
  if (lines.length === 0) return null
  const apply = (key: string) => {
    const line = lines.find((l) => l.key === key)!
    const next = replayChange(current, line, old)
    if (!next) { toast('Can’t apply that change', 'The rule it changed no longer exists in the latest policy. Make the change again by hand.', 'warn'); return }
    onApply(next)
    setDone(new Set(done).add(key))
  }
  return (
    <Panel risk="warn" className="mb-6 px-5 py-4" aria-labelledby="abandoned-h">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 id="abandoned-h" className="ee-h2">Your earlier draft wasn’t published</h2>
          <p className="ee-small ee-ink-2 mt-0.5 max-w-[75ch]">
            {reason === 'conflict'
              ? 'The policy below is the latest version, including the other change that was published. Here is what your draft changed, so you can make those changes again on top of it.'
              : 'This browser tab kept a draft based on an older version of the policy. The policy below is the latest version; apply the changes you still want.'}
          </p>
        </div>
        <Btn variant="ghost" size="sm" onClick={onDismiss}><X aria-hidden />Dismiss</Btn>
      </div>
      <ul className="mt-3 space-y-1.5">
        {lines.map((l) => (
          <li key={l.key} className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 rounded-[7px] border border-[var(--ee-line)] px-3 py-2">
            <span className="ee-small flex min-w-0 items-start gap-2"><CornerDownRight className="mt-0.5 size-3.5 shrink-0 ee-ink-3" aria-hidden />{l.text}</span>
            {canWrite && l.kind !== 'moved' && (done.has(l.key)
              ? <span className="ee-small inline-flex items-center gap-1 text-[var(--ee-valid-ink)]"><Check className="size-3.5" aria-hidden />In your new draft</span>
              : <Btn size="sm" onClick={() => apply(l.key)}>Apply again</Btn>)}
            {canWrite && l.kind === 'moved' && <span className="ee-small ee-ink-3">Reorder by hand</span>}
          </li>
        ))}
      </ul>
    </Panel>
  )
}
