// Impact preview: who changes decision or VLAN if the draft is published, computed server-side against the real
// directory. Each change expands to the decision ledger under the draft rules.
import { forwardRef, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { ChevronDown, Eye, RefreshCw } from 'lucide-react'
import { cn } from '@/ui/lib'
import type { ChangeKind, PreviewChange, PreviewResponse, Vlan } from '../../api/policy'
import { useIdentity } from '../../api/policy'
import { fmtDateTime, plural } from '../../lib/format'
import { paths } from '../../routes'
import { Btn, Callout, Chip, Empty, ErrorState, LoadingBlock, Panel, Seg } from '../../ui'
import { DecisionLedger } from '../../ui/ledger'
import type { Draft } from './draft'
import { BriefOutcomeView, decidedBy, ledgerRulesFromDraft, ledgerVlans } from './shared'

export interface PreviewState { sig: string; data: PreviewResponse; draft: Draft }

export const kindLabel: Record<ChangeKind, string> = { newly_allowed: 'Newly allowed', newly_denied: 'Newly denied', vlan_changed: 'VLAN changes' }

export function holders(changes: PreviewChange[]) {
  const out = { newly_allowed: 0, newly_denied: 0, vlan_changed: 0 }
  for (const c of changes) if (c.has_certificate) out[c.kind] += 1
  return out
}

interface Props {
  tid: string
  preview: PreviewState | null
  stale: boolean
  busy: boolean
  error: unknown
  canWrite: boolean
  vlans: Vlan[]
  onPreview: () => void
}

export const PreviewPanel = forwardRef<HTMLHeadingElement, Props>(function PreviewPanel({ tid, preview, stale, busy, error, vlans, onPreview }, ref) {
  const [filter, setFilter] = useState<'all' | ChangeKind>('all')
  const data = preview?.data
  const listed = useMemo(() => (data ? (filter === 'all' ? data.changes : data.changes.filter((c) => c.kind === filter)) : []), [data, filter])
  const h = data ? holders(data.changes) : null
  const s = data?.summary
  const risk = !data ? 'gold' : stale ? 'warn' : s && s.newly_denied > 0 ? 'crit' : 'gold'

  return (
    <Panel risk={risk} className="px-5 py-5" aria-labelledby="preview-h">
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
        <h2 id="preview-h" ref={ref} tabIndex={-1} className="ee-h2">Impact of your draft</h2>
        {data && <span className="ee-small ee-ink-3">Computed {fmtDateTime(data.computed_at)}</span>}
      </div>

      {busy && !data ? (
        <LoadingBlock rows={5} label="Computing impact" />
      ) : error && !data ? (
        <ErrorState error={error} onRetry={onPreview} title="The preview couldn’t be computed" />
      ) : !data ? (
        <div className="space-y-3">
          <p className="ee-small ee-ink-2 max-w-[65ch]">See exactly who would change decision or VLAN, computed against the people in your directory today. You need to preview the current draft before you can publish it.</p>
          <Btn variant="primary" onClick={onPreview} busy={busy}><Eye aria-hidden />Preview impact</Btn>
        </div>
      ) : (
        <div className={cn('space-y-4', busy && 'opacity-60')} aria-busy={busy || undefined}>
          {stale && (
            <Callout tone="warn" title="The draft changed after this preview" action={<Btn size="sm" onClick={onPreview} busy={busy}><RefreshCw aria-hidden />Preview again</Btn>}>
              These numbers describe an earlier version of your draft. Preview again before publishing.
            </Callout>
          )}
          {error ? <ErrorState error={error} onRetry={onPreview} title="The latest preview failed" /> : null}

          <dl className="divide-y divide-[var(--ee-line)] rounded-[8px] border border-[var(--ee-line)]">
            <SummaryRow label="Newly allowed" n={s!.newly_allowed} tone={s!.newly_allowed ? 'valid' : undefined}
              sub={s!.newly_allowed ? `${data.truncated ? 'At least ' : ''}${plural(h!.newly_allowed, 'holds a certificate', 'hold certificates')} and can connect after publishing` : 'Nobody gains access'} />
            <SummaryRow label="Newly denied" n={s!.newly_denied} tone={s!.newly_denied ? 'crit' : undefined}
              sub={s!.newly_denied ? `${data.truncated ? 'At least ' : ''}${plural(h!.newly_denied, 'holds a certificate', 'hold certificates')} and will be rejected at the next connection` : 'Nobody loses access'} />
            <SummaryRow label="VLAN changes" n={s!.vlan_changed} tone={s!.vlan_changed ? 'warn' : undefined}
              sub={s!.vlan_changed ? `${plural(h!.vlan_changed, 'holds a certificate', 'hold certificates')}; the new VLAN applies when they reconnect` : 'Nobody moves VLAN'} />
            <SummaryRow label="Unchanged" n={s!.unchanged + s!.rule_only}
              sub={s!.rule_only ? `${s!.rule_only} now decided by a different rule, with the same result` : 'Same decision and VLAN'} />
          </dl>
          <p className="ee-small ee-ink-3">
            Evaluated {plural(s!.evaluated, 'person', 'people')} in the directory; {s!.with_certificates} hold an active certificate. People with both a user and a device certificate are counted once per certificate type.
          </p>

          {data.warnings.map((w) => <Callout key={w} tone="warn">{w}</Callout>)}

          {data.changes.length === 0 ? (
            <Empty title="Nobody’s access changes">Publishing this draft keeps every decision and VLAN as it is. It still updates the rules RADIUS uses.</Empty>
          ) : (
            <div>
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <h3 className="ee-h3">Who changes</h3>
                <Seg label="Show changes" value={filter} onChange={setFilter} options={[
                  { value: 'all', label: 'All', count: data.changes.length },
                  ...(['newly_allowed', 'newly_denied', 'vlan_changed'] as const).filter((k) => data.changes.some((c) => c.kind === k)).map((k) => ({ value: k, label: kindLabel[k].replace(' changes', ''), count: data.changes.filter((c) => c.kind === k).length })),
                ]} />
              </div>
              <ul className="ee-divide list-none border-y border-[var(--ee-line)] p-0">
                {listed.map((c) => <ChangeRow key={`${c.identity.id}:${c.purpose}`} tid={tid} c={c} vlans={vlans} draft={preview!.draft} />)}
              </ul>
              {data.truncated && <p className="ee-small ee-ink-3 mt-2">Only the first {data.changes.length} changes are listed. The counts above include everyone.</p>}
            </div>
          )}
        </div>
      )}
    </Panel>
  )
})

function SummaryRow({ label, n, sub, tone }: { label: string; n: number; sub: string; tone?: 'valid' | 'crit' | 'warn' }) {
  const color = tone === 'valid' ? 'text-[var(--ee-valid-ink)]' : tone === 'crit' ? 'text-[var(--ee-crit-ink)]' : tone === 'warn' ? 'text-[var(--ee-warn-ink)]' : 'ee-ink-2'
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-baseline gap-x-4 px-3.5 py-2.5">
      <dt className="text-[13px] font-semibold">{label}<span className="ee-small mt-0.5 block font-normal ee-ink-3">{sub}</span></dt>
      <dd className={cn('ee-num text-[17px] font-semibold', color)}>{n}</dd>
    </div>
  )
}

function ChangeRow({ tid, c, vlans, draft }: { tid: string; c: PreviewChange; vlans: Vlan[]; draft: Draft }) {
  const [open, setOpen] = useState(false)
  const ident = useIdentity(tid, open ? c.identity.id : null)
  const rules = useMemo(() => ledgerRulesFromDraft(draft), [draft])
  const id = `chg-${c.identity.id}-${c.purpose}`
  return (
    <li className="py-2.5">
      <button type="button" className="ee-rowlink grid w-full grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1.5 px-1 py-0.5 hover:bg-[var(--ee-hover)]" aria-expanded={open} aria-controls={id} onClick={() => setOpen((v) => !v)}>
        <span className="min-w-0">
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-semibold">{c.identity.display_name}</span>
            <span className="ee-small ee-ink-3">{c.identity.username}</span>
            <Chip tone="neutral">{c.purpose === 'device' ? 'Device certificate' : 'User certificate'}</Chip>
            {c.has_certificate ? <Chip tone="gold">Holds a certificate</Chip> : <span className="ee-small ee-ink-3">No certificate yet</span>}
          </span>
          <span className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[12.5px]">
            <BriefOutcomeView o={c.before} vlans={vlans} />
            <span className="ee-ink-3" aria-label="becomes">→</span>
            <BriefOutcomeView o={c.after} vlans={vlans} />
          </span>
          <span className="ee-small ee-ink-2 mt-1 block">Decided by {decidedBy(c.before)} now; by {decidedBy(c.after)} in the draft.</span>
        </span>
        <ChevronDown className={cn('mt-1 size-4 ee-ink-3 transition-transform', open && 'rotate-180')} aria-hidden />
      </button>
      {open && (
        <div id={id} className="mt-3 rounded-[8px] border border-[var(--ee-line)] bg-[rgba(6,9,17,0.3)] px-4 py-3.5">
          <p className="ee-small ee-ink-3 mb-3">How the draft decides for {c.identity.display_name} ({c.purpose === 'device' ? 'device' : 'user'} certificate)</p>
          {ident.isLoading ? <LoadingBlock rows={3} label="Loading group membership" /> : (
            <DecisionLedger
              outcome={{ outcome: c.after.outcome, reason_code: c.after.reason_code, deciding_rule_id: c.after.rule_id, vlan_id: c.after.vlan_id, attributes: [], steps: c.steps.filter((s) => s.kind !== 'certificate') }}
              rules={rules}
              identityGroups={ident.data?.groups ?? []}
              vlans={ledgerVlans(vlans)}
              accountState={c.identity.account_state}
              source={ident.data?.source}
              showAttributes={false}
              policyOnly
            />
          )}
          <Link className="ee-small mt-3 inline-block underline" to={paths.user(tid, c.identity.id)}>Open {c.identity.display_name}’s record</Link>
        </div>
      )}
    </li>
  )
}
