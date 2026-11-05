// Test a user: evaluate the live policy for one person (POST /policy/simulate), or see what the draft would do by
// finding them in the draft's preview. Policy only: a certificate is assumed, and the ledger says so.
import { forwardRef, useEffect, useState, type KeyboardEvent } from 'react'
import { Link } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { Search, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import { policyApi, useIdentity, useIdentitySearch, type PolicyResponse, type Purpose } from '../../api/policy'
import { qk } from '../../api/keys'
import { paths } from '../../routes'
import { Btn, Callout, Chip, ErrorState, LoadingBlock, Panel, Seg, SourceTag } from '../../ui'
import { DecisionLedger } from '../../ui/ledger'
import type { PreviewState } from './PreviewPanel'
import { groupName, ledgerRulesFromDraft, ledgerRulesFromLive, ledgerVlans, useGroupSources } from './shared'

function useDebounced<T>(value: T, ms = 200): T {
  const [v, setV] = useState(value)
  useEffect(() => { const id = setTimeout(() => setV(value), ms); return () => clearTimeout(id) }, [value, ms])
  return v
}

function IdentityPicker({ tid, onPick }: { tid: string; onPick: (id: string) => void }) {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const q = useDebounced(query.trim())
  const res = useIdentitySearch(tid, q)
  const items = q ? res.data?.items ?? [] : []
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(items.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(0, i - 1)) }
    else if (e.key === 'Enter') { e.preventDefault(); const it = items[active]; if (it) onPick(it.id) }
  }
  return (
    <div>
      <label htmlFor="test-user-q" className="text-[13px] font-semibold">User</label>
      <div className="ee-input mt-1.5 flex items-center gap-2 px-2.5 focus-within:border-[var(--ee-gold)]">
        <Search className="size-4 shrink-0 ee-ink-3" aria-hidden />
        <input id="test-user-q" role="combobox" aria-expanded={items.length > 0} aria-controls="test-user-list" aria-autocomplete="list"
          aria-activedescendant={items[active] ? `test-user-${active}` : undefined}
          className="h-full min-w-0 flex-1 bg-transparent outline-none placeholder:text-[var(--ee-ink-3)]" placeholder="Search by name, username or email"
          value={query} onChange={(e) => { setQuery(e.target.value); setActive(0) }} onKeyDown={onKey} autoComplete="off" />
      </div>
      {q && (
        <div id="test-user-list" role="listbox" aria-label="Matching users" className="mt-1.5 max-h-[260px] overflow-y-auto rounded-[8px] border border-[var(--ee-line-2)] bg-[rgba(6,9,17,0.35)] p-1">
          {res.isLoading ? <p className="px-2.5 py-2 ee-small ee-ink-2">Searching…</p>
            : res.error ? <div className="p-1"><ErrorState error={res.error} onRetry={() => res.refetch()} title="Search failed" /></div>
            : items.length === 0 ? <p className="px-2.5 py-2 ee-small ee-ink-2">No user matches “{q}”.</p>
            : items.map((it, i) => (
              <div key={it.id} id={`test-user-${i}`} role="option" aria-selected={i === active}
                className={cn('flex cursor-pointer items-center gap-2.5 rounded-[6px] px-2.5 py-1.5', i === active && 'bg-[rgba(237,234,227,0.07)]')}
                onMouseEnter={() => setActive(i)} onMouseDown={(e) => e.preventDefault()} onClick={() => onPick(it.id)}>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[13px] font-medium">{it.display_name}</span>
                  <span className="block truncate text-[12px] ee-ink-3">{it.upn ?? it.username}{it.department ? ` · ${it.department}` : ''}</span>
                </span>
                {it.account_state !== 'enabled' && <Chip tone="crit">{it.account_state}</Chip>}
                <SourceTag source={it.source} />
              </div>
            ))}
        </div>
      )}
    </div>
  )
}

export const TestUser = forwardRef<HTMLHeadingElement, {
  tid: string
  live: PolicyResponse
  identityId: string | null
  onIdentity: (id: string | null) => void
  dirty: boolean
  preview: PreviewState | null
  previewCurrent: boolean
  previewBusy: boolean
  onPreview: () => void
}>(function TestUser({ tid, live, identityId, onIdentity, dirty, preview, previewCurrent, previewBusy, onPreview }, ref) {
  const [purpose, setPurpose] = useState<Purpose>('user')
  const [against, setAgainst] = useState<'live' | 'draft'>('live')
  const ident = useIdentity(tid, identityId)
  const groupSource = useGroupSources(tid)
  const sim = useQuery({
    queryKey: [...qk.policy(tid), 'simulate', identityId, purpose, live.revision],
    queryFn: () => policyApi.simulate(tid, identityId!, purpose),
    enabled: !!identityId,
    staleTime: 10_000,
  })
  const mode = dirty ? against : 'live'
  const change = preview?.data.changes.find((c) => c.identity.id === identityId && c.purpose === purpose)
  const vlans = ledgerVlans(live.vlans)
  const i = ident.data

  return (
    <Panel className="px-5 py-5" aria-labelledby="test-h">
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 id="test-h" ref={ref} tabIndex={-1} className="ee-h2">Test a user</h2>
        <span className="ee-small ee-ink-3">Policy only; a valid certificate is assumed</span>
      </div>

      {!identityId ? (
        <IdentityPicker tid={tid} onPick={(id) => onIdentity(id)} />
      ) : ident.isLoading ? (
        <LoadingBlock rows={3} label="Loading user" />
      ) : ident.error ? (
        <div className="space-y-2">
          <ErrorState error={ident.error} title="That user couldn’t be loaded" onRetry={() => ident.refetch()} />
          <Btn size="sm" onClick={() => onIdentity(null)}>Choose another user</Btn>
        </div>
      ) : i ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3 rounded-[8px] border border-[var(--ee-line)] px-3 py-2.5">
            <div className="min-w-0">
              <p className="flex flex-wrap items-center gap-2 font-semibold">{i.display_name}<SourceTag source={i.source} />{i.account_state !== 'enabled' && <Chip tone="crit">Account {i.account_state}</Chip>}</p>
              <p className="ee-small ee-ink-3 truncate">{i.upn ?? i.username}</p>
              <p className="ee-small ee-ink-2 mt-1">{i.groups.length ? <>Member of {i.groups.map((g) => groupName(g.name, groupSource(g.id))).join(', ')}</> : 'Not a member of any group'}</p>
            </div>
            <Btn size="sm" variant="ghost" onClick={() => onIdentity(null)} aria-label="Choose another user"><X aria-hidden />Change</Btn>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Seg label="Certificate type" value={purpose} onChange={setPurpose} options={[{ value: 'user', label: 'User certificate' }, { value: 'device', label: 'Device certificate' }]} />
            {dirty && <Seg label="Evaluate against" value={against} onChange={setAgainst} options={[{ value: 'live', label: 'Live policy' }, { value: 'draft', label: 'Your draft' }]} />}
          </div>

          {mode === 'live' ? (
            sim.isLoading ? <LoadingBlock rows={4} label="Evaluating" />
              : sim.error ? <ErrorState error={sim.error} onRetry={() => sim.refetch()} title="The test couldn’t run" />
              : sim.data ? (
                <DecisionLedger outcome={sim.data} rules={ledgerRulesFromLive(live.rules)} identityGroups={i.groups} vlans={vlans} accountState={i.account_state} source={i.source} policyOnly />
              ) : null
          ) : !preview || !previewCurrent ? (
            <Callout tone="gold" title="Preview the draft to test against it" action={<Btn size="sm" variant="primary" busy={previewBusy} onClick={onPreview}>Preview impact</Btn>}>
              The draft is evaluated server-side against everyone at once. Run a preview, then this shows what the draft does for {i.display_name}.
            </Callout>
          ) : change ? (
            <DecisionLedger
              outcome={{ outcome: change.after.outcome, reason_code: change.after.reason_code, deciding_rule_id: change.after.rule_id, vlan_id: change.after.vlan_id, attributes: [], steps: change.steps.filter((s) => s.kind !== 'certificate') }}
              rules={ledgerRulesFromDraft(preview.draft)} identityGroups={i.groups} vlans={vlans} accountState={i.account_state} source={i.source} showAttributes={false} policyOnly />
          ) : (
            <Callout tone="neutral" title="Your draft doesn’t change this result">
              {preview.data.truncated ? 'This person isn’t among the listed changes, but the preview listed only the first changes, so check the counts.' : `${i.display_name}’s decision and VLAN for a ${purpose} certificate are the same under the draft. Switch to Live policy to see how it’s decided.`}
            </Callout>
          )}

          <Link to={paths.user(tid, i.id)} className="ee-small inline-block underline">Open {i.display_name}’s record</Link>
        </div>
      ) : null}
    </Panel>
  )
})
