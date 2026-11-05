// Access policy. Rule edits are staged in a local draft (add, edit, remove, enable/disable, reorder, tenant default),
// previewed against the real directory (POST /policy/preview) and published atomically (POST /policy/publish) with
// optimistic concurrency on the policy revision. VLANs and policy settings are not staged and apply immediately.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { Eye, Plus, RefreshCw, Upload } from 'lucide-react'
import { ApiError } from '../api/client'
import { qk } from '../api/keys'
import { policyApi, policyFromPublish, useEnforcement, usePolicy, type PolicyResponse, type PreviewSummary, type RuleAction } from '../api/policy'
import { useTenant } from '../api/tenant'
import { ago, plural } from '../lib/format'
import { useNow } from '../lib/useNow'
import { Btn, Callout, EDialog, ErrorState, LoadingBlock, PageHeader, Panel, SectionHeader, errorMessage, toast } from '../ui'
import { AbandonedDraft } from './policy/AbandonedDraft'
import {
  describeChanges, diffDraft, draftBody, draftFromLive, draftSignature, moveAllow, patchRule, removeRule, revertRule, upsertRule,
  type Draft, type DraftRule,
} from './policy/draft'
import { PreviewPanel, type PreviewState } from './policy/PreviewPanel'
import { PublishDialog } from './policy/PublishDialog'
import { PublishedStatus } from './policy/PublishedStatus'
import { RuleEditor } from './policy/RuleEditor'
import { RuleList } from './policy/RuleList'
import { SettingsSection } from './policy/SettingsSection'
import { useGroupSources, vlanText } from './policy/shared'
import { TestUser } from './policy/TestUser'
import { VlanSection } from './policy/VlanSection'

// The draft survives navigating away and reloading this tab (sessionStorage; never required).
interface Stored { revision: string; base: PolicyResponse; draft: Draft }
const storeKey = (tid: string) => `easyeap.policy-draft.v1.${tid}`
function loadStored(tid: string): Stored | null {
  try { const s = sessionStorage.getItem(storeKey(tid)); return s ? (JSON.parse(s) as Stored) : null } catch { return null }
}
function saveStored(tid: string, s: Stored | null) {
  try { if (s) sessionStorage.setItem(storeKey(tid), JSON.stringify(s)); else sessionStorage.removeItem(storeKey(tid)) } catch { /* storage blocked */ }
}

const CONFLICT_MSG = 'Someone published a policy change after you started this draft, so publishing it would be refused.'

export default function Policy() {
  const { tid, tenant, can } = useTenant()
  const canWrite = can('policy:write')
  const qc = useQueryClient()
  const q = usePolicy(tid)
  const groupSource = useGroupSources(tid)
  const enf = useEnforcement(tid)
  const now = useNow()
  const [params, setParams] = useSearchParams()
  const live = q.data

  const [base, setBase] = useState<PolicyResponse | null>(null)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [preview, setPreview] = useState<PreviewState | null>(null)
  const [previewBusy, setPreviewBusy] = useState(false)
  const [previewError, setPreviewError] = useState<unknown>(null)
  const [conflict, setConflict] = useState<string | null>(null)
  const [abandoned, setAbandoned] = useState<{ draft: Draft; base: PolicyResponse; reason: 'conflict' | 'stored' } | null>(null)
  const [published, setPublished] = useState<{ at: number; serverBefore: string; impact: PreviewSummary } | null>(null)
  const [editor, setEditor] = useState<{ open: boolean; rule: DraftRule | null }>({ open: false, rule: null })
  const [publishOpen, setPublishOpen] = useState(false)
  const [publishBusy, setPublishBusy] = useState(false)
  const [publishError, setPublishError] = useState<string | null>(null)
  const [discardOpen, setDiscardOpen] = useState(false)
  const [testId, setTestId] = useState<string | null>(null)
  const [focusTest, setFocusTest] = useState(false)
  const previewRef = useRef<HTMLHeadingElement>(null)
  const testRef = useRef<HTMLHeadingElement>(null)

  // Follow the live policy. A clean draft follows silently; a dirty one keeps the user's work and flags the conflict.
  useEffect(() => {
    if (!live) return
    if (!base || !draft) {
      const stored = loadStored(tid)
      setBase(live)
      if (stored && stored.revision === live.revision) setDraft(stored.draft)
      else {
        setDraft(draftFromLive(live))
        if (stored && diffDraft(stored.base, stored.draft).count > 0) setAbandoned({ draft: stored.draft, base: stored.base, reason: 'stored' })
      }
      return
    }
    if (live.revision !== base.revision) {
      if (diffDraft(base, draft).count === 0) { setBase(live); setDraft(draftFromLive(live)); setPreview(null) }
      else setConflict(CONFLICT_MSG)
    } else if (live !== base) setBase(live)
  }, [live, base, draft, tid])

  const diff = useMemo(() => (base && draft ? diffDraft(base, draft) : null), [base, draft])
  const sig = useMemo(() => (base && draft ? draftSignature(draft, base.revision) : ''), [base, draft])
  const dirty = !!diff && diff.count > 0
  const previewCurrent = !!preview && preview.sig === sig && preview.data.revision_current
  const stale = !!preview && preview.sig !== sig

  useEffect(() => {
    if (!base || !draft) return
    saveStored(tid, dirty ? { revision: base.revision, base, draft } : null)
  }, [tid, base, draft, dirty])

  useEffect(() => {
    if (!dirty) return
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault() }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])

  // Intent: ?test=<identityId> opens Test a user with that person.
  useEffect(() => {
    const t = params.get('test')
    if (!t) return
    setTestId(t)
    setFocusTest(true)
    const next = new URLSearchParams(params)
    next.delete('test')
    setParams(next, { replace: true })
  }, [params, setParams])
  useEffect(() => {
    // Wait until the draft has been set up and Test a user is on screen (the first loaded render is still a skeleton).
    if (!focusTest || !draft) return
    const id = requestAnimationFrame(() => {
      const el = testRef.current
      if (!el) return
      el.scrollIntoView({ block: 'start', behavior: 'smooth' })
      el.focus({ preventScroll: true })
      setFocusTest(false)
    })
    return () => cancelAnimationFrame(id)
  }, [focusTest, draft])

  const edit = useCallback((f: (d: Draft) => Draft) => setDraft((d) => (d ? f(d) : d)), [])

  const runPreview = useCallback(async (focus = true) => {
    if (!base || !draft) return
    const body = draftBody(draft, base.revision)
    const snapshot = draft
    setPreviewBusy(true)
    setPreviewError(null)
    try {
      const data = await policyApi.preview(tid, body)
      setPreview({ sig: JSON.stringify(body), data, draft: snapshot })
      if (!data.revision_current) setConflict(CONFLICT_MSG)
      if (focus) requestAnimationFrame(() => { previewRef.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); previewRef.current?.focus({ preventScroll: true }) })
    } catch (e) {
      setPreviewError(e)
    } finally {
      setPreviewBusy(false)
    }
  }, [base, draft, tid])

  const publish = async () => {
    if (!base || !draft || !preview) return
    setPublishBusy(true)
    setPublishError(null)
    try {
      const res = await policyApi.publish(tid, draftBody(draft, base.revision))
      const fresh = policyFromPublish(res)
      qc.setQueryData(qk.policy(tid), fresh)
      setBase(fresh)
      setDraft(draftFromLive(fresh))
      setPublished({ at: Date.now(), serverBefore: preview.data.computed_at, impact: res.impact })
      setPreview(null)
      setAbandoned(null)
      setPublishOpen(false)
      saveStored(tid, null)
      qc.invalidateQueries({ queryKey: qk.tenantScope(tid) })
      toast('Policy published', 'RADIUS applies the new snapshot within seconds. This page shows when it has.')
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) { setPublishOpen(false); setConflict(e.message) }
      else setPublishError(errorMessage(e))
    } finally {
      setPublishBusy(false)
    }
  }

  const reload = async () => {
    const r = await q.refetch()
    if (!r.data) { toast('The policy couldn’t be reloaded', errorMessage(r.error), 'crit'); return }
    if (base && draft && diffDraft(base, draft).count > 0) setAbandoned({ draft, base, reason: 'conflict' })
    setBase(r.data)
    setDraft(draftFromLive(r.data))
    setPreview(null)
    setPreviewError(null)
    setConflict(null)
    setPublished(null)
  }

  const discard = () => {
    if (!base) return
    setDraft(draftFromLive(base))
    setPreview(null)
    setPreviewError(null)
    setDiscardOpen(false)
    toast('Draft discarded', 'The live policy is unchanged.', 'gold')
  }

  if (q.isLoading || (live && (!base || !draft))) return <><PageHeader title="Access policy" /><LoadingBlock rows={8} label="Loading policy" /></>
  if (q.error && !live) return <><PageHeader title="Access policy" /><ErrorState error={q.error} onRetry={() => q.refetch()} /></>
  if (!live || !base || !draft || !diff) return null

  const lines = describeChanges(base, draft, (ref) => vlanText(live.vlans, ref))
  const e = enf.data
  const draftStatus = conflict ? 'The live policy changed. Reload it to continue.'
    : previewBusy ? 'Computing impact…'
    : !preview ? 'Preview the impact before you can publish. Nothing has reached RADIUS.'
    : stale ? 'The draft changed after the last preview. Preview again to publish.'
    : `Previewed: ${preview.data.summary.newly_allowed} newly allowed, ${preview.data.summary.newly_denied} newly denied, ${plural(preview.data.summary.vlan_changed, 'VLAN change')}.`

  return (
    <div>
      <PageHeader
        title="Access policy"
        lede="Who gets onto the network and which VLAN they land on. Rule changes are staged as a draft: preview who is affected, then publish."
        actions={canWrite ? <Btn onClick={() => setEditor({ open: true, rule: null })}><Plus aria-hidden />Add rule</Btn> : undefined}
      >
        <p className="ee-small ee-ink-3 mt-2">
          {e === undefined ? 'Checking RADIUS…'
            : !e.enforceable ? 'Not enforceable yet: RADIUS doesn’t use this policy until setup is finished.'
            : e.snapshot_built_at ? <>RADIUS snapshot built {ago(e.snapshot_built_at, now)}, {e.agent_in_sync ? 'applied by RADIUS' : e.agent_online ? 'not yet applied by RADIUS' : 'RADIUS agent not reporting'}.</>
            : 'No RADIUS snapshot has been built for this tenant yet.'}
        </p>
      </PageHeader>

      {!canWrite && <Callout tone="neutral" className="mb-6">You can view the policy and test users. Changing rules, VLANs or settings needs the Wi-Fi Administrator or Tenant Administrator role.</Callout>}
      {conflict && (
        <Callout tone="crit" className="mb-6" title="The live policy changed" action={<Btn size="sm" variant="primary" onClick={reload}><RefreshCw aria-hidden />Reload policy</Btn>}>
          {conflict} Reload to see the latest version; your changes stay listed on this page so you can make them again.
        </Callout>
      )}
      {abandoned && (
        <AbandonedDraft old={abandoned.draft} oldBase={abandoned.base} reason={abandoned.reason} current={draft} vlansFrom={live} canWrite={canWrite}
          onApply={(d) => setDraft(d)} onDismiss={() => setAbandoned(null)} />
      )}
      {published && (
        <div className="mb-6">
          <PublishedStatus tid={tid} publishedAt={published.at} serverBefore={published.serverBefore} impact={published.impact} onDismiss={() => setPublished(null)} />
        </div>
      )}

      <div className="grid items-start gap-x-8 gap-y-8 xl:grid-cols-12">
        <section className="min-w-0 xl:col-span-7" aria-labelledby="rules-h">
          <SectionHeader id="rules-h" title={dirty ? 'Access rules · draft' : 'Access rules'}
            meta={dirty ? `${plural(diff.count, 'unpublished change')} · based on revision ${base.revision.slice(0, 8)}` : `Live · revision ${base.revision.slice(0, 8)}`} />
          <Panel className="px-5 py-5" risk={dirty ? 'gold' : undefined}>
            <RuleList
              draft={draft} diff={diff} vlans={live.vlans} groupSource={groupSource} canWrite={canWrite}
              onAdd={() => setEditor({ open: true, rule: null })}
              onEdit={(r) => setEditor({ open: true, rule: r })}
              onToggle={(key, enabled) => edit((d) => patchRule(d, key, { enabled }))}
              onRemove={(key) => edit((d) => removeRule(d, key))}
              onRestore={(key) => edit((d) => patchRule(d, key, { removed: false }))}
              onRevert={(key) => edit((d) => revertRule(d, base, key))}
              onMove={(key, dir) => edit((d) => moveAllow(d, key, dir))}
              onDefault={(action: RuleAction, vref) => edit((d) => ({ ...d, default_action: action, default_vlan_ref: vref }))}
            />
          </Panel>
        </section>

        <div className="min-w-0 space-y-6 xl:col-span-5">
          {canWrite && (dirty || preview) && (
            <PreviewPanel ref={previewRef} tid={tid} preview={preview} stale={stale} busy={previewBusy} error={previewError} canWrite={canWrite} vlans={live.vlans} onPreview={() => runPreview()} />
          )}
          <TestUser ref={testRef} tid={tid} live={live} identityId={testId} onIdentity={setTestId}
            dirty={canWrite && dirty} preview={preview} previewCurrent={previewCurrent} previewBusy={previewBusy} onPreview={() => runPreview(false)} />
        </div>
      </div>

      <div className="mt-10"><VlanSection tid={tid} live={live} draft={dirty ? draft : null} canWrite={canWrite} /></div>
      <div className="mt-10"><SettingsSection tid={tid} live={live} canWrite={canWrite} canKeygen={can('enrollment:server_keygen')} enforcement={e} /></div>

      {canWrite && (dirty || conflict) && (
        <div className="sticky bottom-3 z-20 mt-8">
          <div role="region" aria-label="Unpublished draft" className="ee-panel flex flex-wrap items-center gap-x-4 gap-y-3 bg-[var(--ee-raised-solid)] px-4 py-3" data-risk={conflict ? 'crit' : 'gold'}>
            <div className="min-w-0 flex-1 basis-[240px]">
              <p className="text-[14px] font-semibold" aria-live="polite">{plural(diff.count, 'unpublished change')}</p>
              <p className="ee-small ee-ink-2">{draftStatus}</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Btn onClick={() => setDiscardOpen(true)} disabled={publishBusy}>Discard</Btn>
              {conflict
                ? <Btn variant="primary" onClick={reload}><RefreshCw aria-hidden />Reload policy</Btn>
                : <>
                  <Btn onClick={() => runPreview()} busy={previewBusy} variant={previewCurrent ? 'default' : 'primary'}><Eye aria-hidden />{preview && !stale ? 'Preview again' : 'Preview impact'}</Btn>
                  <Btn variant={previewCurrent ? 'primary' : 'default'} disabled={!previewCurrent} aria-describedby="publish-why" onClick={() => { setPublishError(null); setPublishOpen(true) }}><Upload aria-hidden />Publish</Btn>
                  {!previewCurrent && <span id="publish-why" className="sr-only">Publish is available after you preview the current draft.</span>}
                </>}
            </div>
          </div>
        </div>
      )}

      <RuleEditor tid={tid} open={editor.open} onOpenChange={(o) => setEditor((s) => ({ ...s, open: o }))} rule={editor.rule} vlans={live.vlans}
        allowedAttributes={live.allowed_extra_attributes} onSave={(r) => edit((d) => upsertRule(d, r))} />
      <PublishDialog open={publishOpen} onOpenChange={setPublishOpen} lines={lines} preview={preview?.data ?? null} busy={publishBusy} error={publishError}
        onConfirm={publish} tenantName={tenant.name} enforceable={e?.enforceable} />
      <EDialog open={discardOpen} onOpenChange={setDiscardOpen} title={`Discard ${plural(diff.count, 'unpublished change')}?`} risk="warn"
        description="Your draft is thrown away and the rules go back to the live policy. Nothing was published, so RADIUS is unaffected."
        footer={<><Btn onClick={() => setDiscardOpen(false)}>Keep draft</Btn><Btn variant="danger-solid" onClick={discard}>Discard draft</Btn></>}>
        <ul className="ee-small list-disc space-y-1 pl-5 ee-ink-2">{lines.map((l) => <li key={l.key}>{l.text}</li>)}</ul>
      </EDialog>
    </div>
  )
}
