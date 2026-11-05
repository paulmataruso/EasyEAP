// After publishing: show, from the RADIUS agent's own reports, when RADIUS has applied the new snapshot. Never claim
// it's live before the agent says so.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { CircleCheck, RefreshCw, X } from 'lucide-react'
import { useEnforcement, type PreviewSummary } from '../../api/policy'
import { fmtTime, plural, relative } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { Btn, Callout, Panel } from '../../ui'

const WATCH_MS = 3 * 60_000

export function PublishedStatus({ tid, publishedAt, serverBefore, impact, onDismiss }: {
  tid: string
  /** Client clock when publish returned (for the watch window only). */
  publishedAt: number
  /** Server time from the preview computed just before publishing; the new snapshot is built after it. */
  serverBefore: string
  impact: PreviewSummary
  onDismiss: () => void
}) {
  const now = useNow(5_000)
  const [watching, setWatching] = useState(true)
  const enf = useEnforcement(tid, { watch: watching })
  const e = enf.data
  const fresh = !!e?.snapshot_built_at && new Date(e.snapshot_built_at).getTime() >= new Date(serverBefore).getTime()
  const applied = fresh && !!e?.agent_in_sync
  const timedOut = now.getTime() - publishedAt > WATCH_MS

  useEffect(() => { if (applied || timedOut || e?.enforceable === false) setWatching(false) }, [applied, timedOut, e?.enforceable])

  let body
  if (!e) body = <p className="ee-small ee-ink-2">Checking whether RADIUS has applied it…</p>
  else if (!e.enforceable) {
    body = <Callout tone="neutral" title="Not enforceable yet" action={<Link to={paths.setup(tid)} className="ee-btn ee-btn-sm">Continue setup</Link>}>RADIUS doesn’t use this tenant’s policy until setup is finished. The published rules apply from then on.</Callout>
  } else if (!fresh) {
    body = <Callout tone="warn" title="No new snapshot yet">EasyEAP hasn’t built a RADIUS snapshot for this tenant since publishing. Check that RADIUS is configured for this tenant.</Callout>
  } else if (applied) {
    body = (
      <Callout tone="valid" title="RADIUS is using the new policy">
        The RADIUS agent reported the snapshot built at {fmtTime(e.snapshot_built_at, true)} as applied. New connections are decided by the published rules. People already connected keep their session until they reconnect or it times out.
      </Callout>
    )
  } else if (!e.agent_online) {
    body = <Callout tone="warn" title="RADIUS agent isn’t reporting" action={<Link to={paths.radius(tid)} className="ee-btn ee-btn-sm">Open RADIUS</Link>}>EasyEAP can’t confirm RADIUS has the new policy. If RADIUS is running it keeps deciding from the snapshot it last applied.</Callout>
  } else if (timedOut) {
    body = <Callout tone="warn" title="Still waiting for RADIUS" action={<Btn size="sm" onClick={() => setWatching(true)}><RefreshCw aria-hidden />Check again</Btn>}>The snapshot published {relative(new Date(publishedAt).toISOString(), now)} isn’t applied yet. RADIUS keeps deciding from its previous snapshot until it is.</Callout>
  } else {
    body = (
      <p className="ee-small ee-ink-2 flex items-center gap-2" role="status">
        <RefreshCw className="size-4 animate-spin text-[var(--ee-gold)]" aria-hidden />
        Waiting for RADIUS to apply the snapshot built at {fmtTime(e.snapshot_built_at, true)}. RADIUS checks for updates every few seconds and keeps using its previous snapshot until then.
      </p>
    )
  }

  return (
    <Panel risk={applied ? 'valid' : 'gold'} className="px-5 py-4" aria-labelledby="published-h">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 id="published-h" className="ee-h2 flex items-center gap-2"><CircleCheck className="size-4 text-[var(--ee-valid)]" aria-hidden />Policy published</h2>
          <p className="ee-small ee-ink-2 mt-0.5">
            Published {relative(new Date(publishedAt).toISOString(), now)} · {plural(impact.newly_allowed, 'person', 'people')} newly allowed, {impact.newly_denied} newly denied, {plural(impact.vlan_changed, 'VLAN change')}. Recorded in the audit log.
          </p>
        </div>
        <Btn variant="ghost" size="sm" icon className="w-7" aria-label="Dismiss" onClick={onDismiss}><X aria-hidden /></Btn>
      </div>
      <div className="mt-3" aria-live="polite">{body}</div>
    </Panel>
  )
}
