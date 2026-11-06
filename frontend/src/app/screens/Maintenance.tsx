// While a restore runs, the API answers 503 to everything except GET /api/system/maintenance. The first 503 (or the
// restore dialog itself, once its request is accepted) switches the whole console to this page, which follows the
// restore step by step and then sends everyone to sign in: the restore signs every administrator out.
import { useEffect, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { LogIn, RotateCcw } from 'lucide-react'
import { backupApi, type RestoreState } from '../api/backup'
import { onMaintenance } from '../api/client'
import { ago, fmtDateTime } from '../lib/format'
import { useNow } from '../lib/useNow'
import { Btn, Callout } from '../ui'
import { RunSteps } from '../ui/RunSteps'
import { AuthFrame } from './Login'

const isRestoreState = (v: unknown): v is RestoreState => !!v && typeof v === 'object' && 'steps' in v && Array.isArray((v as RestoreState).steps)

export function MaintenanceGate({ children }: { children: ReactNode }) {
  const [watching, setWatching] = useState<RestoreState | null>(null)
  useEffect(() => onMaintenance((st) => { if (isRestoreState(st)) setWatching((cur) => cur ?? st) }), [])
  return watching ? <RestoreProgress initial={watching} /> : <>{children}</>
}

/** Reload into a clean console (no cached data from before the restore). */
function reloadTo(hash: string) {
  window.location.hash = hash
  window.location.reload()
}

export function RestoreProgress({ initial }: { initial: RestoreState }) {
  const now = useNow(5_000)
  const [finished, setFinished] = useState(false)
  const poll = useQuery({
    queryKey: ['maintenance', initial.id],
    queryFn: ({ signal }) => backupApi.maintenance(signal),
    refetchInterval: finished ? false : 1000,
    refetchIntervalInBackground: true,
    retry: false,
    gcTime: 0,
  })
  const current = poll.data?.maintenance ?? null
  const last = poll.data?.last_restore ?? null
  // Finished: nothing is running any more. last_restore is the outcome (it can be another restore's only if this one's
  // state was lost, which the "finished" branch below handles without claiming success).
  const outcome = poll.data && !current ? (last && last.id === initial.id ? last : null) : null
  const done = !!poll.data && !current
  useEffect(() => { if (done) setFinished(true) }, [done])
  const shown = current ?? outcome ?? initial
  const firstRun = shown.source === 'first-run'

  if (done && outcome?.status === 'done') {
    return (
      <AuthFrame title="Restore complete" lede={`EasyEAP is running from the backup made ${fmtDateTime(outcome.backup_created_at)}.`}>
        <div className="space-y-4">
          <RunSteps steps={outcome.steps} label="Restore steps" />
          {outcome.warnings.map((w) => <Callout key={w} tone="warn">{w}</Callout>)}
          <Callout tone="neutral" title="Sign in with an account from the backup">
            Everyone was signed out. The administrators, passwords and two-factor settings are the ones in the backup.
          </Callout>
          <Btn variant="primary" size="lg" className="w-full" onClick={() => reloadTo('#/login')}><LogIn aria-hidden />Sign in</Btn>
        </div>
      </AuthFrame>
    )
  }
  if (done && outcome?.status === 'failed') {
    return (
      <AuthFrame title="The restore didn’t complete" lede={firstRun ? 'This server is back to a fresh installation.' : 'EasyEAP put everything back as it was before the restore.'}>
        <div className="space-y-4">
          <Callout tone="crit" title="What went wrong">{outcome.error ?? 'The restore failed.'}</Callout>
          <RunSteps steps={outcome.steps} label="Restore steps" stalled />
          <Btn variant="primary" size="lg" className="w-full" onClick={() => reloadTo(firstRun ? '#/first-run' : '#/system')}>
            <RotateCcw aria-hidden />{firstRun ? 'Back to setup' : 'Back to the console'}
          </Btn>
        </div>
      </AuthFrame>
    )
  }
  if (done) {
    return (
      <AuthFrame title="EasyEAP is available again" lede="The restore has finished, but its result couldn’t be read.">
        <div className="space-y-4">
          <p className="ee-small ee-ink-2">Sign in to check System → Backup and restore and the audit log.</p>
          <Btn variant="primary" size="lg" className="w-full" onClick={() => reloadTo('#/login')}><LogIn aria-hidden />Continue</Btn>
        </div>
      </AuthFrame>
    )
  }

  const rollingBack = shown.status === 'rolling_back'
  const currentLabel = shown.steps.find((s) => s.current)?.label
  return (
    <AuthFrame title={rollingBack ? 'Undoing the restore' : 'Restoring a backup'}
      lede={shown.backup_created_at ? `Backup made ${fmtDateTime(shown.backup_created_at)}.` : undefined}>
      <div className="space-y-4">
        {rollingBack
          ? <Callout tone="warn" title="The restore hit a problem">EasyEAP is putting everything back as it was before the restore started.</Callout>
          : <p className="ee-small ee-ink-2">The console is unavailable until this finishes, usually within a few minutes. RADIUS keeps authenticating with its current configuration meanwhile. Keep this page open.</p>}
        <RunSteps steps={shown.steps} label="Restore steps" />
        <p className="ee-small ee-ink-3" role="status" aria-live="polite">
          {poll.isError ? 'Waiting for EasyEAP to answer…' : currentLabel ? `${currentLabel}…` : 'Starting…'}
          {shown.started_at && <span title={fmtDateTime(shown.started_at)}> Started {ago(shown.started_at, now)}.</span>}
        </p>
      </div>
    </AuthFrame>
  )
}
