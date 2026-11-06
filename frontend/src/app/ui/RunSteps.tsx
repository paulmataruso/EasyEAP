import { Check, LoaderCircle } from 'lucide-react'
import type { ProgressStep } from '../api/backup'

/** Steps of long-running server work (a backup or a restore), as the server reports them. */
export function RunSteps({ steps, label, stalled }: { steps: ProgressStep[]; label: string; stalled?: boolean }) {
  return (
    <ol className="ee-runsteps" aria-label={label}>
      {steps.map((s, i) => {
        const state = s.done ? 'done' : s.current ? 'current' : undefined
        return (
          <li key={s.key} data-state={state} aria-current={s.current ? 'step' : undefined}>
            {s.done ? <Check aria-hidden /> : s.current ? <LoaderCircle className={stalled ? undefined : 'animate-spin motion-reduce:animate-none'} aria-hidden />
              : <span className="ee-runsteps-n" aria-hidden>{i + 1}</span>}
            <span>{s.label}</span>
            <span className="sr-only">{s.done ? ': done' : s.current ? ': in progress' : ': not started'}</span>
          </li>
        )
      })}
    </ol>
  )
}

export function UploadProgress({ sent, total, label }: { sent: number; total: number; label: string }) {
  const pct = total > 0 ? Math.min(100, Math.round((sent / total) * 100)) : 0
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-3 text-[13px]">
        <span>{label}</span>
        <span className="ee-num ee-ink-2">{pct}%</span>
      </div>
      <div className="ee-progress" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        <span style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
