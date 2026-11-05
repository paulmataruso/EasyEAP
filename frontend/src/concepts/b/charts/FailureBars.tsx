import { failureExplanations } from '@/domain/explain'
import type { FailureCode } from '@/domain/types'
import { barScale } from '@/ui/charts'
import { cn } from '@/ui/lib'
import { Tip } from '../ui/Tip'

/**
 * Rejections by plain-language cause (single series, so no legend: the panel title names it).
 * Each row is a button that cross-filters the live stream; hover/focus shows the share.
 */
export function FailureBars({ failures, total, selected, onSelect }: { failures: Array<[string, number]>; total: number; selected: FailureCode | null; onSelect: (code: FailureCode | null) => void }) {
  const max = failures[0]?.[1] ?? 1
  const scale = barScale(max, 100)
  return (
    <ul className="space-y-0.5" aria-label="Rejections by cause, last 24 hours">
      {failures.map(([code, count]) => {
        const info = failureExplanations[code as FailureCode]
        const active = selected === code
        const share = total ? Math.round((count / total) * 100) : 0
        return (
          <li key={code}>
            <Tip label={`${count} rejections · ${share}% of all rejections · ${code}. ${active ? 'Click to clear the filter.' : 'Click to filter the live stream.'}`} side="left">
              <button
                type="button"
                aria-pressed={active}
                onClick={() => onSelect(active ? null : (code as FailureCode))}
                className={cn('group grid w-full grid-cols-[minmax(0,1fr)_36px] items-center gap-x-3 rounded px-2 py-1.5 text-left transition-colors hover:bg-[var(--b-hover)]', active && 'bg-[var(--b-cyan-wash)] ring-1 ring-[rgba(34,211,238,0.35)] ring-inset')}
              >
                <span className="truncate text-[13px] text-[var(--b-text)]">{info?.title ?? code}</span>
                <span className="b-cond b-num row-span-2 text-right text-[15px] font-semibold text-[var(--b-text)]">{count}</span>
                <span className="mt-1 block h-[6px] rounded-r-[3px] bg-transparent" aria-hidden>
                  <span className="block h-full rounded-r-[3px] bg-[var(--b-reject)] transition-[width] duration-300" style={{ width: `${Math.max(2, scale(count))}%`, opacity: selected && !active ? 0.45 : 1 }} />
                </span>
              </button>
            </Tip>
          </li>
        )
      })}
    </ul>
  )
}
