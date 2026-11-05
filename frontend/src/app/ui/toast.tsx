import { useSyncExternalStore } from 'react'
import { CircleCheck, CircleX, Info, TriangleAlert, X } from 'lucide-react'

export type ToastTone = 'valid' | 'warn' | 'crit' | 'gold'
interface ToastItem { id: number; title: string; body?: string; tone: ToastTone }

let items: ToastItem[] = []
let seq = 0
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())

export function toast(title: string, body?: string, tone: ToastTone = 'valid') {
  const id = ++seq
  items = [...items, { id, title, body, tone }].slice(-4)
  emit()
  setTimeout(() => dismiss(id), tone === 'crit' ? 9000 : 5500)
}
const dismiss = (id: number) => { items = items.filter((t) => t.id !== id); emit() }

const icon = { valid: <CircleCheck aria-hidden />, warn: <TriangleAlert aria-hidden />, crit: <CircleX aria-hidden />, gold: <Info aria-hidden /> }
const color = { valid: 'var(--ee-valid)', warn: 'var(--ee-warn)', crit: 'var(--ee-crit-ink)', gold: 'var(--ee-gold)' }

export function Toaster() {
  const list = useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l) }, () => items)
  return (
    <div className="ee-toast-viewport" role="region" aria-label="Notifications">
      <div aria-live="polite" className="contents">
        {list.map((t) => (
          <div key={t.id} className="ee-toast" data-risk={t.tone === 'valid' ? 'ok' : t.tone}>
            <span className="mt-0.5 [&_svg]:size-4" style={{ color: color[t.tone] }}>{icon[t.tone]}</span>
            <div className="min-w-0 flex-1">
              <p className="text-[13.5px] font-semibold">{t.title}</p>
              {t.body && <p className="ee-small ee-ink-2 mt-0.5">{t.body}</p>}
            </div>
            <button type="button" className="rounded ee-ink-3 hover:text-[var(--ee-ink)]" aria-label="Dismiss notification" onClick={() => dismiss(t.id)}>
              <X className="size-4" aria-hidden />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
