import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { Toast } from 'radix-ui'
import { CircleCheck, Info, TriangleAlert, X } from 'lucide-react'

type ToastTone = 'ok' | 'info' | 'warn'
interface ToastItem {
  id: number
  title: string
  description?: string
  tone: ToastTone
}

const ToastContext = createContext<(t: Omit<ToastItem, 'id' | 'tone'> & { tone?: ToastTone }) => void>(() => {})

export const useToast = () => useContext(ToastContext)

const ICON = { ok: CircleCheck, info: Info, warn: TriangleAlert }
const COLOR = { ok: 'text-[var(--a-ok-text)]', info: 'text-[var(--a-info-text)]', warn: 'text-[var(--a-warn-text)]' }

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const push = useCallback((t: Omit<ToastItem, 'id' | 'tone'> & { tone?: ToastTone }) => {
    setItems((xs) => [...xs, { id: Date.now() + Math.random(), tone: 'ok', ...t }])
  }, [])
  const value = useMemo(() => push, [push])
  return (
    <ToastContext.Provider value={value}>
      <Toast.Provider swipeDirection="right" duration={5000}>
        {children}
        {items.map((t) => {
          const Icon = ICON[t.tone]
          return (
            <Toast.Root
              key={t.id}
              className="a-toast a-overlay-glass"
              onOpenChange={(open) => {
                if (!open) setItems((xs) => xs.filter((x) => x.id !== t.id))
              }}
            >
              <Icon className={`mt-0.5 size-[18px] shrink-0 ${COLOR[t.tone]}`} aria-hidden />
              <div className="min-w-0 flex-1">
                <Toast.Title className="text-[14px] font-semibold text-[var(--a-text)]">{t.title}</Toast.Title>
                {t.description && <Toast.Description className="mt-0.5 text-[13px] text-[var(--a-text-2)]">{t.description}</Toast.Description>}
              </div>
              <Toast.Close className="a-icon-btn -mt-1 -mr-1 !size-7" aria-label="Dismiss">
                <X aria-hidden />
              </Toast.Close>
            </Toast.Root>
          )
        })}
        <Toast.Viewport className="fixed right-4 bottom-4 z-[80] flex flex-col gap-2 outline-none" />
      </Toast.Provider>
    </ToastContext.Provider>
  )
}
