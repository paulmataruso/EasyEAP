import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { Toast } from 'radix-ui'
import { X } from 'lucide-react'
import { toneIcon, type Tone } from '../lib/status'

interface ToastItem {
  id: number
  tone: Tone
  title: string
  description?: string
}

const ToastContext = createContext<(t: Omit<ToastItem, 'id'>) => void>(() => {})
export const useToast = () => useContext(ToastContext)

export function ToastHost({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const push = useCallback((t: Omit<ToastItem, 'id'>) => setItems((xs) => [...xs, { ...t, id: Date.now() + Math.random() }]), [])
  return (
    <ToastContext.Provider value={push}>
      <Toast.Provider swipeDirection="right" duration={6000} label="Notification">
        {children}
        {items.map((t) => {
          const Icon = toneIcon[t.tone]
          return (
            <Toast.Root
              key={t.id}
              className="b-toast b-pop"
              onOpenChange={(open) => {
                if (!open) setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== t.id)), 200)
              }}
            >
              <Icon className={`mt-0.5 size-4 shrink-0 b-ink-${t.tone}`} aria-hidden />
              <div className="min-w-0 flex-1">
                <Toast.Title className="text-[13px] font-semibold text-[var(--b-text)]">{t.title}</Toast.Title>
                {t.description && <Toast.Description className="b-t2 mt-0.5 text-[12.5px] leading-relaxed">{t.description}</Toast.Description>}
              </div>
              <Toast.Close className="b-btn b-btn-ghost b-btn-sm b-btn-icon -mr-1 -mt-0.5" aria-label="Dismiss notification">
                <X aria-hidden />
              </Toast.Close>
            </Toast.Root>
          )
        })}
        <Toast.Viewport className="b-toast-viewport" />
      </Toast.Provider>
    </ToastContext.Provider>
  )
}
