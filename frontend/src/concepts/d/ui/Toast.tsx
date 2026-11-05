import { CircleCheck, X } from 'lucide-react'
import { Toast } from 'radix-ui'
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'

interface ToastItem { id: number; title: string; description?: string }
const Ctx = createContext<(t: Omit<ToastItem, 'id'>) => void>(() => {})

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const push = useCallback((t: Omit<ToastItem, 'id'>) => setItems((xs) => [...xs.slice(-2), { ...t, id: Date.now() + Math.random() }]), [])
  return (
    <Ctx.Provider value={push}>
      <Toast.Provider duration={5000} swipeDirection="right" label="Notification">
        {children}
        {items.map((t) => (
          <Toast.Root key={t.id} className="d-toast" onOpenChange={(open) => !open && setItems((xs) => xs.filter((x) => x.id !== t.id))}>
            <CircleCheck aria-hidden="true" />
            <div>
              <Toast.Title className="d-toast-title">{t.title}</Toast.Title>
              {t.description && <Toast.Description className="d-toast-desc">{t.description}</Toast.Description>}
            </div>
            <Toast.Close className="d-btn d-btn--ghost d-btn--sm d-btn--icon" aria-label="Dismiss notification">
              <X aria-hidden="true" />
            </Toast.Close>
          </Toast.Root>
        ))}
        <Toast.Viewport className="d-toasts" />
      </Toast.Provider>
    </Ctx.Provider>
  )
}

export const useToast = () => useContext(Ctx)
