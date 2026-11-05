import { Toast } from 'radix-ui'
import { CircleCheck, X } from 'lucide-react'
import { useConcept } from '../app/context'

/** Glass toasts, bottom right. Confirms what changed after an action completes. */
export function Toaster() {
  const { toasts, dismissToast } = useConcept()
  return (
    <Toast.Provider swipeDirection="right" duration={6000}>
      {toasts.map((t) => (
        <Toast.Root key={t.id} className="c-toast" onOpenChange={(open) => !open && dismissToast(t.id)}>
          <CircleCheck size={18} aria-hidden="true" />
          <Toast.Title className="c-toast-title">{t.title}</Toast.Title>
          <Toast.Close className="c-iconbtn" aria-label="Dismiss" style={{ width: 26, height: 26, gridColumn: 3, gridRow: 1 }}>
            <X size={15} aria-hidden="true" />
          </Toast.Close>
          {t.description ? <Toast.Description className="c-toast-desc">{t.description}</Toast.Description> : null}
        </Toast.Root>
      ))}
      <Toast.Viewport className="c-toasts" />
    </Toast.Provider>
  )
}
