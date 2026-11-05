import type { ReactNode } from 'react'
import { AlertDialog, Dialog, VisuallyHidden } from 'radix-ui'
import { X } from 'lucide-react'
import { cn } from '@/ui/lib'
import { ConceptPortal } from './Portal'

interface SheetProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: ReactNode
  children?: ReactNode
  actions?: ReactNode
  wide?: boolean
}

/** Small centred sheet (14px radius) for short tasks that need protected focus. */
export function Sheet({ open, onOpenChange, title, description, children, actions, wide }: SheetProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <ConceptPortal>
          <Dialog.Overlay className="c-overlay" />
          <Dialog.Content className={cn('c-sheet', wide && 'is-wide')}>
            <Dialog.Title className="c-sheet-title">{title}</Dialog.Title>
            {description ? <Dialog.Description className="c-sheet-desc">{description}</Dialog.Description> : <VisuallyHidden.Root><Dialog.Description>{title}</Dialog.Description></VisuallyHidden.Root>}
            {children ? <div className="c-sheet-body">{children}</div> : null}
            {actions ? <div className="c-sheet-actions">{actions}</div> : null}
            <Dialog.Close className="c-iconbtn c-sheet-close" aria-label="Close">
              <X size={18} aria-hidden="true" />
            </Dialog.Close>
          </Dialog.Content>
        </ConceptPortal>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/**
 * Destructive confirmation. Outside clicks do not dismiss it; Esc and Cancel do.
 * `confirm` must be an <AlertDialog.Action>-compatible element or a plain button (we render it as-is).
 */
export function ConfirmSheet({ open, onOpenChange, title, description, children, cancelLabel = 'Cancel', confirm, wide }: Omit<SheetProps, 'actions'> & { cancelLabel?: string; confirm: ReactNode }) {
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <ConceptPortal>
          <AlertDialog.Overlay className="c-overlay" />
          <AlertDialog.Content className={cn('c-sheet', wide && 'is-wide')}>
            <AlertDialog.Title className="c-sheet-title">{title}</AlertDialog.Title>
            {description ? (
              <AlertDialog.Description className="c-sheet-desc">{description}</AlertDialog.Description>
            ) : (
              <VisuallyHidden.Root>
                <AlertDialog.Description>{title}</AlertDialog.Description>
              </VisuallyHidden.Root>
            )}
            {children ? <div className="c-sheet-body">{children}</div> : null}
            <div className="c-sheet-actions">
              <AlertDialog.Cancel className="c-btn is-secondary">{cancelLabel}</AlertDialog.Cancel>
              {confirm}
            </div>
          </AlertDialog.Content>
        </ConceptPortal>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  )
}
