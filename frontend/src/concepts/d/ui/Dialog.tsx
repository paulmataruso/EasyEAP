import { X } from 'lucide-react'
import { Dialog } from 'radix-ui'
import type { ReactNode } from 'react'
import { cn } from '@/ui/lib'
import { usePortal } from '../model/state'

interface BaseProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  children: ReactNode
  footer?: ReactNode
  width?: number
  /** Adornment next to the title (e.g. the object's label tape). */
  tape?: ReactNode
}

/** Centered modal: focus trap, Esc to close, labelled by its title. */
export function Modal({ open, onOpenChange, title, description, children, footer, width, tape }: BaseProps) {
  const portal = usePortal()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={portal}>
        <Dialog.Overlay className="d-overlay" />
        <Dialog.Content className="d-dialog" style={width ? { width: `min(${width}px, calc(100vw - 32px))` } : undefined}>
          <div className="d-dialog-head">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2.5">
                <Dialog.Title className="d-dialog-title">{title}</Dialog.Title>
                {tape}
              </div>
              {description ? <Dialog.Description className="d-dialog-desc">{description}</Dialog.Description> : <Dialog.Description className="sr-only">{typeof title === 'string' ? title : 'Dialog'}</Dialog.Description>}
            </div>
            <Dialog.Close className="d-btn d-btn--ghost d-btn--icon" aria-label="Close">
              <X aria-hidden="true" />
            </Dialog.Close>
          </div>
          <div className="d-dialog-body">{children}</div>
          {footer && <div className="d-dialog-foot">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/** Right-hand inspector sheet for a record. */
export function Sheet({ open, onOpenChange, title, description, children, footer, tape, side = 'right', className }: BaseProps & { side?: 'right' | 'left'; className?: string }) {
  const portal = usePortal()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={portal}>
        <Dialog.Overlay className="d-overlay" />
        <Dialog.Content className={cn('d-sheet', side === 'left' && 'd-sheet--left', className)}>
          <div className="d-dialog-head">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2.5">
                {tape}
                <Dialog.Title className="d-dialog-title">{title}</Dialog.Title>
              </div>
              {description ? <Dialog.Description className="d-dialog-desc">{description}</Dialog.Description> : <Dialog.Description className="sr-only">{typeof title === 'string' ? title : 'Details'}</Dialog.Description>}
            </div>
            <Dialog.Close className="d-btn d-btn--ghost d-btn--icon" aria-label="Close">
              <X aria-hidden="true" />
            </Dialog.Close>
          </div>
          <div className="d-dialog-body">{children}</div>
          {footer && <div className="d-dialog-foot" style={{ position: 'sticky', bottom: 0, background: 'var(--d-surface)' }}>{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
