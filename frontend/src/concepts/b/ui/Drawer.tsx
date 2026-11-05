import type { CSSProperties, ReactNode } from 'react'
import { Dialog } from 'radix-ui'
import { X } from 'lucide-react'
import { usePortal } from './portal'

/**
 * Right-side slide-over for details and edits (glass: it is an overlay).
 * Radix Dialog supplies the focus trap, Esc to close and focus return.
 */
export function Drawer({
  open,
  onOpenChange,
  title,
  description,
  meta,
  children,
  footer,
  width = 560,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  meta?: ReactNode
  children: ReactNode
  footer?: ReactNode
  width?: number
}) {
  const container = usePortal()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="b-overlay" />
        <Dialog.Content className="b-drawer" style={{ '--b-drawer-w': `${width}px` } as CSSProperties}>
          <header className="b-drawer-head">
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-[16px] font-semibold leading-snug text-[var(--b-text)]">{title}</Dialog.Title>
              {description ? (
                <Dialog.Description className="b-t2 mt-0.5 text-[12.5px]">{description}</Dialog.Description>
              ) : (
                <Dialog.Description className="sr-only">Details panel</Dialog.Description>
              )}
              {meta && <div className="mt-2 flex flex-wrap items-center gap-1.5">{meta}</div>}
            </div>
            <Dialog.Close className="b-btn b-btn-ghost b-btn-sm b-btn-icon -mr-1" aria-label="Close panel">
              <X aria-hidden />
            </Dialog.Close>
          </header>
          <div className="b-drawer-body">{children}</div>
          {footer && <footer className="b-drawer-foot">{footer}</footer>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
