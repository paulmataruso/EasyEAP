import type { ReactNode } from 'react'
import { AlertDialog, Dialog } from 'radix-ui'
import { X } from 'lucide-react'
import { Button, useE } from './ui'

/**
 * Non-modal glass inspector: detail and creation flows open here so the map or table
 * stays usable behind it. Esc or the close button dismisses; clicking elsewhere does not,
 * so selecting another row simply swaps what the inspector shows.
 */
export function Inspector({ open, onClose, title, subtitle, leading, children, footer, label }: { open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; leading?: ReactNode; children: ReactNode; footer?: ReactNode; label?: string }) {
  const { container } = useE()
  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onClose()} modal={false}>
      <Dialog.Portal container={container}>
        <Dialog.Content
          className="e-inspector"
          aria-label={label}
          onInteractOutside={(e) => e.preventDefault()}
          onOpenAutoFocus={(e) => {
            e.preventDefault()
            const root = e.currentTarget as HTMLElement | null
            const target = root?.querySelector<HTMLElement>('[data-autofocus]') ?? root
            target?.focus()
          }}
          tabIndex={-1}
        >
          <div className="e-inspector-head">
            {leading && <div className="mt-0.5 shrink-0">{leading}</div>}
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-[17px] font-bold leading-snug tracking-[-0.01em]">{title}</Dialog.Title>
              {subtitle ? <Dialog.Description className="t2 mt-0.5 text-[13px]">{subtitle}</Dialog.Description> : <Dialog.Description className="sr-only">Details</Dialog.Description>}
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" icon aria-label="Close inspector" className="-mr-1"><X /></Button>
            </Dialog.Close>
          </div>
          <div className="e-inspector-body">{children}</div>
          {footer && <div className="e-inspector-foot">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export function InspectorSection({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="mt-5 first:mt-0">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-[13px] font-bold">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  )
}

/** Modal confirmation, used only for destructive actions. */
export function Confirm({ open, onOpenChange, title, children, confirmLabel, onConfirm, disabled, tone = 'danger', cancelLabel = 'Cancel', hideCancel }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; children: ReactNode; confirmLabel: string; onConfirm: () => void; disabled?: boolean; tone?: 'danger' | 'primary'; cancelLabel?: string; hideCancel?: boolean }) {
  const { container } = useE()
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal container={container}>
        <AlertDialog.Overlay className="e-overlay" />
        <AlertDialog.Content className="e-modal">
          <div className="p-5">
            <AlertDialog.Title className="text-[18px] font-bold leading-snug">{title}</AlertDialog.Title>
            <AlertDialog.Description asChild>
              <div className="mt-3 space-y-3 text-[13.5px] text-[var(--e-text-2)]">{children}</div>
            </AlertDialog.Description>
          </div>
          <div className="flex justify-end gap-2 border-t border-[var(--e-hair)] px-5 py-3.5">
            {!hideCancel && (
              <AlertDialog.Cancel asChild>
                <Button variant="ghost">{cancelLabel}</Button>
              </AlertDialog.Cancel>
            )}
            <Button
              variant={tone === 'danger' ? 'danger' : 'primary'}
              disabled={disabled}
              onClick={(e) => {
                e.preventDefault()
                onConfirm()
              }}
            >
              {confirmLabel}
            </Button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  )
}
