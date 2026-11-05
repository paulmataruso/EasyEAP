import type { ReactNode } from 'react'
import { AlertDialog } from 'radix-ui'
import { TriangleAlert } from 'lucide-react'
import { usePortal } from './portal'

/** Modal confirmation, reserved for destructive actions. */
export function Confirm({
  open,
  onOpenChange,
  title,
  children,
  confirmLabel,
  onConfirm,
  cancelLabel = 'Cancel',
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  confirmLabel: string
  onConfirm: () => void
  cancelLabel?: string
}) {
  const container = usePortal()
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal container={container}>
        <AlertDialog.Overlay className="b-dialog-overlay" />
        <AlertDialog.Content className="b-dialog">
          <div className="flex gap-3">
            <span className="grid size-8 shrink-0 place-items-center rounded-md border border-[rgba(248,113,113,0.3)] bg-[rgba(248,113,113,0.08)] text-[var(--b-crit)]">
              <TriangleAlert className="size-4" aria-hidden />
            </span>
            <div className="min-w-0">
              <AlertDialog.Title className="text-[15px] font-semibold text-[var(--b-text)]">{title}</AlertDialog.Title>
              <AlertDialog.Description asChild>
                <div className="b-t2 mt-1.5 space-y-2 text-[13px] leading-relaxed">{children}</div>
              </AlertDialog.Description>
            </div>
          </div>
          <div className="mt-5 flex justify-end gap-2">
            <AlertDialog.Cancel className="b-btn b-btn-secondary">{cancelLabel}</AlertDialog.Cancel>
            <AlertDialog.Action className="b-btn b-btn-danger-solid" onClick={onConfirm}>
              {confirmLabel}
            </AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  )
}
