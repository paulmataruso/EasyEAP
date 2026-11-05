import type { ReactNode } from 'react'
import { AlertDialog, Dialog } from 'radix-ui'
import { Check, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import { usePortalContainer } from './portal'

/** Centered record-depth glass modal. */
export function GlassDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  width = 560,
  header,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  children: ReactNode
  footer?: ReactNode
  width?: number
  header?: ReactNode
}) {
  const container = usePortalContainer()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="a-scrim" />
        <Dialog.Content className="a-dialog a-overlay-glass" style={{ ['--a-dialog-w' as string]: `${width}px` }}>
          <div className="flex items-start justify-between gap-4 px-6 pt-5 pb-4">
            <div className="min-w-0">
              <Dialog.Title className="text-[18px] leading-snug font-semibold text-[var(--a-text)]">{title}</Dialog.Title>
              {description ? <Dialog.Description className="mt-1 text-[13px] text-[var(--a-text-3)]">{description}</Dialog.Description> : <Dialog.Description className="sr-only">{typeof title === 'string' ? title : 'Dialog'}</Dialog.Description>}
            </div>
            <Dialog.Close className="a-icon-btn -mt-1 -mr-2" aria-label="Close">
              <X aria-hidden />
            </Dialog.Close>
          </div>
          {header}
          <div className="min-h-0 flex-1 overflow-y-auto px-6 pb-5">{children}</div>
          {footer && <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/10 bg-black/10 px-6 py-3.5 [&>*:last-child]:ml-auto">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/** Destructive or irreversible confirmations. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footerStart,
  confirm,
  cancelLabel = 'Cancel',
  width = 520,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  children?: ReactNode
  footerStart?: ReactNode
  /** The confirming action; rendered via AlertDialog.Action only when `asAction` */
  confirm: ReactNode
  cancelLabel?: string
  width?: number
}) {
  const container = usePortalContainer()
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal container={container}>
        <AlertDialog.Overlay className="a-scrim" />
        <AlertDialog.Content className="a-dialog a-overlay-glass" style={{ ['--a-dialog-w' as string]: `${width}px` }}>
          <div className="px-6 pt-5 pb-4">
            <AlertDialog.Title className="text-[18px] leading-snug font-semibold text-[var(--a-text)]">{title}</AlertDialog.Title>
            {description ? <AlertDialog.Description className="mt-1 text-[13px] text-[var(--a-text-3)]">{description}</AlertDialog.Description> : <AlertDialog.Description className="sr-only">{typeof title === 'string' ? title : 'Confirm'}</AlertDialog.Description>}
          </div>
          {children && <div className="min-h-0 flex-1 overflow-y-auto px-6 pb-5">{children}</div>}
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/10 bg-black/10 px-6 py-3.5">
            <div className="min-w-0">{footerStart}</div>
            <div className="ml-auto flex items-center gap-2">
              <AlertDialog.Cancel className="a-btn a-btn-ghost">{cancelLabel}</AlertDialog.Cancel>
              {confirm}
            </div>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  )
}

/** Right-hand inspector drawer at record depth. */
export function Drawer({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  side = 'right',
  headerExtra,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  children: ReactNode
  footer?: ReactNode
  side?: 'right' | 'left'
  headerExtra?: ReactNode
}) {
  const container = usePortalContainer()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="a-scrim" />
        <Dialog.Content className={cn('a-drawer a-overlay-glass', side === 'left' && 'a-drawer-left')}>
          <div className="flex items-start justify-between gap-3 border-b border-white/10 px-5 pt-4 pb-3.5">
            <div className="min-w-0">
              <Dialog.Title className="text-[17px] leading-snug font-semibold break-words text-[var(--a-text)]">{title}</Dialog.Title>
              {description ? <Dialog.Description className="mt-1 text-[13px] text-[var(--a-text-3)]">{description}</Dialog.Description> : <Dialog.Description className="sr-only">Details</Dialog.Description>}
              {headerExtra}
            </div>
            <Dialog.Close className="a-icon-btn -mr-1.5" aria-label="Close">
              <X aria-hidden />
            </Dialog.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer && <div className="flex flex-wrap items-center justify-between gap-2 border-t border-white/10 bg-black/10 px-5 py-3 [&>*:last-child]:ml-auto">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/** Horizontal stepper for multi-step actions inside a modal. Step numbers carry the sequence. */
export function Stepper({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="flex flex-wrap items-center gap-x-3 gap-y-2 border-y border-white/[0.08] bg-black/10 px-6 py-3" aria-label="Progress">
      {steps.map((s, i) => {
        const state = i < current ? 'done' : i === current ? 'current' : 'todo'
        return (
          <li key={s} className="a-step" data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
            <span className="a-step-mark">{state === 'done' ? <Check className="size-3.5" aria-hidden /> : i + 1}</span>
            {s}
            {i < steps.length - 1 && <span className="ml-1 h-px w-6 bg-white/15" aria-hidden />}
          </li>
        )
      })}
    </ol>
  )
}
