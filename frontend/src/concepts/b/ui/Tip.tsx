import type { ReactElement, ReactNode } from 'react'
import { Tooltip } from 'radix-ui'
import { usePortal } from './portal'

/** Themed tooltip. The trigger must be a focusable element so keyboard users get the same text. */
export function Tip({ label, children, side = 'top', align = 'center' }: { label: ReactNode; children: ReactElement; side?: 'top' | 'right' | 'bottom' | 'left'; align?: 'start' | 'center' | 'end' }) {
  const container = usePortal()
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal container={container}>
        <Tooltip.Content side={side} align={align} sideOffset={6} className="b-tooltip">
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}
