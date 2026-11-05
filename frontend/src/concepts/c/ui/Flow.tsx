import type { ReactNode } from 'react'
import { Dialog } from 'radix-ui'
import { Check, X } from 'lucide-react'
import { LogoMark } from '@/ui/Logo'
import { ConceptPortal } from './Portal'

export interface FlowStep {
  id: string
  title: string
  description?: string
}

interface FlowProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** "Add a wireless controller" */
  title: string
  /** Tenant or person the flow acts on */
  context: string
  steps: FlowStep[]
  current: number
  children: ReactNode
  closeLabel?: string
}

/**
 * Full-page focused flow: the shell steps aside, a left column shows progress, and the step
 * occupies a calm reading column. It is a Radix dialog underneath (focus trap, Esc closes).
 */
export function Flow({ open, onOpenChange, title, context, steps, current, children, closeLabel = 'Cancel' }: FlowProps) {
  const step = steps[current]
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <ConceptPortal>
          <Dialog.Content className="c-flow" aria-describedby={undefined}>
            <div className="c-flow-head">
              <div className="c-container c-flow-head-inner">
                <LogoMark className="size-[22px]" title="EasyEAP" />
                <Dialog.Title className="c-flow-head-title" style={{ margin: 0 }}>
                  {title}
                </Dialog.Title>
                <span className="c-flow-head-ctx c-hide-sm">{context}</span>
                <Dialog.Close className="c-btn is-ghost is-sm" style={{ marginLeft: 'auto' }}>
                  <X size={16} aria-hidden="true" />
                  {closeLabel}
                </Dialog.Close>
              </div>
            </div>
            <div className="c-flow-body">
              <ol className="c-progress" aria-label="Progress">
                {steps.map((s, i) => {
                  const state = i < current ? 'done' : i === current ? 'current' : 'upcoming'
                  return (
                    <li key={s.id} data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
                      <span className="c-progress-mark" aria-hidden="true">
                        {state === 'done' ? <Check size={13} strokeWidth={2.6} /> : i + 1}
                      </span>
                      <span className="c-progress-title">
                        {s.title}
                        <span className="sr-only">{state === 'done' ? ' (done)' : state === 'current' ? ' (current step)' : ''}</span>
                      </span>
                      {s.description ? <span className="c-progress-desc">{s.description}</span> : null}
                    </li>
                  )
                })}
              </ol>
              <div className="c-flow-step">
                <p className="c-flow-mobile-step" aria-hidden="true">
                  Step {current + 1} of {steps.length} · {step?.title}
                </p>
                {children}
              </div>
            </div>
          </Dialog.Content>
        </ConceptPortal>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/** Standard step header + body + footer for a Flow. */
export function FlowStepView({ heading, intro, children, back, next }: { heading: string; intro?: ReactNode; children?: ReactNode; back?: ReactNode; next?: ReactNode }) {
  return (
    <>
      <h2>{heading}</h2>
      {intro ? <p className="c-flow-intro">{intro}</p> : null}
      {children ? <div className="c-flow-fields">{children}</div> : null}
      {back || next ? (
        <div className="c-flow-actions">
          <div>{back}</div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>{next}</div>
        </div>
      ) : null}
    </>
  )
}
