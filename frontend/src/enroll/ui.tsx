// Portal primitives: the console's visual language at touch size (every control ≥ 44px), with no console providers.
import { useEffect, useRef, useState, type ComponentProps, type ReactNode } from 'react'
import { clsx } from 'clsx'
import { Check, ChevronDown, CircleCheck, CircleX, Copy, Info, LoaderCircle, TriangleAlert } from 'lucide-react'

export type Tone = 'valid' | 'warn' | 'crit' | 'gold' | 'neutral'

export function Button({ variant = 'default', block, busy, className, children, disabled, ...rest }: ComponentProps<'button'> & { variant?: 'default' | 'primary' | 'ghost'; block?: boolean; busy?: boolean }) {
  return (
    <button
      type="button"
      className={clsx('en-btn', variant !== 'default' && `en-btn-${variant}`, block && 'en-btn-block en-btn-block-sm', className)}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy && <LoaderCircle className="en-spin" aria-hidden />}
      {children}
    </button>
  )
}

export function Note({ tone = 'neutral', title, children, icon, className, role }: { tone?: Tone; title?: ReactNode; children?: ReactNode; icon?: ReactNode; className?: string; role?: 'alert' | 'status' }) {
  const i = icon ?? { valid: <CircleCheck aria-hidden />, warn: <TriangleAlert aria-hidden />, crit: <CircleX aria-hidden />, gold: <Info aria-hidden />, neutral: <Info aria-hidden /> }[tone]
  return (
    <div className={clsx('en-note', className)} data-tone={tone} role={role}>
      {i}
      <div className="min-w-0 flex-1">
        {title && <p className="en-note-title">{title}</p>}
        {children && <div className={clsx('en-note-body', title && 'mt-1')}>{children}</div>}
      </div>
    </div>
  )
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.setAttribute('readonly', '')
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      ta.remove()
      return ok
    } catch {
      return false
    }
  }
}

/** Copy button with its own spoken confirmation. `what` names the value for screen readers ("Copy server name"). */
export function CopyButton({ text, what, label = 'Copy', onCopied, className }: { text: string; what: string; label?: string; onCopied?: () => void; className?: string }) {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle')
  const timer = useRef<number | undefined>(undefined)
  useEffect(() => () => window.clearTimeout(timer.current), [])
  return (
    <>
      <button
        type="button"
        className={clsx('en-btn en-btn-copy', className)}
        aria-label={`${label} ${what}`}
        onClick={async () => {
          const ok = await copyText(text)
          setState(ok ? 'done' : 'failed')
          if (ok) onCopied?.()
          window.clearTimeout(timer.current)
          timer.current = window.setTimeout(() => setState('idle'), 2200)
        }}
      >
        {state === 'done' ? <Check aria-hidden /> : <Copy aria-hidden />}
        <span aria-hidden className="en-copy-label">{state === 'done' ? 'Copied' : label}</span>
      </button>
      <span className="sr-only" role="status" aria-live="polite">
        {state === 'done' ? `${what} copied` : state === 'failed' ? `Couldn’t copy. Select the ${what} and copy it yourself.` : ''}
      </span>
    </>
  )
}

/** A value someone has to type into a settings screen: monospace, with a copy button. */
export function Value({ value, what, copy = true }: { value: string; what: string; copy?: boolean }) {
  return (
    <span className="en-value">
      <span className="en-value-text">{value}</span>
      {copy && <CopyButton text={value} what={what} />}
    </span>
  )
}

/** A command to paste into a terminal: kept on one line (scrolls sideways), with a copy button below. */
export function Command({ value, what }: { value: string; what: string }) {
  return (
    <span className="block">
      <pre className="ee-code !text-[13.5px]" tabIndex={0} aria-label={what}>{value}</pre>
      <span className="mt-2 inline-flex"><CopyButton text={value} what={what} /></span>
    </span>
  )
}

export function Disclosure({ summary, children, defaultOpen, className }: { summary: ReactNode; children: ReactNode; defaultOpen?: boolean; className?: string }) {
  return (
    <details className={clsx('en-more', className)} open={defaultOpen}>
      <summary>
        <span>{summary}</span>
        <ChevronDown aria-hidden />
      </summary>
      <div className="en-more-body">{children}</div>
    </details>
  )
}

export function Checkbox({ checked, onChange, children }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
  return (
    <label className="en-check">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>{children}</span>
    </label>
  )
}

/** Step heading: takes focus when the step changes so keyboard and screen-reader users start at the top. */
export function StepHeading({ children, lede, focusKey }: { children: ReactNode; lede?: ReactNode; focusKey: string }) {
  const ref = useRef<HTMLHeadingElement>(null)
  const first = useRef(true)
  useEffect(() => {
    if (first.current) { first.current = false; return }
    ref.current?.focus({ preventScroll: false })
    window.scrollTo({ top: 0, behavior: 'auto' })
  }, [focusKey])
  return (
    <header className="mb-6">
      <h1 ref={ref} tabIndex={-1} className="en-h1 outline-none">{children}</h1>
      {lede && <div className="en-lede mt-2.5">{lede}</div>}
    </header>
  )
}

export function Steps({ labels, current }: { labels: string[]; current: number }) {
  return (
    <nav aria-label="Progress">
      <ol className="en-steps">
        {labels.map((l, i) => {
          const state = i < current ? 'done' : i === current ? 'current' : 'upcoming'
          return (
            <li key={l} className="en-step" data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
              <span className="en-step-bar" aria-hidden />
              <span className="en-step-row">
                <span className="en-step-dot" aria-hidden>{state === 'done' ? <Check /> : i + 1}</span>
                <span>
                  <span className="sr-only">{`Step ${i + 1} of ${labels.length}: `}</span>
                  {l}
                  {state === 'done' && <span className="sr-only"> (done)</span>}
                </span>
              </span>
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
