import { useId, type ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/ui/lib'

/**
 * Signature move: one sentence leads every screen. The sentence is the page's h1; the page name
 * lives in the breadcrumb and is prefixed for assistive tech.
 */
export function Lede({ page, state, rest, detail, actions, meta }: { page: string; state: ReactNode; rest?: ReactNode; detail?: ReactNode; actions?: ReactNode; meta?: ReactNode }) {
  return (
    <header className="c-lede">
      <div className="c-lede-text">
        <h1 className="c-enter">
          <span className="sr-only">{page}: </span>
          {state}
          {rest ? (
            <>
              {' '}
              <span className="c-lede-rest is-block">{rest}</span>
            </>
          ) : null}
        </h1>
        {detail ? <p className="c-lede-detail c-enter-late">{detail}</p> : null}
        {meta ? <div className="c-lede-meta c-enter-late">{meta}</div> : null}
      </div>
      {actions ? <div className="c-lede-actions">{actions}</div> : null}
    </header>
  )
}

export function Section({ title, description, aside, children, id, flush, className }: { title: string; description?: ReactNode; aside?: ReactNode; children: ReactNode; id?: string; flush?: boolean; className?: string }) {
  const headingId = useId()
  return (
    <section id={id} aria-labelledby={headingId} className={cn('c-section', flush && 'is-flush', className)}>
      <div className="c-section-head">
        <div>
          <h2 id={headingId}>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
        {aside ? <div className="c-section-aside">{aside}</div> : null}
      </div>
      {children}
    </section>
  )
}

export function Empty({ icon: Icon, title, children, action }: { icon: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="c-empty">
      <Icon size={20} strokeWidth={1.7} aria-hidden="true" />
      <div className="c-empty-title">{title}</div>
      {children ? <div className="c-empty-body">{children}</div> : null}
      {action ? <div className="c-empty-action">{action}</div> : null}
    </div>
  )
}

export function Note({ icon: Icon, tone, children }: { icon: LucideIcon; tone?: 'warn' | 'crit'; children: ReactNode }) {
  return (
    <div className="c-note" data-tone={tone}>
      <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
      <div>{children}</div>
    </div>
  )
}

export interface DefItem {
  label: string
  value: ReactNode
}

/** Label/value pairs on hairlines. */
export function DefList({ items, stacked, className }: { items: DefItem[]; stacked?: boolean; className?: string }) {
  return (
    <dl className={cn('c-dl', stacked && 'is-stacked', className)}>
      {items.map((it) => (
        <div key={it.label}>
          <dt>{it.label}</dt>
          <dd>{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** Label-above-value specs laid out in an auto grid (server settings, CA facts). */
export function Specs({ items }: { items: DefItem[] }) {
  return (
    <dl className="c-specs" style={{ margin: 0 }}>
      {items.map((it) => (
        <div key={it.label} className="c-spec">
          <dt className="c-spec-label">{it.label}</dt>
          <dd className="c-spec-value" style={{ margin: 0 }}>{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
