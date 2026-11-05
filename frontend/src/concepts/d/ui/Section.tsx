import type { ReactNode } from 'react'
import { cn } from '@/ui/lib'

export function Section({ id, title, description, actions, children, className }: { id?: string; title: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  const headingId = id ? `${id}-h` : undefined
  return (
    <section id={id} aria-labelledby={headingId} className={cn('d-section scroll-mt-6', className)}>
      <div className="d-section-head">
        <div className="min-w-0">
          <h2 id={headingId} className="d-h2">{title}</h2>
          {description && <p className="d-section-desc">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  )
}

export function PageHeader({ title, meta, actions, lead }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode; lead?: ReactNode }) {
  return (
    <header className="d-pagehead">
      <div className="flex min-w-0 items-start gap-3">
        {lead}
        <div className="min-w-0">
          <h1 className="d-h1">{title}</h1>
          {meta && <div className="d-meta">{meta}</div>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

export const MetaSep = () => <span className="d-meta-sep" aria-hidden="true" />

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="d-empty">
      {icon}
      <p className="d-empty-title">{title}</p>
      {children && <p className="d-empty-body">{children}</p>}
      {action}
    </div>
  )
}

export function Notice({ tone = 'info', icon, children }: { tone?: 'info' | 'warn' | 'crit' | 'ok'; icon: ReactNode; children: ReactNode }) {
  return (
    <div className="d-notice" data-tone={tone} role={tone === 'crit' ? 'alert' : undefined}>
      {icon}
      <div className="min-w-0">{children}</div>
    </div>
  )
}

export function KV({ items }: { items: Array<[ReactNode, ReactNode]> }) {
  return (
    <dl className="d-kv">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  )
}
