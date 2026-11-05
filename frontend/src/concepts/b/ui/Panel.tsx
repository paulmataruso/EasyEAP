import type { HTMLAttributes, ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/ui/lib'
import { toneIcon, type Tone } from '../lib/status'

export function Panel({ className, children, ...rest }: HTMLAttributes<HTMLElement> & { children: ReactNode }) {
  return (
    <section className={cn('b-panel', className)} {...rest}>
      {children}
    </section>
  )
}

/** Panel header: title (h2) on the left, meta and actions on the right. */
export function PanelHead({ title, meta, actions, id, className, as: Heading = 'h2' }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode; id?: string; className?: string; as?: 'h2' | 'h3' }) {
  return (
    <header className={cn('b-panel-head', className)}>
      <Heading id={id} className="b-panel-title">
        {title}
      </Heading>
      {meta && <div className="b-t2 min-w-0 truncate text-[12.5px]">{meta}</div>}
      {actions && <div className="ml-auto flex shrink-0 items-center gap-1.5">{actions}</div>}
    </header>
  )
}

export function EmptyState({ icon: Icon, title, children, action, className }: { icon: LucideIcon; title: string; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-start gap-2 px-4 py-6', className)}>
      <span className="grid size-8 place-items-center rounded-md border border-[var(--b-line-strong)] bg-[var(--b-sunken)] text-[var(--b-text-2)]">
        <Icon className="size-4" aria-hidden />
      </span>
      <p className="text-[13.5px] font-semibold text-[var(--b-text)]">{title}</p>
      {children && <div className="b-t2 max-w-[52ch] text-[12.5px] leading-relaxed">{children}</div>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  )
}

/** Inline callout: tinted ground + icon. */
export function Notice({ tone = 'info', title, children, className, icon }: { tone?: Tone; title?: ReactNode; children?: ReactNode; className?: string; icon?: LucideIcon }) {
  const Icon = icon ?? toneIcon[tone]
  return (
    <div className={cn('b-notice', tone !== 'neutral' && `b-notice-${tone}`, className)} role={tone === 'crit' ? 'alert' : undefined}>
      <Icon className={`b-ink-${tone}`} aria-hidden />
      <div className="min-w-0">
        {title && <p className="mb-0.5 font-semibold text-[var(--b-text)]">{title}</p>}
        {children}
      </div>
    </div>
  )
}

/** Definition rows for inspector-style detail: label left, value right. */
export function KeyValue({ rows, className, labelWidth = 'minmax(120px, 38%)' }: { rows: Array<[ReactNode, ReactNode] | null | false | undefined>; className?: string; labelWidth?: string }) {
  return (
    <dl className={cn('grid gap-x-4 text-[13px]', className)} style={{ gridTemplateColumns: `${labelWidth} minmax(0, 1fr)` }}>
      {rows.filter(Boolean).map((row, i) => {
        const [k, v] = row as [ReactNode, ReactNode]
        return (
          <div key={i} className="contents">
            <dt className="b-t2 border-b border-[var(--b-line-soft)] py-[7px]">{k}</dt>
            <dd className="min-w-0 border-b border-[var(--b-line-soft)] py-[7px] break-words text-[var(--b-text)]">{v}</dd>
          </div>
        )
      })}
    </dl>
  )
}

/** Compact figure: value in the condensed face, label beneath. */
export function Figure({ value, label, sub, tone, className }: { value: ReactNode; label: ReactNode; sub?: ReactNode; tone?: Tone; className?: string }) {
  return (
    <div className={cn('min-w-0', className)}>
      <div className={cn('b-figure text-[26px]', tone && tone !== 'neutral' ? `b-ink-${tone}` : 'text-[var(--b-text)]')}>{value}</div>
      <div className="mt-1 text-[12.5px] text-[var(--b-text-2)]">{label}</div>
      {sub && <div className="mt-0.5 text-[12px] text-[var(--b-text-3)]">{sub}</div>}
    </div>
  )
}
