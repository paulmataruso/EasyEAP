import { useId, useState, type ButtonHTMLAttributes, type ComponentType, type ReactNode } from 'react'
import { Tooltip } from 'radix-ui'
import { Check, Copy } from 'lucide-react'
import { cn, copyText } from '@/ui/lib'
import { usePortalContainer } from './portal'

type IconType = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>

// ── Buttons ──────────────────────────────────────────────────────────────────

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-ghost'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'sm' | 'md'
  icon?: IconType
  ref?: React.Ref<HTMLButtonElement>
}

export function Button({ variant = 'secondary', size = 'md', icon: Icon, className, children, type = 'button', ...rest }: ButtonProps) {
  return (
    <button type={type} className={cn('a-btn', `a-btn-${variant}`, size === 'sm' && 'a-btn-sm', className)} {...rest}>
      {Icon && <Icon aria-hidden />}
      {children}
    </button>
  )
}

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string
  icon: IconType
  tooltip?: boolean
  ref?: React.Ref<HTMLButtonElement>
}

export function IconButton({ label, icon: Icon, tooltip = true, className, type = 'button', ...rest }: IconButtonProps) {
  const btn = (
    <button type={type} aria-label={label} className={cn('a-icon-btn', className)} {...rest}>
      <Icon aria-hidden />
    </button>
  )
  return tooltip ? <Tip content={label}>{btn}</Tip> : btn
}

// ── Tooltip ──────────────────────────────────────────────────────────────────

export function Tip({ content, children, side = 'top' }: { content: ReactNode; children: ReactNode; side?: 'top' | 'bottom' | 'left' | 'right' }) {
  const container = usePortalContainer()
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal container={container}>
        <Tooltip.Content side={side} sideOffset={6} className="a-tooltip">
          {content}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}

// ── Pills ────────────────────────────────────────────────────────────────────

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral'

export function Pill({ tone = 'neutral', icon: Icon, children, className, title }: { tone?: Tone; icon?: IconType; children: ReactNode; className?: string; title?: string }) {
  return (
    <span className={cn('a-pill', `a-pill-${tone}`, className)} title={title}>
      {Icon && <Icon aria-hidden />}
      {children}
    </span>
  )
}

export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('a-tag', className)}>{children}</span>
}

export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span className={cn('a-mono', className)} title={title}>
      {children}
    </span>
  )
}

// ── Copy ─────────────────────────────────────────────────────────────────────

export function CopyButton({ text, label = 'Copy', size = 'sm', variant = 'secondary', onCopied, className }: { text: string; label?: string; size?: 'sm' | 'md'; variant?: ButtonVariant; onCopied?: () => void; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      size={size}
      variant={variant}
      icon={copied ? Check : Copy}
      className={className}
      onClick={async () => {
        await copyText(text)
        setCopied(true)
        onCopied?.()
        window.setTimeout(() => setCopied(false), 1600)
      }}
    >
      <span aria-live="polite">{copied ? 'Copied' : label}</span>
    </Button>
  )
}

// ── Panel (tenant depth by default) ─────────────────────────────────────────

export type Depth = 'platform' | 'tenant' | 'record'

export function Panel({
  depth = 'tenant',
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
  id,
  headingLevel = 2,
}: {
  depth?: Depth
  title?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children?: ReactNode
  className?: string
  bodyClassName?: string
  id?: string
  headingLevel?: 2 | 3
}) {
  const autoId = useId()
  const headingId = `${id ?? autoId}-title`
  const H = headingLevel === 2 ? 'h2' : 'h3'
  return (
    <section id={id} aria-labelledby={title ? headingId : undefined} className={cn('a-panel', `a-depth-${depth}`, className)}>
      {title && (
        <header className="a-panel-head">
          <div className="min-w-0">
            <H id={headingId} className="a-panel-title">
              {title}
            </H>
            {description && <p className="a-panel-desc">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  )
}

// ── Empty state ──────────────────────────────────────────────────────────────

export function EmptyState({ icon: Icon, title, children, action, className }: { icon: IconType; title: string; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-center px-6 py-10 text-center', className)}>
      <span className="mb-3 grid size-10 place-items-center rounded-[10px] border border-white/10 bg-white/[0.04] text-[var(--a-text-3)]">
        <Icon className="size-5" aria-hidden />
      </span>
      <p className="text-[15px] font-semibold text-[var(--a-text)]">{title}</p>
      {children && <div className="mt-1 max-w-[46ch] text-[13px] text-[var(--a-text-3)]">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

// ── Definition list ─────────────────────────────────────────────────────────

type KeyValueItem = { label: ReactNode; value: ReactNode; hint?: ReactNode }

export function KeyValues({ items, className, cols = 1 }: { items: KeyValueItem[]; className?: string; cols?: 1 | 2 }) {
  return (
    <dl className={cn('grid gap-x-6', cols === 2 ? 'sm:grid-cols-2' : 'grid-cols-1', className)}>
      {items.map((it, i) => (
        <div key={i} className="flex min-w-0 items-baseline justify-between gap-4 border-b border-[var(--a-line)] py-2.5 last:border-b-0 sm:[&:nth-last-child(2)]:border-b-0">
          <dt className="shrink-0 text-[13px] text-[var(--a-text-3)]">{it.label}</dt>
          <dd className="min-w-0 text-right text-[14px] text-[var(--a-text)]">
            {it.value}
            {it.hint && <div className="text-[12px] text-[var(--a-text-3)]">{it.hint}</div>}
          </dd>
        </div>
      ))}
    </dl>
  )
}

/** Label-over-value cells for settings with long values or explanations. */
export function SettingsGrid({ items, className }: { items: KeyValueItem[]; className?: string }) {
  return (
    <dl className={cn('grid border-t border-[var(--a-line)] sm:grid-cols-2', className)}>
      {items.map((it, i) => (
        <div key={i} className="min-w-0 border-b border-[var(--a-line)] py-3 last:border-b-0 sm:odd:border-r sm:odd:pr-4 sm:even:pl-4 sm:[&:nth-last-child(2):nth-child(odd)]:border-b-0">
          <dt className="text-[12px] text-[var(--a-text-3)]">{it.label}</dt>
          <dd className="mt-1 min-w-0 text-[14px] break-words text-[var(--a-text)]">{it.value}</dd>
          {it.hint && <dd className="mt-0.5 text-[12px] leading-snug text-[var(--a-text-3)]">{it.hint}</dd>}
        </div>
      ))}
    </dl>
  )
}

export function Avatar({ name, size = 40 }: { name: string; size?: number }) {
  const parts = name.split(/\s+/).filter(Boolean)
  const text = ((parts[0]?.[0] ?? '') + (parts[parts.length - 1]?.[0] ?? '')).toUpperCase()
  return (
    <span
      aria-hidden
      className="grid shrink-0 place-items-center rounded-full border border-white/15 bg-[linear-gradient(160deg,rgba(99,102,241,0.35),rgba(20,184,166,0.25))] font-semibold text-[var(--a-text)]"
      style={{ width: size, height: size, fontSize: size * 0.36 }}
    >
      {text}
    </span>
  )
}

/** Page header: title + one-line context + actions. No eyebrow labels. */
export function PageHeader({ title, description, actions, leading }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; leading?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="flex min-w-0 items-center gap-3.5">
        {leading}
        <div className="min-w-0">
          <h1 className="text-[22px] leading-tight font-semibold tracking-[-0.01em] text-balance text-[var(--a-text)]">{title}</h1>
          {description && <p className="mt-1 text-[14px] text-[var(--a-text-3)]">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
