import { useState, type ComponentProps, type ReactNode } from 'react'
import { Dialog, Select, Switch, ToggleGroup, Tooltip } from 'radix-ui'
import {
  ArrowDown, ArrowUp, Ban, BadgeCheck, Building, CalendarX, Check, ChevronDown, ChevronsUpDown, CircleCheck, CircleDashed, CircleX,
  Clock, Copy, Hourglass, Laptop, Monitor, ServerCog, ShieldCheck, ShieldX, Smartphone, Tablet, TriangleExclamationPoint, UserRound, X,
} from 'lucide-react'
import { cn, copyText } from '@/ui/lib'
import type { CertStatus, HealthState, IdentitySource, Platform, RuleAction, Vlan } from '@/domain/types'
import { certLabel, certShortLabel, certTone, healthLabel, healthTone, toast, usePortal, vlanVar, type Tone } from './lib'

// ── Buttons ─────────────────────────────────────────────────────────────
type BtnVariant = 'default' | 'primary' | 'ghost' | 'danger' | 'danger-solid'
export function Btn({ variant = 'default', size = 'md', icon, className, children, ...rest }: ComponentProps<'button'> & { variant?: BtnVariant; size?: 'sm' | 'md' | 'lg'; icon?: boolean }) {
  return (
    <button
      type="button"
      className={cn('f-btn', variant !== 'default' && `f-btn-${variant}`, size !== 'md' && `f-btn-${size}`, icon && 'f-btn-icon', className)}
      {...rest}
    >
      {children}
    </button>
  )
}

// ── Chips ───────────────────────────────────────────────────────────────
export function Chip({ tone = 'neutral', icon, children, className, title }: { tone?: Tone; icon?: ReactNode; children: ReactNode; className?: string; title?: string }) {
  return (
    <span className={cn('f-chip', className)} data-tone={tone} title={title}>
      {icon}
      {children}
    </span>
  )
}

const healthIcon: Record<HealthState, ReactNode> = {
  ok: <CircleCheck aria-hidden />,
  degraded: <TriangleExclamationPoint aria-hidden />,
  down: <CircleX aria-hidden />,
  unconfigured: <CircleDashed aria-hidden />,
}
export function HealthChip({ state, label }: { state: HealthState; label?: string }) {
  return <Chip tone={healthTone[state]} icon={healthIcon[state]}>{label ?? healthLabel[state]}</Chip>
}

const certIcon: Record<CertStatus, ReactNode> = {
  active: <BadgeCheck aria-hidden />,
  expiring: <Clock aria-hidden />,
  expired: <CalendarX aria-hidden />,
  revoked: <Ban aria-hidden />,
  pending: <Hourglass aria-hidden />,
}
export function CertChip({ status, children }: { status: CertStatus; children?: ReactNode }) {
  return <Chip tone={certTone[status]} icon={certIcon[status]} title={certLabel[status]}>{children ?? certShortLabel[status]}</Chip>
}

export function AccessChip({ outcome }: { outcome: RuleAction }) {
  return outcome === 'allow'
    ? <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>Allowed</Chip>
    : <Chip tone="crit" icon={<ShieldX aria-hidden />}>Denied</Chip>
}

export function ActionChip({ action }: { action: RuleAction }) {
  return action === 'allow'
    ? <Chip tone="valid" icon={<Check aria-hidden />}>Allow</Chip>
    : <Chip tone="crit" icon={<Ban aria-hidden />}>Deny</Chip>
}

export function VlanTag({ vlan, withName = true, className }: { vlan: Vlan | undefined | null; withName?: boolean; className?: string }) {
  if (!vlan) return <span className="f-ink-3">—</span>
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap', className)} title={`VLAN ${vlan.vlanId} · ${vlan.name}`}>
      <span className="f-swatch" style={{ background: vlanVar(vlan) }} aria-hidden />
      <span className="f-num font-semibold">{vlan.vlanId}</span>
      {withName && <span className="f-ink-2 truncate">{vlan.name}</span>}
    </span>
  )
}

export function SourceTag({ source }: { source: IdentitySource }) {
  return source === 'ad' ? (
    <span className="f-tag gap-1" title="Synchronised from Active Directory"><Building className="size-3" aria-hidden />AD</span>
  ) : (
    <span className="f-tag gap-1" title="Local account managed in EasyEAP"><UserRound className="size-3" aria-hidden />Local</span>
  )
}

export function PlatformIcon({ platform, className }: { platform: Platform | null; className?: string }) {
  const c = cn('size-4 f-ink-3', className)
  if (platform === 'ios') return <Smartphone className={c} aria-hidden />
  if (platform === 'android') return <Tablet className={c} aria-hidden />
  if (platform === 'macos' || platform === 'windows') return <Laptop className={c} aria-hidden />
  if (platform === 'linux') return <Monitor className={c} aria-hidden />
  return <ServerCog className={c} aria-hidden />
}

// ── Layout ──────────────────────────────────────────────────────────────
export function Panel({ risk, className, children, as = 'section', ...rest }: { risk?: Tone; className?: string; children: ReactNode; as?: 'section' | 'div' | 'article' | 'aside' } & Omit<ComponentProps<'section'>, 'className' | 'children' | 'ref'>) {
  const As = as as 'section'
  return (
    <As className={cn('f-panel', className)} data-risk={risk} {...rest}>
      {children}
    </As>
  )
}

export function PageHeader({ title, lede, actions, children }: { title: ReactNode; lede?: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  return (
    <header className="mb-7 flex flex-wrap items-end justify-between gap-x-6 gap-y-4">
      <div className="min-w-0">
        <h1 className="f-h1">{title}</h1>
        {lede && <p className="f-lede mt-1.5">{lede}</p>}
        {children}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

export function SectionHeader({ title, meta, actions, id, level = 2 }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode; id?: string; level?: 2 | 3 }) {
  const H = level === 2 ? 'h2' : 'h3'
  return (
    <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
      <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1">
        <H id={id} className={level === 2 ? 'f-h2' : 'f-h3'}>{title}</H>
        {meta && <span className="f-small f-ink-3">{meta}</span>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Empty({ icon, title, children, action, className }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-start gap-2 rounded-[10px] border border-dashed border-[var(--f-line-2)] px-5 py-6', className)}>
      {icon && <span className="f-ink-3 [&_svg]:size-5">{icon}</span>}
      <p className="f-h3">{title}</p>
      {children && <p className="f-small f-ink-2 max-w-[60ch]">{children}</p>}
      {action && <div className="mt-1.5">{action}</div>}
    </div>
  )
}

export function Dl({ items, className, cols = 2 }: { items: Array<[ReactNode, ReactNode, ('wide' | false)?]>; className?: string; cols?: 1 | 2 | 3 }) {
  return (
    <dl className={cn('grid gap-x-6 gap-y-3', cols === 2 && 'sm:grid-cols-2', cols === 3 && 'sm:grid-cols-2 xl:grid-cols-3', className)}>
      {items.map(([k, v, wide], i) => (
        <div key={i} className={cn('min-w-0', wide && 'sm:col-span-full')}>
          <dt className="f-label">{k}</dt>
          <dd className="mt-0.5 min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  )
}

// ── Inputs ──────────────────────────────────────────────────────────────
export function Seg<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: Array<{ value: T; label: ReactNode; count?: number }>; label: string }) {
  return (
    <ToggleGroup.Root type="single" value={value} onValueChange={(v) => v && onChange(v as T)} aria-label={label} className="f-seg">
      {options.map((o) => (
        <ToggleGroup.Item key={o.value} value={o.value} className="f-seg-item">
          {o.label}
          {o.count !== undefined && <span className="f-count">{o.count}</span>}
        </ToggleGroup.Item>
      ))}
    </ToggleGroup.Root>
  )
}

export function FSelect({ value, onChange, options, label, className, placeholder }: { value: string; onChange: (v: string) => void; options: Array<{ value: string; label: ReactNode }>; label: string; className?: string; placeholder?: string }) {
  const container = usePortal()
  return (
    <Select.Root value={value} onValueChange={onChange}>
      <Select.Trigger className={cn('f-select-trigger', className)} aria-label={label}>
        <Select.Value placeholder={placeholder} />
        <Select.Icon><ChevronDown className="size-4 f-ink-3" aria-hidden /></Select.Icon>
      </Select.Trigger>
      <Select.Portal container={container}>
        <Select.Content className="f-menu max-h-[360px]" position="popper" sideOffset={4}>
          <Select.Viewport>
            {options.map((o, idx) => (
              <Select.Item key={`${o.value}#${idx}`} value={o.value} className="f-menu-item justify-between">
                <Select.ItemText>{o.label}</Select.ItemText>
                <Select.ItemIndicator><Check className="size-4 text-[var(--f-gold)]" aria-hidden /></Select.ItemIndicator>
              </Select.Item>
            ))}
          </Select.Viewport>
        </Select.Content>
      </Select.Portal>
    </Select.Root>
  )
}

export function FSwitch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <Switch.Root className="f-switch" checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled}>
      <Switch.Thumb className="f-switch-thumb" />
    </Switch.Root>
  )
}

export function Tip({ content, children, side = 'top' }: { content: ReactNode; children: ReactNode; side?: 'top' | 'bottom' | 'left' | 'right' }) {
  const container = usePortal()
  return (
    <Tooltip.Root delayDuration={250}>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal container={container}>
        <Tooltip.Content side={side} sideOffset={6} className="f-tooltip">{content}</Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}

export function SortTh({ label, sortKey, table, right, className }: { label: string; sortKey: string; table: { toggleSort: (k: string) => void; ariaSort: (k: string) => 'ascending' | 'descending' | 'none' }; right?: boolean; className?: string }) {
  const s = table.ariaSort(sortKey)
  return (
    <th aria-sort={s} className={cn(right && 'f-right', className)}>
      <button type="button" className="f-sort" onClick={() => table.toggleSort(sortKey)}>
        {label}
        {s === 'ascending' ? <ArrowUp aria-hidden /> : s === 'descending' ? <ArrowDown aria-hidden /> : <ChevronsUpDown aria-hidden className="opacity-50" />}
      </button>
    </th>
  )
}

export function CopyButton({ text, label = 'Copy', what, size = 'sm', className }: { text: string; label?: string; what: string; size?: 'sm' | 'md'; className?: string }) {
  const [done, setDone] = useState(false)
  return (
    <Btn
      size={size}
      className={className}
      aria-label={`${label} ${what}`}
      onClick={async () => {
        const ok = await copyText(text)
        if (ok) {
          setDone(true)
          setTimeout(() => setDone(false), 1600)
        } else toast('Copy failed', 'Your browser blocked clipboard access. Select the text and copy it manually.', 'warn')
      }}
    >
      {done ? <Check aria-hidden /> : <Copy aria-hidden />}
      {done ? 'Copied' : label}
    </Btn>
  )
}

// ── Dialog shell ────────────────────────────────────────────────────────
export function FDialog({ open, onOpenChange, title, description, children, wide, risk, footer }: { open: boolean; onOpenChange: (o: boolean) => void; title: ReactNode; description?: ReactNode; children: ReactNode; wide?: boolean; risk?: Tone; footer?: ReactNode }) {
  const container = usePortal()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="f-backdrop" />
        <Dialog.Content className={cn('f-dialog', wide && 'f-dialog-wide')} data-risk={risk} aria-describedby={description ? undefined : undefined}>
          <div className="flex items-start justify-between gap-4 px-6 pt-5">
            <div className="min-w-0">
              <Dialog.Title className="f-h2 text-[18px]">{title}</Dialog.Title>
              {description ? <Dialog.Description className="f-small f-ink-2 mt-1">{description}</Dialog.Description> : <Dialog.Description className="sr-only">{typeof title === 'string' ? title : 'Dialog'}</Dialog.Description>}
            </div>
            <Dialog.Close asChild>
              <Btn variant="ghost" size="sm" icon aria-label="Close"><X aria-hidden /></Btn>
            </Dialog.Close>
          </div>
          <div className="px-6 pb-5 pt-4">{children}</div>
          {footer && <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[var(--f-line)] px-6 py-4">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export function Field({ label, hint, error, children, htmlFor }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-[13px] font-semibold">{label}</label>
      {children}
      {error ? <p className="f-field-error" role="alert">{error}</p> : hint ? <p className="f-small f-ink-3">{hint}</p> : null}
    </div>
  )
}
