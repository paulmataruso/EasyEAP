// Production primitives (design direction F). Every interactive element has a visible :focus-visible ring
// (theme.css), every icon-only button has an accessible name, and dialogs always return focus somewhere real.
import { useEffect, useRef, useState, type ComponentProps, type ReactNode, type RefObject } from 'react'
import { Dialog, Select, Switch, ToggleGroup, Tooltip } from 'radix-ui'
import {
  ArrowDown, ArrowUp, Ban, BadgeCheck, Building, CalendarX, Check, ChevronDown, ChevronsUpDown, CircleAlert, CircleCheck, CircleX,
  Clock, Copy, Info, KeyRound, Laptop, Monitor, RefreshCw, ServerCog, ShieldCheck, ShieldX, Smartphone, Tablet, TriangleAlert, UserRound, X,
} from 'lucide-react'
import { cn } from '@/ui/lib'
import { ApiError } from '../api/client'
import { toast } from './toast'

export { toast, Toaster } from './toast'
export type Tone = 'valid' | 'warn' | 'crit' | 'neutral' | 'gold'

// ── Buttons ─────────────────────────────────────────────────────────────
type BtnVariant = 'default' | 'primary' | 'ghost' | 'danger' | 'danger-solid'
export function Btn({ variant = 'default', size = 'md', icon, busy, className, children, disabled, ...rest }: ComponentProps<'button'> & { variant?: BtnVariant; size?: 'sm' | 'md' | 'lg'; icon?: boolean; busy?: boolean }) {
  return (
    <button
      type="button"
      className={cn('ee-btn', variant !== 'default' && `ee-btn-${variant}`, size !== 'md' && `ee-btn-${size}`, icon && 'ee-btn-icon', className)}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy && <RefreshCw className="animate-spin" aria-hidden />}
      {children}
    </button>
  )
}

// ── Chips & tags ────────────────────────────────────────────────────────
export function Chip({ tone = 'neutral', icon, children, className, title }: { tone?: Tone; icon?: ReactNode; children: ReactNode; className?: string; title?: string }) {
  return <span className={cn('ee-chip', className)} data-tone={tone} title={title}>{icon}{children}</span>
}

export type CertStatus = 'active' | 'expiring' | 'expired' | 'revoked' | 'superseded'
const certMeta: Record<string, { tone: Tone; label: string; icon: ReactNode }> = {
  active: { tone: 'valid', label: 'Active', icon: <BadgeCheck aria-hidden /> },
  expiring: { tone: 'warn', label: 'Expiring', icon: <Clock aria-hidden /> },
  expired: { tone: 'crit', label: 'Expired', icon: <CalendarX aria-hidden /> },
  revoked: { tone: 'crit', label: 'Revoked', icon: <Ban aria-hidden /> },
  superseded: { tone: 'neutral', label: 'Renewed', icon: <RefreshCw aria-hidden /> },
}
export function CertChip({ status }: { status: string }) {
  const m = certMeta[status] ?? { tone: 'neutral' as Tone, label: status, icon: null }
  return <Chip tone={m.tone} icon={m.icon}>{m.label}</Chip>
}

export function OutcomeChip({ outcome, label }: { outcome: 'allow' | 'deny' | 'accept' | 'reject'; label?: string }) {
  const ok = outcome === 'allow' || outcome === 'accept'
  return ok
    ? <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>{label ?? (outcome === 'accept' ? 'Accepted' : 'Allowed')}</Chip>
    : <Chip tone="crit" icon={<ShieldX aria-hidden />}>{label ?? (outcome === 'reject' ? 'Rejected' : 'Denied')}</Chip>
}

/** "Can connect" separates policy (allowed) from reality: a valid certificate, and RADIUS enforcing the tenant right now
 * (`enforcement` is the tenant's status from the backend; a critical one means RADIUS denies everyone or can't answer). */
export function AccessStateChip({ status, enforceable = true, enforcement }: {
  status: 'can_connect' | 'allowed_no_certificate' | 'denied'; enforceable?: boolean; enforcement?: { state: string; tone: string; label: string; detail: string }
}) {
  if (status === 'denied') return <Chip tone="crit" icon={<ShieldX aria-hidden />}>Denied</Chip>
  if (enforcement?.state === 'suspended') return <Chip tone="neutral" icon={<CircleAlert aria-hidden />} title={enforcement.detail}>Tenant suspended</Chip>
  if (!enforceable) return <Chip tone="neutral" icon={<CircleAlert aria-hidden />} title="RADIUS isn’t enforcing this tenant yet">Not enforceable yet</Chip>
  if (enforcement?.tone === 'crit') return <Chip tone="crit" icon={<ShieldX aria-hidden />} title={`${enforcement.label}: ${enforcement.detail}`}>Can’t connect now</Chip>
  if (status === 'can_connect') return <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>Can connect</Chip>
  return <Chip tone="gold" icon={<BadgeCheck aria-hidden />} title="Allowed by policy, but no valid certificate">Allowed · no certificate</Chip>
}

export function SeverityChip({ severity }: { severity: 'critical' | 'warning' | 'info' }) {
  if (severity === 'critical') return <Chip tone="crit" icon={<CircleX aria-hidden />}>Critical</Chip>
  if (severity === 'warning') return <Chip tone="warn" icon={<TriangleAlert aria-hidden />}>Warning</Chip>
  return <Chip tone="neutral" icon={<Info aria-hidden />}>Info</Chip>
}
export const severityRisk = (s: 'critical' | 'warning' | 'info'): Tone => (s === 'critical' ? 'crit' : s === 'warning' ? 'warn' : 'neutral')

export function HealthDot({ tone, label }: { tone: Tone; label: string }) {
  const c = { valid: 'var(--ee-valid)', warn: 'var(--ee-warn)', crit: 'var(--ee-crit)', neutral: 'var(--ee-neutral)', gold: 'var(--ee-gold)' }[tone]
  const i = { valid: <CircleCheck aria-hidden />, warn: <TriangleAlert aria-hidden />, crit: <CircleX aria-hidden />, neutral: <CircleAlert aria-hidden />, gold: <Info aria-hidden /> }[tone]
  return <span className="inline-flex items-center gap-1.5 [&_svg]:size-4" style={{ color: c }}>{i}<span className="text-[var(--ee-ink)]">{label}</span></span>
}

// VLAN colours are stable per VLAN (stored on the VLAN), never by rank.
export const vlanVar = (color: string | null | undefined) => (color ? `var(--ee-vlan-${color})` : 'var(--ee-neutral)')
export const VLAN_COLORS = ['blue', 'violet', 'teal', 'orange', 'amber', 'green', 'rose', 'slate'] as const
export function VlanTag({ vlanId, name, color, className }: { vlanId: number | null | undefined; name?: string | null; color?: string | null; className?: string }) {
  if (vlanId === null || vlanId === undefined) return <span className="ee-ink-3">—</span>
  return (
    <span className={cn('inline-flex min-w-0 items-center gap-1.5 whitespace-nowrap', className)} title={name ? `VLAN ${vlanId} · ${name}` : `VLAN ${vlanId}`}>
      <span className="ee-swatch" style={{ background: vlanVar(color) }} aria-hidden />
      <span className="ee-num font-semibold">{vlanId}</span>
      {name && <span className="ee-ink-2 truncate">{name}</span>}
    </span>
  )
}

export function SourceTag({ source }: { source: string }) {
  return source === 'ad'
    ? <span className="ee-tag gap-1" title="Synchronised from Active Directory"><Building className="size-3" aria-hidden />AD</span>
    : <span className="ee-tag gap-1" title="Local account managed in EasyEAP"><UserRound className="size-3" aria-hidden />Local</span>
}

export function PlatformIcon({ platform, className }: { platform: string | null | undefined; className?: string }) {
  const c = cn('size-4 ee-ink-3', className)
  if (platform === 'ios') return <Smartphone className={c} aria-hidden />
  if (platform === 'android') return <Tablet className={c} aria-hidden />
  if (platform === 'macos' || platform === 'windows') return <Laptop className={c} aria-hidden />
  if (platform === 'linux') return <Monitor className={c} aria-hidden />
  return <ServerCog className={c} aria-hidden />
}
export const platformLabels: Record<string, string> = { windows: 'Windows', macos: 'macOS', ios: 'iPhone / iPad', android: 'Android', linux: 'Linux', other: 'Other' }

// ── Layout ──────────────────────────────────────────────────────────────
const riskAttr = (t?: Tone) => (t === 'valid' ? 'ok' : t === 'crit' ? 'crit' : t === 'warn' ? 'warn' : t)
export function Panel({ risk, className, children, as = 'section', ...rest }: { risk?: Tone; className?: string; children: ReactNode; as?: 'section' | 'div' | 'article' | 'aside' } & Omit<ComponentProps<'section'>, 'className' | 'children' | 'ref'>) {
  const As = as as 'section'
  return <As className={cn('ee-panel', className)} data-risk={riskAttr(risk)} {...rest}>{children}</As>
}

/** Page title. Receives focus on route change so screen-reader and keyboard users land at the top of the new page. */
export function PageHeader({ title, lede, actions, children }: { title: ReactNode; lede?: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null)
  useEffect(() => { if (document.activeElement === document.body || document.activeElement?.id === 'ee-main') ref.current?.focus({ preventScroll: true }) }, [])
  return (
    <header className="mb-7 flex flex-wrap items-end justify-between gap-x-6 gap-y-4">
      <div className="min-w-0">
        <h1 ref={ref} tabIndex={-1} className="ee-h1" data-page-heading>{title}</h1>
        {lede && <p className="ee-lede mt-1.5 max-w-[75ch]">{lede}</p>}
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
        <H id={id} className={level === 2 ? 'ee-h2' : 'ee-h3'}>{title}</H>
        {meta && <span className="ee-small ee-ink-3">{meta}</span>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Empty({ icon, title, children, action, className }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-start gap-2 rounded-[10px] border border-dashed border-[var(--ee-line-2)] px-5 py-6', className)}>
      {icon && <span className="ee-ink-3 [&_svg]:size-5">{icon}</span>}
      <p className="ee-h3">{title}</p>
      {children && <p className="ee-small ee-ink-2 max-w-[65ch]">{children}</p>}
      {action && <div className="mt-1.5">{action}</div>}
    </div>
  )
}

export function Callout({ tone = 'neutral', icon, title, children, action, className }: { tone?: Tone; icon?: ReactNode; title?: ReactNode; children?: ReactNode; action?: ReactNode; className?: string }) {
  const i = icon ?? { valid: <CircleCheck aria-hidden />, warn: <TriangleAlert aria-hidden />, crit: <CircleX aria-hidden />, gold: <Info aria-hidden />, neutral: <Info aria-hidden /> }[tone]
  return (
    <div className={cn('ee-callout', className)} data-tone={tone}>
      {i}
      <div className="min-w-0 flex-1">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className={cn('ee-ink-2', title && 'mt-0.5')}>{children}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}

export function Dl({ items, className, cols = 2 }: { items: Array<[ReactNode, ReactNode, ('wide' | false)?]>; className?: string; cols?: 1 | 2 | 3 }) {
  return (
    <dl className={cn('grid gap-x-6 gap-y-3', cols === 2 && 'sm:grid-cols-2', cols === 3 && 'sm:grid-cols-2 xl:grid-cols-3', className)}>
      {items.map(([k, v, wide], i) => (
        <div key={i} className={cn('min-w-0', wide && 'sm:col-span-full')}>
          <dt className="ee-label">{k}</dt>
          <dd className="mt-0.5 min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <span className={cn('ee-skeleton block h-4', className)} aria-hidden />
}

/** Loading placeholder for a whole panel/page section. */
export function LoadingBlock({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-label={label} className="space-y-3 py-2">
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className={i === 0 ? 'w-2/5' : i % 2 ? 'w-full' : 'w-4/5'} />)}
    </div>
  )
}

/** Error with a retry; the message is the API's own plain-language detail. */
export function ErrorState({ error, onRetry, title = 'This couldn’t be loaded' }: { error: unknown; onRetry?: () => void; title?: string }) {
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : 'Unknown error'
  const forbidden = error instanceof ApiError && error.status === 403
  return (
    <Callout tone={forbidden ? 'neutral' : 'crit'} title={forbidden ? 'You don’t have access to this' : title} action={!forbidden && onRetry ? <Btn size="sm" onClick={onRetry}><RefreshCw aria-hidden />Retry</Btn> : undefined}>
      {forbidden ? 'Your role doesn’t include this area. Ask a Tenant Administrator or the MSP owner for access.' : msg}
    </Callout>
  )
}

export const errorMessage = (e: unknown) => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : 'Something went wrong.')
/** Standard mutation error toast. */
export const toastError = (title: string) => (e: unknown) => toast(title, errorMessage(e), 'crit')

/** Fills a secret EasyEAP keeps into a configuration on screen (api/oneTime.ts useReveal). */
export function FillSecretButton({ what, busy, onClick }: { what: string; busy: boolean; onClick: () => void }) {
  return <Btn size="sm" variant="ghost" busy={busy} onClick={onClick}><KeyRound aria-hidden />Fill in the {what}</Btn>
}

// ── Inputs ──────────────────────────────────────────────────────────────
export function Seg<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: Array<{ value: T; label: ReactNode; count?: number }>; label: string }) {
  return (
    <ToggleGroup.Root type="single" value={value} onValueChange={(v) => v && onChange(v as T)} aria-label={label} className="ee-seg">
      {options.map((o) => (
        <ToggleGroup.Item key={o.value} value={o.value} className="ee-seg-item">
          {o.label}
          {o.count !== undefined && <span className="ee-count">{o.count}</span>}
        </ToggleGroup.Item>
      ))}
    </ToggleGroup.Root>
  )
}

export function ESelect({ value, onChange, options, label, className, placeholder, id, disabled }: { value: string; onChange: (v: string) => void; options: Array<{ value: string; label: ReactNode; disabled?: boolean }>; label: string; className?: string; placeholder?: string; id?: string; disabled?: boolean }) {
  return (
    <Select.Root value={value || undefined} onValueChange={onChange} disabled={disabled}>
      <Select.Trigger id={id} className={cn('ee-select-trigger', className)} aria-label={label}>
        <Select.Value placeholder={placeholder} />
        <Select.Icon><ChevronDown className="size-4 ee-ink-3" aria-hidden /></Select.Icon>
      </Select.Trigger>
      <Select.Portal>
        <Select.Content className="ee-menu max-h-[360px]" position="popper" sideOffset={4}>
          <Select.Viewport>
            {options.map((o) => (
              <Select.Item key={o.value} value={o.value} disabled={o.disabled} className="ee-menu-item justify-between">
                <Select.ItemText>{o.label}</Select.ItemText>
                <Select.ItemIndicator><Check className="size-4 text-[var(--ee-gold)]" aria-hidden /></Select.ItemIndicator>
              </Select.Item>
            ))}
          </Select.Viewport>
        </Select.Content>
      </Select.Portal>
    </Select.Root>
  )
}

export function ESwitch({ checked, onChange, label, disabled, id }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean; id?: string }) {
  return (
    <Switch.Root id={id} className="ee-switch" checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled}>
      <Switch.Thumb className="ee-switch-thumb" />
    </Switch.Root>
  )
}

export function Tip({ content, children, side = 'top' }: { content: ReactNode; children: ReactNode; side?: 'top' | 'bottom' | 'left' | 'right' }) {
  return (
    <Tooltip.Root delayDuration={250}>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content side={side} sideOffset={6} className="ee-tooltip">{content}</Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}

export function SortTh({ label, sortKey, table, right, className }: { label: string; sortKey: string; table: { toggleSort: (k: string) => void; ariaSort: (k: string) => 'ascending' | 'descending' | 'none' }; right?: boolean; className?: string }) {
  const s = table.ariaSort(sortKey)
  return (
    <th aria-sort={s} className={cn(right && 'ee-right', className)}>
      <button type="button" className="ee-sort" onClick={() => table.toggleSort(sortKey)}>
        {label}
        {s === 'ascending' ? <ArrowUp aria-hidden /> : s === 'descending' ? <ArrowDown aria-hidden /> : <ChevronsUpDown aria-hidden className="opacity-50" />}
      </button>
    </th>
  )
}

export async function copyText(text: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(text); return true } catch {
    // Fallback for non-secure contexts (plain-HTTP lab installs).
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
    } catch { return false }
  }
}

export function CopyButton({ text, label = 'Copy', what, size = 'sm', className, onCopied, variant }: { text: string; label?: string; what: string; size?: 'sm' | 'md'; className?: string; onCopied?: () => void; variant?: BtnVariant }) {
  const [done, setDone] = useState(false)
  return (
    <Btn
      size={size}
      variant={variant}
      className={className}
      aria-label={`${label} ${what}`}
      onClick={async () => {
        if (await copyText(text)) {
          setDone(true)
          onCopied?.()
          setTimeout(() => setDone(false), 1600)
        } else toast('Copy failed', 'Your browser blocked clipboard access. Select the text and copy it manually.', 'warn')
      }}
    >
      {done ? <Check aria-hidden /> : <Copy aria-hidden />}
      {done ? 'Copied' : label}
    </Btn>
  )
}

export function Field({ label, hint, error, children, htmlFor, optional }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode; htmlFor?: string; optional?: boolean }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-[13px] font-semibold">{label}{optional && <span className="ml-1.5 font-normal ee-ink-3">optional</span>}</label>
      {children}
      {error ? <p className="ee-field-error" role="alert">{error}</p> : hint ? <p className="ee-small ee-ink-3">{hint}</p> : null}
    </div>
  )
}

// ── Dialog ──────────────────────────────────────────────────────────────
/**
 * Modal dialog. On close, focus returns to `returnFocus` if given, else to the element focused when the dialog opened
 * (if it is still in the document), else to the page heading. `blockDismiss` disables Escape/overlay/close-button
 * dismissal (one-time secrets until acknowledged).
 */
export function EDialog({ open, onOpenChange, title, description, children, wide, risk, footer, returnFocus, blockDismiss }: {
  open: boolean
  onOpenChange: (o: boolean) => void
  title: ReactNode
  description?: ReactNode
  children: ReactNode
  wide?: boolean
  risk?: Tone
  footer?: ReactNode
  returnFocus?: RefObject<HTMLElement | null>
  blockDismiss?: boolean
}) {
  const opener = useRef<Element | null>(null)
  useEffect(() => { if (open) opener.current = document.activeElement }, [open])
  const block = (e: Event) => { if (blockDismiss) e.preventDefault() }
  return (
    <Dialog.Root open={open} onOpenChange={(o) => { if (!o && blockDismiss) return; onOpenChange(o) }}>
      <Dialog.Portal>
        <Dialog.Overlay className="ee-backdrop" />
        <Dialog.Content
          className={cn('ee-dialog', wide && 'ee-dialog-wide')}
          data-risk={riskAttr(risk)}
          onEscapeKeyDown={block}
          onPointerDownOutside={block}
          onInteractOutside={block}
          onCloseAutoFocus={(e) => {
            e.preventDefault()
            const target = returnFocus?.current ?? (opener.current instanceof HTMLElement && opener.current.isConnected ? opener.current : null)
            const fallback = document.querySelector<HTMLElement>('[data-page-heading]')
            ;(target ?? fallback)?.focus()
          }}
        >
          <div className="flex items-start justify-between gap-4 px-6 pt-5">
            <div className="min-w-0">
              <Dialog.Title className="ee-h2 text-[18px]">{title}</Dialog.Title>
              {description ? <Dialog.Description className="ee-small ee-ink-2 mt-1">{description}</Dialog.Description> : <Dialog.Description className="sr-only">{typeof title === 'string' ? title : 'Dialog'}</Dialog.Description>}
            </div>
            {!blockDismiss && (
              <Dialog.Close asChild>
                <Btn variant="ghost" size="sm" icon aria-label="Close"><X aria-hidden /></Btn>
              </Dialog.Close>
            )}
          </div>
          <div className="px-6 pb-5 pt-4">{children}</div>
          {footer && <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[var(--ee-line)] px-6 py-4">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/**
 * A one-time secret (RADIUS shared secret, enrollment link, root-key passphrase). The surrounding dialog should pass
 * `blockDismiss` until `acknowledged` is true: the user must copy it or tick the acknowledgement.
 */
export function OneTimeSecret({ value, what, acknowledged, onAcknowledge, note }: { value: string; what: string; acknowledged: boolean; onAcknowledge: (v: boolean) => void; note?: ReactNode }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-start gap-2">
        <code className="ee-secret min-w-0 flex-1" aria-label={what}>{value}</code>
        <CopyButton text={value} what={what} onCopied={() => onAcknowledge(true)} />
      </div>
      <Callout tone="warn">{note ?? <>EasyEAP shows this {what} once. It can’t be displayed again. If it’s lost, you’ll have to create a new one.</>}</Callout>
      <label className="flex items-center gap-2.5 text-[13px]">
        <input type="checkbox" className="ee-check" checked={acknowledged} onChange={(e) => onAcknowledge(e.target.checked)} />
        I’ve saved the {what} somewhere safe
      </label>
    </div>
  )
}

export function ConfirmText({ expected, value, onChange, label }: { expected: string; value: string; onChange: (v: string) => void; label: string }) {
  return (
    <Field label={label} htmlFor="ee-confirm" hint={<>Type <span className="ee-mono">{expected}</span> to confirm.</>}>
      <input id="ee-confirm" className="ee-input" autoComplete="off" spellCheck={false} value={value} onChange={(e) => onChange(e.target.value)} />
    </Field>
  )
}

