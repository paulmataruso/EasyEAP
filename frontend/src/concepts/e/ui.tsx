import { createContext, useCallback, useContext, useEffect, useId, useLayoutEffect, useRef, useState, type ComponentProps, type ReactNode } from 'react'
import { Select as RSelect, Switch as RSwitch, Toast, Tooltip as RTooltip, ToggleGroup } from 'radix-ui'
import { Check, ChevronDown, CircleCheck, CircleDashed, CircleX, Copy, OctagonX, TriangleExclamationPoint, X } from 'lucide-react'
import type { HealthState, Vlan } from '@/domain/types'
import type { ScreenId } from '../contract'
import { cn, copyText } from '@/ui/lib'
import { INK, LINE, LINE_FORM_LABEL, RAMP, REJECT, STATUS, formStyle, lineWidth, type LineForm } from './theme'

// ── Concept context ──────────────────────────────────────────────────────────
export type Intent =
  | { kind: 'users.filter'; access?: 'allow' | 'deny'; source?: 'ad' | 'local' }
  | { kind: 'certs.filter'; status: string }
  | { kind: 'issue' }
  | { kind: 'policies.test'; identityId?: string }
  | { kind: 'scroll'; target: string }

interface Ctx {
  navigate: (screen: ScreenId, entityId?: string) => void
  go: (screen: ScreenId, opts?: { entityId?: string; intent?: Intent }) => void
  container: HTMLElement | null
  toast: (t: { title: string; body?: string; tone?: 'ok' | 'warn' | 'crit' }) => void
  intent: Intent | null
  clearIntent: () => void
  openPalette: () => void
}
export const ConceptCtx = createContext<Ctx | null>(null)
export function useE() {
  const c = useContext(ConceptCtx)
  if (!c) throw new Error('Concept E context missing')
  return c
}

/** Runs `handler` once when a navigation intent of `kind` arrives (e.g. a menu item's filter preset). */
export function useIntent<K extends Intent['kind']>(kind: K, handler: (i: Extract<Intent, { kind: K }>) => void) {
  const { intent, clearIntent } = useE()
  const ref = useRef(handler)
  useLayoutEffect(() => { ref.current = handler })
  useEffect(() => {
    if (intent && intent.kind === kind) {
      ref.current(intent as Extract<Intent, { kind: K }>)
      clearIntent()
    }
  }, [intent, kind, clearIntent])
}

/** Scroll-to-section intents (from section menus) for the given ids. */
export function useScrollIntent() {
  useIntent('scroll', (i) => {
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const el = document.getElementById(i.target)
      el?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' })
      el?.querySelector<HTMLElement>('h2')?.focus?.()
    }))
  })
}

// ── Toasts ─────────────────────────────────────────────────────────────────
export interface ToastItem { id: number; title: string; body?: string; tone?: 'ok' | 'warn' | 'crit' }
export function useToasts() {
  const [items, setItems] = useState<ToastItem[]>([])
  const push = useCallback((t: Omit<ToastItem, 'id'>) => setItems((xs) => [...xs, { ...t, id: Date.now() + Math.random() }]), [])
  const remove = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), [])
  return { items, push, remove }
}
export function ToastLayer({ items, remove }: { items: ToastItem[]; remove: (id: number) => void }) {
  return (
    <>
      {items.map((t) => (
        <Toast.Root key={t.id} className="e-toast" duration={7000} onOpenChange={(o) => !o && remove(t.id)}>
          <span className="mt-0.5" aria-hidden>
            {t.tone === 'crit' ? <OctagonX size={17} color={STATUS.down.hex} /> : t.tone === 'warn' ? <TriangleExclamationPoint size={17} color={STATUS.degraded.hex} /> : <CircleCheck size={17} color={STATUS.ok.hex} />}
          </span>
          <div className="min-w-0 flex-1">
            <Toast.Title className="text-[13.5px] font-bold">{t.title}</Toast.Title>
            {t.body && <Toast.Description className="t2 mt-0.5 text-[13px]">{t.body}</Toast.Description>}
          </div>
          <Toast.Close className="e-btn e-btn-ghost e-btn-sm e-btn-icon -mr-1 -mt-1" aria-label="Dismiss notification"><X /></Toast.Close>
        </Toast.Root>
      ))}
      <Toast.Viewport className="e-toast-viewport" />
    </>
  )
}

// ── Buttons ────────────────────────────────────────────────────────────────
type BtnProps = ComponentProps<'button'> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'sm' | 'md'; icon?: boolean }
export function Button({ variant = 'secondary', size = 'md', icon, className, type = 'button', ...rest }: BtnProps) {
  return <button type={type} className={cn('e-btn', `e-btn-${variant}`, size === 'sm' && 'e-btn-sm', icon && 'e-btn-icon', className)} {...rest} />
}

export function CopyButton({ text, label = 'Copy', copiedLabel = 'Copied', size = 'sm', variant = 'secondary', className }: { text: string; label?: string; copiedLabel?: string; size?: 'sm' | 'md'; variant?: BtnProps['variant']; className?: string }) {
  const [done, setDone] = useState(false)
  return (
    <Button size={size} variant={variant} className={className} onClick={async () => { const ok = await copyText(text); setDone(ok); if (ok) setTimeout(() => setDone(false), 1800) }}>
      {done ? <Check /> : <Copy />}
      <span aria-live="polite">{done ? copiedLabel : label}</span>
    </Button>
  )
}

// ── Line bullets (VLAN identity on every screen) ─────────────────────────────
export function LineBullet({ vlan, size = 22, className }: { vlan: Vlan; size?: number; className?: string }) {
  const c = LINE[vlan.color]
  const digits = String(vlan.vlanId).length
  return (
    <span
      className={cn('inline-flex shrink-0 items-center justify-center rounded-full font-extrabold leading-none num', className)}
      style={{ background: c.hex, color: c.ink, minWidth: size, height: size, padding: digits > 3 ? '0 5px' : 0, fontSize: size * (digits > 2 ? 0.44 : 0.5), letterSpacing: '-0.02em' }}
      aria-hidden
    >
      {vlan.vlanId}
    </span>
  )
}
export function RejectBullet({ size = 22 }: { size?: number }) {
  return (
    <span className="inline-flex shrink-0 items-center justify-center rounded-full" style={{ background: REJECT.hex, color: REJECT.ink, width: size, height: size }} aria-hidden>
      <X size={size * 0.62} strokeWidth={3} />
    </span>
  )
}
/** VLAN bullet + name, the standard way a VLAN is referenced in text. */
export function VlanRef({ vlan, showName = true, size = 20, className }: { vlan: Vlan | undefined | null; showName?: boolean; size?: number; className?: string }) {
  if (!vlan) return <span className={cn('t3', className)}>No VLAN</span>
  return (
    <span className={cn('inline-flex min-w-0 items-center gap-2', className)}>
      <LineBullet vlan={vlan} size={size} />
      <span className="sr-only">VLAN {vlan.vlanId}</span>
      {showName && <span className="truncate">{vlan.name}</span>}
    </span>
  )
}

// ── Status (always icon + label) ─────────────────────────────────────────────
export function StatusIcon({ state, size = 15 }: { state: HealthState; size?: number }) {
  const color = STATUS[state].hex
  if (state === 'ok') return <CircleCheck size={size} color={color} aria-hidden />
  if (state === 'degraded') return <TriangleExclamationPoint size={size} color={color} aria-hidden />
  if (state === 'down') return <CircleX size={size} color={color} aria-hidden />
  return <CircleDashed size={size} color={color} aria-hidden />
}
export function StatusMark({ state, label, className }: { state: HealthState; label?: string; className?: string }) {
  return (
    <span className={cn('e-state', className)}>
      <StatusIcon state={state} />
      <span>{label ?? STATUS[state].label}</span>
    </span>
  )
}

/** Health bullet: a small roundel; state carried by form (solid / ring / dashed) as well as hue. */
export function HealthBullet({ letter, state, title }: { letter: string; state: HealthState; title: string }) {
  const c = STATUS[state].hex
  const solid = state === 'ok' || state === 'degraded' || state === 'down'
  return (
    <span
      title={`${title}: ${STATUS[state].label}`}
      className="inline-flex size-[18px] shrink-0 items-center justify-center rounded-full text-[9.5px] font-extrabold leading-none"
      style={solid ? { background: c, color: state === 'down' ? '#FFFFFF' : INK.ground } : { border: `1.5px dashed ${c}`, color: INK.text2 }}
      aria-hidden
    >
      {letter}
    </span>
  )
}
export function HealthBullets({ radius, pki, directory }: { radius: HealthState; pki: HealthState; directory: HealthState }) {
  return (
    <span className="inline-flex items-center gap-[3px]">
      <HealthBullet letter="R" state={radius} title="RADIUS" />
      <HealthBullet letter="P" state={pki} title="PKI" />
      <HealthBullet letter="D" state={directory} title="Directory" />
      <span className="sr-only">RADIUS {STATUS[radius].label}, PKI {STATUS[pki].label}, directory {STATUS[directory].label}</span>
    </span>
  )
}

// ── Line form + volume glyphs ────────────────────────────────────────────────
export function LineSample({ form, color = INK.station, width = 4, length = 34 }: { form: LineForm; color?: string; width?: number; length?: number }) {
  const s = formStyle(form, width)
  const h = 14
  return (
    <svg width={length} height={h} aria-hidden className="shrink-0">
      <line x1={2} x2={length - 2} y1={h / 2} y2={h / 2} stroke={color} strokeWidth={width} strokeLinecap="round" strokeDasharray={s.strokeDasharray} opacity={s.opacity} />
      {form === 'disabled' && [0.3, 0.5, 0.7].map((f) => <line key={f} x1={length * f - 3} x2={length * f + 3} y1={h - 1} y2={1} stroke={INK.station} strokeWidth={1.5} strokeLinecap="round" />)}
    </svg>
  )
}
export function VolumeGlyph({ count, color = INK.station, form, length = 40 }: { count: number; color?: string; form?: LineForm; length?: number }) {
  return <LineSample form={form ?? (count > 0 ? 'live' : 'idle')} color={color} width={lineWidth(count)} length={length} />
}
export function RampLegend({ className }: { className?: string }) {
  return (
    <div className={cn('flex flex-wrap items-center gap-x-4 gap-y-2 text-[12px] t2', className)}>
      <span className="font-semibold text-[var(--e-text)]">Line weight, 24h authentications</span>
      {RAMP.map((r) => (
        <span key={r.label} className="inline-flex items-center gap-1.5 num">
          <LineSample form="live" width={r.width} length={26} color={INK.text2} />
          {r.label}
        </span>
      ))}
    </div>
  )
}
export function FormLegend({ forms = ['live', 'idle', 'degraded', 'disabled'], className }: { forms?: LineForm[]; className?: string }) {
  return (
    <div className={cn('flex flex-wrap items-center gap-x-4 gap-y-2 text-[12px] t2', className)}>
      {forms.map((f) => (
        <span key={f} className="inline-flex items-center gap-1.5">
          <LineSample form={f} width={3.5} length={28} color={INK.text2} />
          {LINE_FORM_LABEL[f]}
        </span>
      ))}
    </div>
  )
}

// ── Layout bits ─────────────────────────────────────────────────────────────
export function Panel({ title, desc, actions, children, className, bodyClassName, id, headingLevel = 2 }: { title?: ReactNode; desc?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string; id?: string; headingLevel?: 2 | 3 }) {
  const H = headingLevel === 2 ? 'h2' : 'h3'
  return (
    <section className={cn('e-panel', className)} id={id} aria-labelledby={id ? `${id}-title` : undefined}>
      {(title || actions) && (
        <header className="e-panel-head">
          <div className="min-w-0 flex-[1_1_220px]">
            {title && <H className="e-panel-title" id={id ? `${id}-title` : undefined}>{title}</H>}
            {desc && <p className="e-panel-desc">{desc}</p>}
          </div>
          {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  )
}

export function PageHeader({ title, meta, actions }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3 pb-4 pt-6">
      <div className="min-w-0">
        <h1 className="text-[26px] font-bold leading-tight tracking-[-0.015em]">{title}</h1>
        {meta && <div className="t2 mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function EmptyState({ icon, title, body, action, className }: { icon?: ReactNode; title: string; body?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 px-6 py-10 text-center', className)}>
      {icon && <div className="t2 mb-1 [&_svg]:size-6">{icon}</div>}
      <p className="text-[14.5px] font-bold">{title}</p>
      {body && <p className="t2 max-w-[52ch] text-[13px]">{body}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export function Callout({ tone, icon, children, className }: { tone?: 'warn' | 'crit'; icon?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn('e-callout', className)} data-tone={tone}>
      {icon}
      <div className="min-w-0">{children}</div>
    </div>
  )
}

// ── Form controls ───────────────────────────────────────────────────────────
export function Field({ label, hint, error, children, htmlFor }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode; htmlFor: string }) {
  return (
    <div>
      <label htmlFor={htmlFor} className="e-label mb-1.5 block">{label}</label>
      {children}
      {error ? (
        <p className="e-field-error" id={`${htmlFor}-err`} role="alert"><CircleX size={14} className="mt-[1px] shrink-0" aria-hidden />{error}</p>
      ) : hint ? (
        <p className="e-field-hint" id={`${htmlFor}-hint`}>{hint}</p>
      ) : null}
    </div>
  )
}

export function Select<T extends string>({ value, onValueChange, options, label, placeholder, className, id }: { value: T; onValueChange: (v: T) => void; options: Array<{ value: T; label: string; icon?: ReactNode }>; label: string; placeholder?: string; className?: string; id?: string }) {
  const { container } = useE()
  return (
    <RSelect.Root value={value} onValueChange={(v) => onValueChange(v as T)}>
      <RSelect.Trigger className={cn('e-select-trigger', className)} aria-label={label} id={id}>
        <RSelect.Value placeholder={placeholder} />
        <RSelect.Icon><ChevronDown size={15} className="t2" /></RSelect.Icon>
      </RSelect.Trigger>
      <RSelect.Portal container={container}>
        <RSelect.Content className="e-menu" position="popper" sideOffset={6} style={{ minWidth: 'var(--radix-select-trigger-width)' }}>
          <RSelect.Viewport>
            {options.map((o) => (
              <RSelect.Item key={o.value} value={o.value} className="e-menu-item">
                {o.icon}
                <RSelect.ItemText>{o.label}</RSelect.ItemText>
                <RSelect.ItemIndicator className="ml-auto"><Check size={15} /></RSelect.ItemIndicator>
              </RSelect.Item>
            ))}
          </RSelect.Viewport>
        </RSelect.Content>
      </RSelect.Portal>
    </RSelect.Root>
  )
}

export function Switch({ checked, onCheckedChange, label, id, disabled }: { checked: boolean; onCheckedChange: (v: boolean) => void; label: string; id?: string; disabled?: boolean }) {
  return (
    <RSwitch.Root className="e-switch disabled:cursor-not-allowed disabled:opacity-50" checked={checked} onCheckedChange={onCheckedChange} aria-label={label} id={id} disabled={disabled}>
      <RSwitch.Thumb className="e-switch-thumb" />
    </RSwitch.Root>
  )
}

export function Segmented<T extends string>({ value, onValueChange, options, label, className }: { value: T; onValueChange: (v: T) => void; options: Array<{ value: T; label: ReactNode; ariaLabel?: string }>; label: string; className?: string }) {
  return (
    <ToggleGroup.Root type="single" value={value} onValueChange={(v) => v && onValueChange(v as T)} aria-label={label} className={cn('e-seg', className)}>
      {options.map((o) => (
        <ToggleGroup.Item key={o.value} value={o.value} className="e-seg-item" aria-label={o.ariaLabel}>
          {o.label}
        </ToggleGroup.Item>
      ))}
    </ToggleGroup.Root>
  )
}

export function Tip({ content, children, side = 'top' }: { content: ReactNode; children: ReactNode; side?: 'top' | 'bottom' | 'left' | 'right' }) {
  const { container } = useE()
  return (
    <RTooltip.Root delayDuration={250}>
      <RTooltip.Trigger asChild>{children}</RTooltip.Trigger>
      <RTooltip.Portal container={container}>
        <RTooltip.Content side={side} sideOffset={6} className="e-radix-tip">{content}</RTooltip.Content>
      </RTooltip.Portal>
    </RTooltip.Root>
  )
}

export function SearchInput({ value, onChange, placeholder, label, className }: { value: string; onChange: (v: string) => void; placeholder: string; label: string; className?: string }) {
  const id = useId()
  return (
    <div className={cn('relative', className)}>
      <label htmlFor={id} className="sr-only">{label}</label>
      <svg aria-hidden width="16" height="16" viewBox="0 0 24 24" className="t3 pointer-events-none absolute left-3 top-1/2 -translate-y-1/2" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
      <input id={id} type="search" className="e-input pl-9" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
    </div>
  )
}

/** Count chip for filter options: "Denied 4" */
export function CountChip({ n }: { n: number }) {
  return <span className="num ml-1 rounded-[5px] bg-[rgba(167,177,194,0.12)] px-1.5 text-[11.5px] font-semibold text-[var(--e-text-2)]">{n}</span>
}
