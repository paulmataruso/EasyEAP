import { Check, ChevronDown, CircleAlert, Copy, Search } from 'lucide-react'
import { RadioGroup, Select, Switch, Tooltip } from 'radix-ui'
import { useId, useState, type ReactNode } from 'react'
import { cn, copyText } from '@/ui/lib'
import { usePortal } from '../model/state'
import { useToast } from './Toast'

export interface Option<V extends string = string> { value: V; label: string; prefix?: ReactNode }

/** Labelled Radix select. `label` is visible unless `hideLabel`, then it becomes the accessible name. */
export function SelectField<V extends string>({ label, hideLabel, value, onChange, options, className, prefix, width }: {
  label: string
  hideLabel?: boolean
  value: V
  onChange: (v: V) => void
  options: Option<V>[]
  className?: string
  prefix?: string
  width?: number
}) {
  const portal = usePortal()
  const id = useId()
  const current = options.find((o) => o.value === value)
  return (
    <div className={cn('d-field', className)}>
      {!hideLabel && <label className="d-field-label" htmlFor={id}>{label}</label>}
      <Select.Root value={value} onValueChange={(v) => onChange(v as V)}>
        <Select.Trigger id={id} className="d-select-trigger" aria-label={hideLabel ? label : undefined} style={width ? { minWidth: width } : undefined}>
          <span className="inline-flex items-center gap-2 truncate">
            {prefix && <span className="d-select-prefix">{prefix}</span>}
            {current?.prefix}
            <Select.Value>{current?.label}</Select.Value>
          </span>
          <Select.Icon asChild><ChevronDown aria-hidden="true" /></Select.Icon>
        </Select.Trigger>
        <Select.Portal container={portal}>
          <Select.Content className="d-menu" position="popper" sideOffset={4}>
            <Select.Viewport>
              {options.map((o) => (
                <Select.Item key={o.value} value={o.value} className="d-menu-item">
                  {o.prefix}
                  <Select.ItemText>{o.label}</Select.ItemText>
                  <Select.ItemIndicator asChild><Check className="d-menu-check" aria-hidden="true" /></Select.ItemIndicator>
                </Select.Item>
              ))}
            </Select.Viewport>
          </Select.Content>
        </Select.Portal>
      </Select.Root>
    </div>
  )
}

export function SearchInput({ value, onChange, placeholder, label, className }: { value: string; onChange: (v: string) => void; placeholder: string; label: string; className?: string }) {
  return (
    <div className={cn('d-search', className)}>
      <Search aria-hidden="true" />
      <input type="search" className="d-input" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={label} />
    </div>
  )
}

/** Segmented control (single choice) built on RadioGroup so arrow keys move the choice. */
export function Segmented<V extends string>({ label, value, onChange, options }: { label: string; value: V; onChange: (v: V) => void; options: Option<V>[] }) {
  return (
    <RadioGroup.Root className="d-seg" aria-label={label} value={value} onValueChange={(v) => onChange(v as V)} orientation="horizontal">
      {options.map((o) => (
        <RadioGroup.Item key={o.value} value={o.value} className="d-seg-item">
          {o.prefix}
          {o.label}
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  )
}

export function Toggle({ checked, onChange, label, id }: { checked: boolean; onChange: (v: boolean) => void; label: string; id?: string }) {
  return (
    <Switch.Root id={id} className="d-switch" checked={checked} onCheckedChange={onChange} aria-label={label}>
      <Switch.Thumb className="d-switch-thumb" />
    </Switch.Root>
  )
}

export function TextField({ label, hint, error, value, onChange, placeholder, mono, id: idProp, inputMode, autoFocus }: {
  label: string
  hint?: ReactNode
  error?: string | null
  value: string
  onChange: (v: string) => void
  placeholder?: string
  mono?: boolean
  id?: string
  inputMode?: 'text' | 'numeric' | 'decimal'
  autoFocus?: boolean
}) {
  const gen = useId()
  const id = idProp ?? gen
  const hintId = `${id}-hint`
  const errId = `${id}-err`
  return (
    <div className="d-field">
      <label className="d-field-label" htmlFor={id}>{label}</label>
      <input
        id={id}
        className={cn('d-input', mono && 'mono')}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-invalid={error ? true : undefined}
        aria-describedby={[hint ? hintId : '', error ? errId : ''].filter(Boolean).join(' ') || undefined}
        inputMode={inputMode}
        autoFocus={autoFocus}
        spellCheck={false}
        autoComplete="off"
      />
      {error ? (
        <p id={errId} className="d-field-error"><CircleAlert aria-hidden="true" />{error}</p>
      ) : hint ? (
        <p id={hintId} className="d-field-hint">{hint}</p>
      ) : null}
    </div>
  )
}

export function CopyButton({ text, label = 'Copy', what, small, iconOnly }: { text: string; label?: string; what: string; small?: boolean; iconOnly?: boolean }) {
  const toast = useToast()
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      className={cn('d-btn', small && 'd-btn--sm', iconOnly && 'd-btn--icon')}
      aria-label={iconOnly ? `Copy ${what}` : undefined}
      onClick={async () => {
        const ok = await copyText(text)
        setDone(true)
        window.setTimeout(() => setDone(false), 1600)
        toast(ok ? { title: `Copied ${what}` } : { title: `Couldn’t copy ${what}`, description: 'Your browser blocked clipboard access. Select the text and copy it manually.' })
      }}
    >
      {done ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      {!iconOnly && (done ? 'Copied' : label)}
    </button>
  )
}

export function Tip({ content, children }: { content: ReactNode; children: ReactNode }) {
  const portal = usePortal()
  return (
    <Tooltip.Root delayDuration={250}>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal container={portal}>
        <Tooltip.Content className="d-tooltip" sideOffset={6}>{content}</Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}
