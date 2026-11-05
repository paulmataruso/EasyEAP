import { useId, type InputHTMLAttributes, type ReactNode } from 'react'
import { RadioGroup, Select, Switch } from 'radix-ui'
import { Check, ChevronDown, Search, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import { usePortalContainer } from './portal'

export interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  label: string
  hint?: ReactNode
  error?: string | null
  value: string
  onChange: (value: string) => void
  mono?: boolean
}

export function TextField({ label, hint, error, value, onChange, mono, className, id, ...rest }: TextFieldProps) {
  const auto = useId()
  const inputId = id ?? auto
  const hintId = `${inputId}-hint`
  const errId = `${inputId}-err`
  return (
    <div className={className}>
      <label htmlFor={inputId} className="a-label">
        {label}
      </label>
      <input
        id={inputId}
        className={cn('a-input', mono && 'a-mono')}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={cn(hint && hintId, error && errId) || undefined}
        {...rest}
      />
      {error ? (
        <p id={errId} className="a-error" role="alert">
          {error}
        </p>
      ) : (
        hint && (
          <p id={hintId} className="a-hint">
            {hint}
          </p>
        )
      )}
    </div>
  )
}

export function SearchInput({ value, onChange, placeholder, label, className }: { value: string; onChange: (v: string) => void; placeholder: string; label: string; className?: string }) {
  return (
    <div className={cn('relative', className)}>
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-[var(--a-text-3)]" aria-hidden />
      <input type="search" aria-label={label} className="a-input pr-8 pl-9 [&::-webkit-search-cancel-button]:hidden" placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
      {value && (
        <button type="button" aria-label="Clear search" className="a-icon-btn absolute top-1/2 right-1 !size-7 -translate-y-1/2" onClick={() => onChange('')}>
          <X aria-hidden />
        </button>
      )}
    </div>
  )
}

export interface SelectOption {
  value: string
  label: ReactNode
  /** Text shown in the trigger when this option is selected */
  short?: string
  disabled?: boolean
}

export function SelectField({
  label,
  hideLabel,
  value,
  onChange,
  options,
  placeholder,
  className,
  triggerClassName,
  hint,
  id,
}: {
  label: string
  hideLabel?: boolean
  value: string
  onChange: (v: string) => void
  options: SelectOption[]
  placeholder?: string
  className?: string
  triggerClassName?: string
  hint?: ReactNode
  id?: string
}) {
  const auto = useId()
  const triggerId = id ?? auto
  const container = usePortalContainer()
  return (
    <div className={className}>
      {!hideLabel && (
        <label htmlFor={triggerId} className="a-label">
          {label}
        </label>
      )}
      <Select.Root value={value} onValueChange={onChange}>
        <Select.Trigger id={triggerId} aria-label={hideLabel ? label : undefined} className={cn('a-select-trigger', triggerClassName)}>
          <Select.Value placeholder={placeholder} />
          <Select.Icon>
            <ChevronDown aria-hidden />
          </Select.Icon>
        </Select.Trigger>
        <Select.Portal container={container}>
          <Select.Content position="popper" sideOffset={6} className="a-menu a-overlay-glass max-h-[min(360px,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)]">
            <Select.Viewport>
              {options.map((o) => (
                <Select.Item key={o.value} value={o.value} disabled={o.disabled} className="a-menu-item pr-8 relative">
                  <Select.ItemText>{o.short ?? o.label}</Select.ItemText>
                  {o.short && <span className="sr-only">{o.label}</span>}
                  <Select.ItemIndicator className="absolute right-2.5 inline-flex">
                    <Check className="text-[var(--a-accent-hover)]" aria-hidden />
                  </Select.ItemIndicator>
                </Select.Item>
              ))}
            </Select.Viewport>
          </Select.Content>
        </Select.Portal>
      </Select.Root>
      {hint && <p className="a-hint">{hint}</p>}
    </div>
  )
}

export function Toggle({ checked, onChange, label, id, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; id?: string; disabled?: boolean }) {
  return (
    <Switch.Root id={id} checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled} className="a-switch disabled:cursor-not-allowed disabled:opacity-50">
      <Switch.Thumb className="a-switch-thumb" />
    </Switch.Root>
  )
}

export function SwitchRow({ label, description, checked, onChange }: { label: string; description?: ReactNode; checked: boolean; onChange: (v: boolean) => void }) {
  const id = useId()
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <label htmlFor={id} className="text-[14px] font-medium text-[var(--a-text)]">
          {label}
        </label>
        {description && <p className="mt-0.5 text-[12px] text-[var(--a-text-3)]">{description}</p>}
      </div>
      <Switch.Root id={id} checked={checked} onCheckedChange={onChange} className="a-switch mt-0.5">
        <Switch.Thumb className="a-switch-thumb" />
      </Switch.Root>
    </div>
  )
}

export function Segmented<T extends string>({ value, onChange, options, label, className }: { value: T; onChange: (v: T) => void; options: Array<{ value: T; label: ReactNode; count?: number }>; label: string; className?: string }) {
  return (
    <RadioGroup.Root value={value} onValueChange={(v) => onChange(v as T)} aria-label={label} orientation="horizontal" className={cn('a-segment', className)}>
      {options.map((o) => (
        <RadioGroup.Item key={o.value} value={o.value} className="a-segment-item">
          {o.label}
          {o.count !== undefined && <span className="a-segment-count">{o.count}</span>}
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  )
}

/** Radio choice cards (used for platform and key-generation choices). */
export function ChoiceGroup<T extends string>({ value, onChange, options, label, className }: { value: T; onChange: (v: T) => void; options: Array<{ value: T; title: ReactNode; description?: ReactNode; aside?: ReactNode; disabled?: boolean }>; label: string; className?: string }) {
  return (
    <RadioGroup.Root value={value} onValueChange={(v) => onChange(v as T)} aria-label={label} className={cn('grid gap-2', className)}>
      {options.map((o) => (
        <RadioGroup.Item key={o.value} value={o.value} disabled={o.disabled} className="a-choice disabled:cursor-not-allowed disabled:opacity-50">
          <span className="a-radio-dot" aria-hidden />
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-2 text-[14px] font-semibold text-[var(--a-text)]">
              {o.title}
              {o.aside}
            </span>
            {o.description && <span className="mt-0.5 block text-[13px] leading-snug text-[var(--a-text-3)]">{o.description}</span>}
          </span>
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  )
}
