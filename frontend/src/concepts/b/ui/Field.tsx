import { useId, type InputHTMLAttributes, type ReactNode } from 'react'
import { Select, Switch } from 'radix-ui'
import { Check, ChevronDown, CircleAlert } from 'lucide-react'
import { cn } from '@/ui/lib'
import { usePortal } from './portal'

/** Label + control + hint/error, wired with ids for assistive tech. */
export function Field({ label, hint, error, children, className, htmlFor }: { label: ReactNode; hint?: ReactNode; error?: string | null; children: ReactNode; className?: string; htmlFor?: string }) {
  return (
    <div className={className}>
      <label className="b-field-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <p className="b-field-error" id={htmlFor ? `${htmlFor}-err` : undefined}>
          <CircleAlert className="mt-px size-3.5 shrink-0" aria-hidden />
          {error}
        </p>
      ) : hint ? (
        <p className="b-field-hint" id={htmlFor ? `${htmlFor}-hint` : undefined}>
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export function TextField({ label, hint, error, className, inputClassName, ...rest }: { label: ReactNode; hint?: ReactNode; error?: string | null; inputClassName?: string } & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId()
  return (
    <Field label={label} hint={hint} error={error} className={className} htmlFor={id}>
      <input id={id} className={cn('b-input', inputClassName)} aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-err` : hint ? `${id}-hint` : undefined} {...rest} />
    </Field>
  )
}

export interface Option {
  value: string
  label: string
  hint?: string
}

/** Radix Select styled for the console. */
export function SelectBox({ value, onChange, options, placeholder, ariaLabel, id, size = 'md', className, disabled }: { value: string; onChange: (v: string) => void; options: Option[]; placeholder?: string; ariaLabel?: string; id?: string; size?: 'sm' | 'md'; className?: string; disabled?: boolean }) {
  const container = usePortal()
  return (
    <Select.Root value={value || undefined} onValueChange={onChange} disabled={disabled}>
      <Select.Trigger id={id} aria-label={ariaLabel} className={cn('b-input b-select-trigger', size === 'sm' && 'b-input-sm', className)}>
        <span className="truncate">
          <Select.Value placeholder={placeholder} />
        </span>
        <Select.Icon asChild>
          <ChevronDown aria-hidden />
        </Select.Icon>
      </Select.Trigger>
      <Select.Portal container={container}>
        <Select.Content position="popper" sideOffset={4} className="b-pop max-h-[min(360px,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)] overflow-hidden p-1">
          <Select.Viewport>
            {options.map((o) => (
              <Select.Item key={o.value} value={o.value} className="b-menu-item pr-7">
                <Select.ItemText>{o.label}</Select.ItemText>
                {o.hint && <span className="b-t3 ml-auto pl-3 text-[12px]">{o.hint}</span>}
                <Select.ItemIndicator className="absolute right-2 inline-flex">
                  <Check className="size-3.5 text-[var(--b-cyan)]" aria-hidden />
                </Select.ItemIndicator>
              </Select.Item>
            ))}
          </Select.Viewport>
        </Select.Content>
      </Select.Portal>
    </Select.Root>
  )
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <Switch.Root checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled} className="b-switch disabled:opacity-50">
      <Switch.Thumb className="b-switch-thumb" />
    </Switch.Root>
  )
}

/** Segmented filter: one choice from a short list, each with an optional count. */
export function Segmented<T extends string>({ value, onChange, options, label, className }: { value: T; onChange: (v: T) => void; options: Array<{ value: T; label: ReactNode; count?: number }>; label: string; className?: string }) {
  return (
    <div className={cn('b-seg', className)} role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
          {o.count !== undefined && <span className="b-seg-count">{o.count}</span>}
        </button>
      ))}
    </div>
  )
}
