import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from 'react'
import { RadioGroup, Select, Switch } from 'radix-ui'
import { Check, ChevronDown, CircleAlert, Search } from 'lucide-react'
import { cn } from '@/ui/lib'
import { ConceptPortal } from './Portal'

/** Label + control + hint + error, wired with ids for assistive tech. */
export function Field({ label, hint, error, children, htmlFor }: { label: ReactNode; hint?: ReactNode; error?: string | null; children: ReactNode; htmlFor: string }) {
  return (
    <div className="c-field">
      <label className="c-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <p className="c-error" id={`${htmlFor}-error`} role="alert" style={{ margin: 0 }}>
          <CircleAlert size={14} aria-hidden="true" />
          {error}
        </p>
      ) : hint ? (
        <p className="c-hint" id={`${htmlFor}-hint`} style={{ margin: 0 }}>
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export const TextInput = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { mono?: boolean; invalid?: boolean; describedBy?: string }>(function TextInput(
  { mono, invalid, describedBy, className, ...rest },
  ref,
) {
  return <input ref={ref} className={cn('c-input', mono && 'is-mono', className)} aria-invalid={invalid || undefined} aria-describedby={describedBy} {...rest} />
})

export function SearchInput({ value, onChange, placeholder, label }: { value: string; onChange: (v: string) => void; placeholder: string; label: string }) {
  return (
    <div className="c-search">
      <Search size={16} aria-hidden="true" />
      <input className="c-input" type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={label} />
    </div>
  )
}

export interface Option {
  value: string
  label: string
  count?: number
  description?: string
}

/** Compact filter dropdown: "Access: Any". Shows an active outline when narrowed. */
export function FilterSelect({ label, value, onChange, options, allValue = 'all' }: { label: string; value: string; onChange: (v: string) => void; options: Option[]; allValue?: string }) {
  const current = options.find((o) => o.value === value)
  return (
    <Select.Root value={value} onValueChange={onChange}>
      <Select.Trigger className="c-select" aria-label={label} data-active={value !== allValue ? 'true' : undefined}>
        <span>
          <span className="c-select-prefix">{label}: </span>
          <Select.Value>{current?.label}</Select.Value>
        </span>
        <ChevronDown size={15} aria-hidden="true" />
      </Select.Trigger>
      <SelectContent options={options} />
    </Select.Root>
  )
}

/** Full-width select for forms. */
export function SelectInput({ id, value, onChange, options, placeholder, invalid }: { id: string; value: string; onChange: (v: string) => void; options: Option[]; placeholder?: string; invalid?: boolean }) {
  return (
    <Select.Root value={value || undefined} onValueChange={onChange}>
      <Select.Trigger id={id} className="c-select is-block" aria-invalid={invalid || undefined}>
        <Select.Value placeholder={placeholder} />
        <ChevronDown size={16} aria-hidden="true" />
      </Select.Trigger>
      <SelectContent options={options} />
    </Select.Root>
  )
}

function SelectContent({ options }: { options: Option[] }) {
  return (
    <Select.Portal>
      <ConceptPortal>
        <Select.Content className="c-pop" position="popper" sideOffset={6} style={{ minWidth: 'var(--radix-select-trigger-width)' }}>
          <Select.Viewport className="c-select-viewport">
            {options.map((o) => (
              <Select.Item key={o.value} value={o.value} className="c-option">
                <span style={{ display: 'grid' }}>
                  <Select.ItemText>{o.label}</Select.ItemText>
                  {o.description ? <span className="c-faint c-small">{o.description}</span> : null}
                </span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
                  {o.count !== undefined ? <span className="c-option-count">{o.count}</span> : null}
                  <span style={{ width: 16, display: 'inline-flex' }}>
                    <Select.ItemIndicator>
                      <Check size={16} strokeWidth={2.4} aria-hidden="true" />
                    </Select.ItemIndicator>
                  </span>
                </span>
              </Select.Item>
            ))}
          </Select.Viewport>
        </Select.Content>
      </ConceptPortal>
    </Select.Portal>
  )
}

/** Segmented control (a radio group). Used for source and status filters with live counts. */
export function Segmented({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: Option[] }) {
  return (
    <RadioGroup.Root className="c-seg" aria-label={label} value={value} onValueChange={onChange} orientation="horizontal">
      {options.map((o) => (
        <RadioGroup.Item key={o.value} value={o.value} className="c-seg-item">
          {o.label}
          {o.count !== undefined ? <span className="c-seg-count">{o.count}</span> : null}
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  )
}

/** Monochrome switch (accent stays reserved for primary actions). */
export function Toggle({ checked, onChange, label, id, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; id?: string; disabled?: boolean }) {
  return (
    <Switch.Root id={id} className="c-switch" checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled}>
      <Switch.Thumb className="c-switch-thumb" />
    </Switch.Root>
  )
}

export interface Choice {
  value: string
  title: ReactNode
  description?: ReactNode
  disabled?: boolean
}

/** Stacked radio rows with a title and an explanation, for decisions that need reasons. */
export function ChoiceList({ label, value, onChange, choices }: { label: string; value: string; onChange: (v: string) => void; choices: Choice[] }) {
  const id = useId()
  return (
    <RadioGroup.Root className="c-choices" aria-label={label} value={value} onValueChange={onChange}>
      {choices.map((c) => (
        <RadioGroup.Item key={c.value} value={c.value} className="c-choice" disabled={c.disabled} aria-describedby={c.description ? `${id}-${c.value}` : undefined}>
          <span className="c-choice-dot">
            <RadioGroup.Indicator asChild>
              <span />
            </RadioGroup.Indicator>
          </span>
          <span className="c-choice-title">{c.title}</span>
          {c.description ? (
            <span className="c-choice-desc" id={`${id}-${c.value}`}>
              {c.description}
            </span>
          ) : null}
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  )
}

/** Compact radio tiles (platforms, vendors). */
export function ChoiceGrid({ label, value, onChange, choices, invalid }: { label: string; value: string; onChange: (v: string) => void; choices: Array<{ value: string; label: string; icon?: ReactNode }>; invalid?: boolean }) {
  return (
    <RadioGroup.Root className="c-choice-grid" aria-label={label} value={value} onValueChange={onChange} aria-invalid={invalid || undefined}>
      {choices.map((c) => (
        <RadioGroup.Item key={c.value} value={c.value} className="c-chip-choice">
          {c.icon}
          {c.label}
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  )
}
