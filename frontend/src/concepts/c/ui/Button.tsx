import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { cn } from '@/ui/lib'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-solid'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: 'md' | 'sm'
  icon?: ReactNode
  iconEnd?: ReactNode
}

/** The concept's only button. Primary (champagne) is reserved for the one main action on a view. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon, iconEnd, className, children, type = 'button', ...rest },
  ref,
) {
  return (
    <button ref={ref} type={type} className={cn('c-btn', `is-${variant}`, size === 'sm' && 'is-sm', className)} {...rest}>
      {icon}
      {children}
      {iconEnd}
    </button>
  )
})

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string
}

/** Square icon-only button; `label` becomes the accessible name. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton({ label, className, children, type = 'button', ...rest }, ref) {
  return (
    <button ref={ref} type={type} aria-label={label} title={label} className={cn('c-iconbtn', className)} {...rest}>
      {children}
    </button>
  )
})

/** Inline text action that reads as a link (underlined, ivory). */
export function TextAction({ children, className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" className={cn('c-link', className)} {...rest}>
      {children}
    </button>
  )
}
