import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/ui/lib'
import { Tip } from './Tip'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-solid'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: 'sm' | 'md'
  icon?: LucideIcon
  iconEnd?: LucideIcon
  children?: ReactNode
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon: Icon, iconEnd: IconEnd, className, children, type = 'button', ...rest },
  ref,
) {
  return (
    <button ref={ref} type={type} className={cn('b-btn', `b-btn-${variant}`, size === 'sm' && 'b-btn-sm', className)} {...rest}>
      {Icon && <Icon aria-hidden />}
      {children}
      {IconEnd && <IconEnd aria-hidden />}
    </button>
  )
})

export interface IconButtonProps extends Omit<ButtonProps, 'children' | 'icon'> {
  icon: LucideIcon
  /** Accessible name; also shown as the tooltip */
  label: string
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton({ icon: Icon, label, variant = 'ghost', size = 'sm', className, ...rest }, ref) {
  return (
    <Tip label={label}>
      <button ref={ref} type="button" aria-label={label} className={cn('b-btn b-btn-icon', `b-btn-${variant}`, size === 'sm' && 'b-btn-sm', className)} {...rest}>
        <Icon aria-hidden />
      </button>
    </Tip>
  )
})
