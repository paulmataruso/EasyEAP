import { Laptop, Monitor, Smartphone, SquareTerminal, TabletSmartphone } from 'lucide-react'
import type { Platform } from '@/domain/types'
import { cn } from '@/ui/lib'

const icons = { windows: Monitor, macos: Laptop, ios: TabletSmartphone, android: Smartphone, linux: SquareTerminal } as const

export function PlatformIcon({ platform, className }: { platform: Platform; className?: string }) {
  const Icon = icons[platform]
  return <Icon className={cn('size-3.5 shrink-0', className)} aria-hidden />
}
