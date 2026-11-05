import { Laptop, Monitor, ScanBarcode, Smartphone, type LucideIcon } from 'lucide-react'
import type { Device, Platform } from '@/domain/types'
import { platformLabels } from '@/domain/explain'

const platformIcon: Record<Platform, LucideIcon> = { windows: Laptop, macos: Laptop, ios: Smartphone, android: Smartphone, linux: Monitor }

export function iconForDevice(device: Pick<Device, 'platform' | 'name'>): LucideIcon {
  if (/scanner/i.test(device.name)) return ScanBarcode
  return platformIcon[device.platform]
}

export function iconForPlatform(platform: Platform): LucideIcon {
  return platformIcon[platform]
}

export const PLATFORMS: Platform[] = ['windows', 'macos', 'ios', 'android', 'linux']

export function platformLabel(p: Platform) {
  return platformLabels[p]
}
