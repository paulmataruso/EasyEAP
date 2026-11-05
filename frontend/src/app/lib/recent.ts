// "Recently viewed" per tenant: a per-browser convenience in localStorage (may be unavailable; never required).
import { useSyncExternalStore } from 'react'

export interface RecentItem { kind: 'identity' | 'certificate' | 'controller'; id: string; label: string; sub: string }

const KEY = 'easyeap.recent.v1'
const listeners = new Set<() => void>()
let cache: Record<string, RecentItem[]> | null = null

function load(): Record<string, RecentItem[]> {
  if (cache) return cache
  try { cache = JSON.parse(localStorage.getItem(KEY) ?? '{}') ?? {} } catch { cache = {} }
  return cache!
}

export function pushRecent(tid: string, item: RecentItem) {
  const all = { ...load() }
  all[tid] = [item, ...(all[tid] ?? []).filter((r) => !(r.kind === item.kind && r.id === item.id))].slice(0, 8)
  cache = all
  try { localStorage.setItem(KEY, JSON.stringify(all)) } catch { /* storage blocked */ }
  listeners.forEach((l) => l())
}

export function useRecent(tid: string): RecentItem[] {
  const all = useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l) }, load)
  return all[tid] ?? []
}
