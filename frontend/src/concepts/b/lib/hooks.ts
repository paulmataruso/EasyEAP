import { useEffect, useState, type RefObject } from 'react'

/** Tracks an element's content width (charts render to the real width). */
export function useElementWidth(ref: RefObject<HTMLElement | null>, fallback = 480): number {
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const update = () => setWidth(Math.max(0, Math.floor(el.getBoundingClientRect().width)))
    update()
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return width
}

const query = '(prefers-reduced-motion: reduce)'
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => typeof window !== 'undefined' && window.matchMedia(query).matches)
  useEffect(() => {
    const mq = window.matchMedia(query)
    const on = () => setReduced(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [])
  return reduced
}

/** True while the document is visible: hidden tabs stop doing live work. */
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(() => typeof document === 'undefined' || document.visibilityState === 'visible')
  useEffect(() => {
    const on = () => setVisible(document.visibilityState === 'visible')
    document.addEventListener('visibilitychange', on)
    return () => document.removeEventListener('visibilitychange', on)
  }, [])
  return visible
}

/** Read/write a small per-viewer preference in localStorage; failures fall back to memory. */
export function useStoredState<T>(key: string, initial: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = window.localStorage.getItem(key)
      return raw ? (JSON.parse(raw) as T) : initial
    } catch {
      return initial
    }
  })
  const set = (v: T) => {
    setValue(v)
    try {
      window.localStorage.setItem(key, JSON.stringify(v))
    } catch {
      /* storage unavailable: keep the in-memory value */
    }
  }
  return [value, set]
}

/**
 * True when `inner` is wider than `outer`. Tables use it to pick between a page-sticky header
 * (fits the panel) and a horizontally scrolling body with a sticky first column (too wide).
 */
export function useOverflowX(outer: RefObject<HTMLElement | null>, inner: RefObject<HTMLElement | null>): boolean {
  const [overflow, setOverflow] = useState(false)
  useEffect(() => {
    const o = outer.current
    const i = inner.current
    if (!o || !i) return
    const update = () => setOverflow(i.offsetWidth > o.clientWidth + 1)
    update()
    const ro = new ResizeObserver(update)
    ro.observe(o)
    ro.observe(i)
    return () => ro.disconnect()
  }, [outer, inner])
  return overflow
}
