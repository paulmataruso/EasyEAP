import { useEffect, useState } from 'react'

/** Current time, re-rendering every `everyMs` so relative times ("3 minutes ago", "in 2 hours") stay true. */
export function useNow(everyMs = 30_000): Date {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), everyMs)
    return () => clearInterval(id)
  }, [everyMs])
  return now
}
