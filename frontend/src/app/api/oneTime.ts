// Calls whose request or response carries a one-time secret (RADIUS shared secrets, the root-key ceremony and its
// passphrase). react-query's mutation cache would keep both the variables and the result in memory after the dialog
// closes, so these run outside it: the secret lives only in the calling component's state.
import { useCallback, useEffect, useRef, useState } from 'react'

export interface OneTimeCallbacks<R> { onSuccess?: (result: R) => void; onError?: (error: unknown) => void }

export function useOneTimeCall<A, R>(fn: (arg: A) => Promise<R>, afterSuccess?: () => unknown) {
  const [isPending, setPending] = useState(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const mutate = useCallback((arg: A, cb?: OneTimeCallbacks<R>) => {
    setPending(true)
    fn(arg).then(
      (r) => { void afterSuccess?.(); if (alive.current) cb?.onSuccess?.(r) },
      (e: unknown) => { if (alive.current) cb?.onError?.(e) },
    ).finally(() => { if (alive.current) setPending(false) })
  }, [fn, afterSuccess])
  return { mutate, isPending }
}
