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

/** A secret EasyEAP keeps (a shared secret, a TACACS+ key, SNMP credentials), fetched only when the admin asks
 * (each fetch is in the audit log) and held only in the calling component's state, to fill a configuration. */
export function useReveal<R>(fn: () => Promise<R>) {
  const [value, setValue] = useState<R | null>(null)
  // Another device or switch (fn changes with its id): never show the previous one's secret in its configuration.
  useEffect(() => { setValue(null) }, [fn])
  const call = useOneTimeCall<void, R>(fn)
  const reveal = (onError?: (e: unknown) => void) => call.mutate(undefined, { onSuccess: setValue, onError })
  return { value, reveal, busy: call.isPending, clear: () => setValue(null) }
}
