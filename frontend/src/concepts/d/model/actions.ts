import { useMemo } from 'react'
import { useActions } from '@/prototype/store'
import { markSessionWrite } from './derive'

/** Store actions, wrapped so session-time stamps they create read as "Just now". */
export function useConceptActions() {
  const a = useActions()
  return useMemo(() => {
    const wrap = <A extends unknown[]>(fn: (...args: A) => void) => (...args: A) => { markSessionWrite(); fn(...args) }
    return {
      revokeCertificate: wrap(a.revokeCertificate),
      moveRule: wrap(a.moveRule),
      toggleRule: wrap(a.toggleRule),
      addRadiusClient: wrap(a.addRadiusClient),
      rotateSecret: wrap(a.rotateSecret),
    }
  }, [a])
}
