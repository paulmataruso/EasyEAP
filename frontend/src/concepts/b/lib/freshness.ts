/** Freshness of a telemetry value: fresh → aging → stale. "none" means there is no source to age. */
export type Freshness = 'fresh' | 'aging' | 'stale' | 'none'

export interface FreshnessBudget {
  /** Seconds after which the value is "aging" */
  warnAfter: number
  /** Seconds after which the value is "stale" and must not be trusted */
  staleAfter: number
}

export function classify(ageSeconds: number | null, budget: FreshnessBudget): Freshness {
  if (ageSeconds === null) return 'none'
  if (ageSeconds > budget.staleAfter) return 'stale'
  if (ageSeconds > budget.warnAfter) return 'aging'
  return 'fresh'
}

/** Remaining freshness 1 → 0 across the stale budget (drives the draining bar). */
export function remaining(ageSeconds: number | null, budget: FreshnessBudget): number {
  if (ageSeconds === null) return 0
  return Math.max(0, Math.min(1, 1 - ageSeconds / budget.staleAfter))
}

export const freshnessLabel: Record<Freshness, string> = { fresh: 'Fresh', aging: 'Aging', stale: 'Stale', none: 'No data' }

/** Directory sync runs every 15 minutes; an hour without one is worth a look, two is stale. */
export const DIRECTORY_BUDGET: FreshnessBudget = { warnAfter: 30 * 60, staleAfter: 2 * 3600 }
/** RADIUS fails safe at the tenant's max snapshot age; warn well before. */
export const snapshotBudget = (maxSeconds: number): FreshnessBudget => ({ warnAfter: Math.min(3600, maxSeconds / 4), staleAfter: maxSeconds })
/** A controller that has not sent a request in 15 minutes is suspicious, an hour is stale. */
export const CONTROLLER_BUDGET: FreshnessBudget = { warnAfter: 15 * 60, staleAfter: 3600 }
