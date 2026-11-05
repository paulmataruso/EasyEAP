import { createContext, useContext, useEffect, useMemo, useRef, type ReactNode } from 'react'
import { useDecisions, useTenantData } from '@/prototype/store'
import { seedSummaries, summarize, type TenantSummary } from '../lib/portfolio'

const PortfolioContext = createContext<Map<string, TenantSummary>>(new Map())
export const usePortfolio = () => useContext(PortfolioContext)

/** Per-tenant summaries: seeded for every tenant, replaced by live store data once a tenant has been current. */
export function PortfolioProvider({ children }: { children: ReactNode }) {
  const d = useTenantData()
  const decisions = useDecisions()
  const cache = useRef(new Map<string, TenantSummary>())
  const live = useMemo(() => {
    const authorized = d.identities.filter((i) => decisions.get(i.id)?.outcome === 'allow').length
    return summarize(d, authorized)
  }, [d, decisions])
  useEffect(() => {
    cache.current.set(live.tenantId, live)
  }, [live])
  const value = useMemo(() => {
    const m = new Map(seedSummaries())
    // Tenants seen live this session keep their live numbers (e.g. a revocation made before switching).
    for (const [k, v] of cache.current) m.set(k, v)
    m.set(live.tenantId, live)
    return m
  }, [live])
  return <PortfolioContext.Provider value={value}>{children}</PortfolioContext.Provider>
}
