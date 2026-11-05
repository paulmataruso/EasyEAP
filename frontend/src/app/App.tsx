import { lazy, Suspense, type ReactNode } from 'react'
import { HashRouter, Navigate, Outlet, Route, Routes, useLocation, useMatch, useParams } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Tooltip } from 'radix-ui'
import { ApiError } from './api/client'
import { SessionProvider, useSession } from './api/session'
import { TenantProvider, useTenantQuery } from './api/tenant'
import { paths } from './routes'
import { Shell } from './shell/Shell'
import { Empty, ErrorState, LoadingBlock, Toaster } from './ui'
import { FirstRun } from './screens/FirstRun'
import { Login } from './screens/Login'

const Dashboard = lazy(() => import('./screens/Dashboard'))
const Tenants = lazy(() => import('./screens/Tenants'))
const NewTenant = lazy(() => import('./screens/NewTenant'))
const System = lazy(() => import('./screens/System'))
const Events = lazy(() => import('./screens/Events'))
const Users = lazy(() => import('./screens/Users'))
const UserDetail = lazy(() => import('./screens/UserDetail'))
const Certificates = lazy(() => import('./screens/Certificates'))
const CertificateDetail = lazy(() => import('./screens/CertificateDetail'))
const Policy = lazy(() => import('./screens/Policy'))
const Directory = lazy(() => import('./screens/Directory'))
const Audit = lazy(() => import('./screens/Audit'))
const Admins = lazy(() => import('./screens/Admins'))
const Radius = lazy(() => import('./screens/Radius'))
const Pki = lazy(() => import('./screens/Pki'))
const TenantSetup = lazy(() => import('./screens/TenantSetup'))
const TenantSettings = lazy(() => import('./screens/TenantSettings'))
const Account = lazy(() => import('./screens/Account'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (n, e) => !(e instanceof ApiError && [401, 403, 404].includes(e.status)) && n < 2,
      refetchOnWindowFocus: true,
      staleTime: 15_000,
    },
  },
})

function Loading() {
  return <div className="px-2 py-8"><LoadingBlock rows={5} /></div>
}

/** Signed-in area. Sends first-run installs to setup and signed-out visitors to the sign-in page. */
function RequireSession() {
  const { me, loading, needsSetup } = useSession()
  const location = useLocation()
  if (loading || needsSetup === null) return <Loading />
  if (needsSetup) return <Navigate to={paths.firstRun()} replace />
  if (!me) return <Navigate to={paths.login()} replace state={{ from: location.pathname + location.search }} />
  return <TenantScope><Shell><Suspense fallback={<Loading />}><Outlet /></Suspense></Shell></TenantScope>
}

/** Provides the tenant to the shell (sidebar scope, search, palette) and to every /t/:tid screen. */
function TenantScope({ children }: { children: ReactNode }) {
  const match = useMatch('/t/:tid/*')
  const q = useTenantQuery(match?.params.tid)
  return match && q.data ? <TenantProvider tenant={q.data}>{children}</TenantProvider> : <>{children}</>
}

function TenantRoute() {
  const { tid } = useParams()
  const q = useTenantQuery(tid)
  if (q.isLoading) return <Loading />
  if (q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) return <Empty title="Tenant not found">It may have been deleted, or the link is wrong.</Empty>
    return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  }
  return <Suspense fallback={<Loading />}><Outlet /></Suspense>
}

function Home() {
  const { me, isPlatform } = useSession()
  if (isPlatform) return <Navigate to={paths.tenants()} replace />
  const first = me?.grants[0]
  if (first) return <Navigate to={paths.dashboard(first.tenant_id)} replace />
  return <Empty title="No tenants assigned">Your account doesn’t have access to any tenant yet. Ask the MSP owner to grant you a role.</Empty>
}

function PublicOnly({ children }: { children: ReactNode }) {
  const { me, loading, needsSetup } = useSession()
  if (loading || needsSetup === null) return <Loading />
  if (needsSetup) return <Navigate to={paths.firstRun()} replace />
  if (me) return <Navigate to="/" replace />
  return <>{children}</>
}

function FirstRunOnly() {
  const { needsSetup, loading } = useSession()
  if (loading || needsSetup === null) return <Loading />
  return needsSetup ? <FirstRun /> : <Navigate to="/" replace />
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SessionProvider>
        <Tooltip.Provider delayDuration={250}>
          <HashRouter>
            <Routes>
              <Route path="/login" element={<PublicOnly><Login /></PublicOnly>} />
              <Route path="/first-run" element={<FirstRunOnly />} />
              <Route element={<RequireSession />}>
                <Route index element={<Home />} />
                <Route path="tenants" element={<Tenants />} />
                <Route path="tenants/new" element={<NewTenant />} />
                <Route path="admins" element={<Admins />} />
                <Route path="audit" element={<Audit scope="platform" />} />
                <Route path="system" element={<System />} />
                <Route path="account" element={<Account />} />
                <Route path="t/:tid" element={<TenantRoute />}>
                  <Route index element={<Navigate to="dashboard" replace />} />
                  <Route path="dashboard" element={<Dashboard />} />
                  <Route path="users" element={<Users />} />
                  <Route path="users/:id" element={<UserDetail />} />
                  <Route path="certificates" element={<Certificates />} />
                  <Route path="certificates/:id" element={<CertificateDetail />} />
                  <Route path="events" element={<Events />} />
                  <Route path="policy" element={<Policy />} />
                  <Route path="radius" element={<Radius />} />
                  <Route path="directory" element={<Directory />} />
                  <Route path="pki" element={<Pki />} />
                  <Route path="audit" element={<Audit scope="tenant" />} />
                  <Route path="setup" element={<TenantSetup />} />
                  <Route path="settings" element={<TenantSettings />} />
                </Route>
                <Route path="*" element={<Empty title="Page not found">Use the sidebar or press ⌘K to find what you need.</Empty>} />
              </Route>
            </Routes>
          </HashRouter>
          <Toaster />
        </Tooltip.Provider>
      </SessionProvider>
    </QueryClientProvider>
  )
}
