// Route map. Screens link with these helpers, never with hand-written strings.
//
// Intent query parameters (screens must honour them on load, then clear them with replace):
//   users/:id?issue=1            open "Issue certificate" for that user
//   certificates?status=expiring filter (active | expiring | expired | revoked)
//   certificates?revoke=<certId> open the revoke dialog for that certificate
//   certificates?identity_id=<id> filter to one user's certificates
//   radius?rotate=<clientId>     open "Rotate shared secret" for that controller
//   radius?add=1                 open "Add controller"
//   policy?test=<identityId>     open "Test a user" with that user
//   events?reason=<code>         filter rejects by reason code
//   events?event=<eventId>       open that attempt's detail sheet
import type { ActionTarget } from './api/types'

const t = (tid: string) => `/t/${tid}`
export const paths = {
  login: () => '/login',
  firstRun: () => '/first-run',
  home: () => '/',
  tenants: () => '/tenants',
  newTenant: () => '/tenants/new',
  admins: () => '/admins',
  platformAudit: () => '/audit',
  system: () => '/system',
  account: () => '/account',
  dashboard: (tid: string) => `${t(tid)}/dashboard`,
  users: (tid: string) => `${t(tid)}/users`,
  user: (tid: string, id: string, intent?: { issue?: boolean }) => `${t(tid)}/users/${id}${intent?.issue ? '?issue=1' : ''}`,
  certificates: (tid: string, q?: { status?: string; revoke?: string; identity?: string }) =>
    `${t(tid)}/certificates${q?.status ? `?status=${q.status}` : q?.revoke ? `?revoke=${q.revoke}` : q?.identity ? `?identity_id=${q.identity}` : ''}`,
  certificate: (tid: string, id: string) => `${t(tid)}/certificates/${id}`,
  radius: (tid: string, q?: { rotate?: string; add?: boolean }) => `${t(tid)}/radius${q?.rotate ? `?rotate=${q.rotate}` : q?.add ? '?add=1' : ''}`,
  policy: (tid: string, q?: { test?: string }) => `${t(tid)}/policy${q?.test ? `?test=${q.test}` : ''}`,
  directory: (tid: string) => `${t(tid)}/directory`,
  pki: (tid: string) => `${t(tid)}/pki`,
  events: (tid: string, q?: { reason?: string; result?: string; event?: string }) =>
    `${t(tid)}/events${q?.event ? `?event=${encodeURIComponent(q.event)}` : q?.reason ? `?reason=${q.reason}` : q?.result ? `?result=${q.result}` : ''}`,
  tenantAudit: (tid: string) => `${t(tid)}/audit`,
  setup: (tid: string) => `${t(tid)}/setup`,
  settings: (tid: string) => `${t(tid)}/settings`,
}

/** Map a backend action target (needs-action queue, setup gaps) to a route that exists. */
export function targetPath(tid: string, target: ActionTarget): string {
  const [screen, arg] = target.split(':', 2)
  switch (screen) {
    case 'directory': return paths.directory(tid)
    case 'radius': return paths.radius(tid)
    case 'pki': return paths.pki(tid)
    case 'setup': return paths.setup(tid)
    case 'system': return paths.system()
    case 'tenant': return paths.settings(tid)
    case 'certificates': return paths.certificates(tid, arg ? { status: arg } : undefined)
    case 'events': return paths.events(tid, arg ? { reason: arg } : undefined)
    case 'policy': return paths.policy(tid)
    case 'users': return paths.users(tid)
    default: return paths.dashboard(tid)
  }
}
