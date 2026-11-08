// Route map. Screens link with these helpers, never with hand-written strings.
//
// Intent query parameters (screens must honour them on load, then clear them with replace):
//   users/:id?issue=1            open "Issue certificate" for that user
//   certificates?status=expiring filter (active | expiring | expired | revoked)
//   certificates?revoke=<certId> open the revoke dialog for that certificate
//   certificates?identity_id=<id> filter to one user's certificates
//   radius?rotate=<clientId>     open "Rotate shared secret" for that controller
//   radius?add=1                 open "Add controller"
//   radius?add=switch            open "Add switch"
//   radius?client=<clientId>     select that controller or switch (its guide or switch panel)
//   policy?test=<identityId>     open "Test a user" with that user
//   events?reason=<code>         filter rejects by reason code
//   events?event=<eventId>       open that attempt's detail sheet
//   events?network=wired         filter to wired (or wireless) attempts
//   mac?device=<id>              open that allow-list entry
//   mac?tab=seen                 show “Seen, not allowed”
//   mac?allow=<MAC>              open “Allow a device” with that MAC
//   device-admin?tab=accounts|directory|log|settings   show that tab
//   device-admin?account=<id>    open that local account
//   device-admin?device=<id>     open that device's configuration
//   autoenroll?tab=settings|log  show that tab
//   syslog?device=<clientId>     show one device's syslog
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
  systemLog: () => '/system/logs',
  account: () => '/account',
  dashboard: (tid: string) => `${t(tid)}/dashboard`,
  users: (tid: string) => `${t(tid)}/users`,
  user: (tid: string, id: string, intent?: { issue?: boolean }) => `${t(tid)}/users/${id}${intent?.issue ? '?issue=1' : ''}`,
  certificates: (tid: string, q?: { status?: string; revoke?: string; identity?: string }) =>
    `${t(tid)}/certificates${q?.status ? `?status=${q.status}` : q?.revoke ? `?revoke=${q.revoke}` : q?.identity ? `?identity_id=${q.identity}` : ''}`,
  certificate: (tid: string, id: string) => `${t(tid)}/certificates/${id}`,
  radius: (tid: string, q?: { rotate?: string; add?: boolean | 'switch'; client?: string }) =>
    `${t(tid)}/radius${q?.rotate ? `?rotate=${q.rotate}` : q?.add ? `?add=${q.add === 'switch' ? 'switch' : '1'}` : q?.client ? `?client=${encodeURIComponent(q.client)}` : ''}`,
  policy: (tid: string, q?: { test?: string }) => `${t(tid)}/policy${q?.test ? `?test=${q.test}` : ''}`,
  mac: (tid: string, q?: { device?: string; tab?: 'seen' | 'groups'; allow?: string }) =>
    `${t(tid)}/mac${q?.device ? `?device=${encodeURIComponent(q.device)}` : q?.allow ? `?allow=${encodeURIComponent(q.allow)}` : q?.tab ? `?tab=${q.tab}` : ''}`,
  deviceAdmin: (tid: string, q?: { tab?: 'accounts' | 'directory' | 'log' | 'settings'; account?: string; device?: string }) =>
    `${t(tid)}/device-admin${q?.account ? `?account=${encodeURIComponent(q.account)}` : q?.device ? `?device=${encodeURIComponent(q.device)}` : q?.tab ? `?tab=${q.tab}` : ''}`,
  directory: (tid: string) => `${t(tid)}/directory`,
  autoenroll: (tid: string, q?: { tab?: 'settings' | 'log' }) => `${t(tid)}/autoenroll${q?.tab ? `?tab=${q.tab}` : ''}`,
  pki: (tid: string) => `${t(tid)}/pki`,
  events: (tid: string, q?: { reason?: string; result?: string; event?: string; network?: 'wired' | 'wireless' }) =>
    `${t(tid)}/events${q?.event ? `?event=${encodeURIComponent(q.event)}` : q?.reason ? `?reason=${q.reason}` : q?.result ? `?result=${q.result}` : q?.network ? `?network=${q.network}` : ''}`,
  syslog: (tid: string, q?: { device?: string }) => `${t(tid)}/syslog${q?.device ? `?device=${encodeURIComponent(q.device)}` : ''}`,
  tenantAudit: (tid: string) => `${t(tid)}/audit`,
  setup: (tid: string) => `${t(tid)}/setup`,
  settings: (tid: string) => `${t(tid)}/settings`,
}

/** Map a backend action target (needs-action queue, setup gaps) to a route that exists. */
export function targetPath(tid: string, target: ActionTarget): string {
  const [screen, ...rest] = target.split(':')
  const arg = rest[0]
  switch (screen) {
    case 'directory': return paths.directory(tid)
    case 'autoenroll': return paths.autoenroll(tid)
    case 'radius': return arg === 'client' && rest[1] ? paths.radius(tid, { client: rest[1] }) : paths.radius(tid)
    case 'pki': return paths.pki(tid)
    case 'setup': return paths.setup(tid)
    case 'system': return paths.system()
    case 'tenant': return paths.settings(tid)
    case 'certificates': return paths.certificates(tid, arg ? { status: arg } : undefined)
    case 'events': return paths.events(tid, arg ? { reason: arg } : undefined)
    case 'policy': return paths.policy(tid)
    case 'mac': return paths.mac(tid, arg === 'seen' ? { tab: 'seen' } : undefined)
    case 'users': return paths.users(tid)
    default: return paths.dashboard(tid)
  }
}
