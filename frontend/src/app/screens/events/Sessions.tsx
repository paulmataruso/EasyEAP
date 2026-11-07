// Accounting sessions reported by controllers (RADIUS accounting Start / Interim-Update / Stop). Every row shows when
// the controller last reported it, because a session is only as current as its last update.
import { useState } from 'react'
import { Link } from 'react-router'
import { Activity } from 'lucide-react'
import { controllerFor, useControllers, usePolicyLite, useSessions, type AcctSession } from '../../api/events'
import { useTenant } from '../../api/tenant'
import { ago, fmtDateTime, plural } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { fmtBytes } from './bytes'
import { Empty, ErrorState, LoadingBlock, Panel, Seg, VlanTag } from '../../ui'

/** Wi-Fi, or wired with the switch port the session is on. */
const sessionNetwork = (s: AcctSession) => (s.network === 'wired' ? (s.nas_port_id ? `Wired · ${s.nas_port_id}` : 'Wired') : 'Wi-Fi')

function Times({ s, now }: { s: AcctSession; now: Date }) {
  return (
    <>
      <span className="block" title={fmtDateTime(s.updated_at)}>{s.stopped_at ? `Stopped ${ago(s.stopped_at, now)}` : `Updated ${ago(s.updated_at, now)}`}</span>
      <span className="block text-[12px] ee-ink-3" title={s.started_at ? fmtDateTime(s.started_at) : undefined}>{s.started_at ? `Started ${ago(s.started_at, now)}` : 'Start not reported'}</span>
    </>
  )
}

export function SessionsView() {
  const { tid, can } = useTenant()
  const now = useNow()
  const [scope, setScope] = useState<'active' | 'all'>('active')
  const q = useSessions(tid, scope === 'active')
  const radius = useControllers(tid, can('radius:read'))
  const policy = usePolicyLite(tid, can('policy:read'))
  const vlan = (id: number | null) => policy.data?.vlans.find((v) => v.vlan_id === id)
  const items = q.data?.items ?? []

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <Seg label="Sessions to show" value={scope} onChange={setScope} options={[{ value: 'active', label: 'Active' }, { value: 'all', label: 'All recent' }]} />
        {q.data && <p className="ee-small ee-ink-2">{plural(items.length, scope === 'active' ? 'active session' : 'session')}{items.length === 500 && ' (newest 500)'}</p>}
      </div>
      <p className="ee-small ee-ink-3 mb-4 max-w-[75ch]">
        Sessions come from RADIUS accounting sent by your controllers and switches. A session counts as active when its controller or switch reported it in the last 26 hours and hasn’t sent a Stop. Ones without accounting enabled don’t appear here.
      </p>
      <Panel className="p-5">
      {q.isLoading ? <LoadingBlock rows={5} label="Loading sessions" />
        : q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="Sessions couldn’t be loaded" />
        : items.length === 0 ? (
          <Empty icon={<Activity aria-hidden />} title={scope === 'active' ? 'No active sessions' : 'No sessions reported'}>
            {scope === 'active' ? 'No controller has reported an open session in the last 26 hours.' : 'No controller has sent RADIUS accounting for this tenant recently.'}{' '}
            {can('radius:read') && <>Check accounting is enabled on each controller in <Link to={paths.radius(tid)} className="underline">RADIUS</Link>.</>}
          </Empty>
        ) : (
          <>
            <div className="hidden overflow-x-auto md:block">
              <table className="ee-table">
                <caption className="sr-only">{scope === 'active' ? 'Active sessions' : 'Recent sessions'}</caption>
                <thead><tr><th>User</th><th>Device MAC</th><th>Controller / network</th><th>Client IP</th><th>VLAN</th><th>Last report</th><th className="text-right" title="Acct-Input-Octets / Acct-Output-Octets">Device sent / received</th></tr></thead>
                <tbody>
                  {items.map((s) => {
                    const c = controllerFor(radius.data?.clients, { nas_ip: s.nas_ip })
                    return (
                      <tr key={s.id}>
                        <td className="max-w-[240px] truncate font-medium">{s.username ?? <span className="ee-ink-3 font-normal">Unknown</span>}</td>
                        <td className="ee-mono whitespace-nowrap text-[12.5px] ee-ink-2">{s.calling_station_id ?? '—'}</td>
                        <td>
                          <span className="block">{c?.name ?? s.nas_ip}</span>
                          {c && <span className="ee-mono block text-[12px] ee-ink-3">{s.nas_ip}</span>}
                          {s.network && <span className="block text-[12px] ee-ink-3">{sessionNetwork(s)}</span>}
                        </td>
                        <td className="ee-mono text-[12.5px]">{s.framed_ip ?? <span className="ee-ink-3">—</span>}</td>
                        <td>{s.vlan_id !== null ? <VlanTag vlanId={s.vlan_id} name={vlan(s.vlan_id)?.name} color={vlan(s.vlan_id)?.color} /> : <span className="ee-ink-3">—</span>}</td>
                        <td className="whitespace-nowrap"><Times s={s} now={now} /></td>
                        <td className="ee-num whitespace-nowrap text-right">{fmtBytes(s.input_octets)} / {fmtBytes(s.output_octets)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <ul className="ee-divide md:hidden" aria-label={scope === 'active' ? 'Active sessions' : 'Recent sessions'}>
              {items.map((s) => {
                const c = controllerFor(radius.data?.clients, { nas_ip: s.nas_ip })
                return (
                  <li key={s.id} className="py-3">
                    <p className="font-medium">{s.username ?? 'Unknown user'}</p>
                    <p className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[12px] ee-ink-3">
                      {s.calling_station_id && <span className="ee-mono">{s.calling_station_id}</span>}
                      <span>{c?.name ?? s.nas_ip}</span>
                      {s.network && <span>{sessionNetwork(s)}</span>}
                      {s.framed_ip && <span className="ee-mono">{s.framed_ip}</span>}
                      {s.vlan_id !== null && <span>VLAN {s.vlan_id}</span>}
                    </p>
                    <div className="mt-1 text-[12.5px] ee-ink-2"><Times s={s} now={now} /></div>
                    <p className="ee-num mt-0.5 text-[12px] ee-ink-3">{fmtBytes(s.input_octets)} sent · {fmtBytes(s.output_octets)} received</p>
                  </li>
                )
              })}
            </ul>
          </>
        )}
      </Panel>
    </div>
  )
}
