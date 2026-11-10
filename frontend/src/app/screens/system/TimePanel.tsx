// System → Time: the host's clock, which every log, certificate and session takes its time from, and the NTP servers
// the host's chronyd uses (set here, applied by the easyeap-time service).
import { useState, type ReactNode } from 'react'
import { Clock, Pencil, Plus } from 'lucide-react'
import { fmtOffset, fmtSeconds, useTime, type TimeConfig, type TimeServer, type TimeSource } from '../../api/time'
import { useSession } from '../../api/session'
import { ago, duration, fmtStamp, timeZoneName } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { Btn, Callout, Chip, CopyButton, Dl, Empty, ErrorState, HealthDot, LoadingBlock, Panel, SectionHeader, type Tone } from '../../ui'
import { TimeDialog } from './TimeDialog'

const SELECT: Record<string, [string, Tone]> = {
  best: ['In use: the reference', 'valid'],
  combined: ['In use', 'valid'],
  not_combined: ['Standby', 'neutral'],
  noselect: ['Switched off', 'neutral'],
  not_preferred: ['Standby: another server is preferred', 'neutral'],
  unsynchronised: ['Not usable: not synchronised itself', 'warn'],
  missing_samples: ['Waiting for answers', 'neutral'],
  waits_for_update: ['Waiting for answers', 'neutral'],
  large_distance: ['Not usable: too far away or too unsure', 'warn'],
  jittery: ['Not usable: answers vary too much', 'warn'],
  waits_for_others: ['Waiting for the others', 'neutral'],
  stale: ['Not usable: no recent answer', 'warn'],
  orphan: ['Not usable', 'warn'],
  // chronyc: "does not fully agree with sources that have the trust option" (NTS sources get it by default)
  not_trusted: ['Not used: doesn’t fully agree with the trusted servers', 'warn'],
  falseticker: ['Not used: disagrees with the others', 'crit'],
}

export function sourceState(s: TimeSource): [string, Tone] {
  if (!s.resolved) return ['Name not resolved yet', 'warn']
  if (s.noselect) return [s.switched_off_by_easyeap ? 'Switched off by EasyEAP' : 'Switched off', 'neutral']
  if (!s.reachable) return ['Not answering', 'warn']
  return SELECT[s.select ?? ''] ?? [s.select ?? 'Unknown', 'neutral']
}

/** The browser's clock against the API's: positive when the browser is ahead. Within the request's own time, zero. */
export function browserSkew(apiNow: string, receivedAt: number): number {
  const skew = (receivedAt - Date.parse(apiNow)) / 1000
  return Math.abs(skew) < 2 ? 0 : skew
}

export function deviceConfig(servers: TimeServer[]): string {
  const lines = ['! Time from the same NTP servers as EasyEAP, and log timestamps with the date, to the millisecond, in UTC.']
  if (servers.length) lines.push(...servers.map((s) => `ntp server ${s.address}${s.prefer ? ' prefer' : ''}`))
  else lines.push('ntp server <your NTP server>')
  lines.push('service timestamps log datetime msec show-timezone')
  lines.push('! From a management VRF (Catalyst 9000: Mgmt-vrf), add vrf to each server: ntp server vrf Mgmt-vrf <server>')
  return lines.join('\n')
}

export function TimePanel() {
  const { me } = useSession()
  const owner = me?.platform_role === 'platform_owner'
  const q = useTime()
  const now = useNow()
  const [editing, setEditing] = useState(false)
  const data = q.data
  const tone: Tone | undefined = data ? (data.stale ? 'warn' : data.assessment?.tone) : undefined

  return (
    <Panel risk={tone === 'valid' ? undefined : tone} aria-labelledby="sys-time">
      <div className="p-5">
        <SectionHeader id="sys-time" title="Time"
          meta={data?.status?.mode === 'chrony' ? 'chrony on the host' : data?.status ? 'measured only' : undefined}
          actions={owner && data ? (
            <Btn size="sm" variant={data.settings.servers.length ? 'default' : 'primary'} onClick={() => setEditing(true)}>
              {data.settings.servers.length ? <><Pencil aria-hidden />Edit servers</> : <><Plus aria-hidden />Set NTP servers</>}
            </Btn>
          ) : undefined} />
        {q.isLoading ? <LoadingBlock rows={4} label="Loading time status" />
          : q.error || !data ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="Time status couldn’t be loaded" />
          : <TimeBody data={data} now={now} receivedAt={q.dataUpdatedAt} />}
      </div>
      {owner && data && <TimeDialog open={editing} onOpenChange={setEditing} settings={data.settings} max={data.max_servers} />}
    </Panel>
  )
}

function TimeBody({ data, now, receivedAt }: { data: TimeConfig; now: Date; receivedAt: number }) {
  const st = data.status
  const servers = data.settings.servers
  const skew = browserSkew(data.now, receivedAt)
  if (data.stale || !st) {
    return (
      <Callout tone="warn" title="The time service isn’t reporting">
        {st ? <>Its last report was {ago(st.at, now)}. </> : null}Nothing is watching the host’s clock or applying the servers set here. The
        easyeap-time container restarts on its own; System health shows when it reports again.
      </Callout>
    )
  }
  const ours = st.sources.filter((s) => s.ours)
  const others = st.sources.filter((s) => !s.ours)
  // EasyEAP's servers answer but the host's win: they're marked prefer, or (authselectmode mix, chrony's default) they use
  // NTS and get trust and require, so servers without NTS are used only where they agree with them.
  const held = (s: TimeSource) => s.select === 'not_preferred' || s.select === 'not_trusted'
  const hostWins = ours.length > 0 && ours.every((s) => held(s) || !s.reachable) && ours.some(held)
  const hostNts = others.some((s) => s.authenticated || s.nts) && !ours.some((s) => s.nts)
  const assessment = data.assessment

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1">
        <HealthDot tone={assessment?.tone ?? 'neutral'} label={assessment?.tone === 'valid'
          ? (st.mode === 'chrony' && st.reference ? `Synchronised to ${st.reference}` : 'Synchronised')
          : (assessment?.line ?? '').replace(/^./, (c) => c.toUpperCase())} />
      </div>
      <Dl items={[
        ['This server’s clock', st.offset === null ? (st.synchronised ? 'Synchronised (offset not measured)' : '—') : fmtOffset(st.offset)],
        ...(st.mode === 'chrony' ? [
          ['Stratum', st.stratum ? `${st.stratum}` : '—'],
          ['Last correction', st.reference_time ? <span title={fmtStamp(st.reference_time)}>{ago(st.reference_time, now)}</span> : '—'],
          ['Checks the time every', st.update_interval ? duration(st.update_interval) : '—'],
        ] as Array<[string, ReactNode]> : []),
        ['Your computer’s clock', skew === 0 ? 'Agrees with this server’s' : <span className="text-[var(--ee-warn-ink)]">{fmtSeconds(skew)} {skew > 0 ? 'ahead of' : 'behind'} this server’s</span>],
        ['Times shown in', timeZoneName],
      ]} />
      {skew !== 0 && <p className="ee-small ee-ink-2 mt-2">Times such as “3 minutes ago” are worked out on your computer, so they’re off by that much. Exact times in the logs come from this server and are right.</p>}

      {st.apply_error && <Callout tone="warn" className="mt-4" title="The servers set here aren’t in use">{st.apply_error}</Callout>}
      {st.select_error && <Callout tone="warn" className="mt-4">{st.select_error}</Callout>}
      {hostWins && !data.settings.only_these && (
        <Callout tone="warn" className="mt-4" title="chronyd prefers the host’s own servers">
          {hostNts
            ? <>The host’s own servers use NTS (authenticated time), so chronyd trusts them first and uses servers without NTS only where they agree. Turn on “Use only these servers”, or use servers with NTS.</>
            : <>The host’s configuration marks its own servers <span className="ee-mono">prefer</span>, so chronyd uses these only if all of those fail. Turn on “Use only these servers”, or mark one of these Prefer.</>}
        </Callout>
      )}
      {st.mode === 'sntp' && st.problem && <Callout tone="neutral" className="mt-4" title="EasyEAP measures this clock but doesn’t set it">{st.problem}</Callout>}

      <h3 className="ee-h3 mb-2 mt-5">EasyEAP’s NTP servers</h3>
      {servers.length === 0 ? (
        <Empty icon={<Clock />} title="The host’s own servers keep the clock">
          {st.mode === 'chrony' ? 'chronyd uses the servers in the host’s configuration (below). Set your own to use your network’s time servers, or NTS-secured ones.' : 'Set NTP servers to measure this clock against them.'}
        </Empty>
      ) : st.mode === 'chrony' ? (
        <SourceList sources={ours} servers={servers} />
      ) : (
        <ul className="ee-divide">
          {st.checks.map((c) => (
            <li key={c.server} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2 first:pt-0 last:pb-0 text-[13px]">
              <span className="ee-mono">{c.server}{c.address && c.address !== c.server && <span className="ee-ink-3"> ({c.address})</span>}</span>
              {c.error ? <span className="ee-small text-[var(--ee-warn-ink)]">{c.error}</span>
                : <span className="ee-small ee-ink-2">this clock {fmtOffset(c.offset)} · round trip {fmtSeconds(c.delay)} · stratum {c.stratum}</span>}
            </li>
          ))}
        </ul>
      )}
      {servers.length > 0 && <p className="ee-small ee-ink-3 mt-2">{data.settings.only_these ? 'Only these servers are used while one of them answers; if none does, the host’s own servers keep the clock until one is back.' : 'Used alongside the host’s own servers.'}</p>}

      {st.mode === 'chrony' && others.length > 0 && (
        <>
          <h3 className="ee-h3 mb-2 mt-5">The host’s own servers</h3>
          <SourceList sources={others} />
        </>
      )}

      <details className="mt-5 text-[13px]">
        <summary className="cursor-pointer font-medium">Your switches and controllers</summary>
        <p className="ee-small ee-ink-2 mt-2">Device syslog shows when EasyEAP received each message, by this server’s clock, so lines from different devices line up even if a device’s clock is wrong. Pointing devices at the same servers keeps their own logs (<span className="ee-mono">show logging</span>) in step with EasyEAP’s. For Cisco IOS and IOS XE:</p>
        <pre className="ee-code mt-2 whitespace-pre-wrap text-[12px]">{deviceConfig(servers)}</pre>
        <div className="mt-2"><CopyButton text={deviceConfig(servers)} what="the NTP configuration" /></div>
      </details>
    </>
  )
}

function SourceList({ sources, servers }: { sources: TimeSource[]; servers?: TimeServer[] }) {
  // EasyEAP's own: one group per configured server, its addresses (a pool's) beneath.
  if (servers) {
    return (
      <ul className="ee-divide">
        {servers.map((srv) => {
          const mine = sources.filter((s) => (s.name ?? s.address)?.toLowerCase() === srv.address.toLowerCase())
          return (
            <li key={srv.address} className="py-2.5 first:pt-0 last:pb-0 text-[13px]">
              <div className="flex flex-wrap items-center gap-2">
                <span className="ee-mono font-medium">{srv.address}</span>
                {srv.kind === 'pool' && <Chip>Pool</Chip>}
                {srv.nts && <Chip tone={mine.some((s) => s.nts) ? 'valid' : 'neutral'}>NTS</Chip>}
                {srv.prefer && <Chip>Prefer</Chip>}
              </div>
              {mine.length === 0 ? <p className="ee-small ee-ink-3 mt-0.5">Not in chronyd’s list yet: applied within a few seconds of saving.</p> : (
                <ul className="mt-1 space-y-0.5">{mine.map((s) => <SourceRow key={s.address ?? s.name ?? ''} s={s} showAddress={srv.kind === 'pool' || s.address !== srv.address} />)}</ul>
              )}
            </li>
          )
        })}
      </ul>
    )
  }
  return <ul className="space-y-1">{sources.map((s) => <SourceRow key={s.address ?? s.name ?? ''} s={s} showName />)}</ul>
}

function SourceRow({ s, showAddress = true, showName }: { s: TimeSource; showAddress?: boolean; showName?: boolean }) {
  const [label, tone] = sourceState(s)
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[12.5px]">
      {showName && <span className="ee-mono">{s.name ?? s.address}</span>}
      {showAddress && s.address && (!showName || s.name) && <span className="ee-mono ee-ink-3">{s.address}</span>}
      <HealthDot tone={tone} label={label} />
      {s.reachable && s.offset !== null && <span className="ee-small ee-ink-3">this clock {fmtOffset(s.offset)} ± {fmtSeconds(s.error)}{s.stratum ? ` · stratum ${s.stratum}` : ''}</span>}
      {s.nts && <Chip tone="valid">NTS</Chip>}
    </li>
  )
}
