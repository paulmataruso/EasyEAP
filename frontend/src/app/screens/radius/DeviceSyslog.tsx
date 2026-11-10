// A controller's or switch's syslog (docs/plans/syslog-full.md §6): turn it on, the addresses it sends from, how to
// point the device at EasyEAP, today's counters, what it said and the sessions or clients its log describes.
// A Cisco switch with the switch audit set up has all of this in its audit panel instead.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { Logs } from 'lucide-react'
import { errorField } from '../../api/client'
import { useDeviceSyslog, useSetDeviceSyslog, type DeviceSyslogResponse, type LoggedSession } from '../../api/deviceSyslog'
import type { RadiusClient } from '../../api/radius'
import { useTenant } from '../../api/tenant'
import { ago, fmtCount, fmtDateTime, fmtStamp } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { Btn, Callout, Chip, CopyButton, ESwitch, ErrorState, Field, LoadingBlock, errorMessage, toast, type Tone } from '../../ui'
import { Marked } from './Guide'

const macText = (m: string | null) => (m && m.length === 12 ? m.match(/../g)!.join(':') : m ?? '')

const stateTone: Record<string, Tone> = {
  authorized: 'valid', authenticated: 'valid', connected: 'valid',
  failed: 'crit', unauthorized: 'crit', excluded: 'crit', violation: 'crit', 'no answer': 'warn',
}
const stateText: Record<string, string> = {
  seen: 'Seen', starting: 'Starting', associated: 'Associated', authenticated: 'Authenticated', authorized: 'Authorized', connected: 'Connected',
  failed: 'Failed', unauthorized: 'Not authorized', excluded: 'Excluded', violation: 'Security violation', 'no answer': 'No RADIUS answer',
}

/** Sessions (switches) or clients (controllers, access points) put together from the device's log: last 24 hours. */
export function LoggedSessions({ sessions, now, wireless }: { sessions: LoggedSession[]; now: Date; wireless?: boolean }) {
  if (!sessions.length) return null
  const anyPort = sessions.some((s) => s.port)
  const anyWifi = sessions.some((s) => s.ssid || s.ap)
  return (
    <div>
      <p className="text-[13px] font-semibold mb-1.5">{wireless || (!anyPort && anyWifi) ? 'Clients the device logged' : 'Sessions the switch logged'} <span className="ee-small font-normal ee-ink-3">(last 24 hours, newest first)</span></p>
      <div className="max-h-[320px] overflow-auto rounded-[8px] border border-[var(--ee-line)]">
        <table className="ee-table">
          <caption className="sr-only">Sessions put together from syslog</caption>
          <thead><tr>{anyPort && <th className="pt-2.5">Port</th>}<th className="pt-2.5">Client</th><th className="pt-2.5">State</th><th className="pt-2.5">Details</th><th className="pt-2.5">When</th></tr></thead>
          <tbody>
            {sessions.map((s, i) => (
              <tr key={`${s.port}|${s.mac}|${s.first_at}|${i}`}>
                {anyPort && <td className="ee-mono text-[12.5px] whitespace-nowrap">{s.port ?? '—'}</td>}
                <td className="ee-mono text-[12.5px] whitespace-nowrap">{s.mac ? macText(s.mac) : '—'}{s.ip && <span className="block ee-ink-3">{s.ip}</span>}</td>
                <td className="whitespace-nowrap">
                  <Chip tone={stateTone[s.state] ?? 'neutral'}>{stateText[s.state] ?? s.state}</Chip>
                  {s.active ? null : <span className="block ee-small ee-ink-3">{s.ended ? `Ended: ${s.ended}` : 'Ended'}</span>}
                </td>
                <td className="ee-small ee-ink-2">
                  {[s.method && s.method.toUpperCase().replace('DOT1X', '802.1X'), s.vlan !== null && `VLAN ${s.vlan}`, s.ssid && `SSID ${s.ssid}`, s.ap && `AP ${s.ap}`,
                    s.reason && `Reason: ${s.reason}`].filter(Boolean).join(' · ') || '—'}
                </td>
                <td className="ee-small whitespace-nowrap" title={`${fmtDateTime(s.first_at)} – ${fmtDateTime(s.last_at)}`}>{ago(s.last_at, now)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Counters({ d, now }: { d: DeviceSyslogResponse; now: Date }) {
  const st = d.stats
  if (!st.last_at) return <p className="ee-small ee-ink-2">Nothing received from this device today.</p>
  return (
    <p className="ee-small ee-ink-2">
      Last message {ago(st.last_at, now)}{st.last_tag ? <> (<span className="ee-mono">{st.last_tag}</span>)</> : null}. Today: {fmtCount(st.received ?? 0)} received,{' '}
      {fmtCount(st.kept ?? 0)} kept{st.quota ? <>, <span className="text-[var(--ee-warn)]">{fmtCount(st.quota)} over the rate limit</span></> : null}.
    </p>
  )
}

export function DeviceSyslogPanel({ client }: { client: RadiusClient }) {
  const { tid, can } = useTenant()
  const q = useDeviceSyslog(tid, client.id)
  const save = useSetDeviceSyslog(tid, client.id)
  const now = useNow(30_000)
  const [extra, setExtra] = useState('')
  const [extraError, setExtraError] = useState<string | null>(null)
  const [showRemoval, setShowRemoval] = useState(false)
  const d = q.data
  const savedExtra = d?.settings.addresses.join(', ') ?? ''
  useEffect(() => { setExtra(savedExtra); setExtraError(null) }, [savedExtra, client.id])

  if (q.isLoading) return <LoadingBlock rows={3} label="Loading syslog" />
  if (q.error || !d) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  const g = d.guide
  const canWrite = can('radius:write')
  const addresses = extra.split(/[\s,]+/).map((a) => a.trim()).filter(Boolean)
  const submit = (enabled: boolean, addrs: string[]) => {
    setExtraError(null)
    save.mutate({ enabled, addresses: addrs }, {
      onSuccess: () => toast(enabled ? `Syslog from ${client.name} is on` : `Syslog from ${client.name} is off`, enabled ? 'Messages appear in Device syslog as they arrive.' : 'New messages from it are no longer kept.'),
      onError: (e) => { if (errorField(e) === 'addresses') setExtraError(errorMessage(e)); else toast('Syslog settings weren’t saved', errorMessage(e), 'crit') },
    })
  }
  const live = <Link to={paths.syslog(tid, { device: client.id })} className="ee-btn ee-btn-sm"><Logs aria-hidden />Live view</Link>

  if (d.via_audit) {
    return (
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="ee-small ee-ink-2">This switch sends syslog through its switch audit: what it says is in the audit panel above.</p>
        {live}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 max-w-[720px]">
          <div className="flex items-center gap-3">
            <ESwitch checked={d.settings.enabled} onChange={(v) => submit(v, d.settings.addresses)} disabled={!canWrite || save.isPending} label="Keep syslog from this device" />
            <span className="text-[13.5px] font-medium">Keep syslog from this device</span>
          </div>
          <p className="ee-small ee-ink-3 mt-1">
            The whole log, decoded where EasyEAP understands it (802.1X and MAC authentication, clients joining and leaving, RADIUS servers) and
            shown as it arrives. Syslog isn’t authenticated: it explains what happened, and EasyEAP never acts on it alone.
          </p>
        </div>
        {d.settings.enabled && live}
      </div>

      {!d.receiver.receiving ? (
        <Callout tone="neutral" title="This server doesn’t receive syslog">
          The server’s operator sets <span className="ee-mono">EASYEAP_SYSLOG_BIND</span> to the address devices reach EasyEAP on; until then no device can send.
        </Callout>
      ) : !d.receiver.listening ? (
        <Callout tone="warn" title="The syslog receiver isn’t running">Messages are lost until it is. System health shows its last heartbeat.</Callout>
      ) : !g.can_send ? (
        <Callout tone="warn" title="This device can’t reach EasyEAP’s syslog port">{g.notes[0]}</Callout>
      ) : null}

      {d.settings.enabled && (
        <>
          <Counters d={d} now={now} />
          <Field label="Also sends from" optional htmlFor={`sl-extra-${client.id}`} error={extraError}
            hint={<>EasyEAP keeps messages from <span className="ee-mono">{client.address}</span>. Add other addresses this device sends from (a 9800’s service port, a UniFi console that serves only this tenant), comma separated: at most 8, each an address or a range of up to 256.</>}>
            <div className="flex flex-wrap gap-2">
              <input id={`sl-extra-${client.id}`} className="ee-input min-w-[240px] flex-1 ee-mono" value={extra} onChange={(e) => setExtra(e.target.value)} disabled={!canWrite}
                placeholder="10.0.0.2, 10.0.20.0/24" aria-invalid={!!extraError} />
              {canWrite && <Btn onClick={() => submit(true, addresses)} busy={save.isPending} disabled={extra.trim() === savedExtra.trim()}>Save</Btn>}
            </div>
          </Field>
        </>
      )}

      {(d.settings.enabled || canWrite) && (
        <div className="space-y-3 rounded-[8px] border border-[var(--ee-line)] px-3.5 py-3">
          <p className="text-[13px] font-semibold">Send this device’s syslog to EasyEAP</p>
          {g.steps.length > 0 && (
            <ol className="list-decimal space-y-1.5 pl-5 text-[13.5px] marker:text-[var(--ee-ink-3)] marker:tabular-nums">
              {g.steps.map((s, i) => <li key={i} className="pl-1"><Marked text={s} /></li>)}
            </ol>
          )}
          {g.config && (
            <div>
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <p className="ee-small ee-ink-2">Paste on the device’s CLI:</p>
                <CopyButton text={g.config} what="Syslog configuration" label="Copy" />
              </div>
              <pre className="ee-code max-h-[320px] overflow-auto" tabIndex={0} aria-label="Syslog configuration"><Marked text={g.config} /></pre>
            </div>
          )}
          {g.removal && (
            <div>
              <Btn size="sm" variant="ghost" onClick={() => setShowRemoval((v) => !v)} aria-expanded={showRemoval}>{showRemoval ? 'Hide how to stop sending' : 'How to stop sending'}</Btn>
              {showRemoval && <pre className="ee-code mt-2 overflow-auto" tabIndex={0} aria-label="Lines that stop sending syslog">{g.removal}</pre>}
            </div>
          )}
          {g.notes.filter((n) => g.can_send || n !== g.notes[0]).length > 0 && (
            <ul className="list-disc space-y-1 pl-5 ee-small ee-ink-3">
              {g.notes.filter((n) => g.can_send || n !== g.notes[0]).map((n, i) => <li key={i}>{n}</li>)}
            </ul>
          )}
        </div>
      )}

      {d.recent.length > 0 && (
        <div>
          <p className="text-[13px] font-semibold mb-1.5">What it said about access <span className="ee-small font-normal ee-ink-3">(last 24 hours)</span></p>
          <ul className="ee-small ee-ink-2 space-y-0.5" aria-label="What the device said">
            {d.recent.map((l) => (
              <li key={l.id} className="min-w-0 break-words">
                <span className="ee-mono text-[12px]">{l.tag}</span>{l.count > 1 && ` ×${l.count}`} · <time dateTime={l.last_at} title={ago(l.last_at, now)} className="ee-num">{fmtStamp(l.last_at)}</time>
                {l.mac && <> · <span className="ee-mono text-[12px]">{macText(l.mac)}</span></>}{' · '}{l.text}
              </li>
            ))}
          </ul>
        </div>
      )}
      <LoggedSessions sessions={d.sessions} now={now} wireless={client.vendor !== 'cisco-switch' && client.vendor !== 'meraki'} />
    </div>
  )
}
