// Device syslog (/t/:tid/syslog): everything this tenant's switches and controllers send, live. Polls every second
// from a cursor while the page is visible; a message that repeats within the minute updates its row and moves to the
// top with its count. ?device=<clientId> shows one device.
import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { Eraser, Pause, Play, Search } from 'lucide-react'
import { MAX_HELD, useLiveSyslog, type LiveDevice, type LiveMessage, type Receiver, type UnknownSources } from '../api/deviceSyslog'
import { vendorLabels } from '../api/radius'
import { useTenant } from '../api/tenant'
import { ago, fmtCount, fmtStamp, plural, timeZoneName } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Btn, Callout, Chip, Empty, ErrorState, ESelect, HealthDot, LoadingBlock, PageHeader, Panel, Seg, type Tone } from '../ui'

const macText = (m: string | null) => (m && m.length === 12 ? m.match(/../g)!.join(':') : m ?? '')
const SEVERITY = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug']
const sevTone = (s: number): Tone => (s <= 3 ? 'crit' : s === 4 ? 'warn' : 'neutral')
type Show = 'all' | 'access' | 'warnings'

function useDebounced<T>(value: T, ms = 200): T {
  const [v, setV] = useState(value)
  useEffect(() => { const id = setTimeout(() => setV(value), ms); return () => clearTimeout(id) }, [value, ms])
  return v
}

export function matches(m: LiveMessage, show: Show, q: string): boolean {
  if (show === 'access' && !m.notable) return false
  if (show === 'warnings' && m.severity > 4) return false
  if (!q) return true
  const hay = `${m.tag} ${m.device ?? ''} ${m.port ?? ''} ${m.mac ?? ''} ${macText(m.mac)} ${m.subject ?? ''} ${m.session_id ?? ''} ${m.source ?? ''} ${m.text}`.toLowerCase()
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w))
}

export default function DeviceSyslog() {
  const { tid, can } = useTenant()
  const [params, setParams] = useSearchParams()
  const device = params.get('device')
  const [paused, setPaused] = useState(false)
  const [show, setShow] = useState<Show>('all')
  const [query, setQuery] = useState('')
  const q = useDebounced(query.trim())
  const live = useLiveSyslog(tid, device, paused)
  const now = useNow(5000)

  const shown = useMemo(() => live.messages.filter((m) => matches(m, show, q)), [live.messages, show, q])
  const devices = live.meta?.devices ?? []
  const sending = devices.filter((d) => d.sends)
  const setDevice = (id: string) => {
    const next = new URLSearchParams(params)
    if (id === 'all') next.delete('device'); else next.set('device', id)
    setParams(next, { replace: true })
  }

  if (!can('radius:read')) {
    return <div><PageHeader title="Device syslog" /><Empty title="You don’t have access to device syslog">It’s available to administrators who can see RADIUS.</Empty></div>
  }

  return (
    <div>
      <PageHeader title="Device syslog"
        lede="What your switches and controllers send, as it arrives. Syslog isn’t authenticated: a message is what a device at that address says, so EasyEAP never acts on one by itself."
        actions={<>
          <Btn onClick={() => setPaused((p) => !p)} aria-pressed={paused}>{paused ? <><Play aria-hidden />Resume</> : <><Pause aria-hidden />Pause</>}</Btn>
          <Btn variant="ghost" onClick={live.clear} disabled={!live.messages.length}><Eraser aria-hidden />Clear</Btn>
        </>} />

      <div className="space-y-4">
        <ReceiverStrip receiver={live.meta?.receiver} paused={paused} lastPollAt={live.lastPollAt} error={!!live.error} sending={sending} total={devices.length} now={now} />

        <Panel className="overflow-hidden">
          <div className="flex flex-wrap items-center gap-3 border-b border-[var(--ee-line)] px-4 py-3">
            <ESelect className="w-[220px]" label="Device" value={device ?? 'all'} onChange={setDevice}
              options={[{ value: 'all', label: 'All devices' }, ...devices.map((d) => ({ value: d.id, label: `${d.name}${d.sends ? '' : ' (not sending)'}` }))]} />
            <Seg value={show} onChange={setShow} label="Show" options={[{ value: 'all', label: 'Everything' }, { value: 'access', label: 'Access' }, { value: 'warnings', label: 'Warnings and errors' }]} />
            <div className="ee-input flex min-w-[200px] max-w-[360px] flex-1 items-center gap-2 px-2.5 focus-within:border-[var(--ee-gold)]">
              <Search className="size-4 shrink-0 ee-ink-3" aria-hidden />
              <input aria-label="Filter messages" className="h-full min-w-0 flex-1 bg-transparent outline-none placeholder:text-[var(--ee-ink-3)]"
                placeholder="Port, MAC, user, text…" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            <span className="ee-small ee-ink-3 ml-auto">
              {shown.length === live.messages.length ? plural(shown.length, 'message') : `${fmtCount(shown.length)} of ${plural(live.messages.length, 'message')}`}
              {live.messages.length >= MAX_HELD && ` (the latest ${fmtCount(MAX_HELD)})`}
            </span>
          </div>
          {live.loading ? <div className="p-4"><LoadingBlock rows={8} label="Loading device syslog" /></div>
            : live.error && !live.messages.length ? <div className="p-4"><ErrorState error={live.error} /></div>
            : shown.length === 0 ? (
              <div className="p-4">
                <Empty title={live.messages.length ? 'No messages match' : 'Nothing received yet'}>
                  {live.messages.length ? 'Show everything, or try a different filter.'
                    : sending.length ? 'Messages appear here the moment a device sends one.'
                    : <>No device sends syslog to EasyEAP yet. Turn it on in <Link className="underline underline-offset-2" to={paths.radius(tid)}>RADIUS</Link>: select a controller or switch, then Syslog.</>}
                </Empty>
              </div>
            ) : (
              <MessageTable messages={shown} liveFrom={live.liveFrom} showDevice={!device} />
            )}
          {live.canLoadEarlier && live.messages.length > 0 && live.messages.length < MAX_HELD && (
            <div className="border-t border-[var(--ee-line)] px-4 py-3">
              <Btn onClick={() => void live.loadEarlier()} busy={live.loadingEarlier}>Load earlier messages</Btn>
            </div>
          )}
        </Panel>

        {devices.length > 0 && <DeviceCounters devices={devices} now={now} onPick={setDevice} />}
        {live.meta?.unknown && <UnknownBox u={live.meta.unknown} now={now} />}
      </div>
    </div>
  )
}

function ReceiverStrip({ receiver, paused, lastPollAt, error, sending, total, now }: {
  receiver: Receiver | undefined; paused: boolean; lastPollAt: Date | null; error: boolean; sending: LiveDevice[]; total: number; now: Date
}) {
  if (receiver && !receiver.receiving) {
    return (
      <Callout tone="neutral" title="This server doesn’t receive syslog">
        Devices can’t send until the server’s operator sets <span className="ee-mono">EASYEAP_SYSLOG_BIND</span> to the address devices reach EasyEAP
        on (docs/switch-audit.md). Messages already received are below.
      </Callout>
    )
  }
  if (receiver && !receiver.listening) {
    return <Callout tone="warn" title="The syslog receiver isn’t running">Messages devices send are lost until it is. System health shows its last heartbeat.</Callout>
  }
  const last = sending.map((d) => d.stats.last_at).filter(Boolean).sort().pop()
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 ee-small ee-ink-2">
      {error ? <HealthDot tone="warn" label="Reconnecting…" />
        : paused ? <HealthDot tone="neutral" label="Paused: new messages wait until you resume" />
        : <HealthDot tone="valid" label={lastPollAt ? 'Live: checked every second' : 'Connecting…'} />}
      {receiver?.address && <span>Receiving on <span className="ee-mono">{receiver.address}</span> UDP {receiver.port}{receiver.port_514 && receiver.port !== 514 ? ' and 514' : ''}</span>}
      {total > 0 && <span>{sending.length} of {plural(total, 'device')} sending</span>}
      {last && <span>Last message {ago(last, now)}</span>}
    </div>
  )
}

function MessageTable({ messages, liveFrom, showDevice }: { messages: LiveMessage[]; liveFrom: number | null; showDevice: boolean }) {
  return (
    <div className="max-h-[70vh] overflow-auto">
      <table className="ee-table">
        <caption className="sr-only">Device syslog, newest first</caption>
        <thead className="sticky top-0 z-[1] bg-[var(--ee-panel-solid)]">
          <tr><th className="pt-2.5">Time ({timeZoneName})</th>{showDevice && <th className="pt-2.5">Device</th>}<th className="pt-2.5">Message</th><th className="pt-2.5">Port · client</th><th className="pt-2.5 w-full">Text</th></tr>
        </thead>
        <tbody>
          {messages.map((m) => (
            // The key changes when a repeat updates the row, so it glows again.
            <tr key={`${m.id}:${m.seq}`} className={liveFrom !== null && m.seq > liveFrom ? 'ee-arrive' : undefined}>
              <td className="whitespace-nowrap align-top ee-num text-[12.5px]" title={m.count > 1 ? `First ${fmtStamp(m.first_at)}, last ${fmtStamp(m.last_at)}` : undefined}>
                {fmtStamp(m.last_at)}
              </td>
              {showDevice && <td className="whitespace-nowrap align-top text-[12.5px]">{m.device ?? '—'}{m.source && <span className="block ee-mono text-[11.5px] ee-ink-3">{m.source}</span>}</td>}
              <td className="whitespace-nowrap align-top">
                <Chip tone={sevTone(m.severity)} title={SEVERITY[m.severity] ?? `Severity ${m.severity}`}><span className="ee-mono text-[12px]">{m.tag}</span></Chip>
                {m.count > 1 && <span className="ml-1.5 ee-small ee-ink-2 ee-num" title={`${m.count} times since ${fmtStamp(m.first_at)}`}>×{m.count}</span>}
              </td>
              <td className="whitespace-nowrap align-top text-[12.5px]">
                {m.port && <span className="block ee-mono">{m.port}</span>}
                {m.mac && <span className="block ee-mono">{macText(m.mac)}</span>}
                {!m.port && !m.mac && m.subject && <span className="block ee-ink-2">{m.subject}</span>}
              </td>
              <td className="align-top"><p className="ee-mono text-[12.5px] break-words whitespace-pre-wrap">{m.text}</p></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function DeviceCounters({ devices, now, onPick }: { devices: LiveDevice[]; now: Date; onPick: (id: string) => void }) {
  const { tid } = useTenant()
  const quiet = devices.filter((d) => !d.sends)
  return (
    <Panel className="p-4 sm:p-5" aria-labelledby="dsl-dev-h">
      <h2 id="dsl-dev-h" className="ee-h3 mb-2">Today, per device</h2>
      <div className="overflow-x-auto">
        <table className="ee-table">
          <thead><tr><th>Device</th><th>Sends from</th><th className="ee-right">Received</th><th className="ee-right">Kept</th><th className="ee-right">Over the limit</th><th>Last message</th></tr></thead>
          <tbody>
            {devices.filter((d) => d.sends).map((d) => (
              <tr key={d.id} data-clickable="true" onClick={() => onPick(d.id)}>
                <td><button type="button" className="text-left underline-offset-2 hover:underline" onClick={(e) => { e.stopPropagation(); onPick(d.id) }}>{d.name}</button>
                  <span className="block ee-small ee-ink-3">{vendorLabels[d.vendor] ?? d.vendor}{d.via_audit ? ' · switch audit' : ''}</span></td>
                <td className="ee-mono text-[12.5px]">{[d.address, ...d.addresses].join(', ')}</td>
                <td className="ee-right ee-num">{fmtCount(d.stats.received ?? 0)}</td>
                <td className="ee-right ee-num">{fmtCount(d.stats.kept ?? 0)}</td>
                <td className="ee-right ee-num">{d.stats.quota ? <span className="text-[var(--ee-warn)]">{fmtCount(d.stats.quota)}</span> : '0'}</td>
                <td className="ee-small">{d.stats.last_at ? <>{ago(d.stats.last_at, now)}{d.stats.last_tag && <span className="ee-mono ee-ink-3"> · {d.stats.last_tag}</span>}</> : <span className="ee-ink-3">Nothing today</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {quiet.length > 0 && (
        <p className="ee-small ee-ink-3 mt-3">
          Not sending: {quiet.slice(0, 8).map((d) => d.name).join(', ')}{quiet.length > 8 ? ` and ${quiet.length - 8} more` : ''}. Turn syslog on
          in <Link className="underline underline-offset-2" to={paths.radius(tid)}>RADIUS</Link> (select the device, then Syslog).
        </p>
      )}
    </Panel>
  )
}

const whyText: Record<string, string> = {
  unknown: 'Not a registered device',
  ambiguous: 'Matches devices of more than one tenant',
  disabled: 'A device with syslog off',
}

function UnknownBox({ u, now }: { u: UnknownSources; now: Date }) {
  if (!u.top.length && !u.kernel_drops) return null
  return (
    <Panel className="p-4 sm:p-5" aria-labelledby="dsl-unk-h">
      <h2 id="dsl-unk-h" className="ee-h3">Syslog from other addresses</h2>
      <p className="ee-small ee-ink-3 mt-1 mb-2">
        MSP operators only, across every tenant, since the receiver started{u.at ? ` (as of ${ago(u.at, now)})` : ''}: messages that weren’t kept because
        their source isn’t a device with syslog on. A device that sends from another interface needs that address added to its syslog addresses.
        {u.kernel_drops ? ` The server dropped ${fmtCount(u.kernel_drops)} datagrams before the receiver read them (it’s overloaded).` : ''}
      </p>
      {u.top.length > 0 && (
        <div className="overflow-x-auto">
          <table className="ee-table">
            <thead><tr><th>Address</th><th>Why</th><th className="ee-right">Messages</th><th>Example</th></tr></thead>
            <tbody>
              {u.top.map((t) => (
                <tr key={t.address}>
                  <td className="ee-mono text-[12.5px]">{t.address}</td>
                  <td className="whitespace-nowrap ee-small">{whyText[t.why] ?? t.why}</td>
                  <td className="ee-right ee-num">{fmtCount(t.count)}</td>
                  <td className="ee-mono text-[12px] ee-ink-2 break-all">{t.sample}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
