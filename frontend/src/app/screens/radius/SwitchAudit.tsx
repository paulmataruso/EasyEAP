// Switch audit (docs/plans/switch-audit.md §7): a Cisco switch's SNMP monitoring, what it reports about its ports and
// 802.1X/MAB sessions, and the findings where that differs from what EasyEAP decided and sent.
// The community or SNMPv3 keys are returned once by setup; like a RADIUS shared secret they're kept only in the setup
// dialog's state, filled into the configuration block in the browser, and dropped when the dialog closes.
import { useEffect, useId, useState } from 'react'
import { Activity, Check, Eye, EyeOff, MessageSquareText, RefreshCw, Settings2, ShieldAlert, Trash2 } from 'lucide-react'
import { errorField } from '../../api/client'
import type { RadiusClient } from '../../api/radius'
import {
  AUTH_PLACEHOLDER, COMMUNITY_PLACEHOLDER, PRIV_PLACEHOLDER, fillCredentials, findingTitles, useAckFinding, useMonitoring, usePollNow, useRemoveMonitoring,
  useSetupMonitoring, useTestMonitoring, useUpdateMonitoring,
  type Finding, type MonitoringInput, type MonitoringResponse, type SetupResult, type SnmpVersion, type SyslogLine, type TestResult,
} from '../../api/switchAudit'
import { useTenant } from '../../api/tenant'
import { ago, fmtDateTime } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { Btn, Callout, Chip, CopyButton, EDialog, ESelect, ESwitch, ErrorState, Field, LoadingBlock, OneTimeSecret, Seg, SeverityChip, errorMessage, toast } from '../../ui'
import { Marked } from './Guide'

const macText = (m: string | null) => (m && m.length === 12 ? m.match(/../g)!.join(':') : m ?? '')
const INTERVALS = [5, 10, 15, 30, 60]

function detailText(f: Finding): string | null {
  const d = f.detail as Record<string, unknown>
  switch (f.kind) {
    case 'vlan_mismatch': return `EasyEAP sent VLAN ${d.sent}; the switch has it in ${d.vlan ?? 'no assigned VLAN'}.`
    case 'authorized_after_deny': return `EasyEAP would refuse it now: ${d.reason}.`
    case 'authorized_despite_reject': return d.reason_code ? `EasyEAP’s latest answer: rejected (${d.reason_code}).` : 'EasyEAP’s latest answer: rejected.'
    case 'authorized_without_easyeap': return d.authorized_by ? `The switch says it was authorized by “${d.authorized_by}”.` : null
    case 'err_disabled': return `Cause: ${d.cause}.`
    case 'port_not_covered': return d.control ? `Port control: ${d.control}.` : 'The switch reports no 802.1X settings for it.'
    case 'switch_changed': {
      const parts: string[] = []
      const s = d.serial as { was: string; now: string } | undefined
      const e = d.engine_id as { was: string; now: string } | undefined
      if (s) parts.push(`serial ${s.was} → ${s.now}`)
      if (e) parts.push(`SNMP engine ID ${e.was} → ${e.now}`)
      return parts.join('; ')
    }
    case 'snmp_unreachable': case 'snmp_auth': return typeof d.error === 'string' ? d.error : null
    case 'caf_missing': return d.version ? `IOS-XE ${d.version}.` : null
    default: return null
  }
}

export function SwitchAuditPanel({ client }: { client: RadiusClient }) {
  const { tid, can } = useTenant()
  const q = useMonitoring(tid, client.id)
  const poll = usePollNow(tid, client.id)
  const now = useNow(30_000)
  const [setup, setSetup] = useState(false)
  const [settings, setSettings] = useState(false)
  const [ack, setAck] = useState<Finding | null>(null)
  const [details, setDetails] = useState(false)
  const [said, setSaid] = useState(false)
  const write = can('radius:write')
  const secrets = can('radius:secrets')
  if (q.isLoading) return <LoadingBlock rows={2} label="Loading the switch audit" />
  if (q.error || !q.data) return <ErrorState error={q.error} onRetry={() => q.refetch()} title="The switch audit couldn’t be loaded" />
  const r = q.data
  const mon = r.monitoring
  const st = r.state
  const open = r.findings.filter((f) => !f.acknowledged_at)
  const acked = r.findings.filter((f) => f.acknowledged_at)
  const crit = open.filter((f) => f.severity === 'critical').length
  return (
    <section aria-label="Switch audit" className="space-y-3 rounded-[10px] border border-[var(--ee-line)] px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 max-w-[72ch]">
          <p className="flex flex-wrap items-center gap-2 text-[13px] font-semibold">
            <Activity className="size-4 ee-ink-3" aria-hidden /><span>Switch audit</span>
            {!mon.set_up ? <Chip tone="neutral">Off</Chip>
              : !mon.enabled ? <Chip tone="gold">Not polling</Chip>
                : st && !st.ok ? <Chip tone="crit">Can’t reach the switch</Chip>
                  : crit ? <Chip tone="crit">{crit} critical</Chip>
                    : open.length ? <Chip tone="warn">{open.length} to review</Chip>
                      : st ? <Chip tone="valid" icon={<Check aria-hidden />}>Matches EasyEAP</Chip> : <Chip tone="neutral">Waiting for the first poll</Chip>}
          </p>
          <p className="ee-small ee-ink-3 mt-0.5">
            {!mon.set_up
              ? 'EasyEAP can read this switch’s 802.1X sessions over SNMP (read-only) and compare them with its own answers: unprotected ports, devices it never accepted, VLANs that don’t match.'
              : <>
                {st ? <>Polled {ago(st.polled_at, now)}{st.ok && st.facts.model ? ` · ${st.facts.model}` : ''}{st.ok && st.facts.version ? ` · IOS-XE ${st.facts.version}` : ''}. </> : 'Not polled yet. '}
                SNMP{mon.version === 'v3' ? 'v3' : 'v2c'} to <span className="ee-mono">{mon.host}</span> every {mon.interval_minutes} minutes{mon.enabled ? '' : ' (turned off)'}.
                {st?.slow && ' Polls take a long time on this switch, so it’s polled half as often.'}
              </>}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {!mon.set_up && secrets && <Btn size="sm" onClick={() => setSetup(true)}><Activity aria-hidden />Set up monitoring…</Btn>}
          {mon.set_up && mon.enabled && write && (
            <Btn size="sm" busy={poll.isPending} disabled={!!r.poll_requested_at} onClick={() => poll.mutate(undefined, { onError: (e) => toast('The switch wasn’t polled', errorMessage(e), 'warn') })}>
              <RefreshCw aria-hidden />{r.poll_requested_at ? 'Polling…' : 'Poll now'}
            </Btn>
          )}
          {mon.set_up && write && <Btn size="sm" onClick={() => setSettings(true)}><Settings2 aria-hidden />Settings…</Btn>}
        </div>
      </div>

      {mon.set_up && mon.enabled && !r.collector.alive && (
        <Callout tone="warn" title="The switch collector isn’t running">
          Nothing is polled until it is. On the EasyEAP server: <span className="ee-mono">docker compose up -d easyeap-collector</span> (System health shows its last heartbeat).
        </Callout>
      )}
      {r.syslog?.radius_down.map((d) => (
        <Callout key={d.id} tone={d.ours ? 'warn' : 'neutral'}
          title={d.server === null ? 'The switch says no RADIUS server is responding'
            : d.ours ? 'The switch says EasyEAP’s RADIUS server isn’t responding' : `The switch says RADIUS server ${d.server} isn’t responding`}>
          {d.text} ({ago(d.last_at, now)}).{' '}
          {d.ours
            ? 'Until the switch reaches it again it may admit devices on its own (critical authentication) or turn them away. Check System health and that the switch can reach EasyEAP’s RADIUS address.'
            : 'It isn’t EasyEAP’s address; if the switch is still configured to use it, remove it from the switch’s RADIUS group.'}{' '}
          Syslog isn’t authenticated: this is what a message from the switch’s address says.
        </Callout>
      ))}
      {mon.set_up && !mon.enabled && (
        <Callout tone="neutral" title="Monitoring is set up but not polling" action={write ? <Btn size="sm" onClick={() => setSetup(true)}>Test connection…</Btn> : undefined}>
          It turns on when Test connection reaches the switch, or from Settings.
        </Callout>
      )}

      {r.findings.length > 0 && (
        <ul className="divide-y divide-[var(--ee-line)] rounded-[8px] border border-[var(--ee-line)]" aria-label="Findings">
          {[...open, ...acked].map((f) => (
            <li key={f.id} className="grid gap-1 px-3 py-2.5 sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-4">
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-[13px]">
                  <SeverityChip severity={f.severity} />
                  <span className="font-semibold">{findingTitles[f.kind] ?? f.kind}</span>
                  {f.port && <span className="ee-mono text-[12.5px]">{f.port}</span>}
                  {f.mac && <span className="ee-mono text-[12.5px] ee-ink-2">{macText(f.mac)}</span>}
                  {f.acknowledged_at && <Chip tone="neutral">Acknowledged</Chip>}
                </p>
                <p className="ee-small ee-ink-2 mt-0.5">{f.meaning} {detailText(f)}</p>
                <p className="ee-small ee-ink-3 mt-0.5">{f.fix}</p>
                {(f.switch_says?.length ?? 0) > 0 && <SwitchSays lines={f.switch_says!} now={now} compact />}
                {f.acknowledged_at && <p className="ee-small ee-ink-3 mt-0.5">Acknowledged by {f.acknowledged_by} {ago(f.acknowledged_at, now)}{f.ack_note ? `: “${f.ack_note}”` : ''}.</p>}
                <p className="ee-small ee-ink-3 mt-0.5">Since {fmtDateTime(f.opened_at ?? f.first_seen_at)}</p>
              </div>
              {write && !f.acknowledged_at && <div><Btn size="sm" variant="ghost" onClick={() => setAck(f)}>Acknowledge…</Btn></div>}
            </li>
          ))}
        </ul>
      )}
      {r.pending > 0 && <p className="ee-small ee-ink-3">{r.pending} more difference{r.pending === 1 ? '' : 's'} seen once: shown if the next poll confirms {r.pending === 1 ? 'it' : 'them'}.</p>}
      {st && !st.ok && r.findings.every((f) => !f.kind.startsWith('snmp_')) && <Callout tone="warn" title="The last poll failed">{st.error}</Callout>}
      {st?.ok && st.capabilities.caf === false && r.findings.every((f) => f.kind !== 'caf_missing') && (
        <Callout tone="neutral">This switch doesn’t report its 802.1X sessions over SNMP, so only reachability and err-disabled ports are checked.</Callout>
      )}

      {st?.ok && st.ports.length > 0 && (
        <div>
          <Btn size="sm" variant="ghost" onClick={() => setDetails((v) => !v)} aria-expanded={details}>
            {details ? <EyeOff aria-hidden /> : <Eye aria-hidden />}{details ? 'Hide ports and sessions' : `Show ports and sessions (${st.sessions.length})`}
          </Btn>
          {details && <PortTable data={r} />}
        </div>
      )}

      {mon.set_up && r.syslog && (
        <div>
          <Btn size="sm" variant="ghost" onClick={() => setSaid((v) => !v)} aria-expanded={said}>
            <MessageSquareText aria-hidden />{said ? 'Hide what the switch says' : `What the switch says (${r.syslog.recent.length})`}
          </Btn>
          {said && <SyslogSection data={r} now={now} />}
        </div>
      )}

      {r.resolved.length > 0 && details && (
        <div className="ee-small ee-ink-3">
          <p className="font-semibold ee-ink-2">Recently resolved</p>
          <ul className="mt-1 space-y-0.5">{r.resolved.slice(0, 10).map((f) => <li key={f.id}>{findingTitles[f.kind] ?? f.kind}{f.port ? ` · ${f.port}` : ''}{f.mac ? ` · ${macText(f.mac)}` : ''} · {ago(f.resolved_at, now)}</li>)}</ul>
        </div>
      )}

      <SetupDialog client={client} data={r} open={setup} onClose={() => setSetup(false)} />
      <SettingsDialog client={client} data={r} open={settings} onClose={() => setSettings(false)} onReconfigure={() => { setSettings(false); setSetup(true) }} />
      <AckDialog client={client} finding={ack} onClose={() => setAck(null)} />
    </section>
  )
}

function SwitchSays({ lines, now, compact }: { lines: SyslogLine[]; now: Date; compact?: boolean }) {
  return (
    <ul className={`ee-small ${compact ? 'mt-1 ee-ink-3' : 'ee-ink-2'} space-y-0.5`} aria-label="What the switch says">
      {lines.map((l) => (
        <li key={l.id} className="min-w-0 break-words">
          {compact && 'The switch says: '}<span className="ee-mono text-[12px]">{l.tag}</span>{l.count > 1 && ` ×${l.count}`} · {ago(l.last_at, now)}
          {!compact && l.port && <> · <span className="ee-mono text-[12px]">{l.port}</span></>}
          {!compact && l.mac && <> · <span className="ee-mono text-[12px]">{macText(l.mac)}</span></>}
          {' · '}{l.text}
        </li>
      ))}
    </ul>
  )
}

function SyslogSection({ data, now }: { data: MonitoringResponse; now: Date }) {
  const sl = data.syslog!
  const st = sl.stats
  return (
    <div className="mt-2 space-y-2 rounded-[8px] border border-[var(--ee-line)] px-3 py-2.5">
      <p className="ee-small ee-ink-3">
        Syslog from the switch: the 802.1X, MAB, err-disable, RADIUS server and configuration messages of the last 24 hours. Syslog isn’t
        authenticated, so a message is never a finding on its own; err-disable, security-violation and configuration messages bring the
        next poll forward (to five minutes after the last one at the earliest).
      </p>
      {!sl.receiving ? (
        <Callout tone="neutral" title="This server doesn’t receive syslog">
          Set <span className="ee-mono">EASYEAP_SYSLOG_BIND</span> in the server’s <span className="ee-mono">.env</span> to the address switches reach
          EasyEAP on, then <span className="ee-mono">docker compose up -d</span>. The switch configuration then includes the logging lines.
        </Callout>
      ) : !sl.listening ? (
        <Callout tone="warn" title="The syslog receiver isn’t running">
          Messages from the switch are lost until it is. On the EasyEAP server: <span className="ee-mono">docker compose up -d easyeap-syslog</span> (System
          health shows its last heartbeat).
        </Callout>
      ) : !st.last_at ? (
        <p className="ee-small ee-ink-2">
          Nothing from this switch yet. The configuration (Settings → Show the configuration) has the <span className="ee-mono">logging</span> lines,
          sending to <span className="ee-mono">{sl.address}</span> on UDP port {sl.port}. EasyEAP keeps only messages sent from the address it
          polls, <span className="ee-mono">{data.monitoring.host}</span>, once a poll has succeeded; a switch that sends from another interface
          needs <span className="ee-mono">logging source-interface</span> (it’s in the configuration as a comment).
        </p>
      ) : (
        <p className="ee-small ee-ink-2">
          Last message {ago(st.last_at, now)}{st.last_tag ? ` (${st.last_tag})` : ''}. Today: {st.kept ?? 0} kept, {st.filtered ?? 0} not about access
          {st.quota ? `, ${st.quota} dropped over the rate limit` : ''}.
        </p>
      )}
      {sl.recent.length > 0 && <SwitchSays lines={sl.recent} now={now} />}
    </div>
  )
}

function PortTable({ data }: { data: MonitoringResponse }) {
  const st = data.state!
  const byPort = new Map<string, typeof st.sessions>()
  for (const s of st.sessions) byPort.set(s.port, [...(byPort.get(s.port) ?? []), s])
  const flagged = new Set(data.findings.map((f) => f.port).filter(Boolean))
  return (
    <div className="mt-2 max-h-[360px] overflow-auto rounded-[8px] border border-[var(--ee-line)]">
      <table className="ee-table">
        <caption className="sr-only">Ports and sessions the switch reported at its latest poll</caption>
        <thead><tr><th>Port</th><th>802.1X</th><th>Sessions</th></tr></thead>
        <tbody>
          {st.ports.map((p) => {
            const sessions = byPort.get(p.name) ?? []
            return (
              <tr key={p.if_index} className={flagged.has(p.name) ? 'bg-[rgba(226,120,100,0.06)]' : undefined}>
                <td className="whitespace-nowrap text-[12.5px]"><span className="ee-mono">{p.short || p.name}</span>{p.alias && <span className="ee-ink-3"> · {p.alias}</span>}{p.oper === 'down' && <span className="ee-ink-3"> · down</span>}</td>
                <td className="text-[12.5px]">
                  {p.err_disabled ? <Chip tone="crit">err-disabled: {p.err_disabled}</Chip>
                    : !p.auth ? <span className="ee-ink-3">—</span>
                      : p.auth.control === 'auto' ? <>{p.auth.open ? 'Open' : 'Closed'}{p.auth.host_mode ? ` · ${p.auth.host_mode}` : ''}</>
                        : <span className="ee-ink-3">{p.auth.control ?? '—'}</span>}
                </td>
                <td className="text-[12.5px]">
                  {sessions.length === 0 ? <span className="ee-ink-3">—</span> : (
                    <ul className="space-y-0.5">
                      {sessions.map((s) => (
                        <li key={s.id}><span className="ee-mono">{macText(s.mac)}</span> · {s.method ?? '—'}{s.user ? ` · ${s.user}` : ''}{s.vlan ? ` · VLAN ${s.vlan}` : ''}{s.domain === 'voice' ? ' · voice' : ''} · {s.authorized ? <span className="text-[var(--ee-valid-ink)]">authorized</span> : s.status}</li>
                      ))}
                    </ul>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {st.truncated && <p className="ee-small ee-ink-3 px-3 py-2">The switch reported more than EasyEAP keeps: the list is shortened.</p>}
    </div>
  )
}

function SetupDialog({ client, data, open, onClose }: { client: RadiusClient; data: MonitoringResponse; open: boolean; onClose: () => void }) {
  const { tid, can } = useTenant()
  const id = useId()
  const setupM = useSetupMonitoring(tid, client.id)
  const test = useTestMonitoring(tid, client.id)
  const mon = data.monitoring
  const blank = (): MonitoringInput => ({ host: mon.host ?? data.default_host ?? '', version: mon.set_up ? mon.version : 'v2c', user: mon.user, auth: mon.auth, priv: mon.priv, interval_minutes: mon.interval_minutes })
  const [form, setForm] = useState<MonitoringInput>(blank)
  const [result, setResult] = useState<SetupResult | null>(null)
  const [saved, setSaved] = useState(false)
  const [fieldErr, setFieldErr] = useState<{ field: string; message: string } | null>(null)
  const [tested, setTested] = useState<TestResult | null>(null)
  // A switch already set up opens on Test connection; new credentials are a deliberate second step.
  const [mode, setMode] = useState<'form' | 'test'>(mon.set_up ? 'test' : 'form')
  useEffect(() => {
    if (open) { setForm(blank()); setMode(mon.set_up ? 'test' : 'form'); return }
    const t = setTimeout(() => { setResult(null); setSaved(false); setFieldErr(null); setTested(null); test.reset(); setupM.reset() }, 200)  // the one-time credentials go with the dialog
    return () => clearTimeout(t)
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps
  const config = result ? fillCredentials(result.config, result.credentials) : data.config ?? ''
  const secretValue = result ? (result.credentials.community ?? `${result.credentials.auth_key}  ${result.credentials.priv_key}`) : ''
  const submit = () => setupM.mutate(form, {
    onSuccess: (r) => { setResult(r); setMode('test'); setFieldErr(null) },
    onError: (e) => { const f = errorField(e); if (f) setFieldErr({ field: f, message: errorMessage(e) }); else toast('Monitoring wasn’t set up', errorMessage(e), 'crit') },
  })
  const runTest = () => test.mutate(undefined, { onSuccess: (r) => setTested(r), onError: (e) => toast('The test didn’t run', errorMessage(e), 'crit') })
  const err = (f: string) => (fieldErr?.field === f ? fieldErr.message : null)
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} wide risk={result ? 'gold' : undefined}
      title={mode === 'form' ? `Set up monitoring for ${client.name}` : `Configure SNMP on ${client.name}`}
      description={mode === 'form' ? 'Read-only SNMP from EasyEAP’s address to the six tables the audit reads. EasyEAP generates the credentials.' : 'Paste the block on the switch, then test the connection. Monitoring turns on when the test reaches the switch.'}
      footer={mode === 'form' ? (
        <>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="primary" busy={setupM.isPending} disabled={!form.host.trim()} onClick={submit}>Generate credentials and the configuration</Btn>
        </>
      ) : (
        <>
          {!result && can('radius:secrets') && <Btn variant="ghost" onClick={() => setMode('form')}>New credentials…</Btn>}
          <Btn onClick={onClose} disabled={!!result && !saved && !tested?.ok}>{tested?.ok ? 'Done' : 'Close'}</Btn>
          <Btn variant="primary" busy={test.isPending} onClick={runTest}><Activity aria-hidden />Test connection</Btn>
        </>
      )}>
      {mode === 'form' ? (
        <div className="space-y-4">
          <Field label="Switch management address" htmlFor={`${id}-host`} error={err('host')}
            hint="The address EasyEAP polls: the switch’s management IP. It can differ from the address it sends RADIUS from.">
            <input id={`${id}-host`} className="ee-input ee-mono max-w-[260px]" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.2" autoComplete="off" spellCheck={false} />
          </Field>
          <div className="space-y-1.5">
            <p className="ee-label">SNMP version</p>
            <Seg<SnmpVersion> label="SNMP version" value={form.version} onChange={(v) => setForm({ ...form, version: v })}
              options={[{ value: 'v2c', label: 'SNMPv2c' }, { value: 'v3', label: 'SNMPv3 (encrypted)' }]} />
            <p className="ee-small ee-ink-3">
              {form.version === 'v2c'
                ? 'The community travels in clear text, so EasyEAP generates a long random one, and the configuration limits it to a read-only view and to EasyEAP’s address.'
                : 'Requests are authenticated and encrypted, and no community crosses the network. The user’s keys aren’t stored in the switch’s running configuration.'}
            </p>
          </div>
          {form.version === 'v3' && (
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="User" htmlFor={`${id}-user`} error={err('user')}>
                <input id={`${id}-user`} className="ee-input ee-mono" value={form.user ?? 'easyeap'} onChange={(e) => setForm({ ...form, user: e.target.value })} autoComplete="off" spellCheck={false} />
              </Field>
              <Field label="Authentication" htmlFor={`${id}-auth`} hint={form.auth === 'sha' ? 'For IOS-XE before 16.10.' : undefined}>
                <ESelect id={`${id}-auth`} label="Authentication" value={form.auth ?? 'sha'} onChange={(v) => setForm({ ...form, auth: v as 'sha256' | 'sha', priv: v === 'sha' ? 'aes128' : form.priv })}
                  options={[{ value: 'sha', label: 'SHA-1 (every IOS-XE)' }, { value: 'sha256', label: 'SHA-256 (IOS XE 17.10 or later, where offered)' }]} />
              </Field>
              <Field label="Privacy" htmlFor={`${id}-priv`} error={err('priv')}>
                <ESelect id={`${id}-priv`} label="Privacy" value={form.priv ?? 'aes128'} onChange={(v) => setForm({ ...form, priv: v as 'aes128' | 'aes256' })}
                  options={[{ value: 'aes128', label: 'AES-128' }, { value: 'aes256', label: 'AES-256', disabled: form.auth === 'sha' }]} />
              </Field>
            </div>
          )}
          <Field label="Poll every" htmlFor={`${id}-int`}>
            <ESelect id={`${id}-int`} label="Poll every" className="max-w-[180px]" value={String(form.interval_minutes)} onChange={(v) => setForm({ ...form, interval_minutes: Number(v) })}
              options={INTERVALS.map((n) => ({ value: String(n), label: `${n} minutes` }))} />
          </Field>
          {mon.set_up && <Callout tone="warn">New credentials replace the current ones: polling stops until the switch has the new block and the test passes.</Callout>}
        </div>
      ) : (
        <div className="space-y-5">
          {result && (
            <section aria-label="Credentials">
              <p className="text-[13px] font-semibold mb-2">{result.credentials.community ? 'The community' : `The keys for SNMPv3 user ${result.credentials.user}`}</p>
              <OneTimeSecret value={secretValue} what={result.credentials.community ? 'SNMP community' : 'SNMPv3 keys'} acknowledged={saved} onAcknowledge={setSaved}
                note={<>EasyEAP shows {result.credentials.community ? 'this community' : 'these keys'} once; they’re filled into the block below while this dialog is open. If they’re lost, generate new ones.</>} />
            </section>
          )}
          {result?.retire && (
            <section aria-label="Remove the old credentials">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <p className="text-[13px] font-semibold">First, remove the old credentials</p>
                <CopyButton text={result.retire} what="removal lines" label="Copy" />
              </div>
              <pre className="ee-code overflow-auto" tabIndex={0} aria-label="Lines that remove the old credentials">{result.retire}</pre>
            </section>
          )}
          {config && (
            <section aria-label="Configuration">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <p className="text-[13px] font-semibold">Paste on the switch</p>
                <CopyButton text={config} what="SNMP configuration" label="Copy configuration" />
              </div>
              <pre className="ee-code max-h-[320px] overflow-auto" tabIndex={0} aria-label="SNMP configuration"><Marked text={config} /></pre>
              {!result && [COMMUNITY_PLACEHOLDER, AUTH_PLACEHOLDER, PRIV_PLACEHOLDER].some((p) => config.includes(p)) && (
                <p className="ee-small ee-ink-3 mt-1">The highlighted values are the credentials EasyEAP showed when monitoring was set up; it never shows them again. Generate new ones if they’re lost.</p>
              )}
              {!data.source_address && <p className="ee-small ee-ink-3 mt-1">Replace <span className="ee-mono">&lt;EasyEAP’s address&gt;</span> with the address the switch sees EasyEAP’s requests come from.</p>}
            </section>
          )}
          {tested && (tested.ok ? (
            <Callout tone="valid" title="EasyEAP reached the switch: monitoring is on">
              {[tested.facts?.model, tested.facts?.version ? `IOS-XE ${tested.facts.version}` : null, tested.facts?.serial ? `serial ${tested.facts.serial}` : null].filter(Boolean).join(' · ')}.
              {tested.capabilities?.caf ? ' It reports its 802.1X sessions, so every check runs.' : ' It doesn’t report its 802.1X sessions over SNMP: only reachability and err-disabled ports can be checked.'}
              {' '}The first poll runs within a minute.
            </Callout>
          ) : (
            <Callout tone="crit" title={tested.error_kind === 'auth' ? 'The switch refused the credentials' : tested.error_kind === 'timeout' ? 'No answer from the switch' : 'The test failed'}>
              {tested.error} {tested.error_kind === 'timeout' && 'Check the address, that UDP 161 is open from EasyEAP, and that the ACL in the block names the address EasyEAP’s requests come from.'}
            </Callout>
          ))}
        </div>
      )}
    </EDialog>
  )
}

function SettingsDialog({ client, data, open, onClose, onReconfigure }: { client: RadiusClient; data: MonitoringResponse; open: boolean; onClose: () => void; onReconfigure: () => void }) {
  const { tid, can } = useTenant()
  const id = useId()
  const update = useUpdateMonitoring(tid, client.id)
  const remove = useRemoveMonitoring(tid, client.id)
  const mon = data.monitoring
  const [host, setHost] = useState(mon.host ?? '')
  const [interval, setInterval_] = useState(mon.interval_minutes)
  const [enabled, setEnabled] = useState(mon.enabled)
  const [removal, setRemoval] = useState<string | null>(null)
  const [confirmRemove, setConfirmRemove] = useState(false)
  useEffect(() => {
    if (open) { setHost(mon.host ?? ''); setInterval_(mon.interval_minutes); setEnabled(mon.enabled); return }
    const t = setTimeout(() => { setRemoval(null); setConfirmRemove(false) }, 200)
    return () => clearTimeout(t)
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps
  const save = () => update.mutate({ host: host.trim(), interval_minutes: interval, enabled }, {
    onSuccess: () => { toast('Monitoring settings saved'); onClose() },
    onError: (e) => toast('The settings weren’t saved', errorMessage(e), 'crit'),
  })
  const doRemove = () => remove.mutate(undefined, {
    onSuccess: (r) => setRemoval(r.removal ?? ''),
    onError: (e) => toast('Monitoring wasn’t removed', errorMessage(e), 'crit'),
  })
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} risk={confirmRemove || removal !== null ? 'warn' : undefined}
      title={removal !== null ? `Remove EasyEAP’s SNMP access from ${client.name}` : `Switch audit settings for ${client.name}`}
      description={removal !== null ? 'EasyEAP no longer polls this switch and has forgotten its credentials. Paste these lines to take its access off the switch.' : undefined}
      footer={removal !== null ? <Btn variant="primary" onClick={onClose}>Done</Btn> : confirmRemove ? (
        <>
          <Btn variant="ghost" onClick={() => setConfirmRemove(false)}>Back</Btn>
          <Btn variant="danger" busy={remove.isPending} onClick={doRemove}><Trash2 aria-hidden />Remove monitoring</Btn>
        </>
      ) : (
        <>
          <Btn variant="ghost" onClick={() => setConfirmRemove(true)}><Trash2 aria-hidden />Remove…</Btn>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="primary" busy={update.isPending} onClick={save}>Save</Btn>
        </>
      )}>
      {removal !== null ? (
        <div className="space-y-2">
          <div className="flex justify-end"><CopyButton text={removal} what="removal lines" label="Copy" /></div>
          <pre className="ee-code overflow-auto" tabIndex={0} aria-label="Removal lines"><Marked text={removal} /></pre>
          {mon.version === 'v2c' && <p className="ee-small ee-ink-3">Replace <span className="ee-mono">&lt;community&gt;</span> with the community EasyEAP generated (<span className="ee-mono">show running-config | include snmp-server community</span>).</p>}
        </div>
      ) : confirmRemove ? (
        <p className="text-[13.5px] ee-ink-2">EasyEAP stops polling {client.name}, forgets its SNMP credentials and resolves its open findings. Their history stays for 90 days.</p>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3">
            <span className="text-[13.5px]">Poll this switch</span>
            <ESwitch label="Poll this switch" checked={enabled} onChange={setEnabled} />
          </div>
          <Field label="Switch management address" htmlFor={`${id}-host`}
            hint={can('radius:secrets') ? 'Changing it forgets the switch’s pinned serial number.' : 'Changing it needs the permission to see the SNMP credentials, which would go to the new address.'}>
            <input id={`${id}-host`} className="ee-input ee-mono max-w-[260px]" value={host} onChange={(e) => setHost(e.target.value)} autoComplete="off" spellCheck={false}
              readOnly={!can('radius:secrets')} />
          </Field>
          <Field label="Poll every" htmlFor={`${id}-int`}>
            <ESelect id={`${id}-int`} label="Poll every" className="max-w-[180px]" value={String(interval)} onChange={(v) => setInterval_(Number(v))}
              options={INTERVALS.map((n) => ({ value: String(n), label: `${n} minutes` }))} />
          </Field>
          <p className="ee-small ee-ink-3">
            SNMP{mon.version} {mon.version === 'v3' ? `user ${mon.user} (${mon.auth === 'sha256' ? 'SHA-256' : 'SHA-1'}, ${mon.priv === 'aes256' ? 'AES-256' : 'AES-128'})` : 'community'}
            {mon.credentials_set_at ? `, generated ${fmtDateTime(mon.credentials_set_at)}` : ''}.
            {can('radius:secrets') && <> <button type="button" className="underline decoration-[var(--ee-line-3)] underline-offset-2" onClick={onReconfigure}>Show the configuration, or generate new credentials</button>.</>}
          </p>
        </div>
      )}
    </EDialog>
  )
}

function AckDialog({ client, finding, onClose }: { client: RadiusClient; finding: Finding | null; onClose: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const ackM = useAckFinding(tid, client.id)
  const [note, setNote] = useState('')
  const [shown, setShown] = useState<Finding | null>(finding)
  useEffect(() => {
    if (finding) { setShown(finding); setNote(''); return }
  }, [finding])
  const f = finding ?? shown
  const sticky = f?.kind === 'switch_changed'
  return (
    <EDialog open={!!finding} onOpenChange={(o) => !o && onClose()} risk="gold"
      title={sticky ? 'Accept the switch that answers now?' : 'Acknowledge this finding?'}
      description={sticky ? 'EasyEAP pins its serial number (and SNMP engine ID) and closes the finding.' : 'It leaves the dashboard until its details change. It stays on this switch’s audit, marked acknowledged.'}
      footer={(
        <>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="primary" busy={ackM.isPending} onClick={() => f && ackM.mutate({ id: f.id, note: note.trim() }, {
            onSuccess: () => { toast(sticky ? 'Switch accepted' : 'Finding acknowledged'); onClose() },
            onError: (e) => toast('That wasn’t saved', errorMessage(e), 'crit'),
          })}><ShieldAlert aria-hidden />{sticky ? 'Accept' : 'Acknowledge'}</Btn>
        </>
      )}>
      {f && (
        <div className="space-y-3">
          <p className="text-[13.5px]"><span className="font-semibold">{findingTitles[f.kind] ?? f.kind}</span>{f.port ? ` · ${f.port}` : ''}{f.mac ? ` · ${macText(f.mac)}` : ''}</p>
          <Field label="Note" htmlFor={`${id}-note`} optional hint="Why it’s expected, for whoever looks next.">
            <textarea id={`${id}-note`} className="ee-input min-h-[72px] text-[13px]" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
        </div>
      )}
    </EDialog>
  )
}
