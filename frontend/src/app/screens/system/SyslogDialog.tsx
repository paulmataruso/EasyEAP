// Add or edit a remote syslog destination, with a test message sent from the server before saving.
import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Save, Send } from 'lucide-react'
import { defaultPort, syslogApi, syslogKey, type SyslogCategory, type SyslogDestination, type SyslogDestinationInput, type SyslogTransport } from '../../api/logs'
import { Btn, Callout, EDialog, ESelect, ESwitch, errorMessage, Field, Seg, toast } from '../../ui'

const blank: SyslogDestinationInput = {
  name: '', host: '', port: 6514, transport: 'tls', format: 'rfc5424', body: 'text', framing: 'octet', facility: 'local0',
  categories: ['audit', 'auth', 'system'], system_level: 'info', ca_pem: null, enabled: true,
}

const CATEGORY_HELP: Record<SyslogCategory, [string, string]> = {
  audit: ['Audit trail', 'Every administrator and system action, as in the audit log.'],
  auth: ['Authentication events', 'Every RADIUS accept and reject, with the reason, user, device and VLAN.'],
  system: ['System log', 'Messages from the API, worker, RADIUS agent and FreeRADIUS.'],
}

const facilityLabel = (f: string) => ({ user: 'user (1)', daemon: 'daemon (3)', auth: 'auth (4)', authpriv: 'authpriv (10)' } as Record<string, string>)[f] ?? `${f} (${16 + Number(f.replace('local', ''))})`

export function SyslogDialog({ open, onOpenChange, editing, facilities }: { open: boolean; onOpenChange: (o: boolean) => void; editing: SyslogDestination | null; facilities: string[] }) {
  const qc = useQueryClient()
  const [d, setD] = useState<SyslogDestinationInput>(blank)
  const [busy, setBusy] = useState<'save' | 'test' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tested, setTested] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setD(editing ? { ...blank, ...editing } : blank)
    setError(null)
    setTested(null)
    setBusy(null)
  }, [open, editing])

  const set = <K extends keyof SyslogDestinationInput>(k: K, v: SyslogDestinationInput[K]) => { setD((cur) => ({ ...cur, [k]: v })); setTested(null) }
  const setTransport = (t: SyslogTransport) => {
    setD((cur) => ({ ...cur, transport: t, port: cur.port === defaultPort(cur.transport) ? defaultPort(t) : cur.port, ca_pem: t === 'tls' ? cur.ca_pem : null }))
    setTested(null)
  }
  const toggle = (c: SyslogCategory, on: boolean) => set('categories', on ? [...d.categories, c] : d.categories.filter((x) => x !== c))
  const valid = d.name.trim() && d.host.trim() && d.port >= 1 && d.port <= 65535 && d.categories.length > 0
  const payload = (): SyslogDestinationInput => ({ ...d, name: d.name.trim(), host: d.host.trim(), ca_pem: d.transport === 'tls' && d.ca_pem?.trim() ? d.ca_pem : null })

  const test = async () => {
    setBusy('test')
    setError(null)
    try {
      setTested((await syslogApi.test(payload())).detail)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(null)
    }
  }
  const save = async () => {
    setBusy('save')
    setError(null)
    try {
      if (editing) await syslogApi.update(editing.id, payload())
      else await syslogApi.add(payload())
      toast(editing ? 'Destination saved' : 'Destination added', editing ? undefined : 'EasyEAP sends what happens from now on. It doesn’t replay older messages.')
      void qc.invalidateQueries({ queryKey: syslogKey })
      onOpenChange(false)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(null)
    }
  }

  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide title={editing ? `Edit ${editing.name}` : 'Add a syslog destination'}
      description="Send the audit trail, authentication events and system log to a syslog server or SIEM."
      footer={
        <>
          <Btn className="mr-auto" busy={busy === 'test'} disabled={!valid || !!busy} onClick={test}><Send aria-hidden />Send test message</Btn>
          <Btn onClick={() => onOpenChange(false)}>Cancel</Btn>
          <Btn variant="primary" busy={busy === 'save'} disabled={!valid || !!busy} onClick={save}><Save aria-hidden />{editing ? 'Save' : 'Add destination'}</Btn>
        </>
      }>
      <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (valid) void save() }}>
        <div className="grid gap-3 sm:grid-cols-[1fr_1.4fr_110px]">
          <Field label="Name" htmlFor="sl-name">
            <input id="sl-name" className="ee-input" maxLength={60} value={d.name} onChange={(e) => set('name', e.target.value)} placeholder="SIEM" autoFocus />
          </Field>
          <Field label="Host" htmlFor="sl-host">
            <input id="sl-host" className="ee-input ee-mono" maxLength={253} spellCheck={false} value={d.host} onChange={(e) => set('host', e.target.value)} placeholder="siem.msp.example" />
          </Field>
          <Field label="Port" htmlFor="sl-port">
            <input id="sl-port" className="ee-input ee-num" inputMode="numeric" value={d.port || ''} onChange={(e) => set('port', Number(e.target.value.replace(/\D/g, '').slice(0, 5)))} />
          </Field>
        </div>

        <div className="space-y-2">
          <p className="text-[13px] font-semibold">Transport</p>
          <Seg value={d.transport} onChange={setTransport} label="Transport"
            options={[{ value: 'tls', label: 'TLS (recommended)' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]} />
          {d.transport === 'udp' && <Callout tone="warn">UDP is unencrypted, and messages can be lost without anyone knowing. Use TLS unless the receiver only accepts UDP.</Callout>}
          {d.transport === 'tcp' && <Callout tone="warn">TCP is unencrypted: audit and authentication details cross the network in clear text. Use TLS where you can.</Callout>}
        </div>

        {d.transport === 'tls' && (
          <Field label="CA certificate" htmlFor="sl-ca" optional hint="Paste the PEM certificate of the CA that signed the syslog server’s certificate. Leave it empty if a public CA signed it. The host name must match the certificate either way.">
            <textarea id="sl-ca" className="ee-textarea min-h-[88px]" spellCheck={false} value={d.ca_pem ?? ''} onChange={(e) => set('ca_pem', e.target.value || null)} placeholder="-----BEGIN CERTIFICATE-----" />
          </Field>
        )}

        <fieldset>
          <legend className="mb-2 text-[13px] font-semibold">Send</legend>
          <div className="space-y-2.5">
            {(['audit', 'auth', 'system'] as SyslogCategory[]).map((c) => (
              <label key={c} className="flex items-start gap-2.5 text-[13px]">
                <input type="checkbox" className="ee-check mt-0.5" checked={d.categories.includes(c)} onChange={(e) => toggle(c, e.target.checked)} />
                <span><span className="font-medium">{CATEGORY_HELP[c][0]}</span><span className="block ee-small ee-ink-2">{CATEGORY_HELP[c][1]}</span></span>
              </label>
            ))}
            {d.categories.includes('system') && (
              <div className="pl-[26px]">
                <Seg value={d.system_level} onChange={(v) => set('system_level', v)} label="System log level"
                  options={[{ value: 'info', label: 'Info and above' }, { value: 'warning', label: 'Warnings and errors' }, { value: 'error', label: 'Errors only' }]} />
              </div>
            )}
          </div>
        </fieldset>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Message format" htmlFor="sl-format" hint={d.format === 'rfc5424' ? 'Modern syslog with full timestamps (rsyslog, syslog-ng, most SIEMs).' : 'Legacy BSD syslog for older receivers. Times are in UTC.'}>
            <ESelect id="sl-format" label="Message format" value={d.format} onChange={(v) => set('format', v as SyslogDestinationInput['format'])}
              options={[{ value: 'rfc5424', label: 'RFC 5424' }, { value: 'rfc3164', label: 'RFC 3164 (BSD)' }]} />
          </Field>
          <Field label="Message body" htmlFor="sl-body" hint={d.body === 'json' ? 'One JSON object per message, for SIEM field extraction.' : 'key="value" pairs, readable in a plain log file.'}>
            <ESelect id="sl-body" label="Message body" value={d.body} onChange={(v) => set('body', v as SyslogDestinationInput['body'])}
              options={[{ value: 'text', label: 'Text' }, { value: 'json', label: 'JSON' }]} />
          </Field>
          <Field label="Facility" htmlFor="sl-facility">
            <ESelect id="sl-facility" label="Facility" value={d.facility} onChange={(v) => set('facility', v)} options={facilities.map((f) => ({ value: f, label: facilityLabel(f) }))} />
          </Field>
          {d.transport !== 'udp' && (
            <Field label="Framing" htmlFor="sl-framing" hint={d.framing === 'octet' ? 'Each message is prefixed with its length (RFC 6587). Safe for any content.' : 'Each message ends with a newline. Use only if the receiver needs it.'}>
              <ESelect id="sl-framing" label="Framing" value={d.framing} onChange={(v) => set('framing', v as SyslogDestinationInput['framing'])}
                options={[{ value: 'octet', label: 'Octet counting' }, { value: 'newline', label: 'Newline' }]} />
            </Field>
          )}
        </div>

        {editing && (
          <div className="flex items-center justify-between gap-4 rounded-[10px] border border-[var(--ee-line-2)] px-4 py-3">
            <span className="text-[13px]"><span className="font-medium">Sending</span><span className="block ee-small ee-ink-2">While paused, messages wait and are sent when you turn it back on.</span></span>
            <ESwitch checked={d.enabled} onChange={(v) => set('enabled', v)} label="Sending" />
          </div>
        )}

        {tested && <Callout tone="valid" title="Test message sent">{tested}</Callout>}
        {error && <Callout tone="crit">{error}</Callout>}
        <button type="submit" hidden aria-hidden tabIndex={-1} />
      </form>
    </EDialog>
  )
}
