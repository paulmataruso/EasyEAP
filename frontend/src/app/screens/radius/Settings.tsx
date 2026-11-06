// RADIUS server settings form and the server-certificate card. Used by the RADIUS screen and the setup wizard.
import { useId, useState, type FormEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { RotateCw, Save } from 'lucide-react'
import { useRotateServerCert, useSaveSettings, type RadiusSettings, type SettingsIn } from '../../api/radius'
import { useTenant } from '../../api/tenant'
import { duration, fmtDate, fmtFingerprint, fmtSerial, remaining } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { Btn, Callout, EDialog, ESelect, ESwitch, Field, Seg, errorMessage, toast } from '../../ui'

const TIMEOUTS = [3600, 4 * 3600, 8 * 3600, 12 * 3600, 86_400, 3 * 86_400, 7 * 86_400]
const RESERVED_PORTS = [1812, 1813, 18120]

export const defaultSettings = (domain: string): SettingsIn => ({
  server_hostname: domain ? `radius.${domain}` : '',
  ssid: '',
  wpa3: false,
  dedicated_ports: false,
  auth_port: 1812,
  acct_port: 1813,
  tls_min_version: '1.2',
  tls_session_cache: false,
  session_timeout_seconds: 28_800,
})

const fromSettings = (s: RadiusSettings): SettingsIn => ({
  server_hostname: s.server_hostname, ssid: s.ssid, wpa3: s.wpa3, dedicated_ports: s.dedicated_ports, auth_port: s.auth_port,
  acct_port: s.acct_port, tls_min_version: s.tls_min_version, tls_session_cache: s.tls_session_cache, session_timeout_seconds: s.session_timeout_seconds,
})

function validate(v: SettingsIn) {
  const host = v.server_hostname.trim()
  const port = (p: number) => (!Number.isInteger(p) || p < 1024 || p > 65535 ? 'Use a port between 1024 and 65535.' : RESERVED_PORTS.includes(p) ? 'Dedicated ports can’t be 1812, 1813 or 18120.' : null)
  return {
    server_hostname: !host ? 'Enter the name devices will see in the server certificate, for example radius.example.com.'
      : !/^[A-Za-z0-9.-]+$/.test(host) || host.length < 3 ? 'Use letters, numbers, dots and hyphens only, for example radius.example.com.' : null,
    ssid: !v.ssid.trim() ? 'Enter the Wi-Fi network name (SSID) devices join.' : v.ssid.length > 32 ? 'An SSID is at most 32 characters.' : null,
    auth_port: v.dedicated_ports ? port(v.auth_port) : null,
    acct_port: v.dedicated_ports ? (port(v.acct_port) ?? (v.acct_port === v.auth_port ? 'Use a different port from the authentication port.' : null)) : null,
  }
}

/**
 * Edit RADIUS settings. The first save issues the RADIUS server certificate from the tenant's issuing CA, so the PKI
 * must exist first; a hostname change issues a new certificate.
 */
export function RadiusSettingsForm({ current, onSaved, onCancel, submitLabel }: { current: RadiusSettings | null; onSaved?: (s: RadiusSettings) => void; onCancel?: () => void; submitLabel?: string }) {
  const { tid, tenant, can } = useTenant()
  const [v, setV] = useState<SettingsIn>(() => (current ? fromSettings(current) : defaultSettings(tenant.domain)))
  const [touched, setTouched] = useState(false)
  const [serverError, setServerError] = useState<string | null>(null)
  const save = useSaveSettings(tid)
  const id = useId()
  const errors = validate(v)
  const invalid = Object.values(errors).some(Boolean)
  const set = <K extends keyof SettingsIn>(k: K, val: SettingsIn[K]) => setV((p) => ({ ...p, [k]: val }))
  const first = !current
  const hostChanged = !!current && current.server_hostname !== v.server_hostname.trim().toLowerCase()
  const pkiReady = tenant.health.pki_ready
  const editable = can('radius:write')
  const timeouts = TIMEOUTS.includes(v.session_timeout_seconds) ? TIMEOUTS : [...TIMEOUTS, v.session_timeout_seconds].sort((a, b) => a - b)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    setServerError(null)
    if (invalid) return
    const body = { ...v, server_hostname: v.server_hostname.trim().toLowerCase(), ssid: v.ssid.trim(), ...(v.dedicated_ports ? {} : { auth_port: 1812, acct_port: 1813 }) }
    save.mutate(body, {
      onSuccess: (r) => {
        const issued = first || hostChanged
        toast(issued ? 'RADIUS settings saved and server certificate issued' : 'RADIUS settings saved',
          issued ? `Devices will validate ${r.settings.server_hostname}. RADIUS loads the change with its next configuration refresh.` : 'RADIUS loads the change with its next configuration refresh.')
        onSaved?.(r.settings)
      },
      onError: (err) => setServerError(errorMessage(err)),
    })
  }

  const err = (k: keyof ReturnType<typeof validate>) => (touched ? errors[k] : null)

  return (
    <form onSubmit={submit} noValidate className="space-y-5">
      {!pkiReady && (
        <Callout tone="warn" title="Initialize the certificate authority first" action={<Link className="ee-btn ee-btn-sm" to={paths.pki(tid)}>Certificate authority</Link>}>
          Saving RADIUS settings issues the RADIUS server certificate from this tenant’s issuing CA, which doesn’t exist yet.
        </Callout>
      )}
      {first && pkiReady && (
        <Callout tone="gold">
          The first save issues the RADIUS server certificate for the hostname below from this tenant’s issuing CA. Devices check that name before they send their own certificate.
        </Callout>
      )}
      <div className="grid gap-5 md:grid-cols-2">
        <Field label="Server hostname" htmlFor={`${id}-host`} error={err('server_hostname')}
          hint={hostChanged ? 'Changing the hostname issues a new server certificate. Devices whose Wi-Fi profile names the old server must be re-enrolled.' : 'The name in the server certificate. Wi-Fi profiles tell devices to accept only this name.'}>
          <input id={`${id}-host`} className="ee-input ee-mono" value={v.server_hostname} onChange={(e) => set('server_hostname', e.target.value)} autoComplete="off" spellCheck={false}
            aria-invalid={!!err('server_hostname') || undefined} disabled={!editable} placeholder={tenant.domain ? `radius.${tenant.domain}` : 'radius.example.com'} />
        </Field>
        <Field label="Wi-Fi network name (SSID)" htmlFor={`${id}-ssid`} error={err('ssid')} hint="Used in enrollment profiles and the controller guides.">
          <input id={`${id}-ssid`} className="ee-input" value={v.ssid} maxLength={32} onChange={(e) => set('ssid', e.target.value)} autoComplete="off" aria-invalid={!!err('ssid') || undefined} disabled={!editable} />
        </Field>
      </div>

      <SettingRow label="WPA3-Enterprise" hint="Profiles ask for WPA3-Enterprise. Leave off if any controller or device supports only WPA2-Enterprise.">
        <ESwitch checked={v.wpa3} onChange={(x) => set('wpa3', x)} label="WPA3-Enterprise" disabled={!editable} />
      </SettingRow>

      <div className="space-y-3">
        <SettingRow label="RADIUS ports" hint={v.dedicated_ports ? 'This tenant’s controllers send to their own ports, so their source addresses may overlap another tenant’s.' : 'UDP 1812 for authentication and 1813 for accounting, shared with other tenants. Controller addresses must be unique across those tenants.'}>
          <Seg label="RADIUS ports" value={v.dedicated_ports ? 'dedicated' : 'shared'} onChange={(x) => set('dedicated_ports', x === 'dedicated')}
            options={[{ value: 'shared', label: 'Standard' }, { value: 'dedicated', label: 'Dedicated' }]} />
        </SettingRow>
        {v.dedicated_ports && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Authentication port (UDP)" htmlFor={`${id}-auth`} error={err('auth_port')}>
              <input id={`${id}-auth`} className="ee-input ee-num" inputMode="numeric" value={Number.isNaN(v.auth_port) ? '' : v.auth_port}
                onChange={(e) => set('auth_port', e.target.value === '' ? NaN : Number(e.target.value))} aria-invalid={!!err('auth_port') || undefined} disabled={!editable} />
            </Field>
            <Field label="Accounting port (UDP)" htmlFor={`${id}-acct`} error={err('acct_port')}>
              <input id={`${id}-acct`} className="ee-input ee-num" inputMode="numeric" value={Number.isNaN(v.acct_port) ? '' : v.acct_port}
                onChange={(e) => set('acct_port', e.target.value === '' ? NaN : Number(e.target.value))} aria-invalid={!!err('acct_port') || undefined} disabled={!editable} />
            </Field>
          </div>
        )}
      </div>

      <SettingRow label="Minimum TLS version" hint="TLS 1.3 is stronger, but some older devices (Windows 10, Android 10 and earlier) can’t use EAP-TLS 1.3.">
        <Seg label="Minimum TLS version" value={v.tls_min_version} onChange={(x) => set('tls_min_version', x)} options={[{ value: '1.2', label: 'TLS 1.2' }, { value: '1.3', label: 'TLS 1.3' }]} />
      </SettingRow>

      <SettingRow label="TLS session cache" hint={v.tls_session_cache
        ? 'On: devices reconnect faster by resuming a cached session, which skips the certificate check, so a revoked device can resume until its cached session expires.'
        : 'Off: every connection does a full handshake, so the certificate and revocation list are checked every time.'}>
        <ESwitch checked={v.tls_session_cache} onChange={(x) => set('tls_session_cache', x)} label="TLS session cache" disabled={!editable} />
      </SettingRow>

      <SettingRow label="Session timeout" hint="Devices re-authenticate at least this often. On controllers without CoA, a revoked device stays connected until then.">
        <ESelect label="Session timeout" value={String(v.session_timeout_seconds)} onChange={(x) => set('session_timeout_seconds', Number(x))} disabled={!editable}
          options={timeouts.map((s) => ({ value: String(s), label: duration(s) }))} className="min-w-[140px]" />
      </SettingRow>

      {serverError && <Callout tone="crit" title="Settings weren’t saved">{serverError}</Callout>}
      {editable ? (
        <div className="flex flex-wrap items-center gap-2">
          <Btn type="submit" variant="primary" busy={save.isPending} disabled={!pkiReady}><Save aria-hidden />{submitLabel ?? (first ? 'Save and issue server certificate' : hostChanged ? 'Save and issue new certificate' : 'Save settings')}</Btn>
          {onCancel && <Btn variant="ghost" onClick={onCancel}>Cancel</Btn>}
        </div>
      ) : (
        <p className="ee-small ee-ink-3">Your role can view RADIUS settings but not change them. A Wi-Fi Administrator or Tenant Administrator can.</p>
      )}
    </form>
  )
}

function SettingRow({ label, hint, children }: { label: string; hint: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
      <div className="min-w-0 max-w-[62ch]">
        <p className="text-[13px] font-semibold">{label}</p>
        <p className="ee-small ee-ink-3 mt-0.5">{hint}</p>
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  )
}

/** Read-only summary of the saved settings. */
export function SettingsSummary({ s }: { s: RadiusSettings }) {
  const rows: Array<[string, ReactNode]> = [
    ['Server hostname', <span className="ee-mono text-[13px] break-all">{s.server_hostname}</span>],
    ['SSID', s.ssid],
    ['Security', s.wpa3 ? 'WPA3-Enterprise' : 'WPA2-Enterprise'],
    ['Ports', <span className="ee-num">UDP {s.dedicated_ports ? s.auth_port : 1812} / {s.dedicated_ports ? s.acct_port : 1813}{s.dedicated_ports ? ' · dedicated' : ''}</span>],
    ['Minimum TLS', <span className="ee-num">TLS {s.tls_min_version}</span>],
    ['TLS session cache', s.tls_session_cache ? 'On' : 'Off · full handshake every time'],
    ['Session timeout', duration(s.session_timeout_seconds)],
  ]
  return (
    <dl className="ee-divide">
      {rows.map(([k, val]) => (
        <div key={k} className="grid gap-x-4 gap-y-0.5 py-2 sm:grid-cols-[minmax(0,10rem)_minmax(0,1fr)] sm:items-baseline">
          <dt className="ee-label">{k}</dt>
          <dd className="min-w-0 text-[13.5px]">{val}</dd>
        </div>
      ))}
    </dl>
  )
}

/** The RADIUS server certificate, with seamless rotation. */
export function ServerCertificateCard({ s }: { s: RadiusSettings }) {
  const { tid, can } = useTenant()
  const now = useNow(60_000)
  const [confirm, setConfirm] = useState(false)
  const rotate = useRotateServerCert(tid)
  const c = s.server_certificate
  if (!c) return <Callout tone="warn" title="No server certificate">Save the settings to issue one. Devices can’t connect until RADIUS presents a certificate from this tenant’s CA.</Callout>
  const days = (new Date(c.not_after).getTime() - now.getTime()) / 864e5
  return (
    <div className="space-y-3">
      <dl className="ee-divide">
        <Row k="Subject"><span className="ee-mono text-[13px] break-all">{c.common_name}</span></Row>
        <Row k="Serial"><span className="ee-mono text-[12.5px] break-all">{fmtSerial(c.serial)}</span></Row>
        <Row k="Expires">
          <span className="flex flex-wrap items-baseline justify-between gap-x-3">
            <span>{fmtDate(c.not_after)}</span>
            {/* The queue calls an expiring or expired server certificate critical: devices refuse a server whose certificate has expired. */}
            <span className={days < 0 ? 'ee-remaining text-[var(--ee-crit-ink)]' : days < 30 ? 'ee-remaining text-[var(--ee-warn-ink)]' : 'ee-remaining ee-ink-2'}>{days < 0 ? `Expired ${fmtDate(c.not_after)}: devices refuse to connect` : remaining(c.not_after, now)}</span>
          </span>
        </Row>
        <Row k="SHA-256"><span className="ee-mono text-[12px] leading-[1.6] break-all ee-ink-2">{fmtFingerprint(c.fingerprint_sha256)}</span></Row>
      </dl>
      <div className="flex flex-wrap items-center gap-2">
        {can('radius:write') && <Btn size="sm" onClick={() => setConfirm(true)}><RotateCw aria-hidden />Rotate certificate</Btn>}
        {can('certificates:read') && <Link to={paths.certificate(tid, c.id)} className="ee-btn ee-btn-sm ee-btn-ghost">Certificate record</Link>}
      </div>
      <EDialog open={confirm} onOpenChange={setConfirm} title="Rotate the RADIUS server certificate?" risk="gold"
        description={`Issues a new certificate for ${s.server_hostname} from the issuing CA.`}
        footer={<>
          <Btn variant="ghost" onClick={() => setConfirm(false)}>Cancel</Btn>
          <Btn variant="primary" busy={rotate.isPending} onClick={() => rotate.mutate(undefined, {
            onSuccess: () => { setConfirm(false); toast('New server certificate issued', 'RADIUS presents it after its next configuration refresh. Devices accept it because they trust the CA.') },
            onError: (e) => toast('The certificate wasn’t rotated', errorMessage(e), 'crit'),
          })}><RotateCw aria-hidden />Issue new certificate</Btn>
        </>}>
        <div className="space-y-3 text-[13.5px] ee-ink-2">
          <p>Rotation is seamless. Devices validate the server by its name and the tenant’s CA, not by this particular certificate, so they accept the new one without any change on the device.</p>
          <p>The current certificate is marked superseded rather than revoked, so it stays valid until {fmtDate(c.not_after)}.</p>
        </div>
      </EDialog>
    </div>
  )
}

const Row = ({ k, children }: { k: string; children: ReactNode }) => (
  <div className="grid gap-x-4 gap-y-0.5 py-2 sm:grid-cols-[minmax(0,6.5rem)_minmax(0,1fr)] sm:items-baseline">
    <dt className="ee-label">{k}</dt>
    <dd className="min-w-0 text-[13.5px]">{children}</dd>
  </div>
)
