import { useId, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { RadioGroup } from 'radix-ui'
import { CircleCheck, KeyRound, Laptop, Monitor, ShieldCheck, Smartphone, Tablet, Terminal, TriangleExclamationPoint } from 'lucide-react'
import type { Certificate, Identity, NasVendor, Platform, RadiusClient, RevocationReason } from '@/domain/types'
import { platformLabels, revocationReasonLabels, vendorLabels } from '@/domain/explain'
import { useActions, useTenantData, useTenants, now } from '@/prototype/store'
import { formatDateTime, formatSerial } from '@/ui/lib'
import { Confirm } from './Inspector'
import { markSession } from './theme'
import { Button, Callout, CopyButton, Field, Select, Switch, useE } from './ui'

const PLATFORM_ICON: Record<Platform, ReactNode> = { windows: <Monitor />, macos: <Laptop />, ios: <Tablet />, android: <Smartphone />, linux: <Terminal /> }

function randomToken(len: number) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

// ── Issue Wi-Fi certificate ────────────────────────────────────────────────
export function IssueCertificateForm({ identity, onDone }: { identity: Identity; onDone: () => void }) {
  const d = useTenantData()
  const { current } = useTenants()
  const devices = d.devices.filter((x) => x.identityId === identity.id)
  const tpl = d.templates.find((t) => t.purpose === 'user')
  const [name, setName] = useState('')
  const [platform, setPlatform] = useState<Platform>('ios')
  const [keyMode, setKeyMode] = useState<'device' | 'server'>('device')
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<{ url: string; expires: string } | null>(null)
  const nameId = useId()
  const first = identity.displayName.split(' ')[0]

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const n = name.trim()
    if (!n) return setError(`Enter a device name so ${first} can tell this certificate apart, for example “${first}'s iPad”.`)
    if (n.length > 64) return setError('Use 64 characters or fewer.')
    if (devices.some((x) => x.name.toLowerCase() === n.toLowerCase())) return setError(`${first} already has a device named “${n}”. Each device gets its own certificate; choose a different name.`)
    setError(null)
    setResult({ url: `https://enroll.${current.domain}/e/${randomToken(22)}`, expires: formatDateTime(new Date(now().getTime() + 72 * 3600_000).toISOString()) })
  }

  if (result) {
    return (
      <div className="space-y-4">
        <Callout icon={<CircleCheck color="#3FB950" aria-hidden />}>
          <p className="font-bold">Enrollment link created</p>
          <p className="t2 mt-0.5">For {name.trim()} ({platformLabels[platform]}). The link works once and expires {result.expires}.</p>
        </Callout>
        <div>
          <p className="e-label mb-1.5">One-time enrollment link</p>
          <div className="e-secret !border-[var(--e-hair-strong)]"><span className="min-w-0 flex-1 break-all">{result.url}</span></div>
          <div className="mt-2 flex flex-wrap gap-2">
            <CopyButton text={result.url} label="Copy link" />
            {identity.email && <CopyButton text={identity.email} label={`Copy ${first}'s email`} variant="ghost" />}
          </div>
        </div>
        <div>
          <p className="e-label mb-1.5">What happens next</p>
          <ol className="t2 list-decimal space-y-1.5 pl-5 text-[13px]">
            <li>{first} opens the link on the device itself.</li>
            <li>{keyMode === 'device' ? 'The device generates its private key and sends only a signing request; the key never leaves the device.' : 'EasyEAP generates the key pair and offers a single encrypted PKCS#12 download; the password is shown once on the device.'}</li>
            <li>The {platformLabels[platform]} profile installs the Root CA, the certificate and the Wi-Fi settings, then connects.</li>
          </ol>
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <Button variant="primary" onClick={onDone}>Done</Button>
        </div>
      </div>
    )
  }

  return (
    <form className="space-y-5" onSubmit={submit} noValidate>
      <Field label="Device name" htmlFor={nameId} error={error} hint={`Shown to ${first} and in the certificate list. ${devices.length ? `Existing: ${devices.map((x) => x.name).join(', ')}.` : ''}`}>
        <input id={nameId} data-autofocus className="e-input" value={name} onChange={(e) => { setName(e.target.value); if (error) setError(null) }} placeholder={`${first}'s iPad`} aria-invalid={!!error} aria-describedby={error ? `${nameId}-err` : `${nameId}-hint`} maxLength={80} autoComplete="off" />
      </Field>

      <fieldset>
        <legend className="e-label mb-1.5">Platform</legend>
        <RadioGroup.Root value={platform} onValueChange={(v) => setPlatform(v as Platform)} className="grid grid-cols-2 gap-2" aria-label="Platform">
          {(Object.keys(platformLabels) as Platform[]).map((p) => (
            <RadioGroup.Item key={p} value={p} className="e-radio-card !items-center !py-2.5">
              <span className="t2 [&_svg]:size-4">{PLATFORM_ICON[p]}</span>
              <span className="text-[13.5px] font-semibold">{platformLabels[p]}</span>
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
      </fieldset>

      <fieldset>
        <legend className="e-label mb-1.5">Private key</legend>
        <RadioGroup.Root value={keyMode} onValueChange={(v) => setKeyMode(v as 'device' | 'server')} className="space-y-2" aria-label="Key generation method">
          <RadioGroup.Item value="device" className="e-radio-card">
            <span className="e-radio-dot" aria-hidden />
            <span>
              <span className="flex items-center gap-2 text-[13.5px] font-bold"><ShieldCheck size={15} aria-hidden />Generated on the device<span className="e-tag !h-5">Recommended</span></span>
              <span className="t2 mt-0.5 block text-[12.5px]">The private key is created on {first}&apos;s device and never leaves it. EasyEAP only signs the request.</span>
            </span>
          </RadioGroup.Item>
          <RadioGroup.Item value="server" className="e-radio-card" disabled={tpl ? !tpl.allowServerKeyGeneration : false}>
            <span className="e-radio-dot" aria-hidden />
            <span>
              <span className="flex items-center gap-2 text-[13.5px] font-bold"><KeyRound size={15} aria-hidden />Generated by EasyEAP (admin mode)</span>
              <span className="t2 mt-0.5 block text-[12.5px]">Less secure: the key exists on the server until it is downloaded once as an encrypted PKCS#12 file. Use only for devices that cannot create their own key.</span>
            </span>
          </RadioGroup.Item>
        </RadioGroup.Root>
        {keyMode === 'server' && (
          <Callout tone="warn" className="mt-2" icon={<TriangleExclamationPoint color="#E3B341" aria-hidden />}>
            The download is encrypted and works once; EasyEAP deletes its copy of the key after retrieval or when the link expires. This choice is recorded in the audit trail.
          </Callout>
        )}
      </fieldset>

      {tpl && (
        <p className="t2 text-[12.5px]">
          Template <strong className="text-[var(--e-text)]">{tpl.name}</strong> · ECDSA P-256 · valid {tpl.validityDays} days · subject {tpl.subjectPattern.replace('{upn}', identity.upn ?? identity.username)}
        </p>
      )}
      <div className="flex justify-end gap-2 border-t border-[var(--e-hair)] pt-4">
        <Button variant="ghost" onClick={onDone}>Cancel</Button>
        <Button variant="primary" type="submit"><ShieldCheck />Create enrollment link</Button>
      </div>
    </form>
  )
}

// ── Revoke certificate (modal: destructive) ─────────────────────────────────
export function RevokeDialog({ cert, open, onOpenChange, deviceName }: { cert: Certificate | null; open: boolean; onOpenChange: (o: boolean) => void; deviceName?: string }) {
  const { revokeCertificate } = useActions()
  const d = useTenantData()
  const { toast } = useE()
  const [reason, setReason] = useState<RevocationReason | ''>('')
  const [coa, setCoa] = useState(true)
  const coaClients = d.radiusClients.filter((c) => c.coaEnabled)
  const noCoa = d.radiusClients.filter((c) => !c.coaEnabled)
  const timeout = d.radiusSettings?.sessionTimeoutSeconds ?? 28800
  if (!cert) return null
  const close = (o: boolean) => { onOpenChange(o); if (!o) setReason('') }
  return (
    <Confirm
      open={open}
      onOpenChange={close}
      title={`Revoke certificate for ${deviceName ?? cert.commonName}?`}
      confirmLabel="Revoke certificate"
      disabled={!reason}
      onConfirm={() => {
        if (!reason) return
        revokeCertificate(cert.id, reason)
        markSession(`rev:${cert.id}`)
        toast({ title: 'Certificate revoked', body: `Serial ${formatSerial(cert.serial).slice(0, 19)}… New authentications are rejected within seconds.${coa && coaClients.length ? ` Disconnect sent to ${coaClients.length} controller${coaClients.length > 1 ? 's' : ''} with CoA.` : ''}` })
        close(false)
      }}
    >
      <p>Serial <span className="mono text-[var(--e-text)]">{formatSerial(cert.serial)}</span> · {cert.commonName}</p>
      <div>
        <p className="e-label mb-1.5">Reason (RFC 5280)</p>
        <Select<RevocationReason | ''>
          label="Revocation reason"
          value={reason}
          onValueChange={setReason}
          placeholder="Choose a reason"
          className="w-full"
          options={(Object.keys(revocationReasonLabels) as RevocationReason[]).map((r) => ({ value: r, label: revocationReasonLabels[r] }))}
        />
      </div>
      <ul className="space-y-2">
        <li className="flex gap-2"><CircleCheck size={16} className="mt-0.5 shrink-0" color="#3FB950" aria-hidden /><span><strong className="text-[var(--e-text)]">New connections are rejected within seconds.</strong> The CRL is regenerated and the RADIUS authorization snapshot is updated.</span></li>
        <li className="flex gap-2"><TriangleExclamationPoint size={16} className="mt-0.5 shrink-0" color="#E3B341" aria-hidden /><span><strong className="text-[var(--e-text)]">A device that is already connected stays online</strong> until it reauthenticates (session timeout {Math.round(timeout / 3600)} h) or a CoA disconnect is sent.</span></li>
      </ul>
      {d.radiusClients.length > 0 && (
        <div className="rounded-lg border border-[var(--e-hair)] p-3">
          <label className="flex items-start justify-between gap-3">
            <span>
              <span className="block font-semibold text-[var(--e-text)]">Send CoA disconnect</span>
              <span className="block text-[12.5px]">{coaClients.length ? `To ${coaClients.map((c) => c.name).join(', ')}.` : 'No controller has CoA enabled.'}{noCoa.length ? ` ${noCoa.map((c) => c.name).join(', ')} ${noCoa.length > 1 ? 'have' : 'has'} CoA off: clients there stay connected until reauthentication.` : ''}</span>
            </span>
            <Switch checked={coa && coaClients.length > 0} disabled={!coaClients.length} onCheckedChange={setCoa} label="Send CoA disconnect" />
          </label>
        </div>
      )}
      <p>Revocation cannot be undone. To restore access, issue a new certificate.</p>
    </Confirm>
  )
}

// ── Controller config snippets ─────────────────────────────────────────────
export function configSnippet(vendor: NasVendor, opts: { hostname: string; authPort: number; acctPort: number; coaPort: number; coa: boolean; ssid: string; name: string }) {
  const IP = '<RADIUS_SERVER_IP>'
  const KEY = '<SHARED_SECRET>'
  if (vendor === 'cisco-9800') {
    return [
      `! EasyEAP RADIUS for ${opts.name} (Catalyst 9800)`,
      `! ${IP} = address of ${opts.hostname}`,
      `radius server EASYEAP`,
      ` address ipv4 ${IP} auth-port ${opts.authPort} acct-port ${opts.acctPort}`,
      ` key ${KEY}`,
      `!`,
      `aaa group server radius EASYEAP-GROUP`,
      ` server name EASYEAP`,
      `aaa authentication dot1x EASYEAP-DOT1X group EASYEAP-GROUP`,
      `aaa authorization network EASYEAP-AUTHZ group EASYEAP-GROUP`,
      `aaa accounting identity EASYEAP-ACCT start-stop group EASYEAP-GROUP`,
      ...(opts.coa ? [`aaa server radius dynamic-author`, ` client ${IP} server-key ${KEY}`, ` port ${opts.coaPort}`] : []),
      `!`,
      `wireless profile policy EASYEAP-POLICY`,
      ` aaa-override`,
      ` accounting-list EASYEAP-ACCT`,
      ` no shutdown`,
      `wlan ${opts.ssid} 10 ${opts.ssid}`,
      ` security dot1x authentication-list EASYEAP-DOT1X`,
      ` no shutdown`,
    ].join('\n')
  }
  if (vendor === 'cisco-aireos') {
    return [
      `# EasyEAP RADIUS for ${opts.name} (AireOS); <WLAN_ID> = ID of ${opts.ssid}`,
      `# ${IP} = address of ${opts.hostname}`,
      `config radius auth add 1 ${IP} ${opts.authPort} ascii ${KEY}`,
      `config radius acct add 1 ${IP} ${opts.acctPort} ascii ${KEY}`,
      `config radius auth rfc3576 ${opts.coa ? 'enable' : 'disable'} 1`,
      `config wlan disable <WLAN_ID>`,
      `config wlan radius_server auth add <WLAN_ID> 1`,
      `config wlan radius_server acct add <WLAN_ID> 1`,
      `config wlan security wpa akm 802.1x enable <WLAN_ID>`,
      `config wlan aaa-override enable <WLAN_ID>`,
      `config wlan enable <WLAN_ID>`,
    ].join('\n')
  }
  if (vendor === 'unifi') {
    return [
      `UniFi Network: Settings > Profiles > RADIUS > Create New`,
      `  Name: EasyEAP`,
      `  Authentication server: ${IP}  port ${opts.authPort}  secret ${KEY}`,
      `  Accounting server: ${IP}  port ${opts.acctPort}  secret ${KEY}`,
      `  Enable: Wireless Networks > RADIUS assigned VLAN support`,
      `Settings > WiFi > ${opts.ssid} > Security`,
      `  Protocol: WPA2/WPA3 Enterprise   RADIUS profile: EasyEAP`,
      `# UniFi does not accept CoA from EasyEAP: revoked devices stay`,
      `# connected until they reauthenticate.`,
    ].join('\n')
  }
  return [`# Generic RADIUS client`, `Server: ${IP} (${opts.hostname})`, `Auth port: ${opts.authPort}  Acct port: ${opts.acctPort}`, `Shared secret: ${KEY}`, `EAP method: EAP-TLS   VLAN: RFC 3580 tunnel attributes`].join('\n')
}

export function Snippet({ text }: { text: string }) {
  const parts = text.split(/(<[A-Z_]+>)/g)
  return (
    <pre className="e-code" tabIndex={0} aria-label="Configuration snippet">
      {text.split('\n').map((line, li) => {
        const comment = /^\s*[#!]/.test(line)
        return (
          <span key={li} className={comment ? 'cm' : undefined}>
            {line.split(/(<[A-Z_]+>)/g).map((p, i) => (/^<[A-Z_]+>$/.test(p) ? <span key={i} className="ph">{p}</span> : <span key={i}>{p}</span>))}
            {'\n'}
          </span>
        )
      })}
      <span className="sr-only">{parts.length > 1 ? 'Replace the highlighted placeholders before pasting.' : ''}</span>
    </pre>
  )
}

// ── Register a wireless controller ──────────────────────────────────────────
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
export function validateAddress(v: string, existing: RadiusClient[]): string | null {
  const s = v.trim()
  if (!s) return 'Enter the controller’s management IP, for example 10.20.0.10, or a CIDR range such as 10.20.0.0/24.'
  const [ip, prefix, extra] = s.split('/')
  if (extra !== undefined || !IPV4.test(ip)) return `“${s}” is not an IPv4 address. Use four numbers from 0 to 255 separated by dots, optionally followed by /8 to /32.`
  if (prefix !== undefined) {
    const p = Number(prefix)
    if (!/^\d{1,2}$/.test(prefix) || p < 8 || p > 32) return 'The CIDR prefix must be between /8 and /32.'
  }
  const dup = existing.find((c) => c.address === s)
  if (dup) return `${s} is already registered as ${dup.name}. Each address can belong to one controller.`
  return null
}

export function AddControllerForm({ onClose }: { onClose: () => void }) {
  const { addRadiusClient } = useActions()
  const d = useTenantData()
  const { toast } = useE()
  const [name, setName] = useState('')
  const [vendor, setVendor] = useState<NasVendor>('cisco-9800')
  const [address, setAddress] = useState('')
  const [site, setSite] = useState('')
  const [coa, setCoa] = useState(true)
  const [port, setPort] = useState('1700')
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const [submitted, setSubmitted] = useState(false)
  const [secret, setSecret] = useState<string | null>(null)
  const ids = { name: useId(), vendor: useId(), address: useId(), site: useId(), port: useId() }

  const errors = useMemo(() => ({
    name: !name.trim() ? 'Enter a name, for example “Riverside branch WLC 5520”.' : name.trim().length > 64 ? 'Use 64 characters or fewer.' : d.radiusClients.some((c) => c.name.toLowerCase() === name.trim().toLowerCase()) ? 'A controller with this name already exists. Names must be unique within the tenant.' : null,
    address: validateAddress(address, d.radiusClients),
    site: !site.trim() ? 'Enter the site, for example “Headquarters”. It groups stations on the route map.' : null,
    port: coa && !(/^\d+$/.test(port) && +port >= 1 && +port <= 65535) ? 'Enter a UDP port from 1 to 65535. Catalyst 9800 listens on 1700; most others use 3799.' : null,
  }), [name, address, site, port, coa, d.radiusClients])
  const show = (k: keyof typeof errors) => (submitted || touched[k] ? errors[k] : null)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setSubmitted(true)
    if (Object.values(errors).some(Boolean)) return
    const s = randomToken(32)
    addRadiusClient({ name: name.trim(), vendor, address: address.trim(), site: site.trim(), coaEnabled: coa, coaPort: coa ? +port : vendor === 'cisco-9800' ? 1700 : 3799 })
    setSecret(s)
    toast({ title: `${name.trim()} registered`, body: 'It appears on the route map as an idle line until its first request arrives.' })
  }

  if (secret) {
    return (
      <SecretOnce
        secret={secret}
        title={`Shared secret for ${name.trim()}`}
        onDone={() => { setSecret(null); onClose() }}
        footer={<ConfigBlock vendor={vendor} name={name.trim()} coa={coa} coaPort={+port} />}
      />
    )
  }

  return (
    <form onSubmit={submit} noValidate className="space-y-4">
      <Field label="Name" htmlFor={ids.name} error={show('name')}>
        <input id={ids.name} data-autofocus className="e-input" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched((t) => ({ ...t, name: true }))} aria-invalid={!!show('name')} placeholder="Riverside branch WLC 5520" autoComplete="off" />
      </Field>
      <div>
        <p className="e-label mb-1.5" id={ids.vendor}>Vendor</p>
        <Select<NasVendor>
          label="Vendor"
          value={vendor}
          className="w-full"
          onValueChange={(v) => { setVendor(v); setPort(v === 'cisco-9800' ? '1700' : '3799'); if (v === 'unifi') setCoa(false) }}
          options={(Object.keys(vendorLabels) as NasVendor[]).map((v) => ({ value: v, label: vendorLabels[v] }))}
        />
      </div>
      <Field label="IP address or CIDR" htmlFor={ids.address} error={show('address')} hint="The source address RADIUS requests come from. A CIDR range covers controller clusters.">
        <input id={ids.address} className="e-input mono" value={address} onChange={(e) => setAddress(e.target.value)} onBlur={() => setTouched((t) => ({ ...t, address: true }))} aria-invalid={!!show('address')} placeholder="10.30.0.5" inputMode="decimal" autoComplete="off" spellCheck={false} />
      </Field>
      <Field label="Site" htmlFor={ids.site} error={show('site')}>
        <input id={ids.site} className="e-input" value={site} onChange={(e) => setSite(e.target.value)} onBlur={() => setTouched((t) => ({ ...t, site: true }))} aria-invalid={!!show('site')} placeholder="Riverside branch" autoComplete="off" />
      </Field>
      <div className="rounded-lg border border-[var(--e-hair)] p-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[13.5px] font-semibold">Change of Authorization (CoA)</p>
            <p className="t2 text-[12.5px]">Lets EasyEAP disconnect a client right after its certificate is revoked.{vendor === 'unifi' ? ' UniFi Network does not support CoA from EasyEAP.' : ''}</p>
          </div>
          <Switch checked={coa} onCheckedChange={setCoa} label="Enable CoA" disabled={vendor === 'unifi'} />
        </div>
        {coa && (
          <div className="mt-3 max-w-[180px]">
            <Field label="CoA port (UDP)" htmlFor={ids.port} error={show('port')}>
              <input id={ids.port} className="e-input mono num" value={port} onChange={(e) => setPort(e.target.value)} onBlur={() => setTouched((t) => ({ ...t, port: true }))} aria-invalid={!!show('port')} inputMode="numeric" />
            </Field>
          </div>
        )}
      </div>
      {submitted && Object.values(errors).some(Boolean) && <p className="e-field-error" role="alert">Fix the highlighted fields to register the controller.</p>}
      <div className="flex justify-end gap-2 border-t border-[var(--e-hair)] pt-4">
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" type="submit">Register and generate secret</Button>
      </div>
    </form>
  )
}

export function SecretOnce({ secret, title, onDone, footer }: { secret: string; title: string; onDone: () => void; footer?: ReactNode }) {
  return (
    <div className="space-y-4">
      <div>
        <p className="text-[14px] font-bold">{title}</p>
        <p className="t2 mt-0.5 text-[13px]">Enter it on the controller now. This is the only time EasyEAP shows it; it is stored encrypted and can only be replaced by rotating.</p>
      </div>
      <div className="e-secret" aria-label="Shared secret"><span className="min-w-0 flex-1">{secret}</span></div>
      <div className="flex flex-wrap gap-2">
        <CopyButton text={secret} label="Copy secret" />
      </div>
      {footer}
      <div className="flex justify-end border-t border-[var(--e-hair)] pt-4">
        <Button variant="primary" onClick={onDone}>I have saved the secret</Button>
      </div>
    </div>
  )
}

export function ConfigBlock({ vendor, name, coa, coaPort }: { vendor: NasVendor; name: string; coa: boolean; coaPort: number }) {
  const d = useTenantData()
  const s = d.radiusSettings
  const ssid = d.authEvents.find((e) => e.ssid)?.ssid ?? '<SSID>'
  const text = configSnippet(vendor, { hostname: s?.serverHostname ?? 'radius', authPort: s?.authPort ?? 1812, acctPort: s?.acctPort ?? 1813, coaPort, coa, ssid, name })
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <p className="e-label">{vendorLabels[vendor]} configuration</p>
        <CopyButton text={text} label="Copy config" />
      </div>
      <Snippet text={text} />
    </div>
  )
}

// ── Rotate shared secret (modal: breaks the controller until updated) ────────
export function RotateSecretDialog({ client, open, onOpenChange }: { client: RadiusClient | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { rotateSecret } = useActions()
  const { toast } = useE()
  const [secret, setSecret] = useState<string | null>(null)
  if (!client) return null
  const close = (o: boolean) => { onOpenChange(o); if (!o) setSecret(null) }
  if (secret) {
    return (
      <Confirm open={open} onOpenChange={close} title={`New shared secret for ${client.name}`} confirmLabel="I have saved the secret" tone="primary" hideCancel onConfirm={() => close(false)}>
        <p>Enter it on the controller now. Requests signed with the old secret are rejected from this moment, and this is the only time the new secret is shown.</p>
        <div className="e-secret text-[var(--e-text)]"><span className="min-w-0 flex-1">{secret}</span></div>
        <CopyButton text={secret} label="Copy secret" />
      </Confirm>
    )
  }
  return (
    <Confirm
      open={open}
      onOpenChange={close}
      title={`Rotate the shared secret for ${client.name}?`}
      confirmLabel="Rotate secret"
      onConfirm={() => {
        rotateSecret(client.id)
        markSession(`rot:${client.id}`)
        setSecret(randomToken(32))
        toast({ title: 'Shared secret rotated', body: `${client.name} must be updated with the new secret before it can authenticate again.`, tone: 'warn' })
      }}
    >
      <p>EasyEAP generates a new secret and stops accepting the old one immediately. Wi-Fi authentication through <strong className="text-[var(--e-text)]">{client.name}</strong> ({client.address}) fails until the new secret is entered on the controller.</p>
      <p>Last rotated {formatDateTime(client.secretSetAt)}.</p>
    </Confirm>
  )
}
