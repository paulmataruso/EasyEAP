import { useMemo, useState } from 'react'
import { AlertDialog, Checkbox, RadioGroup } from 'radix-ui'
import { Check, KeyRound, Laptop, Link2, Monitor, ServerCog, ShieldExclamationPoint, Smartphone, Tablet, TriangleExclamationPoint } from 'lucide-react'
import { cn, formatSerial } from '@/ui/lib'
import { now, useActions, useDecision, useTenantData, useTenants } from '@/prototype/store'
import { platformLabels, revocationReasonLabels, vendorLabels } from '@/domain/explain'
import type { Certificate, Identity, NasVendor, Platform, RadiusClient, RevocationReason } from '@/domain/types'
import { addPending, decisionReason, randomSecret, randomToken, toast, usePortal, formatSeconds } from './lib'
import { AccessChip, Btn, CopyButton, FDialog, Field, FSelect, FSwitch, SourceTag } from './ui'

// ── Identity picker (used when issuing from the nav) ────────────────────
export function IdentityPicker({ value, onChange, identities, label = 'User' }: { value: string | null; onChange: (id: string) => void; identities: Identity[]; label?: string }) {
  const [q, setQ] = useState('')
  const list = useMemo(() => {
    const s = q.trim().toLowerCase()
    return identities.filter((i) => !s || i.displayName.toLowerCase().includes(s) || (i.upn ?? '').toLowerCase().includes(s) || i.username.includes(s)).slice(0, 50)
  }, [q, identities])
  return (
    <div className="flex flex-col gap-2">
      <label className="text-[13px] font-semibold" htmlFor="f-pick-q">{label}</label>
      <input id="f-pick-q" className="f-input" placeholder="Search by name or UPN" value={q} onChange={(e) => setQ(e.target.value)} autoComplete="off" />
      <div role="listbox" aria-label="Users" className="max-h-[260px] overflow-y-auto rounded-[8px] border border-[var(--f-line)]">
        {list.length === 0 && <p className="px-3 py-3 f-small f-ink-2">No user matches “{q}”.</p>}
        {list.map((i, idx) => (
          <button
            key={`${i.id}#${idx}`}
            type="button"
            role="option"
            aria-selected={value === i.id}
            onClick={() => onChange(i.id)}
            className={cn('flex w-full items-center gap-3 border-b border-[var(--f-line)] px-3 py-2 text-left last:border-0 hover:bg-[var(--f-hover)]', value === i.id && 'bg-[var(--f-select)]')}
          >
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13.5px] font-medium">{i.displayName}</span>
              <span className="block truncate text-[12px] f-ink-3">{i.upn ?? i.username}</span>
            </span>
            <SourceTag source={i.source} />
            {value === i.id && <Check className="size-4 text-[var(--f-gold)]" aria-hidden />}
          </button>
        ))}
      </div>
    </div>
  )
}

const PLATFORMS: Array<{ id: Platform; icon: React.ReactNode }> = [
  { id: 'windows', icon: <Laptop aria-hidden /> },
  { id: 'macos', icon: <Laptop aria-hidden /> },
  { id: 'ios', icon: <Smartphone aria-hidden /> },
  { id: 'android', icon: <Tablet aria-hidden /> },
  { id: 'linux', icon: <Monitor aria-hidden /> },
]

// ── Issue Wi-Fi certificate ─────────────────────────────────────────────
export function IssueCertificateDialog({ open, onOpenChange, identity: fixedIdentity }: { open: boolean; onOpenChange: (o: boolean) => void; identity?: Identity }) {
  const d = useTenantData()
  const { current } = useTenants()
  const [pickedId, setPickedId] = useState<string | null>(null)
  const identity = fixedIdentity ?? d.identities.find((i) => i.id === pickedId)
  const [deviceName, setDeviceName] = useState('')
  const [platform, setPlatform] = useState<Platform>('windows')
  const [keyMode, setKeyMode] = useState<'device' | 'server'>('device')
  const [touched, setTouched] = useState(false)
  const [done, setDone] = useState<{ link: string; deviceName: string } | null>(null)
  const decision = useDecision(identity)
  const template = d.templates.find((t) => t.purpose === 'user')
  const serverAllowed = template?.allowServerKeyGeneration ?? false
  const devices = d.devices.filter((x) => x.identityId === identity?.id)

  const reset = () => { setPickedId(null); setDeviceName(''); setPlatform('windows'); setKeyMode('device'); setTouched(false); setDone(null) }
  const close = (o: boolean) => { onOpenChange(o); if (!o) setTimeout(reset, 200) }

  const nameError = !deviceName.trim()
    ? 'Name the device so the user and the audit trail can tell it apart, for example “Priya’s iPhone”.'
    : deviceName.trim().length > 64
      ? 'Use 64 characters or fewer.'
      : devices.some((x) => x.name.toLowerCase() === deviceName.trim().toLowerCase())
        ? `${identity?.displayName.split(' ')[0]} already has a device called “${deviceName.trim()}”. One certificate per device: pick a distinct name.`
        : null
  const blocked = identity && identity.accountState !== 'enabled'

  const submit = () => {
    setTouched(true)
    if (!identity || nameError || blocked) return
    const link = `https://wifi.brightline.example/enroll/${randomToken()}`
    addPending({ id: `pe-${Date.now()}`, identityId: identity.id, deviceName: deviceName.trim(), platform, keyMode, link, createdAt: now().toISOString() })
    setDone({ link, deviceName: deviceName.trim() })
    toast('Enrollment link created', `${deviceName.trim()} · ${identity.displayName}`, 'gold')
  }

  const title = done ? 'Enrollment link created' : identity ? `Issue Wi-Fi certificate for ${identity.displayName}` : 'Issue Wi-Fi certificate'
  return (
    <FDialog
      open={open}
      onOpenChange={close}
      title={title}
      risk="gold"
      wide={!done}
      description={done ? 'Send this link to the user. It works once and expires in 24 hours.' : template ? `${template.name} template · ${template.keyAlgorithm.replace('ecdsa-p', 'ECDSA P-')} · valid ${template.validityDays} days · issued by ${d.cas.find((c) => c.role === 'issuing')?.commonName ?? 'the issuing CA'}` : undefined}
      footer={
        done ? (
          <Btn variant="primary" onClick={() => close(false)}>Done</Btn>
        ) : (
          <>
            <Btn variant="ghost" onClick={() => close(false)}>Cancel</Btn>
            {!fixedIdentity && identity && <Btn onClick={() => setPickedId(null)}>Choose another user</Btn>}
            <Btn variant="primary" onClick={submit} disabled={!identity || !!blocked}>
              <Link2 aria-hidden />
              {keyMode === 'server' ? 'Create one-time download' : 'Create enrollment link'}
            </Btn>
          </>
        )
      }
    >
      {done && identity ? (
        <div className="space-y-4">
          <div className="rounded-[8px] border border-[var(--f-line-2)] bg-[rgba(6,9,17,0.5)] p-3">
            <p className="f-mono break-all text-[13px]">{done.link}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <CopyButton text={done.link} what="enrollment link" label="Copy link" size="md" />
            <span className="f-small f-ink-2">for {done.deviceName} · {platformLabels[platform]}</span>
          </div>
          <p className="f-small f-ink-2 max-w-[60ch]">
            {keyMode === 'device'
              ? `${identity.displayName.split(' ')[0]} opens the link on the device. The private key is generated there and never leaves it; EasyEAP signs the request and installs the Wi-Fi profile for ${d.radiusSettings?.serverHostname ?? 'the RADIUS server'}.`
              : `The link downloads an encrypted PKCS#12 once. Send its password through a different channel than the link; EasyEAP deletes its copy of the key after the download.`}
          </p>
        </div>
      ) : !identity ? (
        <IdentityPicker value={pickedId} onChange={setPickedId} identities={d.identities} />
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3 rounded-[8px] border border-[var(--f-line)] px-3 py-2.5">
            <span className="min-w-0 flex-1">
              <span className="block text-[13.5px] font-semibold">{identity.displayName}</span>
              <span className="block truncate text-[12px] f-ink-3">{identity.upn} · {current.name}</span>
            </span>
            {decision && <AccessChip outcome={decision.outcome} />}
          </div>
          {blocked && (
            <p role="alert" className="flex gap-2 rounded-[8px] bg-[rgba(244,63,94,0.1)] px-3 py-2.5 text-[13px] text-[var(--f-crit-ink)]">
              <ShieldExclamationPoint className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span>The directory account is {identity.accountState}, so RADIUS would reject this certificate. Re-enable the account in Active Directory and run a sync, then issue.</span>
            </p>
          )}
          {!blocked && decision?.outcome === 'deny' && (
            <p className="flex gap-2 rounded-[8px] bg-[rgba(245,165,36,0.1)] px-3 py-2.5 text-[13px] text-[var(--f-warn-ink)]">
              <TriangleExclamationPoint className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span>Access policy currently denies this user ({decisionReason(decision, (id) => d.rules.find((r) => r.id === id)?.name ?? id)}). The certificate will be valid, but Wi-Fi stays rejected until a rule allows them.</span>
            </p>
          )}
          <Field label="Device name" htmlFor="f-dev-name" error={touched ? nameError : null} hint="Shown in the certificate list and the audit trail.">
            <input id="f-dev-name" className="f-input" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} placeholder={`${identity.displayName.split(' ')[0]}’s laptop`} aria-invalid={touched && !!nameError} autoComplete="off" />
          </Field>
          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Platform</legend>
            <RadioGroup.Root value={platform} onValueChange={(v) => setPlatform(v as Platform)} className="grid grid-cols-2 gap-2 sm:grid-cols-5" aria-label="Platform">
              {PLATFORMS.map((p) => (
                <RadioGroup.Item key={p.id} value={p.id} className="f-radio-card flex-col items-start gap-1.5 [&_svg]:size-4">
                  <span className="f-ink-2">{p.icon}</span>
                  <span className="text-[13px] font-medium">{platformLabels[p.id]}</span>
                </RadioGroup.Item>
              ))}
            </RadioGroup.Root>
          </fieldset>
          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Key generation</legend>
            <RadioGroup.Root value={keyMode} onValueChange={(v) => setKeyMode(v as 'device' | 'server')} className="grid gap-2 sm:grid-cols-2" aria-label="Key generation">
              <RadioGroup.Item value="device" className="f-radio-card">
                <span className="f-radio-dot" aria-hidden />
                <span>
                  <span className="flex items-center gap-2 text-[13.5px] font-semibold"><KeyRound className="size-4 text-[var(--f-valid)]" aria-hidden />On the device<span className="f-chip" data-tone="valid">Recommended</span></span>
                  <span className="f-small f-ink-2 mt-1 block">The private key is created on the device and never leaves it.</span>
                </span>
              </RadioGroup.Item>
              <RadioGroup.Item value="server" className="f-radio-card" disabled={!serverAllowed}>
                <span className="f-radio-dot" aria-hidden />
                <span>
                  <span className="flex items-center gap-2 text-[13.5px] font-semibold"><ServerCog className="size-4 text-[var(--f-warn)]" aria-hidden />Server-generated<span className="f-chip" data-tone="warn">Admin mode</span></span>
                  <span className="f-small f-ink-2 mt-1 block">EasyEAP creates the key and delivers it once as an encrypted PKCS#12. Less secure: the key exists outside the device while it is delivered.</span>
                </span>
              </RadioGroup.Item>
            </RadioGroup.Root>
            {keyMode === 'server' && <p className="f-small mt-2 text-[var(--f-warn-ink)]">Use this only for devices that cannot run the enrollment page, such as scanners and headless Linux.</p>}
          </fieldset>
        </div>
      )}
    </FDialog>
  )
}

// ── Revoke certificate ──────────────────────────────────────────────────
const REASONS: RevocationReason[] = ['keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'unspecified']
const REASON_CODE: Record<RevocationReason, number> = { unspecified: 0, keyCompromise: 1, affiliationChanged: 3, superseded: 4, cessationOfOperation: 5, certificateHold: 6 }

export function RevokeDialog({ cert, subject, open, onOpenChange, onRevoked }: { cert: Certificate; subject: string; open: boolean; onOpenChange: (o: boolean) => void; onRevoked?: () => void }) {
  const d = useTenantData()
  const { revokeCertificate } = useActions()
  const container = usePortal()
  const [reason, setReason] = useState<RevocationReason | null>(null)
  const [error, setError] = useState<string | null>(null)
  const coa = d.radiusClients.filter((n) => n.coaEnabled)
  const noCoa = d.radiusClients.filter((n) => !n.coaEnabled)
  const timeout = d.radiusSettings?.sessionTimeoutSeconds ?? null

  const confirm = () => {
    if (!reason) { setError('Choose a reason. It is published in the CRL and recorded in the audit trail.'); return }
    revokeCertificate(cert.id, reason)
    onRevoked?.()
    onOpenChange(false)
    setReason(null)
    setError(null)
    toast('Certificate revoked', `Serial ${formatSerial(cert.serial).slice(0, 14)}… · CRL regenerated and RADIUS authorization updated`, 'crit')
  }

  return (
    <AlertDialog.Root open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) { setError(null) } }}>
      <AlertDialog.Portal container={container}>
        <AlertDialog.Overlay className="f-backdrop" />
        <AlertDialog.Content className="f-dialog f-dialog-wide" data-risk="crit">
          <div className="px-6 pt-5">
            <AlertDialog.Title className="f-h2 text-[18px]">Revoke the certificate for {subject}?</AlertDialog.Title>
            <AlertDialog.Description className="f-small f-ink-2 mt-1">
              Serial <span className="f-mono">{formatSerial(cert.serial)}</span>
            </AlertDialog.Description>
          </div>
          <div className="space-y-5 px-6 pb-5 pt-4">
            <fieldset>
              <legend className="mb-2 text-[13px] font-semibold">Reason (RFC 5280)</legend>
              <RadioGroup.Root value={reason ?? ''} onValueChange={(v) => { setReason(v as RevocationReason); setError(null) }} className="grid gap-1.5 sm:grid-cols-2" aria-label="Revocation reason">
                {REASONS.map((r) => (
                  <RadioGroup.Item key={r} value={r} className="f-radio-card items-center py-2">
                    <span className="f-radio-dot mt-0" aria-hidden />
                    <span className="min-w-0">
                      <span className="block text-[13px] font-medium">{revocationReasonLabels[r]}</span>
                      <span className="f-mono block text-[11.5px] f-ink-3">{r} ({REASON_CODE[r]})</span>
                    </span>
                  </RadioGroup.Item>
                ))}
              </RadioGroup.Root>
              {error && <p className="f-field-error mt-2" role="alert">{error}</p>}
              {reason === 'certificateHold' && <p className="f-small f-ink-2 mt-2">EasyEAP treats a hold like a revocation. To restore access, issue the device a new certificate.</p>}
            </fieldset>
            <div className="space-y-2.5 rounded-[8px] border border-[var(--f-line)] bg-[rgba(6,9,17,0.4)] px-4 py-3 text-[13px]">
              <p className="font-semibold">What happens</p>
              <ul className="space-y-2 f-ink-2">
                <li className="flex gap-2"><Check className="mt-0.5 size-4 shrink-0 text-[var(--f-valid)]" aria-hidden /><span><span className="text-[var(--f-ink)]">New authentications are rejected within seconds.</span> The CRL and the RADIUS authorization snapshot regenerate immediately.</span></li>
                <li className="flex gap-2"><TriangleExclamationPoint className="mt-0.5 size-4 shrink-0 text-[var(--f-warn)]" aria-hidden /><span><span className="text-[var(--f-ink)]">A device that is already connected stays online</span> until it reauthenticates{timeout ? ` (session timeout ${formatSeconds(timeout)})` : ''} or a CoA disconnect is sent.{' '}
                  {coa.length > 0 ? <>CoA is enabled on {coa.map((n) => n.name).join(', ')}.</> : <>No controller in this tenant has CoA enabled.</>}
                  {noCoa.length > 0 && <> {noCoa.map((n) => n.name).join(', ')} {noCoa.length === 1 ? 'has' : 'have'} CoA off, so clients there stay connected until they reauthenticate.</>}
                </span></li>
                <li className="flex gap-2"><ShieldExclamationPoint className="mt-0.5 size-4 shrink-0 text-[var(--f-crit-ink)]" aria-hidden /><span>Revocation can’t be undone. If the device should connect again, issue it a new certificate.</span></li>
              </ul>
            </div>
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[var(--f-line)] px-6 py-4">
            <AlertDialog.Cancel asChild><Btn variant="ghost">Keep certificate</Btn></AlertDialog.Cancel>
            <Btn variant="danger-solid" onClick={confirm}>Revoke certificate</Btn>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  )
}

// ── Shared secret reveal (shown once) ───────────────────────────────────
function SecretOnce({ secret, onAck, acked }: { secret: string; onAck: (v: boolean) => void; acked: boolean }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 rounded-[8px] border border-[rgba(226,194,117,0.45)] bg-[rgba(226,194,117,0.06)] p-3">
        <code className="f-mono min-w-0 flex-1 break-all text-[14px] tracking-[0.04em] text-[var(--f-gold)]">{secret}</code>
        <CopyButton text={secret} what="shared secret" size="md" />
      </div>
      <p className="f-small f-ink-2">This is the only time EasyEAP shows the secret. EasyEAP stores it encrypted and never writes it to logs. If you lose it, rotate it.</p>
      <label className="flex items-center gap-2.5 text-[13px]">
        <Checkbox.Root checked={acked} onCheckedChange={(v) => onAck(v === true)} className="grid size-[18px] place-items-center rounded-[4px] border border-[var(--f-line-3)] data-[state=checked]:border-transparent data-[state=checked]:bg-[var(--f-gold)]">
          <Checkbox.Indicator><Check className="size-3.5 text-[var(--f-gold-ink)]" aria-hidden /></Checkbox.Indicator>
        </Checkbox.Root>
        I’ve entered this secret on the controller or stored it safely
      </label>
    </div>
  )
}

// ── Add controller ──────────────────────────────────────────────────────
const VENDORS: NasVendor[] = ['cisco-9800', 'cisco-aireos', 'unifi', 'other']
const defaultCoaPort = (v: NasVendor) => (v === 'cisco-9800' ? 1700 : 3799)

export function validateAddress(raw: string, existing: RadiusClient[]): string | null {
  const v = raw.trim()
  if (!v) return 'Enter the controller’s management IP address, for example 10.20.0.10, or a range such as 10.20.0.0/24.'
  const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/)
  if (!m) return 'That isn’t an IPv4 address or CIDR range. Use the form 10.20.0.10 or 10.20.0.0/24.'
  if (m.slice(1, 5).some((o) => Number(o) > 255)) return 'Each part of the address must be between 0 and 255.'
  if (m[5] !== undefined) {
    const prefix = Number(m[5])
    if (prefix > 32) return 'The prefix after “/” must be 32 or less.'
    if (prefix < 16) return `A /${prefix} range would accept RADIUS requests from far too many hosts. Use the controller’s address or a /16 or narrower range.`
  }
  if (v.startsWith('0.') || v.startsWith('127.')) return 'Use the address the controller sends RADIUS requests from, not a loopback or unspecified address.'
  if (existing.some((c) => c.address === v)) return `${existing.find((c) => c.address === v)?.name} already uses ${v}. Each address can belong to one controller.`
  return null
}

export function AddControllerDialog({ open, onOpenChange, onAdded }: { open: boolean; onOpenChange: (o: boolean) => void; onAdded?: (vendor: NasVendor) => void }) {
  const d = useTenantData()
  const { addRadiusClient } = useActions()
  const [name, setName] = useState('')
  const [vendor, setVendor] = useState<NasVendor>('cisco-9800')
  const [address, setAddress] = useState('')
  const [site, setSite] = useState('')
  const [coa, setCoa] = useState(true)
  const [coaPort, setCoaPort] = useState('1700')
  const [touched, setTouched] = useState(false)
  const [secret, setSecret] = useState<string | null>(null)
  const [acked, setAcked] = useState(false)

  const errors = {
    name: !name.trim() ? 'Name the controller so you can find it in the list, for example “HQ Catalyst 9800”.' : d.radiusClients.some((c) => c.name.toLowerCase() === name.trim().toLowerCase()) ? 'Another controller already has this name.' : null,
    address: validateAddress(address, d.radiusClients),
    site: !site.trim() ? 'Enter the site, for example “Headquarters”. It groups controllers in reports.' : null,
    coaPort: coa && !(/^\d+$/.test(coaPort) && Number(coaPort) >= 1 && Number(coaPort) <= 65535) ? 'Enter a UDP port between 1 and 65535. Catalyst 9800 listens on 1700, most others on 3799.' : null,
  }
  const hasErrors = Object.values(errors).some(Boolean)

  const reset = () => { setName(''); setVendor('cisco-9800'); setAddress(''); setSite(''); setCoa(true); setCoaPort('1700'); setTouched(false); setSecret(null); setAcked(false) }
  const close = (o: boolean) => {
    if (!o && secret && !acked) return // the secret is shown once: require acknowledgement before it disappears
    onOpenChange(o)
    if (!o) setTimeout(reset, 200)
  }
  const submit = () => {
    setTouched(true)
    if (hasErrors) return
    addRadiusClient({ name: name.trim(), vendor, address: address.trim(), site: site.trim(), coaEnabled: coa, coaPort: Number(coaPort) || defaultCoaPort(vendor) })
    setSecret(randomSecret())
    onAdded?.(vendor)
  }

  return (
    <FDialog
      open={open}
      onOpenChange={close}
      title={secret ? `${name.trim()} registered` : 'Add wireless controller'}
      description={secret ? 'Copy the shared secret into the controller’s RADIUS server settings now.' : 'EasyEAP accepts RADIUS requests only from registered controllers.'}
      risk={secret ? 'gold' : undefined}
      footer={
        secret ? (
          <Btn variant="primary" disabled={!acked} onClick={() => close(false)}>Done</Btn>
        ) : (
          <>
            <Btn variant="ghost" onClick={() => close(false)}>Cancel</Btn>
            <Btn variant="primary" onClick={submit}>Add controller and generate secret</Btn>
          </>
        )
      }
    >
      {secret ? (
        <SecretOnce secret={secret} acked={acked} onAck={setAcked} />
      ) : (
        <form className="grid gap-4 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); submit() }} noValidate>
          <div className="sm:col-span-2">
            <Field label="Name" htmlFor="f-nas-name" error={touched ? errors.name : null}>
              <input id="f-nas-name" className="f-input" value={name} onChange={(e) => setName(e.target.value)} aria-invalid={touched && !!errors.name} autoComplete="off" />
            </Field>
          </div>
          <Field label="Vendor" hint="Sets the configuration snippet and the default CoA port.">
            <FSelect label="Vendor" value={vendor} onChange={(v) => { setVendor(v as NasVendor); setCoaPort(String(defaultCoaPort(v as NasVendor))); if (v === 'unifi') setCoa(false) }} options={VENDORS.map((v) => ({ value: v, label: vendorLabels[v] }))} className="w-full" />
          </Field>
          <Field label="IP address or CIDR" htmlFor="f-nas-ip" error={touched ? errors.address : null} hint="The source address of its RADIUS requests.">
            <input id="f-nas-ip" className="f-input f-mono" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.20.0.10" aria-invalid={touched && !!errors.address} autoComplete="off" inputMode="decimal" />
          </Field>
          <Field label="Site" htmlFor="f-nas-site" error={touched ? errors.site : null}>
            <input id="f-nas-site" className="f-input" value={site} onChange={(e) => setSite(e.target.value)} aria-invalid={touched && !!errors.site} autoComplete="off" />
          </Field>
          <div className="flex flex-col gap-1.5">
            <span className="text-[13px] font-semibold" id="f-coa-label">Change of Authorization</span>
            <div className="flex items-center gap-3">
              <FSwitch checked={coa} onChange={setCoa} label="Enable CoA disconnects" />
              <input aria-labelledby="f-coa-label" aria-label="CoA port" className="f-input f-mono w-[110px]" value={coaPort} onChange={(e) => setCoaPort(e.target.value)} disabled={!coa} inputMode="numeric" aria-invalid={touched && !!errors.coaPort} />
              <span className="f-small f-ink-3">UDP port</span>
            </div>
            {touched && errors.coaPort ? <p className="f-field-error" role="alert">{errors.coaPort}</p> : <p className="f-small f-ink-3">Lets EasyEAP disconnect a client right after its certificate is revoked.</p>}
          </div>
        </form>
      )}
    </FDialog>
  )
}

// ── Rotate secret ───────────────────────────────────────────────────────
export function RotateSecretDialog({ client, open, onOpenChange }: { client: RadiusClient; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { rotateSecret } = useActions()
  const container = usePortal()
  const [secret, setSecret] = useState<string | null>(null)
  const [acked, setAcked] = useState(false)
  const close = (o: boolean) => {
    if (!o && secret && !acked) return
    onOpenChange(o)
    if (!o) setTimeout(() => { setSecret(null); setAcked(false) }, 200)
  }
  return (
    <AlertDialog.Root open={open} onOpenChange={close}>
      <AlertDialog.Portal container={container}>
        <AlertDialog.Overlay className="f-backdrop" />
        <AlertDialog.Content className="f-dialog" data-risk={secret ? 'gold' : 'warn'}>
          <div className="px-6 pt-5">
            <AlertDialog.Title className="f-h2 text-[18px]">{secret ? 'New shared secret' : `Rotate the shared secret for ${client.name}?`}</AlertDialog.Title>
            <AlertDialog.Description className="f-small f-ink-2 mt-1">
              {secret ? 'Paste it into the controller now. Requests signed with the old secret are rejected from this moment.' : 'The old secret stops working immediately. Authentication through this controller fails until you enter the new secret on it.'}
            </AlertDialog.Description>
          </div>
          <div className="px-6 pb-5 pt-4">{secret && <SecretOnce secret={secret} acked={acked} onAck={setAcked} />}</div>
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[var(--f-line)] px-6 py-4">
            {secret ? (
              <Btn variant="primary" disabled={!acked} onClick={() => close(false)}>Done</Btn>
            ) : (
              <>
                <AlertDialog.Cancel asChild><Btn variant="ghost">Cancel</Btn></AlertDialog.Cancel>
                <Btn variant="primary" onClick={() => { rotateSecret(client.id); setSecret(randomSecret()); toast('Shared secret rotated', client.name, 'gold') }}>Rotate secret</Btn>
              </>
            )}
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  )
}
