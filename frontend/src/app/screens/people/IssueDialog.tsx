// Issue a Wi-Fi certificate: POST /api/tenants/{tid}/enrollments (routers/enrollments.py, EnrollIn).
// Default: a one-time link; the key is generated on the device. Server-generated keys (a one-time PKCS#12) appear only
// when the tenant allows them (policy settings.allow_server_keygen) AND the role holds enrollment:server_keygen.
// The link and the PKCS#12 password live only in this component's state and are dropped when the dialog closes.
import { useEffect, useMemo, useState, type FormEvent, type ReactNode, type RefObject } from 'react'
import { RadioGroup } from 'radix-ui'
import { Link } from 'react-router'
import { Download, KeyRound, Laptop, Link2, Monitor, ServerCog, Smartphone, Tablet } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { cn } from '@/ui/lib'
import { filenameFrom, saveBlob } from '../../api/client'
import { useTenant } from '../../api/tenant'
import {
  createEnrollment, downloadPackage, invalidatePeople, usePki, usePolicy, useRadius,
  type Certificate, type Device, type EnrollResult, type IdentityEnrollment, type Platform, type Template,
} from '../../api/people'
import type { Outcome } from '../../api/types'
import { paths } from '../../routes'
import { Btn, Callout, Chip, CopyButton, EDialog, ESelect, errorMessage, Field, OneTimeSecret, platformLabels, Skeleton, toast } from '../../ui'
import { reasonText } from '../../ui/ledger'
import { fmtDateTime, relative } from '../../lib/format'
import { keyAlgorithm } from './shared'

export interface IssueSubject {
  id: string
  display_name: string
  upn: string | null
  username: string
  account_state: string
  source: string
  devices: Device[]
  certificates: Certificate[]
  enrollments: IdentityEnrollment[]
  access: { user: Outcome; device: Outcome }
}

const PLATFORMS: Array<{ id: Platform; icon: ReactNode }> = [
  { id: 'windows', icon: <Laptop aria-hidden /> },
  { id: 'macos', icon: <Laptop aria-hidden /> },
  { id: 'ios', icon: <Smartphone aria-hidden /> },
  { id: 'android', icon: <Tablet aria-hidden /> },
  { id: 'linux', icon: <Monitor aria-hidden /> },
]

const TTL = [
  { value: '24', label: '24 hours' },
  { value: '72', label: '3 days' },
  { value: '168', label: '7 days' },
  { value: '336', label: '14 days' },
]

const first = (name: string) => name.split(' ')[0] || name

function nextSteps(platform: Platform, who: string, ssid: string, server: string): string[] {
  const net = ssid ? `“${ssid}”` : 'the Wi-Fi network'
  switch (platform) {
    case 'windows':
      return [`${who} opens the link on the Windows device itself, in Edge or Chrome.`,
        'The page creates the key on the device, then offers an enrollment helper to run in PowerShell. It installs the certificate, trusts your Root CA and adds the Wi-Fi profile.',
        `${who} connects to ${net}. No password is needed.`]
    case 'macos':
    case 'ios':
      return [`${who} opens the link on the ${platform === 'ios' ? 'iPhone or iPad' : 'Mac'} itself, in Safari.`,
        platform === 'ios' ? 'They download the profile, then open Settings → Profile Downloaded → Install.' : 'They download the profile, then open System Settings → Privacy & Security → Profiles to install it.',
        `When asked for the certificate password, they enter the one shown on the enrollment page, then join ${net}.`]
    case 'android':
      return [`${who} opens the link on the Android device itself, in Chrome.`,
        'They download the certificate file and install it from Settings → Security → More security settings → Install from device storage → Wi-Fi certificate.',
        `They join ${net} with EAP method TLS, the installed CA certificate${server ? ` and domain ${server}` : ''}.`]
    default:
      return [`${who} opens the link on the Linux machine itself.`,
        'They save the certificate, key and CA chain under /etc/easyeap/ (key readable by root only).',
        `They install the NetworkManager profile or the wpa_supplicant block the page provides, then connect to ${net}.`]
  }
}

type Done =
  | { kind: 'link'; link: string; expiresAt: string; device: string; platform: Platform }
  | { kind: 'server'; downloadUrl: string; password: string; enrollmentId: string; expiresAt: string; device: string; platform: Platform; note: string }

export function IssueDialog({ identity, open, onOpenChange, returnFocus }: { identity: IssueSubject; open: boolean; onOpenChange: (o: boolean) => void; returnFocus?: RefObject<HTMLElement | null> }) {
  const { tid, can } = useTenant()
  const qc = useQueryClient()
  const pki = usePki(tid, open)
  const policy = usePolicy(tid, open)
  const radius = useRadius(tid, open)

  const [deviceName, setDeviceName] = useState('')
  const [platform, setPlatform] = useState<Platform>('windows')
  const [method, setMethod] = useState<'link' | 'server'>('link')
  const [templateId, setTemplateId] = useState('')
  const [ttl, setTtl] = useState('72')
  const [legacy, setLegacy] = useState(false)
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<Done | null>(null)
  const [ack, setAck] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [downloaded, setDownloaded] = useState(false)

  // Each opening starts clean; closing drops the one-time values from memory.
  useEffect(() => {
    if (!open) {
      setDone(null); setAck(false); setDownloaded(false)
      return
    }
    setDeviceName(''); setPlatform('windows'); setMethod('link'); setTemplateId(''); setTtl('72'); setLegacy(false)
    setTouched(false); setBusy(false); setError(null)
  }, [open])

  const tenantAllowsServer = policy.data?.settings.allow_server_keygen ?? false
  const roleAllowsServer = can('enrollment:server_keygen')
  const serverAvailable = tenantAllowsServer && roleAllowsServer
  const templates = useMemo(
    () => (pki.data?.templates ?? []).filter((t) => t.purpose !== 'radius-server' && (method === 'link' ? t.allow_client_keygen : t.allow_server_keygen)),
    [pki.data, method],
  )
  const template: Template | undefined = templates.find((t) => t.id === templateId) ?? templates.find((t) => t.purpose === 'user') ?? templates[0]
  const issuing = pki.data?.authorities.find((a) => a.role === 'issuing' && a.status === 'active')
  const ssid = radius.data?.settings?.ssid ?? ''
  const server = radius.data?.settings?.server_hostname ?? ''

  const name = deviceName.trim()
  const lower = name.toLowerCase()
  const sameDevice = identity.devices.find((d) => d.name.toLowerCase() === lower)
  const liveCert = sameDevice && identity.certificates.find((c) => c.device?.id === sameDevice.id && (c.status === 'active' || c.status === 'expiring'))
  const pendingSame = identity.enrollments.find((e) => e.status === 'pending' && e.device_name.toLowerCase() === lower)
  const nameError = !name
    ? `Name the device so ${first(identity.display_name)} and the audit log can tell it apart, for example “${first(identity.display_name)}’s laptop”.`
    : name.length > 120 ? 'Use 120 characters or fewer.' : null
  const accountBlocked = identity.account_state !== 'enabled'
  const decision = template?.purpose === 'device' ? identity.access.device : identity.access.user
  const denied = decision.outcome === 'deny'

  const submit = async (e?: FormEvent) => {
    e?.preventDefault()
    setTouched(true)
    if (nameError || accountBlocked || !template) return
    setBusy(true)
    setError(null)
    try {
      const res: EnrollResult = await createEnrollment(tid, {
        identity_id: identity.id, template_id: template.id, device_name: name, platform, method,
        ttl_hours: Number(ttl), ...(method === 'server' ? { legacy_p12: legacy } : {}),
        ...(method === 'link' && liveCert ? { renewal_of: liveCert.id } : {}),
      })
      if ('link' in res) setDone({ kind: 'link', link: res.link, expiresAt: res.enrollment.expires_at, device: name, platform })
      else setDone({ kind: 'server', downloadUrl: res.download_url, password: res.pkcs12_password, enrollmentId: res.enrollment.id, expiresAt: res.enrollment.expires_at, device: name, platform, note: res.note })
      setAck(false)
      void invalidatePeople(qc, tid)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const takePackage = async () => {
    if (done?.kind !== 'server') return
    setDownloading(true)
    try {
      const res = await downloadPackage(tid, done.enrollmentId)
      saveBlob(await res.blob(), filenameFrom(res, `${done.device}.p12`))
      setDownloaded(true)
      toast('Package downloaded', `${done.device}: the one-time download is used, so the user’s download link no longer works.`)
      void invalidatePeople(qc, tid)
    } catch (err) {
      toast('Download failed', errorMessage(err), 'crit')
    } finally {
      setDownloading(false)
    }
  }

  const close = () => onOpenChange(false)
  const loading = pki.isLoading || policy.isLoading

  // ── Result: one-time link or package ─────────────────────────────────
  if (done) {
    const expires = <><time dateTime={done.expiresAt} className="ee-num text-[var(--ee-ink)]">{fmtDateTime(done.expiresAt)}</time> ({relative(done.expiresAt)})</>
    return (
      <EDialog
        open={open}
        onOpenChange={onOpenChange}
        title={done.kind === 'link' ? `Enrollment link for ${done.device}` : `Server-generated package for ${done.device}`}
        description={done.kind === 'link'
          ? <>Send this link to {identity.display_name}. It works once, on the device itself.</>
          : <>A one-time PKCS#12 package for {identity.display_name}. {done.note}</>}
        risk="gold"
        wide
        returnFocus={returnFocus}
        blockDismiss={!ack}
        footer={
          <>
            {!ack && <span className="ee-small ee-ink-3 mr-auto">Copy it or confirm you’ve saved it to close.</span>}
            <Btn variant="primary" disabled={!ack} onClick={close}>Done</Btn>
          </>
        }
      >
        <div className="space-y-5">
          {done.kind === 'link' ? (
            <OneTimeSecret value={done.link} what="enrollment link" acknowledged={ack} onAcknowledge={setAck}
              note={<>EasyEAP shows this link once and stores only a hash of it. If it’s lost, cancel it on the user’s page and create a new one.</>} />
          ) : (
            <>
              <div className="space-y-2">
                <p className="text-[13px] font-semibold">Download link for {first(identity.display_name)}</p>
                <div className="flex flex-wrap items-start gap-2">
                  <code className="ee-secret min-w-0 flex-1 text-[13px]" aria-label="Package download link">{done.downloadUrl}</code>
                  <CopyButton text={done.downloadUrl} what="package download link" />
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Btn onClick={takePackage} busy={downloading} disabled={downloaded}><Download aria-hidden />{downloaded ? 'Package downloaded' : 'Download the package here instead'}</Btn>
                  <span className="ee-small ee-ink-3">{downloaded ? 'Hand the file over yourself; the link above no longer works.' : 'For hand delivery. This uses up the one-time download, so the link stops working.'}</span>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-[13px] font-semibold">PKCS#12 password</p>
                <OneTimeSecret value={done.password} what="PKCS#12 password" acknowledged={ack} onAcknowledge={setAck}
                  note={<>EasyEAP shows this password once and does not keep it. Send it through a different channel from the link, for example by phone or SMS.</>} />
              </div>
            </>
          )}

          <p className="text-[13px] ee-ink-2">Expires {expires}. After that, create a new {done.kind === 'link' ? 'link' : 'package'}.</p>

          <div>
            <p className="text-[13px] font-semibold">Next steps on {platformLabels[done.platform]}</p>
            <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-[13px] ee-ink-2 marker:text-[var(--ee-ink-3)]">
              {(done.kind === 'link'
                ? nextSteps(done.platform, first(identity.display_name), ssid, server)
                : [`${first(identity.display_name)} opens the download link on the device and saves the package, or you hand over the file.`,
                  'Installing it asks for the PKCS#12 password above.',
                  ssid ? `Then they join “${ssid}”${server ? `, checking the server name ${server}` : ''}.` : 'Then they join the Wi-Fi network.']
              ).map((s) => <li key={s}>{s}</li>)}
            </ol>
          </div>
          <p className="ee-small ee-ink-3">One certificate per device. The new certificate appears on {first(identity.display_name)}’s page once the device completes enrollment.</p>
        </div>
      </EDialog>
    )
  }

  // ── Form ─────────────────────────────────────────────────────────────
  return (
    <EDialog
      open={open}
      onOpenChange={(o) => { if (!busy) onOpenChange(o) }}
      title={`Issue a certificate for ${identity.display_name}`}
      description={template ? <>{template.name} template · {keyAlgorithm(template.key_algorithm)} · valid {template.validity_days} days{issuing ? <> · issued by {issuing.common_name}</> : null}</> : 'One certificate per device.'}
      risk="gold"
      wide
      returnFocus={returnFocus}
      footer={
        <>
          <Btn variant="ghost" onClick={close} disabled={busy}>Cancel</Btn>
          <Btn variant="primary" onClick={() => submit()} busy={busy} disabled={accountBlocked || !template || loading}>
            {method === 'server' ? <ServerCog aria-hidden /> : <Link2 aria-hidden />}
            {method === 'server' ? 'Create one-time package' : 'Create enrollment link'}
          </Btn>
        </>
      }
    >
      {loading ? (
        <div className="space-y-3" role="status" aria-label="Loading certificate templates"><Skeleton className="w-3/5" /><Skeleton /><Skeleton className="w-4/5" /></div>
      ) : pki.error || policy.error ? (
        <Callout tone="crit" title="Certificate templates couldn’t be loaded">{errorMessage(pki.error ?? policy.error)}</Callout>
      ) : !pki.data?.initialized ? (
        <Callout tone="warn" title="This tenant has no certificate authority yet" action={<Link to={paths.pki(tid)} className="ee-btn ee-btn-sm">Open PKI</Link>}>
          Initialize the tenant’s PKI before issuing certificates.
        </Callout>
      ) : (
        <form className="space-y-5" onSubmit={submit} noValidate>
          {error && <Callout tone="crit" title="The certificate wasn’t issued">{error}</Callout>}
          {accountBlocked && (
            <Callout tone="crit" title={`The account is ${identity.account_state}`}>
              {identity.source === 'ad'
                ? 'Disabled, locked and deleted accounts can’t be enrolled. Re-enable it in Active Directory; the change arrives with the next directory sync.'
                : 'Disabled accounts can’t be enrolled. Enable the account on this page first.'}
            </Callout>
          )}
          {!accountBlocked && denied && (
            <Callout tone="warn" title="The access policy denies this user">
              {reasonText[decision.reason_code ?? ''] ?? decision.reason_code}. The certificate will be valid, but RADIUS rejects the connection until a rule allows them.
            </Callout>
          )}

          <Field label="Device name" htmlFor="issue-device" error={touched ? nameError : null} hint="Shown in the certificate list and the audit log. Name the physical device, for example “Jordan’s ThinkPad”.">
            <input id="issue-device" className="ee-input" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} placeholder={`${first(identity.display_name)}’s laptop`}
              aria-invalid={touched && !!nameError} autoComplete="off" maxLength={120} autoFocus />
          </Field>
          {liveCert && (
            <Callout tone="gold" title={`${sameDevice!.name} already has an active certificate`}>
              One certificate per device. If this is the same device, this link renews it: the old certificate is marked superseded after enrollment but stays valid until it expires or you revoke it. If it’s another device, give it its own name.
            </Callout>
          )}
          {pendingSame && !liveCert && (
            <Callout tone="gold">There is already a pending link for “{pendingSame.device_name}”. Cancel it on the user’s page if it was sent by mistake.</Callout>
          )}

          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Platform</legend>
            <RadioGroup.Root value={platform} onValueChange={(v) => setPlatform(v as Platform)} className="grid grid-cols-2 gap-2 sm:grid-cols-5" aria-label="Platform">
              {PLATFORMS.map((p) => (
                <RadioGroup.Item key={p.id} value={p.id} className="ee-radio-card flex-col items-start gap-1.5 [&_svg]:size-4">
                  <span className="ee-ink-2">{p.icon}</span>
                  <span className="text-[13px] font-medium">{platformLabels[p.id]}</span>
                </RadioGroup.Item>
              ))}
            </RadioGroup.Root>
          </fieldset>

          <fieldset>
            <legend className="mb-1.5 text-[13px] font-semibold">Key generation</legend>
            <RadioGroup.Root value={method} onValueChange={(v) => { setMethod(v as 'link' | 'server'); setTemplateId('') }} className="grid gap-2 sm:grid-cols-2" aria-label="Key generation">
              <RadioGroup.Item value="link" className="ee-radio-card">
                <span className="ee-radio-dot" aria-hidden />
                <span className="min-w-0">
                  <span className="flex flex-wrap items-center gap-2 text-[13.5px] font-semibold"><KeyRound className="size-4 text-[var(--ee-valid)]" aria-hidden />On the device (one-time link)<Chip tone="valid">Recommended</Chip></span>
                  <span className="ee-small ee-ink-2 mt-1 block">The private key is created on the device and never leaves it. You send a link; it works once.</span>
                </span>
              </RadioGroup.Item>
              {serverAvailable && (
                <RadioGroup.Item value="server" className="ee-radio-card">
                  <span className="ee-radio-dot" aria-hidden />
                  <span className="min-w-0">
                    <span className="flex flex-wrap items-center gap-2 text-[13.5px] font-semibold"><ServerCog className="size-4 text-[var(--ee-warn)]" aria-hidden />Server-generated package<Chip tone="warn">Less secure</Chip></span>
                    <span className="ee-small ee-ink-2 mt-1 block">EasyEAP creates the key and delivers it once as a password-protected PKCS#12. The key exists outside the device until it is installed.</span>
                  </span>
                </RadioGroup.Item>
              )}
            </RadioGroup.Root>
            {!serverAvailable && (
              <p className="ee-small ee-ink-3 mt-2">
                Server-generated keys are off{' '}
                {!tenantAllowsServer && !roleAllowsServer ? <>for this tenant, and your role can’t create them.</>
                  : !tenantAllowsServer ? <>for this tenant. A Tenant Administrator can allow them in <Link className="underline hover:text-[var(--ee-ink)]" to={paths.settings(tid)}>tenant settings</Link>, for devices that can’t open the enrollment page.</>
                    : <>for your role. Only a Tenant Administrator can create server-generated packages.</>}
              </p>
            )}
            {method === 'server' && <p className="ee-small mt-2 text-[var(--ee-warn-ink)]">Use this only for devices that can’t open the enrollment page, such as scanners or headless Linux.</p>}
          </fieldset>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Certificate template" htmlFor="issue-template" hint={template ? `${template.purpose === 'device' ? 'Device' : 'User'} certificate · ${template.subject_pattern}` : undefined}>
              {templates.length === 0
                ? <p className="ee-small text-[var(--ee-warn-ink)]">No template allows {method === 'link' ? 'keys generated on the device' : 'server-generated keys'}. Adjust templates on the PKI page.</p>
                : <ESelect id="issue-template" label="Certificate template" value={template?.id ?? ''} onChange={setTemplateId} className="w-full"
                  options={templates.map((t) => ({ value: t.id, label: `${t.name} · ${t.validity_days} days` }))} />}
            </Field>
            <Field label={method === 'link' ? 'Link expires after' : 'Download expires after'} htmlFor="issue-ttl" hint="Unused links stop working after this.">
              <ESelect id="issue-ttl" label={method === 'link' ? 'Link expires after' : 'Download expires after'} value={ttl} onChange={setTtl} options={TTL} className="w-full" />
            </Field>
          </div>

          {method === 'server' && (
            <label className="flex items-start gap-2.5 text-[13px]">
              <input type="checkbox" className="ee-check mt-0.5" checked={legacy} onChange={(e) => setLegacy(e.target.checked)} />
              <span>Use legacy PKCS#12 encryption<span className="ee-small ee-ink-3 block">Only for older Android and macOS keychains that can’t open the modern format. Weaker protection for the key.</span></span>
            </label>
          )}

          <p className={cn('ee-small ee-ink-3')}>One certificate per device. Issue a separate certificate for each laptop, phone or tablet; never share one between devices.</p>
          <button type="submit" className="sr-only" tabIndex={-1}>Create</button>
        </form>
      )}
    </EDialog>
  )
}
