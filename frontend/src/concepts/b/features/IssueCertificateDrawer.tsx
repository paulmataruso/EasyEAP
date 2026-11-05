import { useId, useMemo, useState } from 'react'
import { RadioGroup } from 'radix-ui'
import { CircleCheck, KeyRound, Link2, ServerCog, Smartphone } from 'lucide-react'
import { useDecision, useTenantData, useTenants } from '@/prototype/store'
import { platformLabels } from '@/domain/explain'
import type { Platform } from '@/domain/types'
import { Drawer } from '../ui/Drawer'
import { Button } from '../ui/Button'
import { TextField } from '../ui/Field'
import { KeyValue, Notice } from '../ui/Panel'
import { CopyButton } from '../ui/CopyButton'
import { keyAlgorithmLabels } from '../lib/labels'
import { PlatformIcon } from './PlatformIcon'

const PLATFORMS: Platform[] = ['windows', 'macos', 'ios', 'android', 'linux']
type KeyMode = 'device' | 'server'

const enrollSteps: Record<Platform, string[]> = {
  windows: ['Open the link on the laptop and sign in with the work account.', 'The enrollment helper generates the key in the Windows certificate store (TPM when available).', 'The Wi-Fi profile installs and the laptop joins the secure SSID.'],
  macos: ['Open the link in Safari on the Mac.', 'The browser generates the key and installs a signed configuration profile.', 'Approve the profile in System Settings; Wi-Fi connects automatically.'],
  ios: ['Open the link on the iPhone or iPad.', 'Install the configuration profile; the device creates its own key.', 'Approve it in Settings, then join the secure SSID.'],
  android: ['Open the link on the Android device.', 'The browser generates the key and downloads the certificate.', 'Add the Wi-Fi network using the certificate and the RADIUS server name shown.'],
  linux: ['Open the link and copy the CSR command shown for NetworkManager.', 'Run it on the workstation; the key stays on the machine.', 'Upload the CSR; the signed certificate and connection file download.'],
}

function token(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = new Uint8Array(12)
  crypto.getRandomValues(bytes)
  const s = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`
}

/** Issue Wi-Fi certificate: device + platform + key-generation method → one-time enrollment link. */
export function IssueCertificateDrawer({ identityId, prefill, open, onOpenChange }: { identityId: string; prefill?: { deviceName?: string; platform?: Platform }; open: boolean; onOpenChange: (o: boolean) => void }) {
  const d = useTenantData()
  const { current } = useTenants()
  const identity = d.identities.find((i) => i.id === identityId)
  const decision = useDecision(identity)
  const template = d.templates.find((t) => t.purpose === 'user')
  const issuer = d.cas.find((c) => c.role === 'issuing')
  const radius = d.radiusSettings
  const formId = useId()
  const [deviceName, setDeviceName] = useState(prefill?.deviceName ?? '')
  const [platform, setPlatform] = useState<Platform>(prefill?.platform ?? 'windows')
  const [keyMode, setKeyMode] = useState<KeyMode>('device')
  const [touched, setTouched] = useState(false)
  const [link, setLink] = useState<string | null>(null)
  const platformLabelId = useId()

  const nameError = useMemo(() => {
    const v = deviceName.trim()
    if (!v) return 'Name the device so the certificate can be found and revoked later, e.g. “Priya’s iPhone”.'
    if (v.length > 64) return 'Keep the device name to 64 characters or fewer.'
    if (d.devices.some((x) => x.identityId === identityId && x.name.toLowerCase() === v.toLowerCase()) && !prefill?.deviceName) return 'This user already has a device with that name. Choose another, or issue a replacement from the device’s certificate.'
    return null
  }, [deviceName, d.devices, identityId, prefill?.deviceName])

  if (!identity) {
    return (
      <Drawer open={open} onOpenChange={onOpenChange} title="User not found">
        <Notice tone="warn">This user is not in the current tenant.</Notice>
      </Drawer>
    )
  }

  const blocked = identity.accountState !== 'enabled'
  const first = identity.displayName.split(' ')[0]
  const submit = () => {
    setTouched(true)
    if (nameError || blocked) return
    setLink(`https://enroll.brightline.example/${current.slug}/${token()}`)
  }

  if (link) {
    return (
      <Drawer
        open={open}
        onOpenChange={onOpenChange}
        title="Enrollment link created"
        description={`${deviceName.trim()} · ${platformLabels[platform]} · ${identity.displayName}`}
        footer={
          <>
            <Button
              onClick={() => {
                setLink(null)
                setDeviceName('')
                setTouched(false)
              }}
            >
              Issue another
            </Button>
            <Button variant="primary" className="ml-auto" onClick={() => onOpenChange(false)}>
              Done
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Notice tone="ok" title="Send this link to the user" icon={CircleCheck}>
            Single use, expires in 72 hours. No certificate exists until {first} completes enrollment on the device; it then appears under this device.
          </Notice>
          <div className="rounded-md border border-[var(--b-line-strong)] bg-[var(--b-sunken)] p-3">
            <p className="b-label mb-1.5">One-time enrollment link</p>
            <p className="b-mono break-all text-[13px] text-[var(--b-cyan)]">{link}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <CopyButton text={link} label="Copy link" />
              {identity.email && <span className="b-t3 self-center text-[12px]">Suggested recipient: {identity.email}</span>}
            </div>
          </div>
          <section aria-labelledby="enroll-steps">
            <h3 id="enroll-steps" className="mb-2 text-[13.5px] font-semibold">
              What {first} will see on {platformLabels[platform]}
            </h3>
            <ol className="space-y-2">
              {(keyMode === 'server'
                ? ['Open the link and sign in.', 'Download the password-protected PKCS#12 file once; the password is shown a single time.', 'Install it and join the secure SSID. The download is destroyed after retrieval.']
                : enrollSteps[platform]
              ).map((s, i) => (
                <li key={i} className="flex gap-2.5 text-[13px]">
                  <span className="b-cond b-num grid size-5 shrink-0 place-items-center rounded border border-[var(--b-line-strong)] text-[12px] font-semibold text-[var(--b-text-2)]">{i + 1}</span>
                  <span className="b-t2">{s}</span>
                </li>
              ))}
            </ol>
          </section>
          {radius && (
            <p className="b-t3 text-[12px]">
              Devices verify the RADIUS server as <span className="b-mono text-[var(--b-text-2)]">{radius.serverHostname}</span>, signed by {d.cas.find((c) => c.role === 'root')?.commonName}.
            </p>
          )}
        </div>
      </Drawer>
    )
  }

  return (
    <Drawer
      open={open}
      onOpenChange={onOpenChange}
      title="Issue Wi-Fi certificate"
      description={`${identity.displayName} · ${identity.upn ?? identity.username}`}
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button type="submit" form={formId} variant="primary" icon={Link2} className="ml-auto" disabled={blocked}>
            Create enrollment link
          </Button>
        </>
      }
    >
      <form
        id={formId}
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        {blocked && (
          <Notice tone="crit" title={`Directory account is ${identity.accountState}`}>
            EasyEAP does not issue certificates to disabled, locked or deleted accounts. Re-enable the account in Active Directory and run a sync first.
          </Notice>
        )}
        {!blocked && decision?.outcome === 'deny' && (
          <Notice tone="warn" title="Policy currently denies this user">
            The certificate can be issued, but RADIUS will reject it until an Allow rule matches one of {first}’s groups.
          </Notice>
        )}
        <TextField
          label="Device name"
          placeholder={`${first}’s laptop`}
          value={deviceName}
          onChange={(e) => setDeviceName(e.target.value)}
          onBlur={() => setTouched(true)}
          error={touched ? nameError : null}
          hint="One certificate per device, so each can be revoked on its own."
          autoFocus
        />
        <fieldset>
          <legend id={platformLabelId} className="b-field-label">
            Platform
          </legend>
          <RadioGroup.Root value={platform} onValueChange={(v) => setPlatform(v as Platform)} aria-labelledby={platformLabelId} className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
            {PLATFORMS.map((p) => (
              <RadioGroup.Item key={p} value={p} className="b-radio-card !items-center">
                <span className="b-radio-dot !mt-0" aria-hidden />
                <PlatformIcon platform={p} className="text-[var(--b-text-2)]" />
                <span className="text-[13px]">{platformLabels[p]}</span>
              </RadioGroup.Item>
            ))}
          </RadioGroup.Root>
        </fieldset>
        <fieldset>
          <legend className="b-field-label">Key generation</legend>
          <RadioGroup.Root value={keyMode} onValueChange={(v) => setKeyMode(v as KeyMode)} className="grid gap-1.5" aria-label="Key generation">
            <RadioGroup.Item value="device" className="b-radio-card" disabled={template ? !template.allowClientKeyGeneration : false}>
              <span className="b-radio-dot" aria-hidden />
              <Smartphone className="mt-0.5 size-4 shrink-0 text-[var(--b-cyan)]" aria-hidden />
              <span className="min-w-0">
                <span className="flex flex-wrap items-center gap-2 text-[13px] font-medium text-[var(--b-text)]">
                  On the device <span className="b-badge b-tone-ok">Recommended</span>
                </span>
                <span className="b-t2 mt-0.5 block text-[12.5px] leading-relaxed">The private key is created on {first}’s device and never leaves it. EasyEAP only signs the request.</span>
              </span>
            </RadioGroup.Item>
            <RadioGroup.Item value="server" className="b-radio-card" disabled={template ? !template.allowServerKeyGeneration : false}>
              <span className="b-radio-dot" aria-hidden />
              <ServerCog className="mt-0.5 size-4 shrink-0 text-[var(--b-text-2)]" aria-hidden />
              <span className="min-w-0">
                <span className="flex flex-wrap items-center gap-2 text-[13px] font-medium text-[var(--b-text)]">
                  Generated by EasyEAP <span className="b-badge b-tone-warn">Admin mode · less secure</span>
                </span>
                <span className="b-t2 mt-0.5 block text-[12.5px] leading-relaxed">
                  EasyEAP creates the key and packages it as an encrypted PKCS#12 for a single download. The key exists outside the device until it is installed; use only for devices that cannot generate keys.
                </span>
              </span>
            </RadioGroup.Item>
          </RadioGroup.Root>
        </fieldset>
        <section aria-labelledby="issue-summary">
          <h3 id="issue-summary" className="b-label mb-1">
            Certificate
          </h3>
          <KeyValue
            rows={[
              ['Template', template?.name ?? 'User Wi-Fi'],
              ['Key', template ? `${keyAlgorithmLabels[template.keyAlgorithm]} · ${template.validityDays} days, renews ${template.renewBeforeDays} days early` : '—'],
              ['Issued by', issuer?.commonName ?? '—'],
              ['Subject', <span key="s" className="b-mono">CN={identity.upn}</span>],
              ['Wi-Fi access', decision ? (decision.outcome === 'allow' ? `Allowed · VLAN ${d.vlans.find((v) => v.id === decision.vlanId)?.vlanId ?? '—'}` : 'Denied by policy') : '—'],
            ]}
          />
        </section>
        <p className="b-t3 flex items-start gap-2 text-[12px]">
          <KeyRound className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Private keys, PKCS#12 passwords and enrollment secrets are never logged.
        </p>
      </form>
    </Drawer>
  )
}
