import { CircleCheck, Laptop, Monitor, ShieldAlert, Smartphone, Tablet, Terminal } from 'lucide-react'
import { RadioGroup } from 'radix-ui'
import { useState, type ReactNode } from 'react'
import type { Identity, Platform } from '@/domain/types'
import { platformLabels } from '@/domain/explain'
import { useTenantData, useTenants } from '@/prototype/store'
import { CopyButton, TextField } from '../ui/Controls'
import { Modal } from '../ui/Dialog'
import { KV, Notice } from '../ui/Section'
import { Tape } from '../ui/Tape'
import { userCode } from '../model/codes'

const PLATFORM_ICON: Record<Platform, ReactNode> = {
  windows: <Laptop aria-hidden="true" className="size-4" />,
  macos: <Monitor aria-hidden="true" className="size-4" />,
  ios: <Tablet aria-hidden="true" className="size-4" />,
  android: <Smartphone aria-hidden="true" className="size-4" />,
  linux: <Terminal aria-hidden="true" className="size-4" />,
}
const ON_DEVICE: Record<Platform, string> = {
  windows: 'Windows creates the key in its certificate store during enrollment.',
  macos: 'The configuration profile has macOS create the key in the keychain.',
  ios: 'The configuration profile has iOS/iPadOS create the key on the device.',
  android: 'The enrollment page creates the key in the Android keystore.',
  linux: 'The enrollment page gives an openssl command; the CSR is uploaded, the key stays local.',
}

function linkCode(seed: string) {
  let h = 2166136261
  for (const ch of seed) h = Math.imul(h ^ ch.charCodeAt(0), 16777619)
  return (h >>> 0).toString(36).toUpperCase().padStart(7, '0').slice(0, 7) + '-' + ((h >>> 3) % 9000 + 1000)
}

/** Primary workflow: issue a Wi-Fi certificate. Stops at "Enrollment link created". */
export function IssueCertificateDialog({ identity, open, onOpenChange }: { identity: Identity; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { current } = useTenants()
  const d = useTenantData()
  const template = d.templates.find((t) => t.purpose === 'user')
  const [name, setName] = useState('')
  const [platform, setPlatform] = useState<Platform>('windows')
  const [keyMode, setKeyMode] = useState<'device' | 'server'>('device')
  const [tried, setTried] = useState(false)
  const [created, setCreated] = useState<string | null>(null)
  const first = identity.displayName.split(' ')[0]

  const trimmed = name.trim()
  const nameError = !trimmed
    ? 'Enter a device name so the certificate can be found and revoked later, e.g. “' + first + '’s Laptop”.'
    : trimmed.length > 64
      ? 'Keep the device name to 64 characters or fewer.'
      : d.devices.some((x) => x.identityId === identity.id && x.name.toLowerCase() === trimmed.toLowerCase())
        ? `${identity.displayName} already has a device called “${trimmed}”. Use a distinct name; each device gets its own certificate.`
        : null

  const reset = () => { setName(''); setPlatform('windows'); setKeyMode('device'); setTried(false); setCreated(null) }
  const close = (o: boolean) => { if (!o) reset(); onOpenChange(o) }
  const submit = () => {
    setTried(true)
    if (nameError) return
    setCreated(`https://enroll.${current.domain.replace(/^(corp|ad)\./, '')}/e/${linkCode(identity.id + trimmed + platform + keyMode)}`)
  }

  if (created) {
    return (
      <Modal
        open={open}
        onOpenChange={close}
        title="Enrollment link created"
        tape={<Tape code={userCode(identity)} />}
        description={<>{trimmed} · {platformLabels[platform]} · {keyMode === 'device' ? 'key generated on the device' : 'server-generated key (admin mode)'}</>}
        footer={<button type="button" className="d-btn d-btn--primary" onClick={() => close(false)}>Done</button>}
      >
        <Notice tone="ok" icon={<CircleCheck aria-hidden="true" />}>
          <strong>Send this link to {identity.displayName}.</strong> It works once, expires in 72 hours, and walks them through installing the Wi-Fi profile on their {platformLabels[platform]} device.
        </Notice>
        <div className="d-field">
          <span className="d-field-label">One-time enrollment link</span>
          <div className="d-secret">
            <span className="min-w-0 flex-1">{created}</span>
            <CopyButton text={created} what="enrollment link" small />
          </div>
          <p className="d-field-hint">Sent nowhere automatically. {identity.email ? <>Their directory email is <span className="mono">{identity.email}</span>.</> : null}</p>
        </div>
        <KV items={[
          ['Template', template ? `${template.name} · ${template.validityDays} days · ECDSA P-256` : 'User Wi-Fi'],
          ['Subject', <span className="mono" key="s">CN={identity.upn ?? identity.username}</span>],
          ['SSID profile', <span className="mono" key="p">{current.slug === 'harborview' ? 'HV-Secure' : `${current.name.split(' ')[0]}-Secure`} · EAP-TLS · server {d.radiusSettings?.serverHostname}</span>],
        ]} />
      </Modal>
    )
  }

  return (
    <Modal
      open={open}
      onOpenChange={close}
      width={640}
      title="Issue Wi-Fi certificate"
      tape={<Tape code={userCode(identity)} />}
      description={<>For {identity.displayName} · <span className="mono">{identity.upn}</span>. One certificate per device; each can be revoked on its own.</>}
      footer={
        <>
          <button type="button" className="d-btn" onClick={() => close(false)}>Cancel</button>
          <button type="button" className="d-btn d-btn--primary" onClick={submit}>Create enrollment link</button>
        </>
      }
    >
      <TextField label="Device name" autoFocus value={name} onChange={setName} placeholder={`${first}’s Laptop`} error={tried ? nameError : null} hint="Shown to admins in the device list and on the certificate record." />

      <fieldset>
        <legend className="d-field-label mb-2">Platform</legend>
        <RadioGroup.Root className="grid grid-cols-2 gap-1.5 sm:grid-cols-5" value={platform} onValueChange={(v) => setPlatform(v as Platform)} orientation="horizontal">
          {(Object.keys(platformLabels) as Platform[]).map((p) => (
            <RadioGroup.Item key={p} value={p} className="d-radio-card !grid-cols-1 !gap-1.5 !px-2.5 !py-2.5 text-[13px]">
              <span className="flex items-center gap-2 text-[var(--d-ink-2)]">{PLATFORM_ICON[p]}</span>
              <span>{platformLabels[p]}</span>
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
      </fieldset>

      <fieldset>
        <legend className="d-field-label mb-2">Key generation</legend>
        <RadioGroup.Root className="grid gap-1.5" value={keyMode} onValueChange={(v) => setKeyMode(v as 'device' | 'server')}>
          <RadioGroup.Item value="device" className="d-radio-card">
            <span className="d-radio-dot"><RadioGroup.Indicator asChild><span /></RadioGroup.Indicator></span>
            <span>
              <span className="flex flex-wrap items-center gap-2 font-semibold">On the device <span className="text-[12px] font-medium text-[var(--d-signal)]">Recommended</span></span>
              <span className="mt-1 block text-[13px] text-[var(--d-ink-2)]">The private key is created on the device and never leaves it. {ON_DEVICE[platform]}</span>
            </span>
          </RadioGroup.Item>
          <RadioGroup.Item value="server" className="d-radio-card" disabled={template ? !template.allowServerKeyGeneration : false}>
            <span className="d-radio-dot"><RadioGroup.Indicator asChild><span /></RadioGroup.Indicator></span>
            <span>
              <span className="font-semibold">Server-generated (admin mode)</span>
              <span className="mt-1 block text-[13px] text-[var(--d-ink-2)]">EasyEAP creates the key and packages it as a password-protected PKCS#12 for one encrypted download. Less secure: the key exists outside the device, so use it only for devices that can’t enroll themselves.</span>
            </span>
          </RadioGroup.Item>
        </RadioGroup.Root>
        {keyMode === 'server' && (
          <div className="mt-2">
            <Notice tone="warn" icon={<ShieldAlert aria-hidden="true" />}>
              The PKCS#12 password is shown once to you and never stored. Deliver it separately from the link.
            </Notice>
          </div>
        )}
      </fieldset>
    </Modal>
  )
}
