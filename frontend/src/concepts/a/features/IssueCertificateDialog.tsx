import { useMemo, useState } from 'react'
import { CircleCheck, KeyRound, Link2, ShieldAlert, Smartphone, TriangleAlert, UserRound } from 'lucide-react'
import type { Identity, Platform } from '@/domain/types'
import { platformLabels } from '@/domain/explain'
import { cn } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { AccessPill, VlanChip } from '../ui/badges'
import { ChoiceGroup, SearchInput, TextField } from '../ui/fields'
import { GlassDialog, Stepper } from '../ui/dialog'
import { Avatar, Button, CopyButton, KeyValues, Mono, Pill } from '../ui/primitives'
import { AffectsLine } from '../ui/scope'
import { decide, enrollmentToken, tenantHealth, useLookups } from '../lib/model'
import { PLATFORM_NOUN, PlatformIcon } from './platform'

type KeyMode = 'device' | 'server'
const PLATFORMS: Platform[] = ['windows', 'macos', 'ios', 'android', 'linux']
const PLATFORM_HELP: Record<Platform, string> = {
  windows: 'Wi-Fi profile + certificate via the EasyEAP installer',
  macos: 'Configuration profile (.mobileconfig)',
  ios: 'Configuration profile, installed from Settings',
  android: 'Certificate + network suggestion for Android 11+',
  linux: 'NetworkManager profile with a CSR made on the device',
}

/** Issue Wi-Fi certificate: (user) → device → key generation → review → enrollment link. */
export function IssueCertificateDialog({ open, onOpenChange, identity: preset }: { open: boolean; onOpenChange: (o: boolean) => void; identity?: Identity }) {
  const d = useTenantData()
  const { current } = useTenants()
  const { vlanById, templateById } = useLookups()
  const steps = preset ? ['Device', 'Key', 'Review'] : ['User', 'Device', 'Key', 'Review']
  const [step, setStep] = useState(0)
  const [picked, setPicked] = useState<string>('')
  const [query, setQuery] = useState('')
  const [platform, setPlatform] = useState<Platform | ''>('')
  const [deviceName, setDeviceName] = useState('')
  const [nameTouched, setNameTouched] = useState(false)
  const [keyMode, setKeyMode] = useState<KeyMode>('device')
  const [link, setLink] = useState<string | null>(null)

  const pickedIndex = picked ? Number(picked) : -1
  const identity = preset ?? (pickedIndex >= 0 ? d.identities[pickedIndex] : undefined)
  const template = templateById.get(`${current.id}:tpl-user`) ?? d.templates.find((t) => t.purpose === 'user')
  const decision = useMemo(() => (identity ? decide(identity, d) : null), [identity, d])
  const stepName = steps[step]
  const first = identity?.displayName.split(' ')[0] ?? ''

  const candidates = useMemo(() => {
    const q = query.trim().toLowerCase()
    return d.identities
      .map((i, index) => ({ i, index }))
      .filter(({ i }) => !q || `${i.displayName} ${i.upn ?? ''} ${i.department ?? ''}`.toLowerCase().includes(q))
      .slice(0, 8)
  }, [d.identities, query])

  const nameError = !deviceName.trim() ? 'Name the device so you can find its certificate later, for example “Priya’s iPhone”.' : deviceName.trim().length > 64 ? 'Use 64 characters or fewer.' : null
  const duplicate = identity && d.devices.some((x) => x.identityId === identity.id && x.name.toLowerCase() === deviceName.trim().toLowerCase())

  const reset = () => {
    setStep(0)
    setPicked('')
    setQuery('')
    setPlatform('')
    setDeviceName('')
    setNameTouched(false)
    setKeyMode('device')
    setLink(null)
  }
  const close = (o: boolean) => {
    onOpenChange(o)
    if (!o) window.setTimeout(reset, 200)
  }

  const canNext = stepName === 'User' ? !!identity : stepName === 'Device' ? !!platform && !nameError : stepName === 'Key' ? !!keyMode : true
  const next = () => {
    if (stepName === 'Device' && nameError) {
      setNameTouched(true)
      return
    }
    if (stepName === 'Review') {
      setLink(`https://enroll.${current.domain}/e/${enrollmentToken()}`)
      return
    }
    setStep((s) => Math.min(steps.length - 1, s + 1))
  }

  const choosePlatform = (p: Platform) => {
    setPlatform(p)
    if (!nameTouched || !deviceName) setDeviceName(first ? `${first}’s ${PLATFORM_NOUN[p]}` : PLATFORM_NOUN[p])
  }

  return (
    <GlassDialog
      open={open}
      onOpenChange={close}
      width={640}
      title={link ? 'Enrollment link created' : 'Issue Wi-Fi certificate'}
      description={identity ? `${identity.displayName} · ${identity.upn ?? identity.username}` : 'Choose who the certificate is for, then the device.'}
      header={!link && <Stepper steps={steps} current={step} />}
      footer={
        link ? (
          <>
            <AffectsLine tenant={current.name} record={`${identity?.displayName} · ${deviceName}`} recordIcon={Smartphone} />
            <Button variant="primary" onClick={() => close(false)}>
              Done
            </Button>
          </>
        ) : (
          <>
            <AffectsLine tenant={current.name} tenantHealth={tenantHealth(current, d.radiusClients).state} record={identity?.displayName} recordIcon={UserRound} />
            <div className="flex items-center gap-2">
              {step > 0 && (
                <Button variant="ghost" onClick={() => setStep((s) => s - 1)}>
                  Back
                </Button>
              )}
              <Button variant="primary" icon={stepName === 'Review' ? Link2 : undefined} disabled={!canNext} onClick={next}>
                {stepName === 'Review' ? 'Create enrollment link' : 'Continue'}
              </Button>
            </div>
          </>
        )
      }
    >
      <div className="pt-4">
        {link ? (
          <div className="flex flex-col gap-4">
            <div className="flex items-start gap-3 rounded-[10px] border border-[rgba(74,222,128,0.22)] bg-[rgba(34,197,94,0.07)] p-3.5">
              <CircleCheck className="mt-0.5 size-5 shrink-0 text-[var(--a-ok-text)]" aria-hidden />
              <div className="text-[14px] text-[var(--a-text-2)]">
                <p className="font-semibold text-[var(--a-text)]">Send this link to {first || 'the user'}. It works once and expires in 24 hours.</p>
                <p className="mt-0.5">
                  {keyMode === 'device'
                    ? `Opened on ${deviceName}, it creates the private key on the device and installs the certificate and Wi-Fi profile.`
                    : `It downloads a password-protected PKCS#12 package for ${deviceName}. The password is shown once on the enrollment page.`}
                </p>
              </div>
            </div>
            <div>
              <p className="a-label">Enrollment link</p>
              <div className="flex flex-wrap items-center gap-2 rounded-[10px] border border-white/10 bg-black/30 p-2 pl-3">
                <Mono className="min-w-0 flex-1 truncate text-[13px] text-[var(--a-text)]">{link}</Mono>
                <CopyButton text={link} label="Copy link" />
              </div>
              <p className="a-hint">The certificate is issued when the user completes enrollment; it then appears under their devices.</p>
            </div>
          </div>
        ) : stepName === 'User' ? (
          <div className="flex flex-col gap-3">
            <SearchInput value={query} onChange={setQuery} label="Find a user" placeholder="Name, UPN or department" />
            <ChoiceGroup
              label="User"
              value={picked}
              onChange={setPicked}
              options={candidates.map(({ i, index }) => ({
                value: String(index),
                title: (
                  <span className="flex items-center gap-2">
                    <Avatar name={i.displayName} size={22} />
                    {i.displayName}
                  </span>
                ),
                description: (
                  <>
                    <Mono>{i.upn ?? i.username}</Mono>
                    {i.department ? ` · ${i.department}` : ''}
                  </>
                ),
                aside: i.accountState !== 'enabled' ? <Pill tone="warn">Account {i.accountState}</Pill> : undefined,
              }))}
            />
            {candidates.length === 0 && <p className="py-4 text-center text-[13px] text-[var(--a-text-3)]">No user matches “{query}”.</p>}
          </div>
        ) : stepName === 'Device' ? (
          <div className="flex flex-col gap-4">
            <div>
              <p className="a-label">
                Platform
              </p>
              <ChoiceGroup
                label="Platform"
                value={platform}
                onChange={(v) => choosePlatform(v as Platform)}
                className="sm:grid-cols-2"
                options={PLATFORMS.map((p) => ({
                  value: p,
                  title: (
                    <span className="flex items-center gap-2">
                      <PlatformIcon platform={p} className="size-4 text-[var(--a-text-2)]" />
                      {platformLabels[p]}
                    </span>
                  ),
                  description: PLATFORM_HELP[p],
                }))}
              />
            </div>
            <TextField
              label="Device name"
              value={deviceName}
              onChange={(v) => {
                setDeviceName(v)
                setNameTouched(true)
              }}
              onBlur={() => setNameTouched(true)}
              placeholder="e.g. Priya’s iPhone"
              error={nameTouched ? nameError : null}
              hint={duplicate ? `${first} already has a device with this name. One certificate per device: use a distinct name.` : 'Shown in the device list and audit trail. One certificate per device.'}
              maxLength={80}
            />
          </div>
        ) : stepName === 'Key' ? (
          <div className="flex flex-col gap-3">
            <ChoiceGroup
              label="Key generation"
              value={keyMode}
              onChange={setKeyMode}
              options={[
                {
                  value: 'device',
                  title: 'Generate the key on the device',
                  aside: <Pill tone="ok">Recommended</Pill>,
                  description: 'The private key is created on the device and never leaves it. The user opens the enrollment link on that device.',
                },
                {
                  value: 'server',
                  title: 'Generate the key on the server',
                  aside: <Pill tone="warn">Admin mode</Pill>,
                  disabled: template ? !template.allowServerKeyGeneration : false,
                  description: 'For devices that cannot enroll themselves. EasyEAP creates the key and hands it over once as an encrypted PKCS#12.',
                },
              ]}
            />
            {keyMode === 'server' && (
              <div className="flex gap-3 rounded-[10px] border border-[rgba(251,191,36,0.26)] bg-[rgba(245,158,11,0.08)] p-3.5 text-[13px] text-[var(--a-text-2)]">
                <ShieldAlert className="mt-0.5 size-4 shrink-0 text-[var(--a-warn-text)]" aria-hidden />
                <p>
                  <span className="font-semibold text-[var(--a-text)]">Less secure.</span> The private key exists outside the device until it is installed, and anyone with the package and its password can connect as {first || 'this user'}. EasyEAP never stores the password and deletes the package after one download.
                </p>
              </div>
            )}
          </div>
        ) : (
          identity && (
            <div className="flex flex-col gap-4">
              <KeyValues
                items={[
                  { label: 'User', value: identity.displayName, hint: <Mono>{identity.upn ?? identity.username}</Mono> },
                  {
                    label: 'Device',
                    value: (
                      <span className="inline-flex items-center gap-2">
                        {platform && <PlatformIcon platform={platform} className="size-4 text-[var(--a-text-3)]" />}
                        {deviceName}
                      </span>
                    ),
                    hint: platform ? platformLabels[platform] : undefined,
                  },
                  { label: 'Template', value: template ? `${template.name} · ECDSA P-256` : 'User Wi-Fi', hint: template ? `Valid ${template.validityDays} days · renew ${template.renewBeforeDays} days before expiry` : undefined },
                  {
                    label: 'Private key',
                    value: (
                      <span className="inline-flex items-center gap-1.5">
                        <KeyRound className="size-3.5 text-[var(--a-text-3)]" aria-hidden />
                        {keyMode === 'device' ? 'On the device' : 'On the server (admin mode)'}
                      </span>
                    ),
                  },
                  {
                    label: 'Wi-Fi access today',
                    value: decision ? (
                      <span className="inline-flex flex-wrap items-center justify-end gap-2">
                        <AccessPill outcome={decision.outcome} />
                        {decision.vlanId && <VlanChip vlan={vlanById.get(decision.vlanId)} />}
                      </span>
                    ) : null,
                  },
                ]}
              />
              {decision?.outcome === 'deny' && (
                <div className={cn('flex gap-3 rounded-[10px] border p-3.5 text-[13px] text-[var(--a-text-2)]', 'border-[rgba(251,191,36,0.26)] bg-[rgba(245,158,11,0.08)]')}>
                  <TriangleAlert className="mt-0.5 size-4 shrink-0 text-[var(--a-warn-text)]" aria-hidden />
                  <p>
                    {identity.displayName} is currently denied Wi-Fi access. The certificate will install, but RADIUS rejects it until an Allow rule matches one of their groups and no Deny rule does.
                  </p>
                </div>
              )}
            </div>
          )
        )}
      </div>
    </GlassDialog>
  )
}
