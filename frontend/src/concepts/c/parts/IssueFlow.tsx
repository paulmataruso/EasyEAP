import { useMemo, useState } from 'react'
import { CircleAlert, KeyRound, Link2, ShieldCheck } from 'lucide-react'
import { now, useDecision, useTenantData } from '@/prototype/store'
import type { Identity, Platform } from '@/domain/types'
import { formatDateTime } from '@/ui/lib'
import { Flow, FlowStepView, type FlowStep } from '../ui/Flow'
import { Button } from '../ui/Button'
import { ChoiceGrid, ChoiceList, Field, TextInput } from '../ui/Field'
import { DefList, Note } from '../ui/Layout'
import { CopyButton } from '../ui/Code'
import { AccessMark } from '../ui/Status'
import { VlanTag } from '../ui/Vlan'
import { useConcept } from '../app/context'
import { keyAlgorithmLabel, firstName, possessive } from '../lib/format'
import { PLATFORMS, iconForPlatform, platformLabel } from './Platform'

const STEPS: FlowStep[] = [
  { id: 'device', title: 'Device', description: 'Name and platform' },
  { id: 'key', title: 'Private key', description: 'Where it is generated' },
  { id: 'review', title: 'Review', description: 'Template and access' },
  { id: 'done', title: 'Enrollment link', description: 'Send it to the person' },
]

const DEVICE_NOUN: Record<Platform, string> = { windows: 'Laptop', macos: 'MacBook', ios: 'iPhone', android: 'Phone', linux: 'Workstation' }
const LINK_HOURS = 72

/** Deterministic token so the prototype is stable; production uses a server-issued secret. */
function linkToken(seed: string) {
  let h = 2166136261
  for (const ch of seed) h = Math.imul(h ^ ch.charCodeAt(0), 16777619)
  const alphabet = 'ABCDEFGHJKMNPQRSTVWXYZ23456789'
  let out = ''
  for (let i = 0; i < 12; i++) {
    h = Math.imul(h ^ (h >>> 13), 1274126177)
    out += alphabet[Math.abs(h) % alphabet.length]
  }
  return `${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8)}`
}

export function IssueFlow({ identity, open, onOpenChange, initial }: { identity: Identity; open: boolean; onOpenChange: (o: boolean) => void; initial?: { deviceName?: string; platform?: string } }) {
  const d = useTenantData()
  const decision = useDecision(identity)
  const { toast } = useConcept()
  const [step, setStep] = useState(0)
  const [platform, setPlatform] = useState<Platform | ''>((initial?.platform as Platform) ?? '')
  const [deviceName, setDeviceName] = useState(initial?.deviceName ?? '')
  const [keyMode, setKeyMode] = useState<'device' | 'server'>('device')
  const [touched, setTouched] = useState(false)
  const template = d.templates.find((t) => t.purpose === 'user')
  const vlan = d.vlans.find((v) => v.id === decision?.vlanId)
  const domain = identity.upn?.split('@')[1] ?? 'example'
  const token = useMemo(() => linkToken(`${identity.id}:${deviceName}:${platform}:${keyMode}`), [identity.id, deviceName, platform, keyMode])
  const link = `https://enroll.${domain}/e/${token}`
  const expires = new Date(now().getTime() + LINK_HOURS * 3_600_000).toISOString()

  const existing = d.devices.filter((x) => x.identityId === identity.id).map((x) => x.name.toLowerCase())
  const nameError = !deviceName.trim()
    ? 'Enter a device name so the person can tell their certificates apart, for example “Priya’s iPhone”.'
    : existing.includes(deviceName.trim().toLowerCase()) && !initial?.deviceName
      ? `${identity.displayName} already has a device called “${deviceName.trim()}”. Use a distinct name; each device gets its own certificate.`
      : null
  const platformError = !platform ? 'Choose the platform so the link delivers the right Wi-Fi profile.' : null

  const close = (o: boolean) => {
    onOpenChange(o)
    if (!o) {
      setStep(0)
      setTouched(false)
      setKeyMode('device')
      setPlatform((initial?.platform as Platform) ?? '')
      setDeviceName(initial?.deviceName ?? '')
    }
  }

  const choosePlatform = (p: string) => {
    setPlatform(p as Platform)
    if (!deviceName.trim() || Object.values(DEVICE_NOUN).some((n) => deviceName === `${possessive(firstName(identity.displayName))} ${n}`)) {
      setDeviceName(`${possessive(firstName(identity.displayName))} ${DEVICE_NOUN[p as Platform]}`)
    }
  }

  return (
    <Flow open={open} onOpenChange={close} title="Issue a Wi-Fi certificate" context={`${identity.displayName} · ${identity.upn ?? identity.username}`} steps={STEPS} current={step} closeLabel={step === 3 ? 'Close' : 'Cancel'}>
      {step === 0 ? (
        <FlowStepView
          heading={`Which device is this certificate for?`}
          intro={`Each device gets its own certificate, so you can revoke one lost phone without touching ${possessive(firstName(identity.displayName))} laptop.`}
          next={
            <Button
              variant="primary"
              onClick={() => {
                setTouched(true)
                if (!nameError && !platformError) setStep(1)
              }}
            >
              Continue
            </Button>
          }
        >
          <div className="c-field">
            <span className="c-label" id="c-issue-platform-label">
              Platform
            </span>
            <ChoiceGrid
              label="Platform"
              value={platform}
              onChange={choosePlatform}
              invalid={touched && Boolean(platformError)}
              choices={PLATFORMS.map((p) => {
                const Icon = iconForPlatform(p)
                return { value: p, label: platformLabel(p), icon: <Icon size={18} strokeWidth={1.7} aria-hidden="true" /> }
              })}
            />
            {touched && platformError ? (
              <p className="c-error" role="alert" style={{ margin: 0 }}>
                <CircleAlert size={14} aria-hidden="true" />
                {platformError}
              </p>
            ) : null}
          </div>
          <Field label="Device name" htmlFor="c-issue-name" hint="Shown to the person on their enrollment page and in your audit trail." error={touched ? nameError : null}>
            <TextInput id="c-issue-name" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} placeholder={`${possessive(firstName(identity.displayName))} iPhone`} invalid={touched && Boolean(nameError)} describedBy={touched && nameError ? 'c-issue-name-error' : 'c-issue-name-hint'} autoComplete="off" />
          </Field>
        </FlowStepView>
      ) : null}

      {step === 1 ? (
        <FlowStepView
          heading="Where should the private key be generated?"
          intro="The private key proves the device's identity to RADIUS. Whoever holds it can join the network as this person."
          back={<Button variant="ghost" onClick={() => setStep(0)}>Back</Button>}
          next={<Button variant="primary" onClick={() => setStep(2)}>Continue</Button>}
        >
          <ChoiceList
            label="Key generation"
            value={keyMode}
            onChange={(v) => setKeyMode(v as 'device' | 'server')}
            choices={[
              {
                value: 'device',
                title: (
                  <>
                    On the device <span className="c-tag is-strong">Recommended</span>
                  </>
                ),
                description: `The key is created on ${possessive(firstName(identity.displayName))} ${platform ? platformLabel(platform as Platform) : 'device'} and never leaves it. EasyEAP only sees a signing request, so there is nothing to intercept or leak.`,
              },
              {
                value: 'server',
                title: (
                  <>
                    On the server <span className="c-tag is-outline">Admin mode</span>
                  </>
                ),
                disabled: template ? !template.allowServerKeyGeneration : true,
                description: 'EasyEAP creates the key and hands it over once as a password-protected PKCS#12 file. Less secure: the key briefly exists outside the device. Use it only for devices that cannot generate keys, such as some scanners.',
              },
            ]}
          />
          {keyMode === 'server' ? (
            <Note icon={KeyRound} tone="warn">
              <strong>The download works once.</strong> The PKCS#12 password is shown to the person when they retrieve it and is never stored or logged by EasyEAP.
            </Note>
          ) : null}
        </FlowStepView>
      ) : null}

      {step === 2 ? (
        <FlowStepView
          heading="Review before creating the link"
          intro="Nothing is issued yet. The certificate is signed only when the person completes enrollment on the device."
          back={<Button variant="ghost" onClick={() => setStep(1)}>Back</Button>}
          next={
            <Button
              variant="primary"
              icon={<Link2 size={16} aria-hidden="true" />}
              onClick={() => {
                setStep(3)
                toast('Enrollment link created', `${deviceName} · expires in ${LINK_HOURS} hours`)
              }}
            >
              Create enrollment link
            </Button>
          }
        >
          <DefList
            items={[
              { label: 'Person', value: `${identity.displayName} (${identity.upn ?? identity.username})` },
              { label: 'Device', value: `${deviceName} · ${platform ? platformLabel(platform as Platform) : ''}` },
              { label: 'Template', value: template ? `${template.name} · ${keyAlgorithmLabel[template.keyAlgorithm]} · ${template.validityDays} days` : 'User Wi-Fi' },
              { label: 'Subject', value: <span className="c-mono">CN={identity.upn}</span> },
              { label: 'Private key', value: keyMode === 'device' ? 'Generated on the device' : 'Generated by EasyEAP, delivered once as PKCS#12' },
              { label: 'Link', value: `Works once, expires ${formatDateTime(expires)}` },
              {
                label: 'Wi-Fi access today',
                value: decision ? (
                  <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
                    <AccessMark outcome={decision.outcome} />
                    {decision.outcome === 'allow' ? <VlanTag vlan={vlan} /> : null}
                  </span>
                ) : (
                  '—'
                ),
              },
            ]}
          />
          {decision?.outcome === 'deny' ? (
            <Note icon={CircleAlert} tone="warn">
              <strong>Current rules deny {firstName(identity.displayName)}.</strong> A certificate proves who the device belongs to; it does not grant access. The device will be rejected until a rule allows one of their groups.
            </Note>
          ) : null}
        </FlowStepView>
      ) : null}

      {step === 3 ? (
        <FlowStepView heading="Enrollment link created" intro={`Send this link to ${firstName(identity.displayName)}. It opens on the device, installs the Root CA and the Wi-Fi profile for ${d.radiusSettings?.serverHostname ?? 'the RADIUS server'}, then requests the certificate.`} next={<Button variant="primary" onClick={() => close(false)}>Done</Button>}>
          <div className="c-secret" style={{ borderColor: 'var(--c-hairline-strong)' }}>
            <div style={{ minWidth: 0 }}>
              <div className="c-faint c-small" style={{ marginBottom: 4 }}>
                One-time link for {deviceName}
              </div>
              <code style={{ fontSize: 14 }}>{link}</code>
            </div>
            <CopyButton text={link} label="Copy link" variant="secondary" />
          </div>
          <DefList
            items={[
              { label: 'Expires', value: `${formatDateTime(expires)} (in ${LINK_HOURS} hours)` },
              { label: 'Uses', value: 'Once. Opening it again shows “already used”.' },
              { label: 'Key', value: keyMode === 'device' ? 'Created on the device during enrollment' : 'PKCS#12 download after the person signs in' },
            ]}
          />
          <Note icon={ShieldCheck}>Send the link over a channel the person already trusts, such as their work email. Anyone who opens it first can enroll a device as {firstName(identity.displayName)}.</Note>
        </FlowStepView>
      ) : null}
    </Flow>
  )
}
