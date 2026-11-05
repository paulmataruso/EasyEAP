import { useState } from 'react'
import { AlertDialog, Checkbox } from 'radix-ui'
import { Check, KeyRound, RotateCw, Router, ShieldAlert } from 'lucide-react'
import type { NasVendor, RadiusClient } from '@/domain/types'
import { vendorLabels } from '@/domain/explain'
import { useActions, useTenantData, useTenants } from '@/prototype/store'
import { SelectField, SwitchRow, TextField } from '../ui/fields'
import { ConfirmDialog, GlassDialog, Stepper } from '../ui/dialog'
import { Button, CopyButton, Mono } from '../ui/primitives'
import { AffectsLine } from '../ui/scope'
import { useToast } from '../ui/toast'
import { generateSecret, tenantHealth } from '../lib/model'
import { ConfigSnippet } from './ConfigSnippet'

const VENDOR_OPTIONS: Array<{ value: NasVendor; label: string }> = (['cisco-9800', 'cisco-aireos', 'unifi', 'other'] as NasVendor[]).map((v) => ({ value: v, label: vendorLabels[v] }))
const defaultCoa = (v: NasVendor) => ({ enabled: v !== 'unifi', port: v === 'cisco-9800' ? 1700 : 3799 })

// ── Validation ──────────────────────────────────────────────────────────────

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

export function validateAddress(raw: string, existing: RadiusClient[]): string | null {
  const v = raw.trim()
  if (!v) return 'Enter the controller’s IP address, for example 10.20.0.10, or a CIDR range such as 10.20.0.0/24.'
  const [ip, prefix, ...extra] = v.split('/')
  if (extra.length || !IPV4.test(ip)) return `“${v}” is not an IPv4 address. Use four numbers from 0 to 255 separated by dots, e.g. 10.20.0.10.`
  if (prefix !== undefined) {
    if (!/^\d{1,2}$/.test(prefix) || Number(prefix) > 32) return 'The CIDR prefix must be a number from 16 to 32, e.g. /24.'
    if (Number(prefix) < 16) return `/${prefix} would accept RADIUS from ${(2 ** (32 - Number(prefix))).toLocaleString()} addresses. Use /16 or narrower.`
  }
  const dup = existing.find((c) => c.address === v)
  if (dup) return `${v} is already registered as “${dup.name}”. Each controller address can be registered once.`
  return null
}

function validateName(raw: string, existing: RadiusClient[]): string | null {
  const v = raw.trim()
  if (!v) return 'Name the controller as your team knows it, e.g. “Riverside branch WLC 5520”.'
  if (v.length > 64) return 'Use 64 characters or fewer.'
  if (existing.some((c) => c.name.toLowerCase() === v.toLowerCase())) return `A controller called “${v}” already exists in this tenant.`
  return null
}

function validatePort(raw: string): string | null {
  if (!/^\d+$/.test(raw.trim())) return 'Enter a port number, e.g. 3799 (RFC 5176) or 1700 (Catalyst 9800 default).'
  const n = Number(raw)
  if (n < 1 || n > 65535) return 'Ports range from 1 to 65535.'
  return null
}

// ── Secret reveal (shown once) ──────────────────────────────────────────────

function SecretOnce({ secret, acknowledged, onAcknowledge }: { secret: string; acknowledged: boolean; onAcknowledge: (v: boolean) => void }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-3 rounded-[10px] border border-[rgba(251,191,36,0.26)] bg-[rgba(245,158,11,0.08)] p-3.5 text-[13px] text-[var(--a-text-2)]">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-[var(--a-warn-text)]" aria-hidden />
        <p>
          <span className="font-semibold text-[var(--a-text)]">This is the only time EasyEAP shows this secret.</span> Store it in your password manager, then paste it into the controller. It is never logged and cannot be displayed again; if it is lost, rotate it.
        </p>
      </div>
      <div>
        <p className="a-label">Shared secret</p>
        <div className="flex flex-wrap items-center gap-2 rounded-[10px] border border-white/10 bg-black/35 p-2 pl-3">
          <Mono className="min-w-0 flex-1 text-[14px] break-all text-[var(--a-text)] select-all">{secret}</Mono>
          <CopyButton text={secret} label="Copy secret" />
        </div>
        <p className="a-hint">32 characters, generated in this browser session.</p>
      </div>
      <label className="flex cursor-pointer items-center gap-2.5 text-[14px] text-[var(--a-text)]">
        <Checkbox.Root checked={acknowledged} onCheckedChange={(v) => onAcknowledge(v === true)} className="grid size-[18px] shrink-0 place-items-center rounded-[5px] border border-white/30 bg-black/20 data-[state=checked]:border-[var(--a-accent)] data-[state=checked]:bg-[var(--a-accent)]">
          <Checkbox.Indicator>
            <Check className="size-3.5 text-[var(--a-on-accent)]" aria-hidden />
          </Checkbox.Indicator>
        </Checkbox.Root>
        I have stored the shared secret
      </label>
    </div>
  )
}

// ── Add controller ──────────────────────────────────────────────────────────

export function AddControllerDialog({ open, onOpenChange, onAdded }: { open: boolean; onOpenChange: (o: boolean) => void; onAdded?: (name: string) => void }) {
  const d = useTenantData()
  const { current } = useTenants()
  const { addRadiusClient } = useActions()
  const toast = useToast()
  const [step, setStep] = useState(0)
  const [name, setName] = useState('')
  const [vendor, setVendor] = useState<NasVendor>('cisco-9800')
  const [address, setAddress] = useState('')
  const [site, setSite] = useState('')
  const [coa, setCoa] = useState(true)
  const [coaPort, setCoaPort] = useState('1700')
  const [touched, setTouched] = useState(false)
  const [secret, setSecret] = useState('')
  const [ack, setAck] = useState(false)
  const [added, setAdded] = useState<RadiusClient | null>(null)

  const errors = {
    name: validateName(name, d.radiusClients),
    address: validateAddress(address, d.radiusClients),
    site: site.trim() ? null : 'Enter the site, e.g. “Headquarters”, so alerts say where the controller is.',
    coaPort: coa ? validatePort(coaPort) : null,
  }
  const valid = Object.values(errors).every((e) => !e)

  const reset = () => {
    setStep(0)
    setName('')
    setVendor('cisco-9800')
    setAddress('')
    setSite('')
    setCoa(true)
    setCoaPort('1700')
    setTouched(false)
    setSecret('')
    setAck(false)
    setAdded(null)
  }
  const close = (o: boolean) => {
    onOpenChange(o)
    if (!o) window.setTimeout(reset, 200)
  }

  const register = () => {
    setTouched(true)
    if (!valid) return
    const client = { name: name.trim(), vendor, address: address.trim(), site: site.trim(), coaEnabled: coa, coaPort: Number(coaPort) || defaultCoa(vendor).port }
    addRadiusClient(client)
    setAdded({ ...client, id: 'pending', tenantId: current.id, secretSetAt: new Date().toISOString(), lastRequestAt: null, status: 'unconfigured' })
    setSecret(generateSecret())
    setStep(1)
    toast({ title: 'Controller registered', description: `${client.name} (${client.address}) can send RADIUS once it has the shared secret.` })
    onAdded?.(client.name)
  }

  const show = (k: keyof typeof errors) => (touched ? errors[k] : null)

  return (
    <GlassDialog
      open={open}
      onOpenChange={close}
      width={step === 2 ? 760 : 620}
      title={step === 0 ? 'Add wireless controller' : step === 1 ? 'Store the shared secret' : 'Configure the controller'}
      description={step === 0 ? 'Register a controller that will send RADIUS requests to EasyEAP.' : `${added?.name} · ${added?.address}`}
      header={<Stepper steps={['Controller', 'Shared secret', 'Configure']} current={step} />}
      footer={
        <>
          <AffectsLine tenant={current.name} tenantHealth={tenantHealth(current, d.radiusClients).state} record={added?.name ?? (name.trim() || 'New controller')} recordIcon={Router} />
          <div className="flex items-center gap-2">
            {step === 0 && (
              <>
                <Button variant="ghost" onClick={() => close(false)}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={register}>
                  Register controller
                </Button>
              </>
            )}
            {step === 1 && (
              <Button variant="primary" disabled={!ack} onClick={() => setStep(2)}>
                Continue
              </Button>
            )}
            {step === 2 && (
              <Button variant="primary" onClick={() => close(false)}>
                Done
              </Button>
            )}
          </div>
        </>
      }
    >
      <div className="pt-4">
        {step === 0 && (
          <form
            noValidate
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(e) => {
              e.preventDefault()
              register()
            }}
          >
            <TextField className="sm:col-span-2" label="Name" value={name} onChange={setName} error={show('name')} placeholder="e.g. Riverside branch WLC 5520" autoFocus />
            <SelectField
              label="Vendor"
              value={vendor}
              onChange={(v) => {
                const nv = v as NasVendor
                setVendor(nv)
                setCoa(defaultCoa(nv).enabled)
                setCoaPort(String(defaultCoa(nv).port))
              }}
              options={VENDOR_OPTIONS}
              triggerClassName="w-full"
            />
            <TextField label="IP address or CIDR" value={address} onChange={setAddress} error={show('address')} placeholder="10.30.0.5 or 10.30.0.0/24" mono inputMode="decimal" hint="RADIUS from any other source is dropped." />
            <TextField className="sm:col-span-2" label="Site" value={site} onChange={setSite} error={show('site')} placeholder="e.g. Riverside branch" />
            <div className="rounded-[10px] border border-white/10 bg-white/[0.03] p-3.5 sm:col-span-2">
              <SwitchRow
                label="Change of Authorization (CoA)"
                description="Lets EasyEAP disconnect a session immediately after a revocation. UniFi Network does not support it."
                checked={coa}
                onChange={setCoa}
              />
              {coa && <TextField className="mt-3 max-w-[200px]" label="CoA port (UDP)" value={coaPort} onChange={setCoaPort} error={show('coaPort')} mono inputMode="numeric" hint={vendor === 'cisco-9800' ? 'Catalyst 9800 listens on 1700 by default.' : 'RFC 5176 default is 3799.'} />}
            </div>
            <button type="submit" className="hidden" aria-hidden tabIndex={-1} />
          </form>
        )}
        {step === 1 && <SecretOnce secret={secret} acknowledged={ack} onAcknowledge={setAck} />}
        {step === 2 && <ConfigSnippet controller={d.radiusClients.find((c) => c.name === added?.name) ?? added} compact />}
      </div>
    </GlassDialog>
  )
}

// ── Rotate secret ───────────────────────────────────────────────────────────

export function RotateSecretDialog({ controller, open, onOpenChange }: { controller: RadiusClient; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { rotateSecret } = useActions()
  const { current } = useTenants()
  const d = useTenantData()
  const toast = useToast()
  const [secret, setSecret] = useState<string | null>(null)
  const [ack, setAck] = useState(false)
  const close = (o: boolean) => {
    onOpenChange(o)
    if (!o)
      window.setTimeout(() => {
        setSecret(null)
        setAck(false)
      }, 200)
  }
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={close}
      width={560}
      title={secret ? 'Store the new shared secret' : `Rotate shared secret for ${controller.name}?`}
      description={`${vendorLabels[controller.vendor]} · ${controller.address}`}
      footerStart={<AffectsLine tenant={current.name} tenantHealth={tenantHealth(current, d.radiusClients).state} record={controller.name} recordIcon={Router} />}
      cancelLabel={secret ? 'Close' : 'Cancel'}
      confirm={
        secret ? (
          <AlertDialog.Action asChild>
            <Button variant="primary" disabled={!ack}>
              Done
            </Button>
          </AlertDialog.Action>
        ) : (
          <Button
            variant="danger"
            icon={RotateCw}
            onClick={() => {
              rotateSecret(controller.id)
              setSecret(generateSecret())
              toast({ title: 'Shared secret rotated', description: `Update ${controller.name} now; requests with the old secret are rejected.`, tone: 'warn' })
            }}
          >
            Rotate secret
          </Button>
        )
      }
    >
      {secret ? (
        <SecretOnce secret={secret} acknowledged={ack} onAcknowledge={setAck} />
      ) : (
        <div className="flex gap-3 rounded-[10px] border border-[rgba(248,113,113,0.24)] bg-[rgba(239,68,68,0.07)] p-3.5 text-[14px] text-[var(--a-text-2)]">
          <KeyRound className="mt-0.5 size-4 shrink-0 text-[var(--a-danger-text)]" aria-hidden />
          <p>
            EasyEAP starts using the new secret immediately. Until you paste it into {controller.name}, its RADIUS requests fail and clients at {controller.site} cannot join Wi-Fi. Rotate during a maintenance window, or with the controller console open.
          </p>
        </div>
      )}
    </ConfirmDialog>
  )
}
