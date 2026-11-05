import { useId, useState } from 'react'
import { Plus } from 'lucide-react'
import { useActions, useTenantData } from '@/prototype/store'
import { vendorLabels } from '@/domain/explain'
import type { NasVendor } from '@/domain/types'
import { Drawer } from '../ui/Drawer'
import { Button } from '../ui/Button'
import { Field, SelectBox, TextField, Toggle } from '../ui/Field'
import { generateSecret, SecretReveal } from './SecretReveal'

const VENDORS: NasVendor[] = ['cisco-9800', 'cisco-aireos', 'unifi', 'other']
const defaultCoaPort = (v: NasVendor) => (v === 'cisco-9800' ? 1700 : 3799)

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
export function validateAddress(value: string): string | null {
  const v = value.trim()
  if (!v) return 'Enter the controller’s IP address or a CIDR range, e.g. 10.20.0.10 or 10.20.0.0/24.'
  const [ip, prefix, extra] = v.split('/')
  if (extra !== undefined || !IPV4.test(ip)) return `“${v}” is not an IPv4 address. Use four numbers from 0 to 255, e.g. 10.20.0.10.`
  if (prefix !== undefined) {
    if (!/^\d{1,2}$/.test(prefix) || Number(prefix) > 32) return 'The CIDR prefix must be between /0 and /32.'
    if (Number(prefix) < 16) return 'A range wider than /16 would let too many hosts act as this controller. Use /16 or narrower.'
  }
  return null
}

interface Form {
  name: string
  vendor: NasVendor
  address: string
  site: string
  coaEnabled: boolean
  coaPort: string
}

/** Register a wireless controller; the generated shared secret is shown once on success. */
export function AddControllerDrawer({ open, onOpenChange, onConfigure }: { open: boolean; onOpenChange: (o: boolean) => void; onConfigure: (address: string) => void }) {
  const d = useTenantData()
  const { addRadiusClient } = useActions()
  const vendorId = useId()
  const formId = useId()
  const [form, setForm] = useState<Form>({ name: '', vendor: 'cisco-9800', address: '', site: '', coaEnabled: true, coaPort: '1700' })
  const [portTouched, setPortTouched] = useState(false)
  const [submitted, setSubmitted] = useState(false)
  const [secret, setSecret] = useState<string | null>(null)
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }))

  const errors = {
    name: !form.name.trim() ? 'Enter a name your team will recognise, e.g. “HQ Catalyst 9800”.' : d.radiusClients.some((c) => c.name.toLowerCase() === form.name.trim().toLowerCase()) ? 'A controller with this name already exists in this tenant.' : null,
    address: validateAddress(form.address) ?? (d.radiusClients.find((c) => c.address === form.address.trim()) ? `${form.address.trim()} is already registered as ${d.radiusClients.find((c) => c.address === form.address.trim())!.name}.` : null),
    site: !form.site.trim() ? 'Enter the site this controller serves, e.g. “Headquarters”.' : null,
    coaPort: form.coaEnabled && !(/^\d+$/.test(form.coaPort) && Number(form.coaPort) >= 1 && Number(form.coaPort) <= 65535) ? 'Use a UDP port from 1 to 65535 (Catalyst 9800 defaults to 1700, others to 3799).' : null,
  }
  const valid = !Object.values(errors).some(Boolean)
  const show = (k: keyof typeof errors) => (submitted ? errors[k] : null)

  const submit = () => {
    setSubmitted(true)
    if (!valid) return
    addRadiusClient({ name: form.name.trim(), vendor: form.vendor, address: form.address.trim(), site: form.site.trim(), coaEnabled: form.coaEnabled, coaPort: Number(form.coaPort) || defaultCoaPort(form.vendor) })
    setSecret(generateSecret())
  }

  if (secret) {
    return (
      <Drawer
        open={open}
        onOpenChange={onOpenChange}
        width={500}
        title="Controller registered"
        description={`${form.name.trim()} · ${vendorLabels[form.vendor]} · ${form.address.trim()}`}
        footer={
          <>
            <Button
              onClick={() => {
                onConfigure(form.address.trim())
                onOpenChange(false)
              }}
            >
              Show configuration snippet
            </Button>
            <Button variant="primary" className="ml-auto" onClick={() => onOpenChange(false)}>
              Done, hide secret
            </Button>
          </>
        }
      >
        <SecretReveal secret={secret} controllerName={form.name.trim()} />
        <p className="b-t3 mt-4 text-[12px]">The controller shows as “Not set up” until its first request reaches EasyEAP. An audit entry (radius.client.create) was recorded.</p>
      </Drawer>
    )
  }

  return (
    <Drawer
      open={open}
      onOpenChange={onOpenChange}
      width={500}
      title="Add wireless controller"
      description="Registers a RADIUS client and generates its shared secret."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button type="submit" form={formId} variant="primary" icon={Plus} className="ml-auto">
            Add controller
          </Button>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <TextField label="Name" value={form.name} onChange={(e) => set('name', e.target.value)} error={show('name')} placeholder="HQ Catalyst 9800" autoFocus />
        <Field label="Vendor" htmlFor={vendorId}>
          <SelectBox
            id={vendorId}
            value={form.vendor}
            onChange={(v) => {
              const vendor = v as NasVendor
              setForm((f) => ({ ...f, vendor, coaPort: portTouched ? f.coaPort : String(defaultCoaPort(vendor)) }))
            }}
            options={VENDORS.map((v) => ({ value: v, label: vendorLabels[v] }))}
          />
        </Field>
        <TextField
          label="IP address or CIDR"
          value={form.address}
          onChange={(e) => set('address', e.target.value)}
          error={show('address')}
          placeholder="10.20.0.10"
          inputClassName="b-mono"
          hint="Requests from any other source address are dropped."
          inputMode="decimal"
          spellCheck={false}
        />
        <TextField label="Site" value={form.site} onChange={(e) => set('site', e.target.value)} error={show('site')} placeholder="Headquarters" />
        <div className="rounded-md border border-[var(--b-line)] p-3">
          <div className="flex items-start gap-3">
            <Toggle checked={form.coaEnabled} onChange={(v) => set('coaEnabled', v)} label="Enable Change of Authorization (CoA)" />
            <div>
              <p className="text-[13px] font-medium text-[var(--b-text)]">Change of Authorization (CoA)</p>
              <p className="b-t2 text-[12.5px]">Lets EasyEAP disconnect a session immediately after a revocation. Without it, revoked devices stay online until they reauthenticate.</p>
            </div>
          </div>
          {form.coaEnabled && (
            <TextField
              className="mt-3 max-w-[180px]"
              label="CoA port (UDP)"
              value={form.coaPort}
              onChange={(e) => {
                setPortTouched(true)
                set('coaPort', e.target.value)
              }}
              error={show('coaPort')}
              inputMode="numeric"
              inputClassName="b-mono"
            />
          )}
        </div>
      </form>
    </Drawer>
  )
}
