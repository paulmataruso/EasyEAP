import { useState, type FormEvent } from 'react'
import type { NasVendor, RadiusClient } from '@/domain/types'
import { vendorLabels } from '@/domain/explain'
import { useTenantData } from '@/prototype/store'
import { useConceptActions } from '../model/actions'
import { SelectField, TextField, Toggle } from '../ui/Controls'

/** IPv4 address or IPv4 CIDR (/8–/32). Returns an error that names the problem and the fix. */
export function validateAddress(raw: string, existing: RadiusClient[]): string | null {
  const v = raw.trim()
  if (!v) return 'Enter the controller’s management IP, e.g. 10.20.0.10, or a subnet such as 10.20.0.0/24.'
  const [ip, prefix, extra] = v.split('/')
  if (extra !== undefined) return 'Use a single slash: address/prefix, e.g. 10.20.0.0/24.'
  const parts = ip.split('.')
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return `“${ip}” isn’t an IPv4 address. Use four numbers from 0 to 255 separated by dots.`
  if (prefix !== undefined) {
    if (!/^\d{1,2}$/.test(prefix) || Number(prefix) < 8 || Number(prefix) > 32) return 'The prefix must be between /8 and /32. Broader ranges would let any device on the network send RADIUS requests.'
  }
  const clash = existing.find((n) => n.address === v)
  if (clash) return `${v} is already registered to ${clash.name}. Each controller needs its own address or subnet.`
  return null
}

export function generateSecret(): string {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const DEFAULT_COA: Record<NasVendor, number> = { 'cisco-9800': 1700, 'cisco-aireos': 3799, unifi: 3799, other: 3799 }

export function AddControllerForm({ onCreated, onCancel }: { onCreated: (name: string, secret: string) => void; onCancel: () => void }) {
  const d = useTenantData()
  const { addRadiusClient } = useConceptActions()
  const [name, setName] = useState('')
  const [vendor, setVendor] = useState<NasVendor>('cisco-9800')
  const [address, setAddress] = useState('')
  const [site, setSite] = useState('')
  const [coa, setCoa] = useState(true)
  const [coaPort, setCoaPort] = useState(String(DEFAULT_COA['cisco-9800']))
  const [portTouched, setPortTouched] = useState(false)
  const [tried, setTried] = useState(false)

  const errors = {
    name: !name.trim() ? 'Name the controller so it can be found in logs, e.g. “Riverside Catalyst 9800-L”.' : d.radiusClients.some((n) => n.name.toLowerCase() === name.trim().toLowerCase()) ? `A controller called “${name.trim()}” already exists. Use a distinct name.` : null,
    address: validateAddress(address, d.radiusClients),
    site: !site.trim() ? 'Enter the site this controller serves, e.g. Headquarters.' : null,
    coaPort: coa && (!/^\d+$/.test(coaPort) || Number(coaPort) < 1 || Number(coaPort) > 65535) ? 'Enter a UDP port from 1 to 65535. Catalyst 9800 listens on 1700 by default; most others use 3799.' : null,
  }
  const invalid = Object.values(errors).some(Boolean)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTried(true)
    if (invalid) {
      const first = (Object.keys(errors) as Array<keyof typeof errors>).find((k) => errors[k])
      document.getElementById(`nas-${first}`)?.focus()
      return
    }
    addRadiusClient({ name: name.trim(), vendor, address: address.trim(), site: site.trim(), coaEnabled: coa, coaPort: Number(coaPort) || DEFAULT_COA[vendor] })
    onCreated(name.trim(), generateSecret())
  }

  return (
    <form onSubmit={submit} noValidate className="grid gap-4 border-b border-[var(--d-line)] py-5" aria-label="Add wireless controller">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <TextField id="nas-name" label="Name" value={name} onChange={setName} placeholder="Riverside Catalyst 9800-L" error={tried ? errors.name : null} />
        <SelectField
          label="Vendor"
          value={vendor}
          onChange={(v) => { setVendor(v); if (!portTouched) setCoaPort(String(DEFAULT_COA[v])) }}
          options={(Object.keys(vendorLabels) as NasVendor[]).map((v) => ({ value: v, label: vendorLabels[v] }))}
        />
        <TextField id="nas-address" label="IP address or CIDR" mono value={address} onChange={setAddress} placeholder="10.30.0.5 or 10.30.0.0/24" error={tried ? errors.address : null} hint="Requests from any other source are dropped." />
        <TextField id="nas-site" label="Site" value={site} onChange={setSite} placeholder="Riverside branch" error={tried ? errors.site : null} />
      </div>
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
        <div className="flex items-center gap-3 pb-1.5">
          <Toggle id="nas-coa-toggle" checked={coa} onChange={setCoa} label="Send CoA disconnects" />
          <label htmlFor="nas-coa-toggle" className="text-[13px]">
            Send CoA disconnects <span className="text-[var(--d-ink-2)]">so revocations take effect on connected devices</span>
          </label>
        </div>
        {coa && (
          <div className="w-32">
            <TextField id="nas-coaPort" label="CoA port (UDP)" mono inputMode="numeric" value={coaPort} onChange={(v) => { setCoaPort(v); setPortTouched(true) }} error={tried ? errors.coaPort : null} />
          </div>
        )}
        <div className="ml-auto flex gap-2 pb-0.5">
          <button type="button" className="d-btn" onClick={onCancel}>Cancel</button>
          <button type="submit" className="d-btn d-btn--primary">Register and generate secret</button>
        </div>
      </div>
    </form>
  )
}
