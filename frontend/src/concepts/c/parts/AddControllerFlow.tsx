import { useState } from 'react'
import { CircleAlert, EyeOff, Router, Server, Wifi } from 'lucide-react'
import { useActions, useTenantData, useTenants } from '@/prototype/store'
import { vendorLabels } from '@/domain/explain'
import type { NasVendor } from '@/domain/types'
import { Flow, FlowStepView, type FlowStep } from '../ui/Flow'
import { Button } from '../ui/Button'
import { ChoiceGrid, Field, TextInput, Toggle } from '../ui/Field'
import { DefList, Note } from '../ui/Layout'
import { SecretOnce, SnippetBlock } from '../ui/Code'
import { useConcept } from '../app/context'
import { defaultCoaPort, generateSecret, snippetFor } from '../lib/snippets'
import { validateAddress, validateName, validatePort } from '../lib/validate'

const STEPS: FlowStep[] = [
  { id: 'controller', title: 'Controller', description: 'Name, vendor and site' },
  { id: 'network', title: 'Network', description: 'Address and CoA' },
  { id: 'review', title: 'Review', description: 'Check before creating' },
  { id: 'configure', title: 'Configure', description: 'Secret and commands' },
]

const VENDORS: NasVendor[] = ['cisco-9800', 'cisco-aireos', 'unifi', 'other']
const vendorIcon = { 'cisco-9800': Router, 'cisco-aireos': Router, unifi: Wifi, other: Server } as const

interface Draft {
  name: string
  vendor: NasVendor | ''
  site: string
  address: string
  coaEnabled: boolean
  coaPort: string
}

const EMPTY: Draft = { name: '', vendor: '', site: '', address: '', coaEnabled: true, coaPort: '3799' }

/** Full-page flow: register a controller, then show its shared secret exactly once. */
export function AddControllerFlow({ open, onOpenChange, ssid, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; ssid?: string; onCreated?: (name: string) => void }) {
  const d = useTenantData()
  const { current: tenant } = useTenants()
  const { addRadiusClient } = useActions()
  const { toast } = useConcept()
  const [step, setStep] = useState(0)
  const [draft, setDraft] = useState<Draft>(EMPTY)
  const [touched, setTouched] = useState<Record<number, boolean>>({})
  const [secret, setSecret] = useState<string | null>(null)
  const set = (patch: Partial<Draft>) => setDraft((x) => ({ ...x, ...patch }))

  const nameError = validateName(draft.name, d.radiusClients)
  const vendorError = draft.vendor ? null : 'Choose the controller type so EasyEAP can give you the right configuration.'
  const addressError = validateAddress(draft.address, d.radiusClients)
  const portError = draft.coaEnabled ? validatePort(draft.coaPort) : null
  const showErr = (s: number, e: string | null) => (touched[s] ? e : null)

  const reset = () => {
    setStep(0)
    setDraft(EMPTY)
    setTouched({})
    setSecret(null)
  }
  const close = (o: boolean) => {
    onOpenChange(o)
    if (!o) reset()
  }
  const advance = (from: number, errors: Array<string | null>) => {
    setTouched((t) => ({ ...t, [from]: true }))
    if (errors.every((e) => !e)) setStep(from + 1)
  }
  const create = () => {
    if (!draft.vendor) return
    addRadiusClient({ name: draft.name.trim(), vendor: draft.vendor, address: draft.address.trim(), coaEnabled: draft.coaEnabled, coaPort: Number(draft.coaPort) || defaultCoaPort(draft.vendor), site: draft.site.trim() || 'Unassigned' })
    setSecret(generateSecret())
    setStep(3)
    toast(`${draft.name.trim()} added`, 'Status shows “Not set up” until the controller sends its first request.')
    onCreated?.(draft.name.trim())
  }

  return (
    <Flow open={open} onOpenChange={close} title="Add a wireless controller" context={tenant.name} steps={STEPS} current={step} closeLabel={step === 3 ? 'Close' : 'Cancel'}>
      {step === 0 ? (
        <FlowStepView heading="Which controller is joining?" intro="EasyEAP accepts RADIUS only from registered controllers. Each one gets its own shared secret." next={<Button variant="primary" onClick={() => advance(0, [nameError, vendorError])}>Continue</Button>}>
          <div className="c-field">
            <span className="c-label">Controller type</span>
            <ChoiceGrid
              label="Controller type"
              value={draft.vendor}
              invalid={Boolean(showErr(0, vendorError))}
              onChange={(v) => set({ vendor: v as NasVendor, coaPort: String(defaultCoaPort(v as NasVendor)) })}
              choices={VENDORS.map((v) => {
                const Icon = vendorIcon[v]
                return { value: v, label: vendorLabels[v], icon: <Icon size={18} strokeWidth={1.7} aria-hidden="true" /> }
              })}
            />
            {showErr(0, vendorError) ? (
              <p className="c-error" role="alert" style={{ margin: 0 }}>
                <CircleAlert size={14} aria-hidden="true" />
                {vendorError}
              </p>
            ) : null}
          </div>
          <Field label="Name" htmlFor="c-nas-name" hint="Shown in authentication logs and alerts." error={showErr(0, nameError)}>
            <TextInput id="c-nas-name" value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="Riverside branch WLC" invalid={Boolean(showErr(0, nameError))} describedBy={showErr(0, nameError) ? 'c-nas-name-error' : 'c-nas-name-hint'} autoComplete="off" />
          </Field>
          <Field label="Site (optional)" htmlFor="c-nas-site" hint="Where the controller lives, so alerts say which people are affected.">
            <TextInput id="c-nas-site" value={draft.site} onChange={(e) => set({ site: e.target.value })} placeholder="Riverside branch" describedBy="c-nas-site-hint" autoComplete="off" />
          </Field>
        </FlowStepView>
      ) : null}

      {step === 1 ? (
        <FlowStepView
          heading="Where will requests come from?"
          intro="RADIUS drops packets from any address that is not registered, so use the controller’s management address."
          back={<Button variant="ghost" onClick={() => setStep(0)}>Back</Button>}
          next={<Button variant="primary" onClick={() => advance(1, [addressError, portError])}>Continue</Button>}
        >
          <Field label="IP address or CIDR range" htmlFor="c-nas-addr" hint="A single address such as 10.30.0.5, or a range such as 10.30.0.0/28 for a controller cluster." error={showErr(1, addressError)}>
            <TextInput id="c-nas-addr" mono value={draft.address} onChange={(e) => set({ address: e.target.value })} placeholder="10.30.0.5" inputMode="decimal" invalid={Boolean(showErr(1, addressError))} describedBy={showErr(1, addressError) ? 'c-nas-addr-error' : 'c-nas-addr-hint'} autoComplete="off" spellCheck={false} />
          </Field>
          <div className="c-field">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
              <Toggle id="c-nas-coa" checked={draft.coaEnabled} onChange={(v) => set({ coaEnabled: v })} label="Allow EasyEAP to send disconnects (CoA)" />
              <label htmlFor="c-nas-coa" style={{ cursor: 'pointer' }}>
                <span className="c-label" style={{ display: 'block' }}>Allow disconnects (CoA)</span>
                <span className="c-hint">Lets EasyEAP disconnect a device the moment its certificate is revoked. Without it, the device stays online until it reauthenticates.</span>
              </label>
            </div>
          </div>
          {draft.coaEnabled ? (
            <Field label="CoA port" htmlFor="c-nas-port" hint={draft.vendor === 'cisco-9800' ? 'Catalyst 9800 listens on UDP 1700 by default.' : 'RFC 5176 default is UDP 3799.'} error={showErr(1, portError)}>
              <TextInput id="c-nas-port" mono value={draft.coaPort} onChange={(e) => set({ coaPort: e.target.value })} inputMode="numeric" style={{ maxWidth: 160 }} invalid={Boolean(showErr(1, portError))} describedBy={showErr(1, portError) ? 'c-nas-port-error' : 'c-nas-port-hint'} />
            </Field>
          ) : null}
        </FlowStepView>
      ) : null}

      {step === 2 && draft.vendor ? (
        <FlowStepView
          heading="Create this controller?"
          intro="EasyEAP generates a shared secret when you create it. You will see the secret once, on the next step."
          back={<Button variant="ghost" onClick={() => setStep(1)}>Back</Button>}
          next={<Button variant="primary" onClick={create}>Create controller</Button>}
        >
          <DefList
            items={[
              { label: 'Name', value: draft.name.trim() },
              { label: 'Type', value: vendorLabels[draft.vendor] },
              { label: 'Site', value: draft.site.trim() || 'Unassigned' },
              { label: 'Address', value: <span className="c-mono">{draft.address.trim()}</span> },
              { label: 'Disconnects (CoA)', value: draft.coaEnabled ? <span className="tnum">On, UDP {draft.coaPort}</span> : 'Off' },
              { label: 'RADIUS server', value: <span className="tnum">{d.radiusSettings?.serverHostname}, UDP {d.radiusSettings?.authPort} / {d.radiusSettings?.acctPort}</span> },
            ]}
          />
        </FlowStepView>
      ) : null}

      {step === 3 && draft.vendor && secret && d.radiusSettings ? (
        <FlowStepView heading="Copy the secret into the controller" intro={`${draft.name.trim()} is registered. Paste this secret and the commands below into the controller; its status turns healthy when the first request arrives.`} next={<Button variant="primary" onClick={() => close(false)}>I’ve stored the secret</Button>}>
          <SecretOnce secret={secret} />
          <Note icon={EyeOff} tone="warn">
            <strong>This is the only time the secret is shown.</strong> EasyEAP stores it encrypted for RADIUS and never displays it again. If it is lost, rotate it from the controller’s row.
          </Note>
          <SnippetBlock snippet={snippetFor(draft.vendor, d.radiusSettings, { client: { coaEnabled: draft.coaEnabled, coaPort: Number(draft.coaPort), name: draft.name }, secret, ssid })} caption={`${snippetFor(draft.vendor, d.radiusSettings, {}).label} for ${draft.name.trim()}`} />
        </FlowStepView>
      ) : null}
    </Flow>
  )
}
