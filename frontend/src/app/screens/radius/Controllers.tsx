// Wireless controller (RADIUS client) dialogs: add, edit, rotate shared secret, delete.
// The shared secret is returned once by the API. It lives only in this component's state while the dialog is open,
// the dialog can't be dismissed until it has been copied or acknowledged, and it is dropped when the dialog closes.
import { useEffect, useId, useState, type FormEvent, type RefObject } from 'react'
import { Plus, RotateCw, Trash2 } from 'lucide-react'
import {
  VENDORS, defaultCoaPort, useCreateClient, useDeleteClient, useRotateSecret, useUpdateClient, vendorLabels,
  type ClientIn, type RadiusClient, type RadiusSettings,
} from '../../api/radius'
import { useTenant } from '../../api/tenant'
import { Btn, Callout, EDialog, ESelect, ESwitch, Field, OneTimeSecret, errorMessage, toast } from '../../ui'
import { VendorGuide } from './Guide'

const blank: ClientIn = { name: '', vendor: 'cisco-9800', address: '', site: '', coa_enabled: true, coa_port: 1700 }

function addressProblem(a: string): string | null {
  const v = a.trim()
  if (!v) return 'Enter the source address of the controller’s RADIUS requests, for example 10.20.0.5 or 10.20.0.0/28.'
  const v4 = /^(\d{1,3})(\.\d{1,3}){3}(\/\d{1,2})?$/
  if (v4.test(v)) {
    const [ip, bits] = v.split('/')
    if (ip.split('.').some((o) => Number(o) > 255)) return 'Each part of an IPv4 address is 0–255.'
    if (bits !== undefined && (Number(bits) > 32)) return 'An IPv4 prefix is /0 to /32.'
    if (bits !== undefined && Number(bits) < 16) return 'The range is too broad. Use /16 or narrower so each controller is identifiable.'
    return null
  }
  if (v.includes(':') && /^[0-9a-fA-F:]+(\/\d{1,3})?$/.test(v)) return null
  return 'Enter an IP address or CIDR range, for example 10.20.0.5 or 10.20.0.0/28.'
}

function ControllerForm({ value, onChange, touched, existing, formId, onSubmit }: { value: ClientIn; onChange: (v: ClientIn) => void; touched: boolean; existing: RadiusClient[]; formId: string; onSubmit: () => void }) {
  const id = useId()
  const set = <K extends keyof ClientIn>(k: K, v: ClientIn[K]) => onChange({ ...value, [k]: v })
  const errors = controllerErrors(value, existing)
  const err = (k: keyof typeof errors) => (touched ? errors[k] : null)
  return (
    <form id={formId} className="grid gap-4 sm:grid-cols-2" noValidate onSubmit={(e: FormEvent) => { e.preventDefault(); onSubmit() }}>
      <div className="sm:col-span-2">
        <Field label="Name" htmlFor={`${id}-name`} error={err('name')} hint="How it appears in the authentication log, for example “HQ Catalyst 9800”.">
          <input id={`${id}-name`} className="ee-input" value={value.name} maxLength={120} onChange={(e) => set('name', e.target.value)} aria-invalid={!!err('name') || undefined} autoComplete="off" autoFocus />
        </Field>
      </div>
      <Field label="Controller type" htmlFor={`${id}-vendor`} hint="Selects the configuration guide and the default CoA port.">
        <ESelect id={`${id}-vendor`} label="Controller type" value={value.vendor} className="w-full"
          onChange={(v) => onChange({ ...value, vendor: v, coa_port: defaultCoaPort(v), coa_enabled: v === 'unifi' ? false : value.coa_enabled })}
          options={VENDORS.map((v) => ({ value: v, label: vendorLabels[v] }))} />
      </Field>
      <Field label="Source address or CIDR" htmlFor={`${id}-addr`} error={err('address')} hint="The address its RADIUS requests come from.">
        <input id={`${id}-addr`} className="ee-input ee-mono" value={value.address} onChange={(e) => set('address', e.target.value)} placeholder="10.20.0.5" inputMode="decimal"
          aria-invalid={!!err('address') || undefined} autoComplete="off" spellCheck={false} />
      </Field>
      <Field label="Site" htmlFor={`${id}-site`} optional hint="Groups controllers, for example “Head office”.">
        <input id={`${id}-site`} className="ee-input" value={value.site} maxLength={120} onChange={(e) => set('site', e.target.value)} autoComplete="off" />
      </Field>
      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-semibold" id={`${id}-coa`}>Change of Authorization (CoA)</span>
        <div className="flex items-center gap-3">
          <ESwitch checked={value.coa_enabled} onChange={(v) => set('coa_enabled', v)} label="Send CoA disconnects to this controller" />
          <input aria-label="CoA port (UDP)" className="ee-input ee-num w-[96px]" value={value.coa_port ?? ''} inputMode="numeric" disabled={!value.coa_enabled}
            onChange={(e) => set('coa_port', e.target.value === '' ? null : Number(e.target.value.replace(/[^0-9]/g, '')))} aria-invalid={!!err('coa_port') || undefined} />
          <span className="ee-small ee-ink-3">UDP</span>
        </div>
        {err('coa_port') ? <p className="ee-field-error" role="alert">{err('coa_port')}</p> : (
          <p className="ee-small ee-ink-3">{value.vendor === 'unifi'
            ? 'Not every UniFi version accepts CoA from an external server. Leave it off unless you’ve verified it.'
            : 'Lets EasyEAP end a session when you revoke its certificate. Without it, the session lasts until the session timeout.'}</p>
        )}
      </div>
    </form>
  )
}

function controllerErrors(v: ClientIn, existing: RadiusClient[]) {
  return {
    name: !v.name.trim() ? 'Name the controller so you can recognise it in the log.' : existing.some((c) => c.name.toLowerCase() === v.name.trim().toLowerCase()) ? 'Another controller already has this name.' : null,
    address: addressProblem(v.address),
    coa_port: v.coa_enabled && !(Number.isInteger(v.coa_port) && (v.coa_port ?? 0) >= 1 && (v.coa_port ?? 0) <= 65535) ? 'Enter a UDP port from 1 to 65535. Catalyst 9800 listens on 1700, most others on 3799.' : null,
  }
}

/** The one-time step shared by "add" and "rotate": the secret, then the vendor configuration filled with it. */
function SecretStep({ secret, vendor, settings, acked, onAck, rotated }: { secret: string; vendor: string; settings: RadiusSettings; acked: boolean; onAck: (v: boolean) => void; rotated?: boolean }) {
  return (
    <div className="space-y-5">
      <OneTimeSecret value={secret} what="shared secret" acknowledged={acked} onAcknowledge={onAck}
        note={rotated
          ? <>EasyEAP shows this secret once. The old secret stops working as soon as RADIUS applies the change, usually within seconds, so enter this one on the controller now.</>
          : undefined} />
      <section aria-label="Controller configuration" className="border-t border-[var(--ee-line)] pt-4">
        <h3 className="ee-h3 mb-1">{rotated ? 'Update the controller' : 'Configure the controller'}</h3>
        <p className="ee-small ee-ink-2 mb-3">Filled with this tenant’s RADIUS address, ports and the new secret. {rotated ? 'Replace the old key on the RADIUS server entry (and the CoA client, if you use it).' : 'Paste it into the controller, then test with one enrolled device.'}</p>
        <VendorGuide vendor={vendor} settings={settings} secret={secret} onCopied={() => onAck(true)} compact />
      </section>
    </div>
  )
}

export function AddControllerDialog({ open, onOpenChange, settings, clients, onAdded }: { open: boolean; onOpenChange: (o: boolean) => void; settings: RadiusSettings; clients: RadiusClient[]; onAdded?: (c: RadiusClient) => void }) {
  const { tid } = useTenant()
  const create = useCreateClient(tid)
  const [v, setV] = useState<ClientIn>(blank)
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<{ client: RadiusClient; secret: string } | null>(null)
  const [acked, setAcked] = useState(false)
  const formId = useId()

  useEffect(() => {
    if (!open) {
      // Drop the secret from memory once the dialog is closed.
      const t = setTimeout(() => { setResult(null); setAcked(false); setV(blank); setTouched(false); setError(null) }, 200)
      return () => clearTimeout(t)
    }
  }, [open])

  const submit = () => {
    setTouched(true)
    setError(null)
    if (Object.values(controllerErrors(v, clients)).some(Boolean)) return
    create.mutate({ ...v, name: v.name.trim(), address: v.address.trim(), site: v.site.trim(), coa_port: v.coa_enabled ? v.coa_port : v.coa_port ?? defaultCoaPort(v.vendor) }, {
      onSuccess: (r) => { setResult({ client: r.client, secret: r.shared_secret }); onAdded?.(r.client) },
      onError: (e) => setError(errorMessage(e)),
    })
  }

  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide blockDismiss={!!result && !acked} risk={result ? 'gold' : undefined}
      title={result ? `${result.client.name} added` : 'Add wireless controller'}
      description={result ? `RADIUS accepts requests from ${result.client.address} once it applies the change, usually within seconds.` : 'RADIUS answers only registered controllers. EasyEAP generates the shared secret.'}
      footer={result ? (
        <>
          {!acked && <span className="ee-small ee-ink-3 mr-auto">Copy the secret or tick the box to continue.</span>}
          <Btn variant="primary" disabled={!acked} onClick={() => onOpenChange(false)}>Done</Btn>
        </>
      ) : (
        <>
          <Btn variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Btn>
          <Btn variant="primary" type="submit" form={formId} busy={create.isPending}><Plus aria-hidden />Add and generate secret</Btn>
        </>
      )}>
      {result ? (
        <SecretStep secret={result.secret} vendor={result.client.vendor} settings={settings} acked={acked} onAck={setAcked} />
      ) : (
        <div className="space-y-4">
          <ControllerForm value={v} onChange={setV} touched={touched} existing={clients} formId={formId} onSubmit={submit} />
          {error && <Callout tone="crit" title="The controller wasn’t added">{error}</Callout>}
        </div>
      )}
    </EDialog>
  )
}

export function EditControllerDialog({ client, onClose, clients, returnFocus }: { client: RadiusClient | null; onClose: () => void; clients: RadiusClient[]; returnFocus?: RefObject<HTMLElement | null> }) {
  const { tid } = useTenant()
  const update = useUpdateClient(tid)
  const [v, setV] = useState<ClientIn>(blank)
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const formId = useId()
  useEffect(() => {
    if (client) {
      setV({ name: client.name, vendor: client.vendor, address: client.address, site: client.site, coa_enabled: client.coa_enabled, coa_port: client.coa_port })
      setTouched(false)
      setError(null)
    }
  }, [client])
  const others = clients.filter((c) => c.id !== client?.id)
  const submit = () => {
    if (!client) return
    setTouched(true)
    setError(null)
    if (Object.values(controllerErrors(v, others)).some(Boolean)) return
    update.mutate({ id: client.id, body: { ...v, name: v.name.trim(), address: v.address.trim(), site: v.site.trim() } }, {
      onSuccess: () => { toast('Controller updated', `${v.name.trim()}. RADIUS applies the change with its next configuration refresh.`); onClose() },
      onError: (e) => setError(errorMessage(e)),
    })
  }
  return (
    <EDialog open={!!client} onOpenChange={(o) => !o && onClose()} returnFocus={returnFocus} wide title={`Edit ${client?.name ?? 'controller'}`} description="The shared secret doesn’t change. Use Rotate secret for that."
      footer={<>
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="primary" type="submit" form={formId} busy={update.isPending}>Save changes</Btn>
      </>}>
      <div className="space-y-4">
        <ControllerForm value={v} onChange={setV} touched={touched} existing={others} formId={formId} onSubmit={submit} />
        {error && <Callout tone="crit" title="Changes weren’t saved">{error}</Callout>}
      </div>
    </EDialog>
  )
}

export function RotateSecretDialog({ client, onClose, settings, returnFocus }: { client: RadiusClient | null; onClose: () => void; settings: RadiusSettings; returnFocus?: RefObject<HTMLElement | null> }) {
  const { tid } = useTenant()
  const rotate = useRotateSecret(tid)
  const [secret, setSecret] = useState<string | null>(null)
  const [acked, setAcked] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [shown, setShown] = useState<RadiusClient | null>(client)
  useEffect(() => {
    if (client) { setShown(client); return }
    const t = setTimeout(() => { setSecret(null); setAcked(false); setError(null) }, 200)
    return () => clearTimeout(t)
  }, [client])
  const c = client ?? shown
  return (
    <EDialog open={!!client} onOpenChange={(o) => !o && onClose()} returnFocus={returnFocus} wide={!!secret} blockDismiss={!!secret && !acked} risk={secret ? 'gold' : 'warn'}
      title={secret ? `New shared secret for ${c?.name}` : `Rotate the shared secret for ${c?.name}?`}
      description={secret ? 'Enter it on the controller now.' : `${c?.address} · ${vendorLabels[c?.vendor ?? ''] ?? c?.vendor}`}
      footer={secret ? (
        <>
          {!acked && <span className="ee-small ee-ink-3 mr-auto">Copy the secret or tick the box to continue.</span>}
          <Btn variant="primary" disabled={!acked} onClick={onClose}>Done</Btn>
        </>
      ) : (
        <>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="primary" busy={rotate.isPending} onClick={() => c && rotate.mutate(c.id, {
            onSuccess: (r) => { setSecret(r.shared_secret); setError(null) },
            onError: (e) => setError(errorMessage(e)),
          })}><RotateCw aria-hidden />Rotate secret now</Btn>
        </>
      )}>
      {secret && c ? (
        <SecretStep secret={secret} vendor={c.vendor} settings={settings} acked={acked} onAck={setAcked} rotated />
      ) : (
        <div className="space-y-3">
          <Callout tone="warn" title="Update the controller at the same moment">
            The current secret stops working as soon as RADIUS applies the change, usually within seconds. Until the new secret is entered on {c?.name}, every authentication through it fails, including devices re-authenticating mid-session.
          </Callout>
          <p className="text-[13.5px] ee-ink-2">Open the controller’s RADIUS server settings before you rotate. EasyEAP shows the new secret once, with the configuration filled in.</p>
          {error && <Callout tone="crit" title="The secret wasn’t rotated">{error}</Callout>}
        </div>
      )}
    </EDialog>
  )
}

export function DeleteControllerDialog({ client, onClose, returnFocus }: { client: RadiusClient | null; onClose: () => void; returnFocus?: RefObject<HTMLElement | null> }) {
  const { tid } = useTenant()
  const del = useDeleteClient(tid)
  const [shown, setShown] = useState<RadiusClient | null>(client)
  useEffect(() => { if (client) setShown(client) }, [client])
  const c = client ?? shown
  return (
    <EDialog open={!!client} onOpenChange={(o) => !o && onClose()} returnFocus={returnFocus} risk="crit" title={`Delete ${c?.name}?`} description={`${c?.address} · ${vendorLabels[c?.vendor ?? ''] ?? c?.vendor}`}
      footer={<>
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="danger-solid" busy={del.isPending} onClick={() => c && del.mutate(c.id, {
          onSuccess: () => { toast('Controller deleted', `RADIUS stops answering ${c.address} once it applies the change.`); onClose() },
          onError: (e) => toast('The controller wasn’t deleted', errorMessage(e), 'crit'),
        })}><Trash2 aria-hidden />Delete controller</Btn>
      </>}>
      <div className="space-y-3 text-[13.5px] ee-ink-2">
        <p>RADIUS stops answering requests from {c?.address} once it applies the change, usually within seconds. New connections through this controller then fail.</p>
        <p>Devices already connected stay connected until they next re-authenticate. Its shared secret is deleted and can’t be recovered; adding the controller again generates a new one.</p>
      </div>
    </EDialog>
  )
}

