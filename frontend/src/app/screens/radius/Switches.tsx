// Wired 802.1X (docs/plans/wired-8021x.md §6): the Add switch wizard, a switch's panel (rollout mode, port plan,
// configuration), Enforce / back to monitor, editing the port plan, and the Windows wired kit.
// Like Add controller, the shared secret is returned once, kept only in this component's state while the dialog is
// open, filled into the configuration in the browser, and dropped when the dialog closes.
import { useCallback, useEffect, useId, useState, type FormEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { ArrowLeft, ArrowRight, Cable, Check, Download, Eye, Lock, Pencil, ShieldCheck, Undo2 } from 'lucide-react'
import { cn } from '@/ui/lib'
import { errorField, saveBlob } from '../../api/client'
import {
  ADDRESS_PLACEHOLDER, MAB_VENDORS, SECRET_PLACEHOLDER, SWITCH_VENDORS, ciscoPlatformLabels, defaultCoaPort, defaultWiredProfile, fillText, remainingPlaceholders, showClientSecret, supportsMab, switchVendorLabels,
  useActivity, useCheckSessions, useCiscoDetect, useCiscoPlatforms, useConfigApplied, useCreateClient, useRadius, useReadiness, useSetMab, useSetWiredMode, useUpdateClient, useWiredGuide, useWiredKit,
  type CiscoDetected, type CiscoPlatform, type MabHealth, type RadiusClient, type RadiusSettings, type SwitchCaps, type WiredGuide, type WiredProfile,
} from '../../api/radius'
import { useReveal } from '../../api/oneTime'
import { useTenant } from '../../api/tenant'
import { failureExplanations } from '@/domain/explain'
import type { FailureCode } from '@/domain/types'
import { ago, fmtDate, fmtDateTime } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { Btn, Callout, Chip, CopyButton, EDialog, ESelect, ESwitch, ErrorState, Field, FillSecretButton, LoadingBlock, OneTimeSecret, Seg, errorMessage, toast, toastError } from '../../ui'
import { paths } from '../../routes'
import { addressProblem } from './Controllers'
import { Marked } from './Guide'
import { SwitchAuditPanel } from './SwitchAudit'

type SwitchVendor = (typeof SWITCH_VENDORS)[number]
const reasonTitle = (code: string | null) => (code ? failureExplanations[code as FailureCode]?.title ?? code : null)

// ── Port plan form (Add switch step 2, Edit port plan) ──────────────────────

const PLAN_FIELDS = new Set(['interfaces', 'exclude', 'source_interface', 'vrf', 'access_vlan', 'no_supplicant_vlan', 'server_down_vlan', 'fallback_vlan', 'wired_profile',
  'platform', 'series', 'version', 'host_mode', 'no_supplicant', 'server_down'])
const CISCO_PLATFORMS: CiscoPlatform[] = ['ibns2', 'classic', 'nxos', 'cbs']

/** What each Cisco family covers, how it names its ports, and how it prints its release. */
const FAMILY: Record<CiscoPlatform, { covers: string; ports: string; portsHint: string; exclude: string; version: string }> = {
  ibns2: { covers: 'Catalyst 9000, 3650, 3850, IE 3x00 and other switches on IOS-XE 16, 17 or 26, or IOS-XE 3.x on a 3650, 3850 or 4500E.',
    ports: 'GigabitEthernet1/0/1 - 24', portsHint: 'Gi1/0/1-24, Gi2/0/1-48', exclude: 'Gi1/0/48, Te1/1/1', version: '17.9.4a' },
  classic: { covers: 'Catalyst 2960, 2960-X, 2960-L, 3560, 3750 and IE 2000 on IOS 12.2 or 15.',
    ports: 'GigabitEthernet1/0/1 - 24', portsHint: 'Gi1/0/1-24, Fa0/1-48', exclude: 'Gi1/0/48, Gi1/0/49', version: '15.2(7)E3' },
  nxos: { covers: 'Nexus 9000, 3000, 5000, 6000 and 7000 on NX-OS.',
    ports: 'Ethernet1/1 - 48', portsHint: 'Ethernet1/1-48, Ethernet2/1-24', exclude: 'Ethernet1/49-54', version: '9.3(8)' },
  cbs: { covers: 'Catalyst 1200 and 1300, CBS220, CBS250 and CBS350, and the SG/SF 200 to 550X small business switches.',
    ports: 'gi1/0/1 - 24', portsHint: 'gi1/0/1-24, gi2/0/1-24', exclude: 'gi1/0/25-28', version: '3.1.1.7' },
}

function vlanNumber(v: string): number | null {
  const n = Number(v.replace(/[^0-9]/g, ''))
  return v.trim() === '' || !Number.isFinite(n) ? null : n
}

function planProblems(vendor: string, p: WiredProfile): Partial<Record<keyof WiredProfile, string>> {
  const out: Partial<Record<keyof WiredProfile, string>> = {}
  const badVlan = (n: number | null) => n !== null && (n < 1 || n > 4094)
  if (vendor === 'cisco-switch' && !p.interfaces.trim()) out.interfaces = `List the access ports to configure, for example ${FAMILY[p.platform]?.ports ?? FAMILY.ibns2.ports}.`
  if (vendor === 'cisco-switch' && (p.platform === 'nxos' || p.platform === 'cbs') && !p.series) out.series = 'Choose the switch’s model family.'
  if (p.no_supplicant === 'vlan' && p.no_supplicant_vlan === null) out.no_supplicant_vlan = 'Choose the VLAN for devices without 802.1X.'
  if (p.server_down === 'vlan' && p.server_down_vlan === null) out.server_down_vlan = 'Choose the VLAN for new devices while EasyEAP is unreachable.'
  for (const k of ['access_vlan', 'no_supplicant_vlan', 'server_down_vlan', 'fallback_vlan'] as const) if (badVlan(p[k])) out[k] = 'A VLAN is 1 to 4094.'
  return out
}

function VlanInput({ id, value, onChange, label, invalid }: { id: string; value: number | null; onChange: (v: number | null) => void; label: string; invalid?: boolean }) {
  return <input id={id} aria-label={label} className="ee-input ee-num w-[96px]" inputMode="numeric" value={value ?? ''} aria-invalid={invalid || undefined}
    onChange={(e) => onChange(vlanNumber(e.target.value))} autoComplete="off" />
}

const hostModes: Record<WiredProfile['host_mode'], string> = {
  'multi-auth': 'Multi-auth: every device on the port authenticates (docks, small switches)',
  'single-host': 'Single host: one device per port',
  'multi-host': 'Multi-host: the first device opens the port for all',
}
const serverDownLabels: Record<WiredProfile['server_down'], string> = { wait: 'Wait', open: 'Allow on the port’s VLAN', vlan: 'Allow on a VLAN' }

function describeDefaults(p: WiredProfile, vendor = 'cisco-switch'): string[] {
  const cisco = vendor === 'cisco-switch'
  return [
    hostModes[p.host_mode].split(':')[0],
    `${p.mab ? 'Devices not on the MAC allow list' : 'Devices without 802.1X'}: ${p.no_supplicant === 'vlan' ? `VLAN ${p.no_supplicant_vlan ?? '?'} once enforced` : 'blocked once enforced'}`,
    p.server_down === 'open' ? 'EasyEAP unreachable: new devices allowed on the port’s VLAN' : p.server_down === 'vlan' ? `EasyEAP unreachable: new devices on VLAN ${p.server_down_vlan ?? '?'}` : 'EasyEAP unreachable: new devices wait, connected ones keep working',
    p.access_vlan ? `Access VLAN ${p.access_vlan}` : 'Each port keeps its VLAN',
    ...(cisco ? [p.source_interface ? `RADIUS from ${p.source_interface}` : 'RADIUS from the switch’s default address'] : []),
    ...(cisco && p.vrf ? [`VRF ${p.vrf}`] : []),
  ]
}

/** MAC authentication in the port plan: chosen when the switch is added; afterwards its own change on the switch's panel. */
function MabChoice({ vendor, value, onChange, mode, supported, caps }: { vendor: string; value: WiredProfile; onChange: (v: boolean) => void; mode: 'create' | 'edit'; supported: boolean; caps: SwitchCaps | null }) {
  if (!MAB_VENDORS.includes(vendor)) return <Callout tone="neutral">IP phones, printers and other devices without 802.1X can’t be admitted by MAC address on this platform: list their ports under “leave alone”.</Callout>
  if (caps && caps.mab === null) {
    return <Callout tone="neutral">This switch can’t admit devices by MAC address. Leave the ports of IP phones, printers and other devices without 802.1X out of the plan (“leave alone”).</Callout>
  }
  if (caps?.monitor === 'server') {
    return (
      <Callout tone="neutral" title="MAC authentication: on">
        This switch has no open (monitor) mode, so EasyEAP monitors it through MAC authentication: until you enforce, it accepts every MAC request from the switch and logs what it would decide.
        Once enforced, devices without 802.1X are admitted only from the MAC allow list.
      </Callout>
    )
  }
  if (mode === 'edit') {
    return <Callout tone="neutral">MAC authentication is {value.mab ? 'on' : 'off'} for this switch. Turn it {value.mab ? 'off' : 'on'} from the switch’s panel: it’s a change of its own on the switch.</Callout>
  }
  const on = !!value.mab && supported
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0 max-w-[62ch]">
        <p className="text-[13px] font-semibold">Admit devices without 802.1X by MAC address</p>
        <p className="ee-small ee-ink-3 mt-0.5">{!supported
          ? 'RADIUS needs updating first (System health shows its version). You can turn it on later from the switch’s panel.'
          : on ? (vendor === 'unifi'
            ? 'Ports you set to MAC-Based check their devices against the MAC allow list.'
            : 'Printers, cameras and phones that don’t answer 802.1X are checked against the MAC allow list after about 30 seconds. Devices that answer 802.1X never fall back to their MAC.')
            : 'Off: devices without 802.1X are refused once enforced, or put on the VLAN for them below. You can turn it on later.'}</p>
      </div>
      <ESwitch checked={on} onChange={onChange} disabled={!supported} label="Admit devices without 802.1X by MAC address" />
    </div>
  )
}

/** "Paste show version": EasyEAP reads the family, model and release. Nothing is stored. */
function DetectSwitch({ onDetected }: { onDetected: (d: CiscoDetected) => void }) {
  const { tid } = useTenant()
  const id = useId()
  const detect = useCiscoDetect(tid)
  const [open, setOpen] = useState(false)
  const [text, setText] = useState('')
  const d = detect.data?.detected
  const run = () => detect.mutate(text, {
    onSuccess: (r) => { if (r.detected.platform && !r.detected.unsupported) { onDetected(r.detected); setOpen(false); setText('') } },
    onError: (e) => toast('That couldn’t be read', errorMessage(e), 'crit'),
  })
  return (
    <div className="rounded-[10px] border border-[var(--ee-line)] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 max-w-[62ch]">
          <p className="text-[13px] font-semibold">Read it from the switch</p>
          <p className="ee-small ee-ink-3 mt-0.5">Paste the output of <span className="ee-mono">show version</span> (Cisco Business: <span className="ee-mono">show system</span> and <span className="ee-mono">show version</span>) and EasyEAP sets the family, model and release below. Nothing you paste is stored.</p>
        </div>
        {!open && <Btn size="sm" onClick={() => setOpen(true)}>Paste show version</Btn>}
      </div>
      {open && (
        <div className="mt-3 space-y-2">
          <label htmlFor={`${id}-sv`} className="sr-only">Output of show version</label>
          <textarea id={`${id}-sv`} className="ee-input ee-mono min-h-[110px] text-[12px]" value={text} maxLength={20000} onChange={(e) => setText(e.target.value)} spellCheck={false} autoFocus />
          <div className="flex gap-2">
            <Btn size="sm" variant="primary" disabled={!text.trim()} busy={detect.isPending} onClick={run}>Read it</Btn>
            <Btn size="sm" variant="ghost" onClick={() => { setOpen(false); setText('') }}>Cancel</Btn>
          </div>
        </div>
      )}
      <div aria-live="polite">
        {d && (d.unsupported
          ? <Callout tone="crit" className="mt-3" title={`${d.model || d.family || 'This switch'}: EasyEAP can’t configure 802.1X on it`}>{d.unsupported}</Callout>
          : !d.platform
            ? <Callout tone="warn" className="mt-3" title="EasyEAP didn’t recognise that">Choose the family below. If it’s a Cisco switch, paste the whole output from its first line.</Callout>
            : <p className="ee-small ee-ink-2 mt-3 flex items-center gap-1.5"><Check className="size-3.5 shrink-0 text-[var(--ee-valid)]" aria-hidden />{[d.family, d.model, d.version, d.lan_lite ? 'LAN Lite' : ''].filter(Boolean).join(' · ')}. Set below.</p>)}
      </div>
    </div>
  )
}

/** What the chosen switch can't do, and what EasyEAP assumed because the release isn't given. */
function CapsNotes({ caps }: { caps: SwitchCaps | null }) {
  if (!caps || (!caps.notes.length && !caps.warnings.length)) return null
  const list = (xs: string[]) => (xs.length === 1 ? xs[0] : <ul className="list-disc space-y-0.5 pl-5">{xs.map((x) => <li key={x} className="pl-1">{x}</li>)}</ul>)
  return (
    <div className="space-y-2">
      {caps.warnings.length > 0 && <Callout tone="warn" title="EasyEAP assumed">{list(caps.warnings)}</Callout>}
      {caps.notes.length > 0 && <Callout tone="neutral" title="About this switch">{list(caps.notes)}</Callout>}
    </div>
  )
}

export function PortPlanForm({ vendor, value, onChange, touched, serverError, mab = 'create' }: { vendor: string; value: WiredProfile; onChange: (p: WiredProfile) => void; touched: boolean; serverError?: { field: string; message: string } | null; mab?: 'create' | 'edit' }) {
  const { tid } = useTenant()
  const radius = useRadius(tid)
  const mabSupported = supportsMab(radius.data?.agent)
  const id = useId()
  const [more, setMore] = useState(false)
  const cisco = vendor === 'cisco-switch'
  const meraki = vendor === 'meraki'
  const platforms = useCiscoPlatforms(tid, vendor, value, cisco || meraki)
  const caps = cisco || meraki ? platforms.data?.capabilities ?? null : null
  const fresh = !!caps && !platforms.isPlaceholderData
  const set = <K extends keyof WiredProfile>(k: K, v: WiredProfile[K]) => onChange({ ...value, [k]: v })
  const problems = planProblems(vendor, value)
  const err = (k: keyof WiredProfile) => (serverError?.field === k || serverError?.field === `wired_profile.${k}` ? serverError.message : touched ? problems[k] ?? null : null)
  // A server error about a field hidden behind "Change" opens it.
  useEffect(() => { if (serverError && ['source_interface', 'vrf', 'access_vlan', 'no_supplicant_vlan', 'server_down_vlan', 'host_mode', 'server_down', 'no_supplicant'].includes(serverError.field.replace(/^wired_profile\./, ''))) setMore(true) }, [serverError])
  // Choices this switch can't carry out move to one it can (the backend refuses them anyway).
  useEffect(() => {
    if (!fresh || !caps) return
    const fix: Partial<WiredProfile> = {}
    if (!caps.host_modes.includes(value.host_mode)) fix.host_mode = caps.host_modes[0]
    if (!caps.server_down.includes(value.server_down)) fix.server_down = caps.server_down[0]
    if (value.no_supplicant === 'vlan' && !caps.no_supplicant_vlan) fix.no_supplicant = 'block'
    if (Object.keys(fix).length) onChange({ ...value, ...fix })
  }, [fresh, caps, value, onChange])

  if (vendor === 'unifi') {
    return (
      <div className="space-y-4">
        <Field label="Fallback VLAN" htmlFor={`${id}-fb`} optional error={err('fallback_vlan')}
          hint="UniFi puts devices that fail 802.1X, or don’t try it, on this VLAN. While you test, use the VLAN the ports use today: that’s UniFi’s monitor mode. Choose a restricted VLAN when you enforce.">
          <VlanInput id={`${id}-fb`} label="Fallback VLAN" value={value.fallback_vlan} onChange={(v) => set('fallback_vlan', v)} invalid={!!err('fallback_vlan')} />
        </Field>
        <MabChoice vendor={vendor} value={value} onChange={(v) => set('mab', v)} mode={mab} supported={mabSupported} caps={null} />
        {!value.mab && <p className="ee-small ee-ink-3">Without it, leave the ports of IP phones, printers and other devices without 802.1X on Force Authorized.</p>}
      </div>
    )
  }
  if (!cisco && !meraki) return null
  const fam = FAMILY[value.platform] ?? FAMILY.ibns2
  const seriesOptions = (platforms.data?.series[meraki ? 'meraki' : value.platform] ?? []).filter(Boolean)
  const seriesLabels = platforms.data?.series_labels ?? {}
  const hostOptions = caps?.host_modes ?? (Object.keys(hostModes) as WiredProfile['host_mode'][])
  const downOptions = caps?.server_down ?? (['wait', 'open', 'vlan'] as WiredProfile['server_down'][])
  const nsVlan = caps?.no_supplicant_vlan !== false
  return (
    <div className="space-y-5">
      {cisco && <DetectSwitch onDetected={(d) => onChange({ ...value, platform: d.platform ?? value.platform, series: d.series, version: d.version, lan_lite: d.lan_lite })} />}
      {cisco && (
        <Field label="Family" htmlFor={`${id}-plat`} hint={fam.covers}>
          <Seg label="Switch family" value={value.platform} onChange={(v) => onChange({ ...value, platform: v, series: '', version: '', lan_lite: false })}
            options={CISCO_PLATFORMS.map((v) => ({ value: v, label: ciscoPlatformLabels[v] }))} />
        </Field>
      )}
      {(meraki || value.platform === 'nxos' || value.platform === 'cbs') && (
        <Field label="Model" htmlFor={`${id}-ser`} error={err('series')}
          hint={meraki ? 'The switch’s own open (monitor) mode exists only on the MS130 and MS150 with MS 18 or later.' : 'What 802.1X can do differs by model.'}>
          <ESelect id={`${id}-ser`} label="Model" className="w-full" value={value.series || (meraki ? 'ms' : '')} placeholder="Choose the model family"
            onChange={(v) => set('series', v)} disabled={!seriesOptions.length} options={seriesOptions.map((s) => ({ value: s, label: seriesLabels[s] ?? s }))} />
        </Field>
      )}
      {cisco && (
        <div className="flex flex-wrap items-start gap-x-8 gap-y-4">
          <Field label="Software release" htmlFor={`${id}-ver`} optional error={err('version')}
            hint={<>As <span className="ee-mono">show version</span> prints it, for example {fam.version}. Blank: EasyEAP assumes a recent release.</>}>
            <input id={`${id}-ver`} className="ee-input ee-mono max-w-[200px]" value={value.version ?? ''} maxLength={40} onChange={(e) => set('version', e.target.value.trim())}
              placeholder={fam.version} spellCheck={false} autoComplete="off" aria-invalid={!!err('version') || undefined} />
          </Field>
          {value.platform === 'classic' && (
            <div className="flex min-w-0 max-w-[40ch] items-start gap-3 pt-6">
              <ESwitch checked={!!value.lan_lite} onChange={(v) => set('lan_lite', v)} label="LAN Lite image" />
              <p className="ee-small ee-ink-3">LAN Lite image: <span className="ee-mono">show version</span> names a LANLITE image (2960-L, some 2960 and 2960-X).</p>
            </div>
          )}
        </div>
      )}
      <CapsNotes caps={caps} />
      {cisco && (
        <>
          <Field label="Access ports" htmlFor={`${id}-if`} error={err('interfaces')} hint={`The ports users plug into, as the switch names them. Ranges and commas are fine: ${fam.portsHint}.`}>
            <textarea id={`${id}-if`} className="ee-input ee-mono min-h-[64px]" value={value.interfaces} onChange={(e) => set('interfaces', e.target.value)}
              placeholder={fam.ports} spellCheck={false} aria-invalid={!!err('interfaces') || undefined} />
          </Field>
          <Field label="Ports to leave alone" htmlFor={`${id}-ex`} optional error={err('exclude')}
            hint="Uplinks, access points, printers, phones, and the port you’re connected through. Skipped even when they fall inside the access-port ranges.">
            <input id={`${id}-ex`} className="ee-input ee-mono" value={value.exclude} onChange={(e) => set('exclude', e.target.value)} placeholder={fam.exclude} spellCheck={false}
              aria-invalid={!!err('exclude') || undefined} autoComplete="off" />
          </Field>
        </>
      )}
      {cisco && (value.platform === 'ibns2' || value.platform === 'classic') && (
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0 max-w-[62ch]">
            <p className="text-[13px] font-semibold">The switch already uses AAA</p>
            <p className="ee-small ee-ink-3 mt-0.5">{value.has_aaa
              ? 'Its login and exec settings are left exactly as they are.'
              : <>Off: the configuration turns AAA on and keeps logins on the switch’s local users. Check with <span className="ee-mono">show running-config | include ^aaa new-model</span>: on only if it prints exactly <span className="ee-mono">aaa new-model</span> (<span className="ee-mono">no aaa new-model</span> means off).</>}</p>
          </div>
          <ESwitch checked={value.has_aaa} onChange={(v) => set('has_aaa', v)} label="The switch already uses AAA" />
        </div>
      )}
      <MabChoice vendor={vendor} value={value} onChange={(v) => set('mab', v)} mode={mab} supported={mabSupported} caps={caps} />

      <div className="rounded-[10px] border border-[var(--ee-line)] p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-[13px] font-semibold">Defaults</p>
            {!more && <ul className="ee-small ee-ink-2 mt-1 space-y-0.5">{describeDefaults(value, vendor).map((d) => <li key={d}>{d}</li>)}</ul>}
          </div>
          <Btn size="sm" variant="ghost" onClick={() => setMore((m) => !m)} aria-expanded={more}>{more ? 'Done' : 'Change'}</Btn>
        </div>
        {more && (
          <div className="mt-4 space-y-4">
            <Field label="Devices per port" htmlFor={`${id}-hm`} error={serverError?.field.endsWith('host_mode') ? serverError.message : null}>
              <ESelect id={`${id}-hm`} label="Devices per port" value={value.host_mode} onChange={(v) => set('host_mode', v as WiredProfile['host_mode'])} className="w-full"
                options={hostOptions.map((v) => ({ value: v, label: hostModes[v] }))} />
            </Field>
            <Field label={value.mab ? 'Devices not on the MAC allow list, once enforced' : 'Devices without 802.1X, once enforced'} htmlFor={`${id}-ns`}
              error={err('no_supplicant_vlan') ?? (serverError?.field.endsWith('no_supplicant') ? serverError.message : null)}
              hint={caps?.monitor === 'none' ? 'This switch has no monitor mode: they’re blocked as soon as their port is configured.' : 'In monitor mode they keep their access either way.'}>
              {nsVlan ? (
                <div className="flex flex-wrap items-center gap-3">
                  <Seg label="Devices without 802.1X" value={value.no_supplicant} onChange={(v) => set('no_supplicant', v)}
                    options={[{ value: 'block', label: 'Blocked' }, { value: 'vlan', label: 'Put on a VLAN' }]} />
                  {value.no_supplicant === 'vlan' && <VlanInput id={`${id}-nsv`} label="VLAN for devices without 802.1X" value={value.no_supplicant_vlan} onChange={(v) => set('no_supplicant_vlan', v)} invalid={!!err('no_supplicant_vlan')} />}
                </div>
              ) : <p className="text-[13px] ee-ink-2">Blocked: this switch has no VLAN for them.</p>}
            </Field>
            <Field label="New devices while EasyEAP is unreachable" htmlFor={`${id}-sd`} error={err('server_down_vlan') ?? (serverError?.field.endsWith('server_down') ? serverError.message : null)}
              hint={value.server_down === 'wait'
                ? 'Fails closed: a device that connects during an outage waits until EasyEAP is back. Devices already connected keep working either way.'
                : value.server_down === 'open'
                  ? 'Fails open: during an outage any device that plugs in gets the port’s VLAN without a certificate.'
                  : 'During an outage new devices get this VLAN without a certificate. Make it a restricted one.'}>
              {downOptions.length > 1 ? (
                <div className="flex flex-wrap items-center gap-3">
                  <Seg label="New devices while EasyEAP is unreachable" value={value.server_down} onChange={(v) => set('server_down', v)}
                    options={downOptions.map((v) => ({ value: v, label: serverDownLabels[v] }))} />
                  {value.server_down === 'vlan' && <VlanInput id={`${id}-sdv`} label="VLAN while EasyEAP is unreachable" value={value.server_down_vlan} onChange={(v) => set('server_down_vlan', v)} invalid={!!err('server_down_vlan')} />}
                </div>
              ) : <p className="text-[13px] ee-ink-2">Wait: this switch has no way to let new devices through while EasyEAP is unreachable.</p>}
            </Field>
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="Access VLAN" htmlFor={`${id}-av`} optional error={err('access_vlan')} hint={meraki ? 'The VLAN these ports use. Blank: EasyEAP’s steps say “the VLAN these ports use”.' : 'Blank keeps each port’s VLAN.'}>
                <VlanInput id={`${id}-av`} label="Access VLAN" value={value.access_vlan} onChange={(v) => set('access_vlan', v)} invalid={!!err('access_vlan')} />
              </Field>
              {cisco && (
                <Field label="RADIUS source interface" htmlFor={`${id}-src`} optional error={err('source_interface')} hint={value.platform === 'nxos' ? 'For example mgmt0 or Vlan10.' : 'For example Vlan10 or Loopback0.'}>
                  <input id={`${id}-src`} className="ee-input ee-mono" value={value.source_interface} onChange={(e) => set('source_interface', e.target.value.trim())} placeholder={value.platform === 'nxos' ? 'mgmt0' : 'Vlan10'} spellCheck={false} autoComplete="off" />
                </Field>
              )}
              {cisco && value.platform !== 'cbs' && (
                <Field label="VRF" htmlFor={`${id}-vrf`} optional error={err('vrf')} hint={value.platform === 'nxos' ? 'Blank: management.' : 'When EasyEAP is reached through one, for example Mgmt-vrf.'}>
                  <input id={`${id}-vrf`} className="ee-input ee-mono" value={value.vrf} onChange={(e) => set('vrf', e.target.value.trim())} spellCheck={false} autoComplete="off" />
                </Field>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Wired configuration ─────────────────────────────────────────────────────

/** A wired guide: preflight, the configuration, safe-paste, steps. The shared secret is filled in when given (just
 * created) or when an admin who may see secrets asks for it (`clientId`: EasyEAP fetches it, and audits that). */
export function WiredGuideBody({ guide, settings, secret, onCopied, which = 'initial', secretOf, clientId }: {
  guide: WiredGuide; settings: RadiusSettings; secret?: string | null; onCopied?: () => void; which?: 'initial' | 'enforce' | 'monitor' | 'mab'; secretOf?: string
  clientId?: string
}) {
  const id = useId()
  const { tid, can } = useTenant()
  const [address, setAddress] = useState('')
  const shown = useReveal(useCallback(() => showClientSecret(tid, clientId ?? ''), [tid, clientId]))
  const fill = { secret: secret ?? shown.value?.shared_secret ?? null, address: settings.radius_address ? null : address.trim() || null }
  const rawCli = which === 'enforce' ? guide.enforce_cli : which === 'monitor' ? guide.monitor_cli : which === 'mab' ? guide.mab_cli : guide.cli
  const rawSteps = which === 'enforce' ? guide.enforce_steps : which === 'monitor' ? guide.monitor_steps : which === 'mab' ? guide.mab_steps : guide.steps
  const cli = rawCli ? fillText(rawCli, fill) : null
  const steps = (rawSteps ?? []).map((s) => fillText(s, fill))
  const left = remainingPlaceholders([cli ?? '', ...steps].join('\n'))
  const needsAddress = [rawCli ?? '', ...(rawSteps ?? [])].join('\n').includes(ADDRESS_PLACEHOLDER)
  const mayFill = !!clientId && can('radius:secrets')
  const fillButton = mayFill && left.includes(SECRET_PLACEHOLDER)
    ? <FillSecretButton what="shared secret" busy={shown.busy} onClick={() => shown.reveal(toastError('The shared secret can’t be shown'))} />
    : null
  return (
    <div className="space-y-5">
      {needsAddress && (
        <Field label="RADIUS address" htmlFor={`${id}-addr`} hint={settings.radius_address_problem ?? 'This EasyEAP server has no RADIUS address configured (EASYEAP_RADIUS_ADDRESS in the deploy .env). Enter the address your switches reach it on.'}>
          <input id={`${id}-addr`} className="ee-input ee-mono max-w-[260px]" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.10" autoComplete="off" spellCheck={false} />
        </Field>
      )}
      {which === 'initial' && !!guide.warnings?.length && (
        <Callout tone="warn" title="EasyEAP assumed">{guide.warnings.join(' ')} Check each command as you paste it, and add the release to the port plan if you can.</Callout>
      )}
      {which === 'initial' && guide.preflight.length > 0 && (
        <section aria-label="Before you paste">
          <p className="text-[13px] font-semibold mb-2">1. Check the switch first</p>
          <ol className="space-y-2">
            {guide.preflight.map((c) => (
              <li key={c.command} className="grid gap-1 sm:grid-cols-[minmax(0,22rem)_minmax(0,1fr)] sm:gap-4">
                <code className="ee-mono text-[12.5px] break-all">{c.command}</code>
                <span className="ee-small ee-ink-2">{c.look_for}</span>
              </li>
            ))}
          </ol>
        </section>
      )}
      {cli && (
        <section aria-label="Configuration">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-[13px] font-semibold">{which === 'initial' && guide.preflight.length ? '2. ' : ''}{which === 'enforce' ? 'The change that enforces' : which === 'monitor' ? 'The change back to monitor mode' : which === 'mab' ? `The change that turns MAC authentication ${guide.mab ? 'on' : 'off'}` : 'Configuration'}</p>
            <div className="flex flex-wrap items-center gap-2">
              {fillButton}
              <CopyButton text={cli} what={`${guide.title} configuration`} label="Copy configuration" onCopied={onCopied} />
            </div>
          </div>
          <pre className="ee-code max-h-[420px] overflow-auto" tabIndex={0} aria-label={`${guide.title} configuration`}><Marked text={cli} /></pre>
        </section>
      )}
      {which === 'initial' && guide.safe_paste.length > 0 && (
        <section aria-label="Paste it safely">
          <p className="text-[13px] font-semibold mb-2">3. Paste it safely</p>
          <ol className="list-decimal space-y-1 pl-5 text-[13.5px] marker:text-[var(--ee-ink-3)]">
            {guide.safe_paste.map((s) => <li key={s} className="pl-1">{s}</li>)}
          </ol>
        </section>
      )}
      {steps.length > 0 && (
        <section aria-label="Steps">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-[13px] font-semibold">{cli ? 'Then' : 'Steps'}</p>
            {!cli && <div className="flex flex-wrap items-center gap-2">{fillButton}<CopyButton text={steps.map((s, i) => `${i + 1}. ${s}`).join('\n')} what={`${guide.title} steps`} label="Copy steps" onCopied={onCopied} /></div>}
          </div>
          <ol className="list-decimal space-y-1.5 pl-5 text-[13.5px] marker:text-[var(--ee-ink-3)] marker:tabular-nums">
            {steps.map((s, i) => <li key={i} className="pl-1"><Marked text={s} /></li>)}
          </ol>
        </section>
      )}
      {which === 'initial' && (
        <section aria-label="Before you enforce">
          <p className="text-[13px] font-semibold mb-2">Before you enforce</p>
          <ul className="list-disc space-y-1.5 pl-5 text-[13px] ee-ink-2 marker:text-[var(--ee-ink-3)]">{guide.checks.map((c) => <li key={c} className="pl-1">{c}</li>)}</ul>
        </section>
      )}
      {left.length > 0 && (
        <div className="ee-small ee-ink-3">
          <p>Replace the highlighted values before you paste:</p>
          <ul className="mt-1 space-y-0.5">
            {left.map((p) => <li key={p}><mark className="ee-mono rounded-[3px] bg-[rgba(226,194,117,0.16)] px-1 text-[var(--ee-gold)]">{p}</mark>{' '}
              {p === SECRET_PLACEHOLDER ? (mayFill ? `${secretOf ?? 'this switch'}’s shared secret: Fill in the shared secret puts it in` : `${secretOf ?? 'this switch'}’s shared secret (an administrator who manages RADIUS secrets can fill it in)`) : p === ADDRESS_PLACEHOLDER ? 'the address your switches use to reach EasyEAP RADIUS' : 'a value from your switch'}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}

/** "Waiting for the first request": the latest results from this switch, or why none arrived. */
export function FirstRequest({ client }: { client: RadiusClient }) {
  const { tid } = useTenant()
  const now = useNow()
  const q = useActivity(tid, client.id)
  const ev = q.data?.events ?? []
  const diag = q.data?.diagnostics ?? []
  return (
    <section aria-label="First request" aria-live="polite" className="rounded-[10px] border border-[var(--ee-line)] p-4">
      {ev.length === 0 ? (
        <>
          <p className="text-[13px] font-semibold flex items-center gap-2"><span className="motion-safe:animate-pulse size-2 rounded-full bg-[var(--ee-gold)]" aria-hidden />Waiting for the first request from {client.name}</p>
          <p className="ee-small ee-ink-3 mt-1">Plug a device with an EasyEAP certificate into a configured port. Results appear here within a few seconds.</p>
          {diag.map((d) => (
            <Callout key={`${d.kind}-${d.address}`} tone="warn" className="mt-3" title={d.kind === 'unknown_client' ? `Requests from ${d.address}, which isn’t registered` : `Wrong shared secret from ${d.address}`}>
              {d.message} <span className="ee-ink-3">Seen {ago(d.at, now)}.</span>
            </Callout>
          ))}
        </>
      ) : (
        <>
          <p className="text-[13px] font-semibold">Requests from {client.name}</p>
          <ul className="mt-2 divide-y divide-[var(--ee-line)]">
            {ev.slice(0, 5).map((e) => (
              <li key={e.id} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2 text-[13px]">
                <span className="min-w-0">
                  <Chip tone={e.result === 'accept' ? 'valid' : 'crit'}>{e.result === 'accept' ? 'Accepted' : 'Rejected'}</Chip>{' '}
                  <span className="ee-mono text-[12.5px]">{e.username ?? e.calling_station_id ?? 'Unknown device'}</span>
                  {e.nas_port_id && <span className="ee-ink-3"> on {e.nas_port_id}</span>}
                </span>
                <span className="ee-small ee-ink-2">
                  {e.result === 'reject' ? reasonTitle(e.reason_code) : e.monitor ? `Would get VLAN ${e.vlan_id ?? 'none'} (monitor mode: not sent)` : e.vlan_id ? `VLAN ${e.vlan_id}` : 'Port’s own VLAN'}
                  {' · '}<span title={fmtDateTime(e.at)}>{ago(e.at, now)}</span>
                </span>
              </li>
            ))}
          </ul>
          {ev[0].network === 'wireless' && <Callout tone="warn" className="mt-3">EasyEAP counted the latest request as Wi-Fi. If it came from a switch port, the switch doesn’t report its port type: register this switch for wired only.</Callout>}
        </>
      )}
    </section>
  )
}

// ── Add switch ──────────────────────────────────────────────────────────────

const VENDOR_HINTS: Record<string, string> = {
  'cisco-switch': 'Catalyst (IOS and IOS-XE), Nexus and Cisco Business switches: the next step asks which.',
  meraki: 'Set up in the Meraki Dashboard: EasyEAP gives the steps.',
  unifi: 'UniFi switches managed by a UniFi Network application.',
  other: 'Any switch that does 802.1X with RADIUS: EasyEAP gives the RADIUS settings, and you configure the ports.',
}

interface SwitchBasics { vendor: SwitchVendor; name: string; address: string; site: string; coa_enabled: boolean; coa_port: number | null }
const blankBasics: SwitchBasics = { vendor: 'cisco-switch', name: '', address: '', site: '', coa_enabled: true, coa_port: 1700 }

const STEPS = [{ id: 'switch', title: 'Switch' }, { id: 'ports', title: 'Ports' }, { id: 'configure', title: 'Configure' }] as const
type StepId = (typeof STEPS)[number]['id']

function StepDots({ current, skipPorts }: { current: StepId; skipPorts: boolean }) {
  const steps = STEPS.filter((s) => !(skipPorts && s.id === 'ports'))
  const idx = steps.findIndex((s) => s.id === current)
  return (
    <ol className="ee-steps mb-5" aria-label="Add switch steps">
      {steps.map((s, i) => (
        <li key={s.id}>
          <span className="ee-step" data-state={i === idx ? 'current' : i < idx ? 'done' : undefined} aria-current={i === idx ? 'step' : undefined}>
            {i < idx ? <Check className="size-3.5" aria-hidden /> : <span className="ee-num" aria-hidden>{i + 1}</span>}{s.title}
          </span>
        </li>
      ))}
    </ol>
  )
}

export function AddSwitchDialog({ open, onOpenChange, settings, clients, onAdded }: { open: boolean; onOpenChange: (o: boolean) => void; settings: RadiusSettings; clients: RadiusClient[]; onAdded?: (c: RadiusClient) => void }) {
  const { tid } = useTenant()
  const create = useCreateClient(tid)
  const update = useUpdateClient(tid)
  const id = useId()
  const [step, setStep] = useState<StepId>('switch')
  const [b, setB] = useState<SwitchBasics>(blankBasics)
  const [plan, setPlan] = useState<WiredProfile>(defaultWiredProfile)
  // UniFi: a new registration, or turning wired on for an existing UniFi registration (one range for APs and switches).
  const unifiExisting = clients.filter((c) => c.vendor === 'unifi' && !c.networks.includes('wired'))
  const [target, setTarget] = useState<string>('new')
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  const [result, setResult] = useState<{ client: RadiusClient; secret: string | null } | null>(null)
  const [acked, setAcked] = useState(false)
  const guide = useWiredGuide(tid, result?.client.id ?? null, !!result)

  useEffect(() => {
    if (!open) {
      const t = setTimeout(() => { setStep('switch'); setB(blankBasics); setPlan(defaultWiredProfile); setTarget('new'); setTouched(false); setError(null); setResult(null); setAcked(false) }, 200)
      return () => clearTimeout(t)
    }
  }, [open])

  const existing = target !== 'new' ? clients.find((c) => c.id === target) ?? null : null
  const skipPorts = b.vendor === 'other'
  const basicsErrors = existing ? {} : {
    name: !b.name.trim() ? 'Name the switch so you can recognise it in the log.' : clients.some((c) => c.name.toLowerCase() === b.name.trim().toLowerCase()) ? 'Another controller or switch already has this name.' : null,
    address: addressProblem(b.address),
    coa_port: b.coa_enabled && !(Number.isInteger(b.coa_port) && (b.coa_port ?? 0) >= 1 && (b.coa_port ?? 0) <= 65535) ? 'Enter a UDP port from 1 to 65535. Cisco and Meraki switches listen on 1700.' : null,
  }
  const berr = (k: 'name' | 'address' | 'coa_port') => (error && error.field === k ? error.message : touched ? (basicsErrors as Record<string, string | null>)[k] ?? null : null)

  const submit = () => {
    setTouched(true)
    setError(null)
    if (Object.values(basicsErrors).some(Boolean)) { setStep('switch'); return }
    if (Object.values(planProblems(b.vendor, plan)).some(Boolean)) { setStep('ports'); return }
    const wired_profile = b.vendor === 'other' ? {} : plan
    const onError = (e: unknown) => {
      const field = errorField(e)
      const message = errorMessage(e)
      setError({ field: field ?? '', message })
      if (field && PLAN_FIELDS.has(field.replace(/^wired_profile\./, ''))) setStep(b.vendor === 'other' ? 'switch' : 'ports')
      else setStep('switch')
    }
    if (existing) {
      update.mutate({ id: existing.id, body: { networks: ['wireless', 'wired'], wired_profile } }, {
        onSuccess: (r) => { setResult({ client: r.client, secret: null }); setAcked(true); setStep('configure'); onAdded?.(r.client) },
        onError,
      })
      return
    }
    create.mutate({ name: b.name.trim(), vendor: b.vendor, address: b.address.trim(), site: b.site.trim(), coa_enabled: b.coa_enabled,
      coa_port: b.coa_enabled ? b.coa_port : b.coa_port ?? defaultCoaPort(b.vendor), networks: ['wired'], wired_profile }, {
      onSuccess: (r) => { setResult({ client: r.client, secret: r.shared_secret }); setStep('configure'); onAdded?.(r.client) },
      onError,
    })
  }

  const next = () => {
    if (step === 'switch') {
      setTouched(true)
      if (Object.values(basicsErrors).some(Boolean)) return
      setTouched(false)
      if (skipPorts) submit()
      else setStep('ports')
    } else if (step === 'ports') submit()
  }

  const busy = create.isPending || update.isPending
  const title = result ? (existing ? `Wired on for ${result.client.name}` : `${result.client.name} added`) : 'Add switch'
  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide blockDismiss={!!result && !acked} risk={result ? 'gold' : undefined} title={title}
      description={result
        ? 'Monitor mode: ports stay open and EasyEAP sends no VLAN, so nothing changes for users while you check the results.'
        : 'Wired 802.1X for switch ports, in the same certificate and policy as Wi-Fi. It starts in monitor mode.'}
      footer={result ? (
        <>
          {!acked && <span className="ee-small ee-ink-3 mr-auto">Copy the secret or tick the box to continue.</span>}
          <Btn variant="primary" disabled={!acked} onClick={() => onOpenChange(false)}>Done</Btn>
        </>
      ) : (
        <>
          {step === 'ports' && <Btn variant="ghost" className="mr-auto" onClick={() => setStep('switch')}><ArrowLeft aria-hidden />Back</Btn>}
          <Btn variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Btn>
          <Btn variant="primary" type="submit" form={`${id}-form`} busy={busy}>
            {step === 'ports' || skipPorts ? <>{existing ? 'Turn on wired' : 'Add and generate secret'}<ArrowRight aria-hidden /></> : <>Next<ArrowRight aria-hidden /></>}
          </Btn>
        </>
      )}>
      <StepDots current={step} skipPorts={skipPorts} />
      {step !== 'configure' && (
        <form id={`${id}-form`} noValidate onSubmit={(e: FormEvent) => { e.preventDefault(); next() }} className="space-y-4">
          {step === 'switch' && (
            <>
              <Field label="Switch platform" htmlFor={`${id}-plat`} hint={VENDOR_HINTS[b.vendor]}>
                <Seg label="Switch platform" value={b.vendor} onChange={(v) => { setB({ ...b, vendor: v, coa_port: defaultCoaPort(v), coa_enabled: v === 'cisco-switch' }); setPlan(v === 'meraki' ? { ...defaultWiredProfile, series: 'ms' } : defaultWiredProfile); setTarget('new'); setError(null) }}
                  options={SWITCH_VENDORS.map((v) => ({ value: v, label: switchVendorLabels[v] }))} />
              </Field>
              {b.vendor === 'unifi' && unifiExisting.length > 0 && (
                <Field label="Registration" htmlFor={`${id}-tgt`} hint="UniFi sends RADIUS for access points and switches from the same addresses. If your existing UniFi registration covers the switches, turn wired on for it.">
                  <ESelect id={`${id}-tgt`} label="Registration" value={target} onChange={setTarget} className="w-full"
                    options={[{ value: 'new', label: 'A new registration for the switches' }, ...unifiExisting.map((c) => ({ value: c.id, label: `Turn on wired for ${c.name} (${c.address})` }))]} />
                </Field>
              )}
              {existing && !existing.address.includes('/') && (
                <Callout tone="warn" title={`${existing.name} is a single address`}>Each UniFi switch sends RADIUS from its own management address. Unless {existing.address} is where the switches send from, add a new registration covering their addresses instead.</Callout>
              )}
              {!existing && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="sm:col-span-2">
                    <Field label="Name" htmlFor={`${id}-name`} error={berr('name')} hint="How it appears in the authentication log, for example “Floor 2 access”.">
                      <input id={`${id}-name`} className="ee-input" value={b.name} maxLength={120} onChange={(e) => setB({ ...b, name: e.target.value })} aria-invalid={!!berr('name') || undefined} autoComplete="off" autoFocus />
                    </Field>
                  </div>
                  <Field label="Source address or CIDR" htmlFor={`${id}-addr`} error={berr('address')}
                    hint={b.vendor === 'unifi' ? 'The switches’ management addresses (a range covers several switches).'
                      : b.vendor === 'meraki' ? 'The switch’s management (LAN) IP, or its Alternate Management Interface IP if you set one. A range covers several switches.'
                        : 'The address its RADIUS requests come from: the management VLAN interface, or the source interface in the port plan.'}>
                    <input id={`${id}-addr`} className="ee-input ee-mono" value={b.address} onChange={(e) => setB({ ...b, address: e.target.value })} placeholder="10.20.0.21" inputMode="decimal"
                      aria-invalid={!!berr('address') || undefined} autoComplete="off" spellCheck={false} />
                  </Field>
                  <Field label="Site" htmlFor={`${id}-site`} optional>
                    <input id={`${id}-site`} className="ee-input" value={b.site} maxLength={120} onChange={(e) => setB({ ...b, site: e.target.value })} autoComplete="off" />
                  </Field>
                  <div className="flex flex-col gap-1.5 sm:col-span-2">
                    <span className="text-[13px] font-semibold">Change of Authorization (CoA)</span>
                    <div className="flex items-center gap-3">
                      <ESwitch checked={b.coa_enabled} onChange={(v) => setB({ ...b, coa_enabled: v })} label="Send CoA disconnects to this switch" />
                      <input aria-label="CoA port (UDP)" className="ee-input ee-num w-[96px]" value={b.coa_port ?? ''} inputMode="numeric" disabled={!b.coa_enabled}
                        onChange={(e) => setB({ ...b, coa_port: e.target.value === '' ? null : Number(e.target.value.replace(/[^0-9]/g, '')) })} aria-invalid={!!berr('coa_port') || undefined} />
                      <span className="ee-small ee-ink-3">UDP</span>
                    </div>
                    {berr('coa_port') ? <p className="ee-field-error" role="alert">{berr('coa_port')}</p> : (
                      <p className="ee-small ee-ink-3">{b.vendor === 'unifi' ? 'Not verified on UniFi switches. Leave it off unless you’ve tested it.'
                        : b.vendor === 'meraki' ? 'Leave it off: Meraki needs a session ID in each answer that EasyEAP doesn’t send yet.'
                          : 'Lets EasyEAP end a port’s session when you revoke its certificate. Some Cisco switches can’t: the next step says.'}</p>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
          {step === 'ports' && <PortPlanForm vendor={b.vendor} value={plan} onChange={setPlan} touched={touched} serverError={error} />}
          {error && !(step === 'ports' && PLAN_FIELDS.has(error.field.replace(/^wired_profile\./, ''))) && !(step === 'switch' && ['name', 'address', 'coa_port'].includes(error.field)) && (
            <Callout tone="crit" title="The switch wasn’t added">{error.message}</Callout>
          )}
        </form>
      )}
      {step === 'configure' && result && (
        <div className="space-y-5">
          {result.secret && <OneTimeSecret value={result.secret} what="shared secret" acknowledged={acked} onAcknowledge={setAcked} />}
          <section aria-label="Switch configuration" className={cn(result.secret && 'border-t border-[var(--ee-line)] pt-4')}>
            <h3 className="ee-h3 mb-3">Configure {result.client.name}</h3>
            {guide.isLoading ? <LoadingBlock rows={6} label="Building the configuration" />
              : guide.error ? <ErrorState error={guide.error} onRetry={() => guide.refetch()} title="The configuration couldn’t be built" />
                : guide.data ? <WiredGuideBody guide={guide.data} settings={settings} secret={result.secret} onCopied={() => setAcked(true)} secretOf={result.client.name} clientId={result.client.id} /> : null}
          </section>
          <FirstRequest client={result.client} />
        </div>
      )}
    </EDialog>
  )
}

// ── A switch's panel ────────────────────────────────────────────────────────

export function ModeChip({ c }: { c: RadiusClient }) {
  if (!c.networks.includes('wired') || !c.wired_mode) return null
  return c.wired_mode === 'monitor'
    ? <Chip tone="gold" icon={<Eye aria-hidden />}>Monitor mode</Chip>
    : <Chip tone="valid" icon={<Lock aria-hidden />}>{c.wired_profile ? 'Enforcing' : 'Sends VLANs'}</Chip>
}

export function SwitchPanel({ client, settings }: { client: RadiusClient; settings: RadiusSettings }) {
  const { tid, can } = useTenant()
  const [view, setView] = useState(false)
  const [enforce, setEnforce] = useState(false)
  const [monitor, setMonitor] = useState(false)
  const [edit, setEdit] = useState(false)
  const [mabChange, setMabChange] = useState(false)
  const now = useNow(60_000)
  const p = client.wired_profile
  const guide = useWiredGuide(tid, client.id, view && !!p)
  const write = can('radius:write')
  if (!client.networks.includes('wired')) return null
  if (!p) {
    return (
      <Callout tone="neutral" title={`${client.name} is registered for Wi-Fi and wired`}>
        It was registered before EasyEAP knew about switches, so it may send wired requests, and EasyEAP answers them as it always has (with VLANs).
        If it’s only a wireless controller, edit it and turn wired off so its requests can’t be read as switch ports.
      </Callout>
    )
  }
  const since = p.mode_set_at ? Math.floor((now.getTime() - new Date(p.mode_set_at).getTime()) / 864e5) : null
  const caps = client.capabilities
  const cmd = sessionCommand(client)
  const ciscoLike = client.vendor === 'cisco-switch' || client.vendor === 'meraki'
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-2 text-[13.5px]"><ModeChip c={client} />
            <span className="ee-ink-2">
              {client.wired_mode !== 'monitor' ? 'Ports admit only accepted devices; EasyEAP sends VLANs.'
                : caps?.monitor === 'server' ? 'The switch has no open mode: EasyEAP accepts its MAC requests, logs what it would decide, and sends no VLAN.'
                  : caps?.monitor === 'none' ? 'The switch has no open mode: its configured ports already require 802.1X. EasyEAP sends no VLAN.'
                    : 'Ports open; EasyEAP decides and logs, and sends no VLAN.'}
            </span>
          </p>
          <p className="ee-small ee-ink-3 mt-1">
            Set in EasyEAP{p.mode_set_at ? ` on ${fmtDate(p.mode_set_at)}` : ''}{p.mode_set_by ? ` by ${p.mode_set_by}` : ''}.
            {client.monitoring?.enabled ? ' The switch audit below reads what the switch itself reports.' : <> EasyEAP can’t read the switch{client.vendor === 'cisco-switch' && caps?.audit !== null ? ' unless the switch audit is set up' : ''}:
              check with {cmd ? <span className="ee-mono">{cmd}</span> : client.vendor === 'meraki' ? 'Switch ports in the Meraki Dashboard' : client.vendor === 'unifi' ? 'the UniFi port settings' : 'the switch’s 802.1X status'}.</>}
            {client.wired_mode === 'monitor' && since !== null && since >= 14 && <span className="text-[var(--ee-warn-ink)]"> In monitor mode for {since} days.</span>}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Btn size="sm" onClick={() => setView((v) => !v)} aria-expanded={view}>{view ? 'Hide configuration' : 'Show configuration'}</Btn>
          {write && client.wired_mode === 'monitor' && <Btn size="sm" onClick={() => setEdit(true)}><Pencil aria-hidden />Edit port plan</Btn>}
          {write && client.wired_mode === 'monitor' && <Btn size="sm" variant="primary" onClick={() => setEnforce(true)}><ShieldCheck aria-hidden />Enforce…</Btn>}
          {write && client.wired_mode === 'enforce' && <Btn size="sm" onClick={() => setMonitor(true)}><Undo2 aria-hidden />Back to monitor mode…</Btn>}
        </div>
      </div>
      {ciscoLike && (
        <dl className="grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-[auto_minmax(0,1fr)]">
          <dt className="ee-label">Switch</dt><dd>{client.switch_family ?? (p.platform === 'classic' ? 'Classic IOS' : 'IOS-XE (IBNS 2.0)')}</dd>
          {client.vendor === 'cisco-switch' && <><dt className="ee-label">Access ports</dt><dd className="ee-mono text-[12.5px] break-words">{p.interfaces}</dd></>}
          {client.vendor === 'cisco-switch' && p.exclude && <><dt className="ee-label">Left alone</dt><dd className="ee-mono text-[12.5px] break-words">{p.exclude}</dd></>}
          <dt className="ee-label">Defaults</dt><dd>{describeDefaults(p, client.vendor).join(' · ')}</dd>
        </dl>
      )}
      {MAB_VENDORS.includes(client.vendor) && caps?.mab !== null && <MabRow client={client} onChange={() => setMabChange(true)} />}
      {client.vendor === 'cisco-switch' && (caps?.audit !== null || client.monitoring?.set_up) && <SwitchAuditPanel client={client} />}
      {view && (guide.isLoading ? <LoadingBlock rows={5} label="Loading the configuration" />
        : guide.error ? <ErrorState error={guide.error} onRetry={() => guide.refetch()} />
          : guide.data ? <WiredGuideBody guide={guide.data} settings={settings} secretOf={client.name} clientId={client.id} /> : null)}
      {view && client.wired_mode === 'enforce' && guide.data?.enforce_cli && (
        <WiredGuideBody guide={guide.data} settings={settings} which="enforce" secretOf={client.name} clientId={client.id} />
      )}
      {view && client.wired_mode === 'monitor' && (guide.data?.mab_cli || guide.data?.mab_steps) && (
        <WiredGuideBody guide={guide.data} settings={settings} which="mab" secretOf={client.name} clientId={client.id} />
      )}
      <MabDialog client={mabChange ? client : null} onClose={() => setMabChange(false)} settings={settings} />
      <EnforceDialog client={enforce ? client : null} onClose={() => setEnforce(false)} settings={settings} />
      <MonitorDialog client={monitor ? client : null} onClose={() => setMonitor(false)} settings={settings} />
      <EditPortPlanDialog client={edit ? client : null} onClose={() => setEdit(false)} />
    </div>
  )
}

// ── MAC authentication ──────────────────────────────────────────────────────

function MabRow({ client, onChange }: { client: RadiusClient; onChange: () => void }) {
  const { tid, can } = useTenant()
  const radius = useRadius(tid)
  const on = !!client.wired_profile?.mab
  const supported = supportsMab(radius.data?.agent)
  const monitor = client.wired_mode === 'monitor'
  // No open mode on the switch: MAC authentication is how EasyEAP monitors it, so it stays on.
  const required = client.capabilities?.monitor === 'server'
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 rounded-[10px] border border-[var(--ee-line)] px-4 py-3">
      <div className="min-w-0 max-w-[70ch]">
        <p className="flex flex-wrap items-center gap-2 text-[13px] font-semibold"><Cable className="size-4 ee-ink-3" aria-hidden /><span>MAC authentication</span><Chip tone={on ? 'valid' : 'neutral'}>{on ? 'On' : 'Off'}</Chip></p>
        <p className="ee-small ee-ink-3 mt-0.5">
          {on ? <>Devices that don’t answer 802.1X are checked against the {can('mac:read') ? <Link className="underline decoration-[var(--ee-line-3)] underline-offset-2" to={paths.mac(tid)}>MAC allow list</Link> : 'MAC allow list'}.</>
            : 'Devices without 802.1X (printers, cameras, phones) aren’t admitted by MAC address.'}
          {required && ' It stays on: this switch has no open mode, so it’s how EasyEAP monitors it.'}
          {!required && !monitor && ' Move the switch back to monitor mode to change it.'}
          {monitor && !on && !supported && ' RADIUS needs updating before it can be turned on (System health shows its version).'}
        </p>
      </div>
      {can('radius:write') && monitor && !(required && on) && (on || supported) && <Btn size="sm" onClick={onChange}>{on ? 'Turn off…' : 'Turn on…'}</Btn>}
    </div>
  )
}

function MabHealthView({ health, hours }: { health: MabHealth; hours: number }) {
  const { tid, can } = useTenant()
  const seen = can('mac:read') ? <Link className="underline decoration-[var(--ee-line-3)] underline-offset-2" to={paths.mac(tid, { tab: 'seen' })}>Seen, not allowed</Link> : '“Seen, not allowed”'
  if (health.answered === 0) {
    return (
      <Callout tone="warn" title={`No MAC authentication requests in the last ${hours} hours`}>
        Enforce waits for one: plug in a device without 802.1X and check the Authentication log. If none arrives, check that the ports have MAC authentication on (the configuration EasyEAP gave you), then the switch’s RADIUS debug output.
      </Callout>
    )
  }
  return (
    <p className="ee-small ee-ink-2">
      MAC authentication: {health.answered.toLocaleString('en-GB')} request{health.answered === 1 ? '' : 's'} answered, {health.accepted.toLocaleString('en-GB')} accepted.
      {health.unknown > 0 && <> {health.unknown} device{health.unknown === 1 ? ' isn’t' : 's aren’t'} on the MAC allow list ({seen}): once enforced, {health.unknown === 1 ? 'it’s' : 'they’re'} {health.unknown_action === 'vlan' ? `put on VLAN ${health.unknown_vlan}` : 'refused'}.</>}
    </p>
  )
}

export function MabDialog({ client, onClose, settings }: { client: RadiusClient | null; onClose: () => void; settings: RadiusSettings }) {
  const { tid } = useTenant()
  const set = useSetMab(tid)
  const [done, setDone] = useState<WiredGuide | null>(null)
  const [shown, setShown] = useState<RadiusClient | null>(client)
  useEffect(() => {
    if (client) { setShown(client); return }
    const t = setTimeout(() => setDone(null), 200)
    return () => clearTimeout(t)
  }, [client])
  const c = client ?? shown
  const on = !!c?.wired_profile?.mab
  const unifi = c?.vendor === 'unifi'
  return (
    <EDialog open={!!client} onOpenChange={(o) => !o && onClose()} wide={!!done} risk="gold"
      title={done ? `${unifi ? 'Change' : 'Paste the change on'} ${c?.name}` : `Turn ${on ? 'off' : 'on'} MAC authentication for ${c?.name}?`}
      description={done ? 'The ports stay open while you make the change: the switch is in monitor mode.' : on
        ? 'Devices without 802.1X are no longer checked by MAC address. In monitor mode they keep their access; once enforced they’re refused or put on the VLAN for them.'
        : 'Devices that don’t answer 802.1X are checked against the MAC allow list. In monitor mode their ports stay open, and EasyEAP logs what it would decide.'}
      footer={done ? <Btn variant="primary" onClick={onClose}>Done</Btn> : (
        <>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="primary" busy={set.isPending} onClick={() => c && set.mutate({ id: c.id, enabled: !on }, {
            onSuccess: (r) => setDone(r.guide),
            onError: (e) => toast('MAC authentication wasn’t changed', errorMessage(e), 'crit'),
          })}><Cable aria-hidden />Turn {on ? 'off' : 'on'} and show the change</Btn>
        </>
      )}>
      {done && c ? <WiredGuideBody guide={done} settings={settings} which="mab" secretOf={c.name} clientId={c.id} /> : !on ? (
        <ul className="list-disc space-y-1.5 pl-5 text-[13px] ee-ink-2 marker:text-[var(--ee-ink-3)]">
          <li className="pl-1">A device gets about 30 seconds to answer 802.1X before the switch asks for its MAC address. Devices that answer and fail never fall back.</li>
          <li className="pl-1">A MAC address is easy to copy. Put these devices in groups whose VLAN reaches only what they need.</li>
          <li className="pl-1">Before you enforce, allow the devices this switch sees from the MAC allow list → Seen, not allowed.</li>
        </ul>
      ) : <p className="text-[13.5px] ee-ink-2">Their entries stay on the MAC allow list for other switches.</p>}
    </EDialog>
  )
}

// ── Enforce / back to monitor ───────────────────────────────────────────────

function ReadinessView({ client }: { client: RadiusClient }) {
  const { tid } = useTenant()
  const q = useReadiness(tid, client.id)
  if (q.isLoading) return <LoadingBlock rows={3} label="Loading what EasyEAP saw" />
  if (q.error || !q.data) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  const r = q.data
  if (r.ports.length === 0) {
    return <Callout tone="crit" title={`No wired requests from this switch in the last ${r.hours} hours`}>Enforcing now would cut off every device on its ports. Check that devices are plugged in and that the switch’s requests reach EasyEAP (Authentication log, filter: Wired).</Callout>
  }
  return (
    <div className="space-y-2">
      <p className="ee-small ee-ink-2">{r.events} request{r.events === 1 ? '' : 's'} on {r.ports.length} port{r.ports.length === 1 ? '' : 's'}. {r.rejected_devices > 0 ? `${r.rejected_devices} device${r.rejected_devices === 1 ? ' was' : 's were'} rejected: they lose access once enforced.` : 'Every device that tried was accepted.'}</p>
      <div className="max-h-[220px] overflow-auto rounded-[8px] border border-[var(--ee-line)]">
        <table className="ee-table">
          <caption className="sr-only">Latest result per port and device, last 24 hours</caption>
          <thead><tr><th>Port</th><th>Device</th><th>Latest result</th></tr></thead>
          <tbody>
            {r.ports.flatMap((p) => p.devices.map((d) => (
              <tr key={`${p.port}-${d.mac}`}>
                <td className="ee-mono whitespace-nowrap text-[12.5px]">{p.port}</td>
                <td className="text-[12.5px]"><span className="ee-mono">{d.username ?? d.mac ?? '—'}</span>{d.method === 'mac' && <span className="ml-1.5"><Chip tone="neutral">MAC</Chip></span>}</td>
                <td>{d.result === 'accept' ? <Chip tone="valid">Accepted{d.vlan_id ? ` · VLAN ${d.vlan_id}` : ''}</Chip> : <Chip tone="crit">{reasonTitle(d.reason_code) ?? 'Rejected'}</Chip>}</td>
              </tr>
            )))}
          </tbody>
        </table>
      </div>
      {r.mab && <MabHealthView health={r.mab} hours={r.hours} />}
      {r.would_assign_vlans.length > 0 && <p className="ee-small ee-ink-2">Once enforced, EasyEAP assigns VLAN {r.would_assign_vlans.join(', ')} on this switch. Each must exist on it (<span className="ee-mono">show vlan brief</span>), or those devices fail.</p>}
    </div>
  )
}

/** The command that lists the switch's 802.1X sessions in a form EasyEAP reads; null where there's none. */
function sessionCommand(c: RadiusClient): string | null {
  if (c.capabilities !== undefined) return c.capabilities?.session_command ?? null
  if (c.vendor !== 'cisco-switch') return null
  return c.wired_profile?.platform === 'classic' ? 'show authentication sessions' : 'show access-session'
}

function SessionsCheckView({ client, cmd }: { client: RadiusClient; cmd: string }) {
  const { tid } = useTenant()
  const id = useId()
  const check = useCheckSessions(tid)
  const readiness = useReadiness(tid, client.id)
  const [text, setText] = useState('')
  const [paste, setPaste] = useState(false)
  const polled = readiness.data?.switch_sessions
  if (polled && !paste) {
    return (
      <div className="space-y-2">
        <p className="ee-small ee-ink-3">From the switch audit’s latest poll, {fmtDateTime(polled.at)}. <button type="button" className="underline decoration-[var(--ee-line-3)] underline-offset-2" onClick={() => setPaste(true)}>Paste the session list instead</button></p>
        {polled.would_lose_access.length === 0
          ? <Callout tone="valid" title={`All ${polled.sessions} session${polled.sessions === 1 ? ' is' : 's are'} authorized`}>Nothing the switch reported would lose access.</Callout>
          : (
            <Callout tone="crit" title={`${polled.would_lose_access.length} of ${polled.sessions} would lose access`}>
              <ul className="mt-1 space-y-0.5">{polled.would_lose_access.slice(0, 50).map((s) => <li key={`${s.interface}-${s.mac}`} className="ee-mono text-[12.5px]">{s.interface} · {s.mac} · {s.status}</li>)}</ul>
              {polled.would_lose_access.length > 50 && <p className="mt-1">…and {polled.would_lose_access.length - 50} more.</p>}
              <p className="mt-2">Move those ports to “leave alone” (Edit port plan), or enroll the devices, before you enforce.</p>
            </Callout>
          )}
      </div>
    )
  }
  const r = check.data
  return (
    <div className="space-y-3">
      <Field label="The switch’s session list" htmlFor={`${id}-s`}
        hint={<>Run <span className="ee-mono">{cmd}</span> and paste the output. Devices that never try 802.1X (printers, cameras, phones) never reach EasyEAP; the switch’s own list shows them. Nothing you paste is stored.</>}>
        <textarea id={`${id}-s`} className="ee-input ee-mono min-h-[96px] text-[12px]" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
      </Field>
      <Btn size="sm" disabled={!text.trim()} busy={check.isPending} onClick={() => check.mutate({ id: client.id, text }, { onError: (e) => toast('That couldn’t be checked', errorMessage(e), 'crit') })}>Check</Btn>
      {r && (!r.parsed
        ? <Callout tone="warn">EasyEAP couldn’t find any sessions in that. Paste the full output of <span className="ee-mono">{cmd}</span>, including the header line.</Callout>
        : r.would_lose_access.length === 0
          ? <Callout tone="valid" title={`All ${r.sessions} session${r.sessions === 1 ? ' is' : 's are'} authorized`}>Nothing the switch sees right now would lose access.</Callout>
          : (
            <Callout tone="crit" title={`${r.would_lose_access.length} of ${r.sessions} would lose access`}>
              <ul className="mt-1 space-y-0.5">{r.would_lose_access.slice(0, 50).map((s) => <li key={`${s.interface}-${s.mac}`} className="ee-mono text-[12.5px]">{s.interface} · {s.mac} · {s.status}</li>)}</ul>
              {r.would_lose_access.length > 50 && <p className="mt-1">…and {r.would_lose_access.length - 50} more.</p>}
              <p className="mt-2">Move those ports to “leave alone” (Edit port plan), or enroll the devices, before you enforce.</p>
            </Callout>
          ))}
    </div>
  )
}

export function EnforceDialog({ client, onClose, settings }: { client: RadiusClient | null; onClose: () => void; settings: RadiusSettings }) {
  const { tid } = useTenant()
  const setMode = useSetWiredMode(tid)
  const [confirmed, setConfirmed] = useState(false)
  const [done, setDone] = useState<WiredGuide | null>(null)
  const [doneAt, setDoneAt] = useState<number | null>(null)
  const [early, setEarly] = useState(false)
  const [blocked, setBlocked] = useState<string | null>(null)
  const applied = useConfigApplied(tid, doneAt)
  const [shown, setShown] = useState<RadiusClient | null>(client)
  useEffect(() => {
    if (client) { setShown(client); return }
    const t = setTimeout(() => { setConfirmed(false); setDone(null); setDoneAt(null); setEarly(false); setBlocked(null) }, 200)
    return () => clearTimeout(t)
  }, [client])
  // Re-render while waiting so the 20 s fallback for an older agent and the 90 s "slow" notice take effect.
  const [, tick] = useState(0)
  useEffect(() => {
    if (doneAt === null || applied.state === 'live') return
    const t = setInterval(() => tick((n) => n + 1), 2000)
    return () => clearInterval(t)
  }, [doneAt, applied.state])
  const c = client ?? shown
  const cmd = c ? sessionCommand(c) : null
  // The closed-mode change is shown only once RADIUS sends VLANs: pasted earlier, `clear access-session` would
  // re-authenticate devices while EasyEAP still withholds VLANs, leaving them on the port's VLAN for hours.
  const live = applied.state === 'live' || early
  return (
    <EDialog open={!!client} onOpenChange={(o) => !o && onClose()} wide risk={done ? 'gold' : 'warn'}
      title={done ? (live ? `Paste the change on ${c?.name}` : `Applying the change for ${c?.name}`) : `Enforce 802.1X on ${c?.name}?`}
      description={done ? (live ? 'RADIUS now sends VLANs to this switch. The ports close once you paste the change.' : 'RADIUS starts sending VLANs to this switch within about 15 seconds. The change to paste appears here then.') : 'Once enforced, a port lets a device on only after EasyEAP accepts it.'}
      footer={done ? <Btn variant="primary" onClick={onClose}>Done</Btn> : (
        <>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="primary" disabled={!confirmed} busy={setMode.isPending} onClick={() => c && setMode.mutate({ id: c.id, mode: 'enforce', confirmed: true }, {
            onSuccess: (r) => { setDone(r.guide); setDoneAt(Date.now()) },
            onError: (e) => (errorField(e) === 'mab' ? setBlocked(errorMessage(e)) : toast('The switch wasn’t switched to enforce', errorMessage(e), 'crit')),
          })}><ShieldCheck aria-hidden />Enforce and show the change</Btn>
        </>
      )}>
      {done && c && live ? <WiredGuideBody guide={done} settings={settings} which="enforce" secretOf={c.name} clientId={c.id} /> : done && c ? (
        <div className="space-y-3" role="status" aria-live="polite">
          {applied.state === 'rejected' ? (
            <Callout tone="crit" title="RADIUS rejected the new configuration">
              Don’t paste anything on the switch yet: RADIUS keeps running its previous configuration, so it still withholds VLANs. {applied.error}
              {' '}System health shows the error.
            </Callout>
          ) : (
            <p className="flex items-center gap-2 text-[13.5px] ee-ink-2"><span className="motion-safe:animate-pulse size-2 rounded-full bg-[var(--ee-gold)]" aria-hidden />Waiting for RADIUS to apply the change…</p>
          )}
          {applied.state === 'slow' && (
            <Callout tone="warn" title="This is taking longer than usual" action={<Btn size="sm" onClick={() => setEarly(true)}>Show the change anyway</Btn>}>
              RADIUS hasn’t confirmed the change after 90 seconds. Check the RADIUS agent on System health. Pasted before RADIUS applies it, devices re-authenticate without their VLAN and stay on the port’s VLAN until their next re-authentication.
            </Callout>
          )}
        </div>
      ) : c ? (
        <div className="space-y-5">
          <section aria-label="What EasyEAP saw"><h3 className="ee-h3 mb-2">What EasyEAP saw from {c.name}</h3><ReadinessView client={c} /></section>
          {cmd && <section aria-label="What the switch sees" className="border-t border-[var(--ee-line)] pt-4"><h3 className="ee-h3 mb-2">What the switch sees</h3><SessionsCheckView client={c} cmd={cmd} /></section>}
          {!cmd && <Callout tone="neutral">{c.vendor === 'meraki'
            ? 'Meraki has no session list to paste here: in the Dashboard, check Switch ports for devices on these ports that EasyEAP hasn’t accepted.'
            : c.vendor === 'unifi' || c.vendor === 'other'
              ? 'UniFi and other switches don’t list sessions the same way: check the switch’s client list for devices on 802.1X ports that EasyEAP hasn’t accepted.'
              : 'This switch doesn’t list sessions in a form EasyEAP reads: check its 802.1X status for devices on these ports that EasyEAP hasn’t accepted.'}</Callout>}
          {blocked && <Callout tone="crit" title="MAC authentication hasn’t proved itself yet">{blocked}</Callout>}
          <label className="flex items-start gap-2.5 text-[13px]">
            <input type="checkbox" className="ee-check mt-0.5" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            <span>I’ve checked which devices would lose access, and enforcing {c.name} is what I want.</span>
          </label>
        </div>
      ) : null}
    </EDialog>
  )
}

export function MonitorDialog({ client, onClose, settings }: { client: RadiusClient | null; onClose: () => void; settings: RadiusSettings }) {
  const { tid } = useTenant()
  const setMode = useSetWiredMode(tid)
  const [done, setDone] = useState<WiredGuide | null>(null)
  const [shown, setShown] = useState<RadiusClient | null>(client)
  useEffect(() => {
    if (client) { setShown(client); return }
    const t = setTimeout(() => setDone(null), 200)
    return () => clearTimeout(t)
  }, [client])
  const c = client ?? shown
  return (
    <EDialog open={!!client} onOpenChange={(o) => !o && onClose()} wide={!!done} risk="gold"
      title={done ? `Paste the change on ${c?.name}` : `Move ${c?.name} back to monitor mode?`}
      description={done ? 'EasyEAP stopped sending VLANs to this switch.' : 'Ports open again: devices that fail 802.1X, or don’t try it, get on the network.'}
      footer={done ? <Btn variant="primary" onClick={onClose}>Done</Btn> : (
        <>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="primary" busy={setMode.isPending} onClick={() => c && setMode.mutate({ id: c.id, mode: 'monitor' }, {
            onSuccess: (r) => setDone(r.guide),
            onError: (e) => toast('The switch wasn’t moved back', errorMessage(e), 'crit'),
          })}><Undo2 aria-hidden />Move back and show the change</Btn>
        </>
      )}>
      {done && c ? <WiredGuideBody guide={done} settings={settings} which="monitor" secretOf={c.name} clientId={c.id} /> : (
        <p className="text-[13.5px] ee-ink-2">Use this while you fix something, for example a VLAN that doesn’t exist on the switch. EasyEAP keeps deciding and logging every request.</p>
      )}
    </EDialog>
  )
}

export function EditPortPlanDialog({ client, onClose }: { client: RadiusClient | null; onClose: () => void }) {
  const { tid } = useTenant()
  const update = useUpdateClient(tid)
  const id = useId()
  const [plan, setPlan] = useState<WiredProfile>(defaultWiredProfile)
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  useEffect(() => { if (client?.wired_profile) { setPlan({ ...defaultWiredProfile, ...client.wired_profile }); setTouched(false); setError(null) } }, [client])
  const submit = () => {
    if (!client) return
    setTouched(true)
    setError(null)
    if (Object.values(planProblems(client.vendor, plan)).some(Boolean)) return
    update.mutate({ id: client.id, body: { wired_profile: plan } }, {
      onSuccess: () => { toast('Port plan saved', 'Show configuration has the updated commands. Paste them on the switch.'); onClose() },
      onError: (e) => setError({ field: errorField(e) ?? '', message: errorMessage(e) }),
    })
  }
  return (
    <EDialog open={!!client} onOpenChange={(o) => !o && onClose()} wide title={`Edit the port plan for ${client?.name}`}
      description="Ports you remove keep their 802.1X configuration on the switch until you clear it there (default interface <port>)."
      footer={<>
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="primary" type="submit" form={`${id}-f`} busy={update.isPending}>Save port plan</Btn>
      </>}>
      <form id={`${id}-f`} noValidate onSubmit={(e) => { e.preventDefault(); submit() }} className="space-y-4">
        {client && <PortPlanForm vendor={client.vendor} value={plan} onChange={setPlan} touched={touched} serverError={error} mab="edit" />}
        {error && !PLAN_FIELDS.has(error.field.replace(/^wired_profile\./, '')) && <Callout tone="crit" title="The port plan wasn’t saved">{error.message}</Callout>}
      </form>
    </EDialog>
  )
}

// ── Windows wired kit ───────────────────────────────────────────────────────

export function WiredKitDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { tid } = useTenant()
  const q = useWiredKit(tid, open)
  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide title="Windows wired kit" description="Wired 802.1X on Windows needs administrator rights, so IT deploys it. It uses each user’s EasyEAP certificate and contains nothing secret.">
      {q.isLoading ? <LoadingBlock rows={4} label="Building the kit" /> : q.error || !q.data ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : (
        <div className="space-y-5">
          <div className="flex flex-wrap gap-2">
            {q.data.files.map((f) => (
              <Btn key={f.name} onClick={() => saveBlob(new Blob([f.content], { type: f.type }), f.name)}><Download aria-hidden />{f.name}</Btn>
            ))}
          </div>
          <ul className="list-disc space-y-1.5 pl-5 text-[13px] ee-ink-2 marker:text-[var(--ee-ink-3)]">{q.data.notes.map((n) => <li key={n} className="pl-1">{n}</li>)}</ul>
          <section aria-label="Group Policy">
            <p className="text-[13px] font-semibold mb-2">Or with Group Policy</p>
            <ol className="list-decimal space-y-1.5 pl-5 text-[13px] marker:text-[var(--ee-ink-3)]">{q.data.gpo_steps.map((s) => <li key={s} className="pl-1">{s}</li>)}</ol>
            <p className="ee-small ee-ink-3 mt-2">RADIUS server name: <span className="ee-mono">{q.data.server_name}</span></p>
          </section>
        </div>
      )}
    </EDialog>
  )
}

export function ServesChips({ c }: { c: RadiusClient }): ReactNode {
  return <span className="inline-flex flex-wrap gap-1">{c.networks.map((n) => <Chip key={n} tone="neutral">{n === 'wired' ? 'Wired' : 'Wi-Fi'}</Chip>)}</span>
}
