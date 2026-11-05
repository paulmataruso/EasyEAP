// Vendor configuration guides from GET /radius/guide/{vendor}. The API fills the tenant's real values; this view
// fills what it can't know (the one-time shared secret, an unset RADIUS address, controller-local IDs) in memory only.
import { Fragment, useId, useMemo, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Tabs } from 'radix-ui'
import { api } from '../../api/client'
import { qk } from '../../api/keys'
import {
  ADDRESS_PLACEHOLDER, LOCAL_PLACEHOLDERS, SECRET_PLACEHOLDER, fillText, remainingPlaceholders, useGuide, vendorLabels,
  type FillValues, type Guide, type RadiusSettings,
} from '../../api/radius'
import { useTenant } from '../../api/tenant'
import { CopyButton, ErrorState, Field, LoadingBlock } from '../../ui'

/** Render text with any remaining <placeholder> highlighted. */
function Marked({ text }: { text: string }) {
  const parts = text.split(/(<[a-z][a-z0-9-]*>)/g)
  return <>{parts.map((p, i) => (/^<[a-z][a-z0-9-]*>$/.test(p) ? <mark key={i}>{p}</mark> : <Fragment key={i}>{p}</Fragment>))}</>
}

const placeholderLabels: Record<string, string> = {
  [SECRET_PLACEHOLDER]: 'the shared secret you saved when you added the controller (EasyEAP never shows it again)',
  [ADDRESS_PLACEHOLDER]: 'the address your controllers use to reach EasyEAP RADIUS',
  [LOCAL_PLACEHOLDERS.wlanId]: 'the WLAN ID on the controller',
  [LOCAL_PLACEHOLDERS.policyProfile]: 'the policy profile your WLAN uses',
  [LOCAL_PLACEHOLDERS.defaultVlan]: 'the VLAN devices use when RADIUS assigns none',
}

/** Policy default VLAN (raw GET /policy, shared key) to pre-fill <default-vlan>. */
function useDefaultVlan(tid: string, enabled: boolean): string | undefined {
  const q = useQuery({
    queryKey: qk.policy(tid),
    queryFn: ({ signal }) => api.get<{ vlans: Array<{ id: string; vlan_id: number }>; settings: { default_vlan_ref: string | null } }>(`/api/tenants/${tid}/policy`, signal),
    enabled,
  })
  const ref = q.data?.settings.default_vlan_ref
  const v = ref ? q.data?.vlans.find((x) => x.id === ref) : undefined
  return v ? String(v.vlan_id) : undefined
}

/** Full text of a guide (steps + CLI) for copying, filled with the given values. */
export function guideText(g: Guide, fill: FillValues): string {
  const steps = g.steps.map((s, i) => `${i + 1}. ${fillText(s, fill)}`).join('\n')
  return g.cli ? fillText(g.cli, fill) : steps
}

/**
 * One vendor's guide body. `secret` is passed only on the one-time step right after a controller is created or its
 * secret rotated; `onCopied` lets that step count copying the filled configuration as copying the secret.
 */
export function GuideBody({ guide, settings, secret, onCopied, compact }: { guide: Guide; settings: RadiusSettings; secret?: string | null; onCopied?: () => void; compact?: boolean }) {
  const { tid, can } = useTenant()
  const id = useId()
  const defaultVlan = useDefaultVlan(tid, can('policy:read'))
  const [address, setAddress] = useState('')
  const [wlanId, setWlanId] = useState('')
  const [profile, setProfile] = useState('')
  const [vlan, setVlan] = useState<string | null>(null)
  const raw = [guide.cli ?? '', ...guide.steps].join('\n')
  const has = (p: string) => raw.includes(p)
  const fill: FillValues = { secret, address: settings.radius_address ? null : address.trim() || null, wlanId: wlanId.trim(), policyProfile: profile.trim(), defaultVlan: (vlan ?? defaultVlan ?? '').trim() }
  const cli = guide.cli ? fillText(guide.cli, fill) : null
  const steps = guide.steps.map((s) => fillText(s, fill))
  const left = remainingPlaceholders([cli ?? '', ...steps].join('\n'))
  const copyText = guideText(guide, fill)

  const inputs: ReactNode[] = []
  if (has(ADDRESS_PLACEHOLDER) || !settings.radius_address) {
    inputs.push(
      <Field key="addr" label="RADIUS address" htmlFor={`${id}-addr`} hint={settings.radius_address_problem ?? 'This EasyEAP server has no RADIUS address configured (EASYEAP_RADIUS_ADDRESS in the deploy .env). Enter the address your controllers reach it on.'}>
        <input id={`${id}-addr`} className="ee-input ee-mono" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.10" autoComplete="off" spellCheck={false} />
      </Field>,
    )
  }
  if (has(LOCAL_PLACEHOLDERS.wlanId)) inputs.push(
    <Field key="wlan" label="WLAN ID" htmlFor={`${id}-wlan`} optional>
      <input id={`${id}-wlan`} className="ee-input ee-num" inputMode="numeric" value={wlanId} onChange={(e) => setWlanId(e.target.value.replace(/[^0-9]/g, ''))} autoComplete="off" />
    </Field>,
  )
  if (has(LOCAL_PLACEHOLDERS.policyProfile)) inputs.push(
    <Field key="prof" label="Policy profile" htmlFor={`${id}-prof`} optional>
      <input id={`${id}-prof`} className="ee-input ee-mono" value={profile} onChange={(e) => setProfile(e.target.value.replace(/\s/g, ''))} autoComplete="off" spellCheck={false} />
    </Field>,
  )
  if (has(LOCAL_PLACEHOLDERS.defaultVlan)) inputs.push(
    <Field key="vlan" label="Default VLAN" htmlFor={`${id}-vlan`} optional hint={defaultVlan && vlan === null ? 'From this tenant’s access policy default.' : undefined}>
      <input id={`${id}-vlan`} className="ee-input ee-num" inputMode="numeric" value={vlan ?? defaultVlan ?? ''} onChange={(e) => setVlan(e.target.value.replace(/[^0-9]/g, ''))} autoComplete="off" />
    </Field>,
  )

  return (
    <div className="space-y-4">
      {inputs.length > 0 && (
        <div>
          <p className="ee-small ee-ink-2 mb-2.5">Values from your controller. They fill the configuration below in this browser only and aren’t saved.</p>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{inputs}</div>
        </div>
      )}
      {cli && (
        <div>
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-[13px] font-semibold">Configuration{guide.vendor === 'cisco-9800' ? ' (IOS-XE CLI)' : guide.vendor === 'cisco-aireos' ? ' (AireOS CLI)' : ''}</p>
            <CopyButton text={copyText} what={`${guide.title} configuration`} label="Copy configuration" onCopied={onCopied} />
          </div>
          <pre className="ee-code max-h-[420px] overflow-auto" tabIndex={0} aria-label={`${guide.title} configuration`}><Marked text={cli} /></pre>
        </div>
      )}
      <div>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <p className="text-[13px] font-semibold">{cli ? 'Where to find it in the web interface' : 'Steps'}</p>
          {!cli && <CopyButton text={copyText} what={`${guide.title} steps`} label="Copy steps" onCopied={onCopied} />}
        </div>
        <ol className="list-decimal space-y-1.5 pl-5 text-[13.5px] marker:text-[var(--ee-ink-3)] marker:tabular-nums">
          {steps.map((s, i) => <li key={i} className="pl-1"><Marked text={s} /></li>)}
        </ol>
      </div>
      {!compact && (
        <div>
          <p className="text-[13px] font-semibold mb-2">Before you test</p>
          <ul className="list-disc space-y-1.5 pl-5 text-[13px] ee-ink-2 marker:text-[var(--ee-ink-3)]">
            {guide.checks.map((c, i) => <li key={i} className="pl-1">{c}</li>)}
          </ul>
        </div>
      )}
      {left.length > 0 && (
        <div className="ee-small ee-ink-3">
          <p>Replace the highlighted values before you paste:</p>
          <ul className="mt-1 space-y-0.5">
            {left.map((p) => <li key={p}><mark className="ee-mono rounded-[3px] bg-[rgba(226,194,117,0.16)] px-1 text-[var(--ee-gold)]">{p}</mark> {placeholderLabels[p] ?? 'a value from your controller'}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}

/** Fetches and renders one vendor's guide. */
export function VendorGuide({ vendor, settings, secret, onCopied, compact }: { vendor: string; settings: RadiusSettings; secret?: string | null; onCopied?: () => void; compact?: boolean }) {
  const { tid } = useTenant()
  const q = useGuide(tid, vendor)
  if (q.isLoading) return <LoadingBlock rows={5} label={`Loading the ${vendorLabels[vendor] ?? vendor} guide`} />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} title="The configuration guide couldn’t be loaded" />
  if (!q.data) return null
  return <GuideBody guide={q.data} settings={settings} secret={secret} onCopied={onCopied} compact={compact} />
}

const GUIDE_TABS = ['cisco-9800', 'cisco-aireos', 'unifi', 'other'] as const

/** "Controller setup guides" section: one tab per vendor. */
export function ControllerGuides({ settings, vendor, onVendor, forName }: { settings: RadiusSettings; vendor: string; onVendor: (v: string) => void; forName?: string | null }) {
  const tabs = useMemo(() => GUIDE_TABS.map((v) => ({ v, label: v === 'cisco-9800' ? 'Catalyst 9800' : v === 'cisco-aireos' ? 'AireOS' : v === 'unifi' ? 'UniFi' : 'Other' })), [])
  return (
    <Tabs.Root value={vendor} onValueChange={onVendor}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <Tabs.List className="ee-seg" aria-label="Controller type">
          {tabs.map((t) => (
            <Tabs.Trigger key={t.v} value={t.v} className="ee-seg-item data-[state=active]:bg-[var(--ee-raised-solid)] data-[state=active]:text-[var(--ee-ink)] data-[state=active]:shadow-[inset_0_0_0_1px_var(--ee-line-2)]">
              {t.label}
            </Tabs.Trigger>
          ))}
        </Tabs.List>
        {forName && <p className="ee-small ee-ink-3">Showing the guide for {forName}</p>}
      </div>
      {tabs.map((t) => (
        <Tabs.Content key={t.v} value={t.v} className="outline-none">
          <VendorGuide vendor={t.v} settings={settings} />
        </Tabs.Content>
      ))}
    </Tabs.Root>
  )
}
