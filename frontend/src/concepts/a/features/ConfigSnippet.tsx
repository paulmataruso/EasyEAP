import { Fragment, useMemo, useState } from 'react'
import { Tabs } from 'radix-ui'
import type { RadiusClient } from '@/domain/types'
import { vendorLabels } from '@/domain/explain'
import { useTenantData, useTenants } from '@/prototype/store'
import { TextField } from '../ui/fields'
import { CopyButton } from '../ui/primitives'
import { ADDRESS_TOKEN, buildSnippet, SECRET_TOKEN, type SnippetVendor } from '../lib/snippets'

const VENDORS: Array<{ id: SnippetVendor; label: string }> = [
  { id: 'cisco-9800', label: 'Catalyst 9800 CLI' },
  { id: 'cisco-aireos', label: 'AireOS CLI' },
  { id: 'unifi', label: 'UniFi steps' },
]

function highlight(text: string) {
  const parts = text.split(/(<[a-z-]+>)/g)
  return parts.map((p, i) =>
    /^<[a-z-]+>$/.test(p) ? (
      <span key={i} className="a-code-token">
        {p}
      </span>
    ) : (
      <Fragment key={i}>{p}</Fragment>
    ),
  )
}

function CodeLines({ text }: { text: string }) {
  return (
    <pre className="a-code" tabIndex={0} aria-label="Configuration snippet">
      {text.split('\n').map((line, i) => (
        <div key={i} className={line.startsWith('!') || line.startsWith('#') ? 'a-code-comment' : undefined}>
          {highlight(line) }
        </div>
      ))}
    </pre>
  )
}

/** Copy-ready controller configuration for the selected vendor. Secrets are never re-displayed. */
export function ConfigSnippet({ controller, compact = false }: { controller: RadiusClient | null; compact?: boolean }) {
  const d = useTenantData()
  const { current } = useTenants()
  const initialVendor: SnippetVendor = controller && controller.vendor !== 'other' ? controller.vendor : 'cisco-9800'
  const [vendor, setVendor] = useState<SnippetVendor>(initialVendor)
  const [address, setAddress] = useState('')
  const [lastController, setLastController] = useState(controller?.id)
  if (controller?.id !== lastController) {
    setLastController(controller?.id)
    setVendor(initialVendor)
  }
  const ssid = useMemo(() => {
    const counts = new Map<string, number>()
    for (const e of d.authEvents) if (e.ssid && (!controller || e.nasClientId === controller.id)) counts.set(e.ssid, (counts.get(e.ssid) ?? 0) + 1)
    return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? `${current.name.split(' ')[0]}-Secure`
  }, [d.authEvents, controller, current.name])
  if (!d.radiusSettings) return null
  const snippet = buildSnippet({ vendor, settings: d.radiusSettings, controller, serverAddress: address, ssid, tenantName: current.name })
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <TextField
          label="EasyEAP RADIUS address"
          value={address}
          onChange={setAddress}
          placeholder="IP the controller sends RADIUS to"
          mono
          className="w-full max-w-[300px]"
          hint={address ? undefined : `Until you enter it, the snippet shows ${ADDRESS_TOKEN}.`}
        />
        <CopyButton text={snippet.text} label="Copy configuration" variant="primary" size="md" />
      </div>
      <Tabs.Root value={vendor} onValueChange={(v) => setVendor(v as SnippetVendor)}>
        <Tabs.List aria-label="Controller vendor" className="a-segment mb-3 max-w-full overflow-x-auto">
          {VENDORS.map((v) => (
            <Tabs.Trigger key={v.id} value={v.id} className="a-segment-item data-[state=active]:bg-white/10 data-[state=active]:text-[var(--a-text)]">
              {v.label}
            </Tabs.Trigger>
          ))}
        </Tabs.List>
        {VENDORS.map((v) => (
          <Tabs.Content key={v.id} value={v.id} className="outline-none">
            {snippet.kind === 'steps' && snippet.steps ? (
              <ol className="flex flex-col gap-2.5">
                {snippet.steps.map((s, i) => (
                  <li key={s.title} className="flex gap-3 rounded-[10px] border border-white/[0.08] bg-black/20 p-3">
                    <span className="a-step-mark shrink-0">{i + 1}</span>
                    <div className="min-w-0 text-[13px]">
                      <p className="font-semibold text-[var(--a-text)]">{s.title}</p>
                      <p className="mt-0.5 text-[var(--a-text-2)]">{highlight(s.detail)}</p>
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <CodeLines text={snippet.text} />
            )}
          </Tabs.Content>
        ))}
      </Tabs.Root>
      <p className="text-[12px] text-[var(--a-text-3)]">
        Replace <span className="a-mono text-[var(--a-warn-text)]">{SECRET_TOKEN}</span> with the secret you stored when {controller ? `${controller.name} was added or last rotated` : 'you added the controller'}. EasyEAP never shows a secret twice.
        {!compact && controller && ` Snippet for ${vendorLabels[controller.vendor]}, SSID ${ssid}.`}
      </p>
    </div>
  )
}
