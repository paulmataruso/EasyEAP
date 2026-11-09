// Tenant setup wizard. Every step's state comes from the live API (PKI, directory, RADIUS, policy, tenant status),
// so the wizard can be left and re-entered at any point; only which step is open is local.
import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, BookUser, Check, EthernetPort, KeyRound, ListOrdered, Plus, Power, Router } from 'lucide-react'
import { cn } from '@/ui/lib'
import { api } from '../api/client'
import { qk } from '../api/keys'
import { usePki } from '../api/pki'
import { useRadius } from '../api/radius'
import { useTenant } from '../api/tenant'
import type { Tenant } from '../api/types'
import { ago, fmtDate, relative } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths, targetPath } from '../routes'
import { Btn, Callout, Chip, Empty, ErrorState, LoadingBlock, PageHeader, Panel, SectionHeader, Skeleton, errorMessage, toast } from '../ui'
import { AddControllerDialog } from './radius/Controllers'
import { AddSwitchDialog, ModeChip } from './radius/Switches'
import { RadiusSettingsForm, SettingsSummary } from './radius/Settings'
import { CeremonyForm } from './setup/Ceremony'
import { useDirectoryLite, useEnforcement, usePolicyLite } from './setup/data'

type StepId = 'ca' | 'directory' | 'radius' | 'policy' | 'activate'
type StepState = 'done' | 'todo' | 'attention' | 'unknown'

interface Step { id: StepId; title: string; state: StepState; summary: string; optional?: boolean }

export default function TenantSetup() {
  const { tid, tenant, can } = useTenant()
  const pki = usePki(tid, can('certificates:read'))
  const dir = useDirectoryLite(tid, can('directory:read'))
  const radius = useRadius(tid)
  const policy = usePolicyLite(tid, can('policy:read'))
  const enf = useEnforcement(tid)
  const [open, setOpen] = useState<StepId | null>(null)

  const loading = pki.isLoading || radius.isLoading || (can('directory:read') && dir.isLoading) || (can('policy:read') && policy.isLoading)

  const steps: Step[] = [
    pki.data
      ? { id: 'ca', title: 'Certificate authority', state: pki.data.initialized ? 'done' : 'todo', summary: pki.data.initialized ? (pki.data.authorities.find((a) => a.role === 'issuing')?.common_name ?? 'Initialized') : 'Not created' }
      : { id: 'ca', title: 'Certificate authority', state: tenant.health.pki_ready ? 'done' : 'todo', summary: tenant.health.pki_ready ? 'Initialized' : 'Not created' },
    (() => {
      const c = dir.data?.config
      if (!dir.data) return { id: 'directory' as const, title: 'Directory', state: 'unknown' as const, summary: 'Status unavailable', optional: true }
      if (!c) return { id: 'directory' as const, title: 'Directory', state: 'todo' as const, summary: 'Not connected', optional: true }
      if (c.last_sync_status === 'failed') return { id: 'directory' as const, title: 'Directory', state: 'attention' as const, summary: 'Sync failing', optional: true }
      if (c.last_sync_status === 'ok') return { id: 'directory' as const, title: 'Directory', state: 'done' as const, summary: `${c.domain} synced`, optional: true }
      return { id: 'directory' as const, title: 'Directory', state: 'todo' as const, summary: 'Waiting for first sync', optional: true }
    })(),
    (() => {
      const s = radius.data?.settings
      const all = radius.data?.clients ?? []
      const n = all.length
      const sw = all.filter((c) => c.networks.includes('wired') && !c.networks.includes('wireless')).length
      const counted = [n - sw && `${n - sw} controller${n - sw === 1 ? '' : 's'}`, sw && `${sw} switch${sw === 1 ? '' : 'es'}`].filter(Boolean).join(', ')
      const done = !!s?.server_certificate && n > 0
      return { id: 'radius' as const, title: 'RADIUS and controllers', state: done ? 'done' as const : 'todo' as const, summary: !s ? 'Not configured' : n === 0 ? 'No controllers yet' : counted }
    })(),
    (() => {
      if (!policy.data) return { id: 'policy' as const, title: 'Access policy', state: 'unknown' as const, summary: 'Status unavailable' }
      const vlans = policy.data.vlans.length
      const allows = policy.data.rules.filter((r) => r.action === 'allow' && r.enabled).length
      return { id: 'policy' as const, title: 'Access policy', state: vlans > 0 && allows > 0 ? 'done' as const : 'todo' as const, summary: `${vlans} VLAN${vlans === 1 ? '' : 's'}, ${allows} allow rule${allows === 1 ? '' : 's'}` }
    })(),
    { id: 'activate', title: 'Activate', state: tenant.status === 'active' ? 'done' : 'todo', summary: tenant.status === 'active' ? 'Active' : tenant.status === 'suspended' ? 'Suspended' : 'In setup' },
  ]
  // Re-entry opens the first required step that isn't done; optional steps (directory) stay one click away.
  const firstOpen = steps.find((s) => s.state !== 'done' && !s.optional)?.id ?? 'activate'
  const current = open ?? firstOpen
  const idx = steps.findIndex((s) => s.id === current)
  const next = () => setOpen(steps[Math.min(idx + 1, steps.length - 1)].id)

  // When the open step completes from live data (e.g. after the ceremony dialog closes), stay on it so its result shows.
  useEffect(() => { if (open === null && !loading) setOpen(firstOpen) }, [open, loading, firstOpen])

  const doneCount = steps.filter((s) => s.state === 'done').length
  return (
    <div>
      <PageHeader
        title={tenant.status === 'active' ? (doneCount === steps.length ? `${tenant.name} is set up` : `${tenant.name} is active`) : `Set up ${tenant.name}`}
        lede={tenant.status === 'active'
          ? 'Every step below reflects the tenant’s live configuration.'
          : 'Each step shows the tenant’s live configuration, so you can leave and come back. Nobody in this tenant can connect until it’s active and RADIUS can enforce it.'}
        actions={tenant.status === 'active' ? <Link to={paths.dashboard(tid)} className="ee-btn ee-btn-primary">Go to dashboard<ArrowRight aria-hidden /></Link> : undefined}
      />

      <nav aria-label="Setup steps" className="mb-6">
        <ol className="ee-steps">
          {steps.map((s, i) => (
            <li key={s.id}>
              <button type="button" className={cn('ee-step cursor-pointer hover:text-[var(--ee-ink)]', s.state === 'attention' && 'text-[var(--ee-warn-ink)]')}
                data-state={s.id === current ? 'current' : s.state === 'done' ? 'done' : undefined}
                aria-current={s.id === current ? 'step' : undefined} onClick={() => setOpen(s.id)}>
                {s.state === 'done' ? <Check className="size-3.5" aria-hidden /> : <span className="ee-num" aria-hidden>{i + 1}</span>}
                {s.title}
                <span className="sr-only">: {s.state === 'done' ? 'done' : s.state === 'attention' ? 'needs attention' : s.optional ? 'optional, not done' : 'not done'}</span>
              </button>
            </li>
          ))}
        </ol>
        <p className="ee-small ee-ink-3 mt-2.5">{loading ? 'Checking the tenant’s configuration…' : `${doneCount} of ${steps.length} steps done`}</p>
      </nav>

      {loading ? <LoadingBlock rows={6} label="Loading setup state" /> : (
        <Panel className="max-w-[1100px] p-5 sm:p-6" risk={steps[idx]?.state === 'done' ? 'valid' : 'gold'} aria-labelledby="setup-step-h">
          {current === 'ca' && <CaStep step={steps[0]} labMode={pki.data?.lab_mode ?? false} onNext={next} />}
          {current === 'directory' && <DirectoryStep step={steps[1]} onNext={next} />}
          {current === 'radius' && <RadiusStep step={steps[2]} onNext={next} />}
          {current === 'policy' && <PolicyStep step={steps[3]} onNext={next} />}
          {current === 'activate' && <ActivateStep steps={steps} missing={enf.data?.enforcement.missing ?? []} enfError={enf.error} />}
        </Panel>
      )}
    </div>
  )
}

function StepHeader({ step, n, children }: { step: Step; n: number; children?: ReactNode }) {
  return (
    <SectionHeader id="setup-step-h" title={<>{n}. {step.title}</>}
      meta={step.state === 'done' ? undefined : step.optional ? 'Optional' : undefined}
      actions={<>{children}{step.state === 'done' ? <Chip tone="valid" icon={<Check aria-hidden />}>Done</Chip> : step.state === 'attention' ? <Chip tone="warn">Needs attention</Chip> : <Chip tone="neutral">Not done</Chip>}</>} />
  )
}

function NextBtn({ onNext, label = 'Next step' }: { onNext: () => void; label?: string }) {
  return <Btn onClick={onNext}>{label}<ArrowRight aria-hidden /></Btn>
}

function CaStep({ step, labMode, onNext }: { step: Step; labMode: boolean; onNext: () => void }) {
  const { tid, tenant } = useTenant()
  const pki = usePki(tid)
  const now = useNow(60_000)
  if (step.state !== 'done') {
    return (
      <div>
        <StepHeader step={step} n={1} />
        <p className="ee-small ee-ink-2 mb-5 max-w-[75ch]">Every device certificate and the RADIUS server certificate come from {tenant.name}’s own certificate authority, created once here.</p>
        <CeremonyForm labMode={labMode} />
      </div>
    )
  }
  const cas = pki.data?.authorities ?? []
  return (
    <div className="space-y-4">
      <StepHeader step={step} n={1} />
      <ul className="space-y-2 text-[13.5px]">
        {cas.map((ca) => (
          <li key={ca.id} className="flex flex-wrap items-baseline gap-x-3">
            <KeyRound className="size-4 self-center ee-ink-3" aria-hidden />
            <span className="font-semibold">{ca.common_name}</span>
            <span className="ee-ink-3">{ca.role === 'root' ? (ca.offline ? 'Root, offline' : 'Root, online (lab)') : 'Issuing'} · valid until {fmtDate(ca.not_after)} ({relative(ca.not_after, now)})</span>
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <NextBtn onNext={onNext} />
        <Link to={paths.pki(tid)} className="ee-btn ee-btn-ghost">Certificate authority details</Link>
      </div>
    </div>
  )
}

function DirectoryStep({ step, onNext }: { step: Step; onNext: () => void }) {
  const { tid, can } = useTenant()
  const dir = useDirectoryLite(tid, can('directory:read'))
  const now = useNow()
  const c = dir.data?.config
  return (
    <div className="space-y-4">
      <StepHeader step={step} n={2} />
      <p className="ee-small ee-ink-2 max-w-[75ch]">
        Connect Active Directory over LDAPS so access rules can use AD groups and disabled accounts lose access automatically. Without a directory, only local users you add in EasyEAP can enroll.
      </p>
      {dir.error ? <ErrorState error={dir.error} onRetry={() => dir.refetch()} />
        : !c ? <Callout tone="neutral" title="No directory connected">The directory settings have their own page. Save and sync there, then come back here; setup continues where you left off.</Callout>
          : c.last_sync_status === 'failed' ? <Callout tone="crit" title="Directory sync is failing">{c.last_sync_error ?? 'The last sync failed without detail.'} Fix it on the Directory page, then come back here.</Callout>
            : c.last_sync_status === 'ok' ? (
              <Callout tone="valid" title={`Connected to ${c.domain}`}>
                Last synced {ago(c.last_sync_at, now)}{typeof c.last_sync_stats?.users === 'number' ? `: ${c.last_sync_stats.users} users` : ''}{dir.data ? `, ${dir.data.group_count} groups` : ''}.
              </Callout>
            ) : <Callout tone="neutral" title={`Saved for ${c.domain}`}>The first sync hasn’t finished yet. It runs in the background within a few minutes.</Callout>}
      <div className="flex flex-wrap gap-2">
        {can('directory:read') && (
          <Link to={paths.directory(tid)} className={cn('ee-btn', !c && 'ee-btn-primary')}>
            <BookUser aria-hidden />{c ? 'Open directory settings' : 'Connect Active Directory'}
          </Link>
        )}
        <NextBtn onNext={onNext} label={step.state === 'done' ? 'Next step' : 'Skip for now'} />
      </div>
    </div>
  )
}

function RadiusStep({ step, onNext }: { step: Step; onNext: () => void }) {
  const { tid, tenant, can } = useTenant()
  const q = useRadius(tid)
  const [adding, setAdding] = useState(false)
  const [addingSwitch, setAddingSwitch] = useState(false)
  const now = useNow()
  if (q.error || !q.data) return <><StepHeader step={step} n={3} /><ErrorState error={q.error} onRetry={() => q.refetch()} /></>
  const s = q.data.settings
  const clients = q.data.clients.filter((c) => c.networks.includes('wireless'))
  const switches = q.data.clients.filter((c) => c.networks.includes('wired'))
  return (
    <div className="space-y-6">
      <StepHeader step={step} n={3} />
      <section aria-labelledby="setup-rad-a" className="space-y-3">
        <h3 id="setup-rad-a" className="ee-h3 flex items-center gap-2">{s?.server_certificate ? <Check className="size-4 text-[var(--ee-valid)]" aria-hidden /> : <span className="ee-num ee-ink-3">a</span>}RADIUS server settings</h3>
        {!s ? (
          can('radius:write') ? <RadiusSettingsForm current={null} /> : <Callout tone="neutral">A Wi-Fi Administrator or Tenant Administrator saves these settings.</Callout>
        ) : (
          <div className="max-w-[640px]">
            <SettingsSummary s={s} />
            <p className="ee-small ee-ink-3 mt-2">Server certificate {s.server_certificate ? `issued, valid until ${fmtDate(s.server_certificate.not_after)}` : 'not issued'}. <Link className="underline" to={paths.radius(tid)}>Change on the RADIUS page</Link></p>
          </div>
        )}
      </section>
      <section aria-labelledby="setup-rad-b" className="space-y-3 border-t border-[var(--ee-line)] pt-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 id="setup-rad-b" className="ee-h3 flex items-center gap-2">{clients.length ? <Check className="size-4 text-[var(--ee-valid)]" aria-hidden /> : <span className="ee-num ee-ink-3">b</span>}Wireless controllers</h3>
          {s && can('radius:write') && <Btn size="sm" variant={clients.length ? 'default' : 'primary'} onClick={() => setAdding(true)}><Plus aria-hidden />{clients.length ? 'Add another controller' : 'Add controller'}</Btn>}
        </div>
        {clients.length === 0 ? (
          <Empty icon={<Router />} title={s ? 'No controllers yet' : 'Save the RADIUS settings first'}>
            {!s ? `Controllers are registered against ${tenant.name}’s RADIUS server.` : switches.length ? 'Not needed if this tenant uses only wired 802.1X.' : `RADIUS answers only registered controllers. EasyEAP generates a shared secret for each and shows it once, with the controller’s configuration filled in.`}
          </Empty>
        ) : (
          <>
            <ul className="divide-y divide-[var(--ee-line)] border-y border-[var(--ee-line)] text-[13.5px]">
              {clients.map((c) => (
                <li key={c.id} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2.5">
                  <span><span className="font-semibold">{c.name}</span> <span className="ee-mono text-[12.5px] ee-ink-2">{c.address}</span></span>
                  <span className="ee-small ee-ink-3">{c.last_request_at ? `Last request ${ago(c.last_request_at, now)}` : 'No requests yet'}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
      <section aria-labelledby="setup-rad-c" className="space-y-3 border-t border-[var(--ee-line)] pt-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 id="setup-rad-c" className="ee-h3 flex items-center gap-2">{switches.length ? <Check className="size-4 text-[var(--ee-valid)]" aria-hidden /> : <span className="ee-num ee-ink-3">c</span>}Switches <span className="ee-small ee-ink-3 font-normal">optional</span></h3>
          {s && can('radius:write') && <Btn size="sm" onClick={() => setAddingSwitch(true)}><EthernetPort aria-hidden />{switches.length ? 'Add another switch' : 'Add switch'}</Btn>}
        </div>
        {switches.length === 0 ? (
          <p className="ee-small ee-ink-3 max-w-[70ch]">For wired 802.1X on switch ports, using the same device certificates. A new switch starts in monitor mode: devices are checked and logged, but no port is closed until you enforce. You can add switches later from the RADIUS page.</p>
        ) : (
          <ul className="divide-y divide-[var(--ee-line)] border-y border-[var(--ee-line)] text-[13.5px]">
            {switches.map((c) => (
              <li key={c.id} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2.5">
                <span className="inline-flex flex-wrap items-baseline gap-2"><Link className="font-semibold underline-offset-2 hover:underline" to={paths.radius(tid, { client: c.id })}>{c.name}</Link> <span className="ee-mono text-[12.5px] ee-ink-2">{c.address}</span><ModeChip c={c} /></span>
                <span className="ee-small ee-ink-3">{c.last_request_at ? `Last request ${ago(c.last_request_at, now)}` : 'No requests yet'}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
      <div className="flex flex-wrap gap-2 border-t border-[var(--ee-line)] pt-5">
        <NextBtn onNext={onNext} />
        <Link to={paths.radius(tid)} className="ee-btn ee-btn-ghost">RADIUS page</Link>
      </div>
      {s && <AddControllerDialog open={adding} onOpenChange={setAdding} settings={s} clients={q.data.clients} />}
      {s && <AddSwitchDialog open={addingSwitch} onOpenChange={setAddingSwitch} settings={s} clients={q.data.clients} />}
    </div>
  )
}

function PolicyStep({ step, onNext }: { step: Step; onNext: () => void }) {
  const { tid, can } = useTenant()
  const q = usePolicyLite(tid, can('policy:read'))
  const d = q.data
  const allows = d?.rules.filter((r) => r.action === 'allow' && r.enabled) ?? []
  return (
    <div className="space-y-4">
      <StepHeader step={step} n={4} />
      <p className="ee-small ee-ink-2 max-w-[75ch]">Access rules decide who may connect and which VLAN they land on. Create at least one VLAN and one Allow rule; anyone no rule matches gets the default action.</p>
      {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : !d ? <Skeleton className="w-1/2" /> : (
        <dl className="grid max-w-[640px] grid-cols-3 gap-4">
          <div className="flex flex-col"><dt className="ee-label">VLANs</dt><dd className="mt-auto pt-0.5 ee-num text-[20px] font-semibold">{d.vlans.length}</dd></div>
          <div className="flex flex-col"><dt className="ee-label">Allow rules (enabled)</dt><dd className="mt-auto pt-0.5 ee-num text-[20px] font-semibold">{allows.length}</dd></div>
          <div className="flex flex-col"><dt className="ee-label">Default action</dt><dd className="mt-auto pt-0.5 text-[15px] font-semibold">{d.settings.default_action === 'deny' ? 'Deny' : 'Allow'}</dd></div>
        </dl>
      )}
      {d && step.state !== 'done' && (
        <Callout tone="neutral">{d.vlans.length === 0 ? 'No VLANs yet. ' : ''}{allows.length === 0 ? `No enabled Allow rule yet, so everyone gets the default action (${d.settings.default_action}).` : ''}</Callout>
      )}
      <div className="flex flex-wrap gap-2">
        {can('policy:read') && <Link to={paths.policy(tid)} className={cn('ee-btn', step.state !== 'done' && 'ee-btn-primary')}><ListOrdered aria-hidden />Open access policy</Link>}
        <NextBtn onNext={onNext} />
      </div>
    </div>
  )
}

function ActivateStep({ steps, missing, enfError }: { steps: Step[]; missing: Array<{ code: string; message: string; target: string }>; enfError: unknown }) {
  const { tid, tenant, can } = useTenant()
  const qc = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const activate = useMutation({
    mutationFn: () => api.patch<Tenant>(`/api/tenants/${tid}`, { status: 'active' }),
    onSuccess: () => Promise.all([qc.invalidateQueries({ queryKey: qk.tenantScope(tid) }), qc.invalidateQueries({ queryKey: qk.tenants() }), qc.invalidateQueries({ queryKey: qk.overview() })]),
  })
  const step = steps[4]
  const open = steps.filter((s) => s.id !== 'activate' && s.state !== 'done')
  const gaps = missing.filter((m) => m.code !== 'tenant_status')

  if (tenant.status === 'active') {
    return (
      <div className="space-y-4">
        <StepHeader step={step} n={5} />
        <Callout tone="valid" title={`${tenant.name} is active`}>
          {gaps.length === 0 ? 'RADIUS serves this tenant. Enrolled devices that the access policy allows can connect.' : `RADIUS serves this tenant, but it isn’t enforceable yet: ${gaps.map((g) => g.message.toLowerCase()).join('; ')}.`}
        </Callout>
        {steps[3].state === 'todo' && (
          <Callout tone="warn" title="No access rule allows anyone yet">Every device gets the default action until the access policy has a VLAN and an enabled Allow rule. <Link className="underline" to={paths.policy(tid)}>Access policy</Link></Callout>
        )}
        <Link to={paths.dashboard(tid)} className="ee-btn ee-btn-primary">Go to dashboard<ArrowRight aria-hidden /></Link>
      </div>
    )
  }
  return (
    <div className="space-y-4">
      <StepHeader step={step} n={5} />
      <p className="ee-small ee-ink-2 max-w-[75ch]">
        Activating hands the tenant to RADIUS. From then on devices with a valid certificate that the access policy allows can connect through its controllers.
        {tenant.status === 'suspended' && ' This tenant is suspended; activating restores service.'}
      </p>
      {open.length > 0 && (
        <Callout tone="warn" title={`${open.length} step${open.length === 1 ? '' : 's'} not done`}>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            {open.map((s) => <li key={s.id}>{s.title}: {s.summary}{s.optional ? ' (optional)' : ''}</li>)}
          </ul>
        </Callout>
      )}
      {enfError ? <ErrorState error={enfError} title="Enforcement status couldn’t be loaded" /> : gaps.length > 0 && (
        <div>
          <p className="text-[13px] font-semibold mb-1.5">RADIUS can’t enforce this tenant until:</p>
          <ul className="space-y-1 text-[13.5px]">
            {gaps.map((g) => <li key={g.code}><Link className="underline underline-offset-3" to={targetPath(tid, g.target)}>{g.message}</Link></li>)}
          </ul>
        </div>
      )}
      {error && <Callout tone="crit" title="The tenant wasn’t activated">{error}</Callout>}
      {can('tenant:write') ? (
        <Btn variant="primary" size="lg" busy={activate.isPending} onClick={() => { setError(null); activate.mutate(undefined, {
          onSuccess: () => toast(`${tenant.name} is active`, 'RADIUS starts serving it with its next configuration refresh, usually within seconds.'),
          onError: (e) => setError(errorMessage(e)),
        }) }}><Power aria-hidden />Activate {tenant.name}</Btn>
      ) : <p className="ee-small ee-ink-3">Activating a tenant needs the Tenant Administrator role.</p>}
    </div>
  )
}
