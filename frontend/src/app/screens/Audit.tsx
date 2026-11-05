// Audit log (tenant: /t/:tid/audit, platform: /audit). Append-only and hash-chained in the backend; each entry
// expands to its recorded detail. "Verify integrity" re-walks the whole chain server-side and reports the result
// exactly as computed.
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useMutation } from '@tanstack/react-query'
import { ChevronDown, Search, ShieldCheck, ShieldX } from 'lucide-react'
import { cn } from '@/ui/lib'
import { useAudit, verifyAudit, type AuditEvent, type VerifyResult } from '../api/governance'
import { useSession } from '../api/session'
import { useOptionalTenant, useTenantList } from '../api/tenant'
import { ago, fmtDateTime, plural } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Btn, Callout, Chip, Empty, ErrorState, LoadingBlock, PageHeader, Panel, errorMessage } from '../ui'

import { actionLabel, actionTone, actorTypeLabel, AuditDetail } from './governance/auditFormat'

function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value)
  useEffect(() => { const id = setTimeout(() => setV(value), ms); return () => clearTimeout(id) }, [value, ms])
  return v
}

// What the target is, in words (target_type is a backend id).
const targetTypeLabel: Record<string, string> = {
  admin: 'Administrator', backup: 'Backup', ca: 'Certificate authority', certificate: 'Certificate', directory: 'Directory',
  enrollment: 'Enrollment link', group: 'Group', identity: 'User', policy: 'Access policy', radius: 'RADIUS', radius_client: 'RADIUS client',
  rule: 'Access rule', template: 'Certificate template', tenant: 'Tenant', vlan: 'VLAN',
}
const typeText = (t: string | null) => (t ? targetTypeLabel[t] ?? t : null)

function targetHref(a: AuditEvent): string | null {
  const tid = a.tenant_id
  if (!tid) return null
  switch (a.target_type) {
    case 'identity': return a.target_id ? paths.user(tid, a.target_id) : paths.users(tid)
    case 'certificate': return a.target_id ? paths.certificate(tid, a.target_id) : paths.certificates(tid)
    case 'rule': case 'vlan': case 'policy': return paths.policy(tid)
    case 'directory': case 'group': return paths.directory(tid)
    case 'radius': case 'radius_client': return paths.radius(tid)
    case 'ca': case 'template': return paths.pki(tid)
    case 'enrollment': return paths.users(tid)
    case 'tenant': return paths.settings(tid)
    default: return null
  }
}

export default function Audit({ scope }: { scope: 'tenant' | 'platform' }) {
  const tctx = useOptionalTenant()
  const { me } = useSession()
  const tid = scope === 'tenant' ? tctx?.tid ?? null : null
  const canRead = scope === 'tenant' ? !!tctx?.can('audit:read') : me?.platform_role === 'platform_owner' || me?.platform_role === 'platform_auditor'
  // Anyone who can read a tenant's log can verify it (the server checks the whole chain and discloses only this tenant's share).
  const canVerify = scope === 'tenant' ? canRead : me?.platform_role === 'platform_owner' || me?.platform_role === 'platform_auditor'
  const [query, setQuery] = useState('')
  const q = useDebounced(query.trim())
  const audit = useAudit(scope, tid, q, canRead)
  const tenants = useTenantList()
  const tenantName = useMemo(() => new Map((tenants.data ?? []).map((t) => [t.id, t.name])), [tenants.data])
  const [result, setResult] = useState<(VerifyResult & { at: string }) | null>(null)
  const verify = useMutation({ mutationFn: () => verifyAudit(tid), onSuccess: (r) => setResult({ ...r, at: new Date().toISOString() }) })
  const now = useNow()
  const title = scope === 'tenant' ? 'Audit log' : 'Platform audit'

  if (!canRead) {
    return (
      <div>
        <PageHeader title={title} />
        <Empty title="You don’t have access to the audit log">
          {scope === 'platform' ? 'The platform audit covers every tenant and is available to the Super Administrator and MSP Auditors.' : 'Your role in this tenant doesn’t include the audit log. Ask a Tenant Administrator or the MSP owner for access.'}
        </Empty>
      </div>
    )
  }

  const items = audit.data?.pages.flatMap((p) => p.items) ?? []

  return (
    <div>
      <PageHeader
        title={title}
        lede={scope === 'tenant'
          ? 'Every change made in this tenant, newest first. Entries are append-only and hash-chained; nobody can edit or delete them from EasyEAP.'
          : 'Every change made in EasyEAP across all tenants and MSP settings, newest first. Entries are append-only and hash-chained.'}
        actions={canVerify ? <Btn onClick={() => { setResult(null); verify.mutate() }} busy={verify.isPending}><ShieldCheck aria-hidden />Verify integrity</Btn> : undefined}
      />

      {verify.error && <Callout tone="crit" className="mb-6" title="Verification couldn’t run">{errorMessage(verify.error)}</Callout>}
      {result && (result.ok ? (
        <Callout tone="valid" className="mb-6" icon={<ShieldCheck aria-hidden />} title="The audit chain is intact">
          All {result.checked.toLocaleString('en-GB')} entries were checked at {fmtDateTime(result.at)}. Each one’s hash matches its content and the entry before it, so none has been altered or removed. The check covers the whole platform chain, not only this {scope === 'tenant' ? 'tenant' : 'view'}.
        </Callout>
      ) : scope === 'tenant' && !result.break_in_this_tenant ? (
        <Callout tone="crit" className="mb-6" icon={<ShieldX aria-hidden />} title="The platform audit chain is broken outside this tenant">
          This tenant’s {plural(result.tenant_entries ?? 0, 'entry', 'entries')} are not where the break is, but entries recorded after it can’t be trusted as recorded. Tell the MSP: the Super Administrator can see where the chain breaks in the platform audit.
        </Callout>
      ) : (
        <Callout tone="crit" className="mb-6" icon={<ShieldX aria-hidden />} title={`The chain is broken at entry ${result.first_bad_id}`}>
          {plural(result.checked, 'entry', 'entries')} verified before it. Entry {result.first_bad_id}, or one before it, was changed or deleted outside EasyEAP, so entries from there on can’t be trusted as recorded. Preserve the database as it is and investigate who has direct database access.
        </Callout>
      ))}

      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--ee-line)] px-4 py-3">
          <div className="ee-input flex max-w-[420px] flex-1 basis-[240px] items-center gap-2 px-2.5 focus-within:border-[var(--ee-gold)]">
            <Search className="size-4 shrink-0 ee-ink-3" aria-hidden />
            <input aria-label="Search the audit log" className="h-full min-w-0 flex-1 bg-transparent outline-none placeholder:text-[var(--ee-ink-3)]"
              placeholder="Search action, actor or target" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <span className="ee-small ee-ink-3" aria-live="polite">{audit.isFetching && !audit.isFetchingNextPage ? 'Loading…' : `${plural(items.length, 'entry', 'entries')} shown${audit.hasNextPage ? ', more available' : ''}`}</span>
        </div>

        {audit.isLoading ? <div className="px-4 py-4"><LoadingBlock rows={8} label="Loading audit log" /></div>
          : audit.error ? <div className="p-4"><ErrorState error={audit.error} onRetry={() => audit.refetch()} /></div>
          : items.length === 0 ? <div className="p-4"><Empty title={q ? 'No entries match' : 'Nothing recorded yet'}>{q ? `Nothing in the log matches “${q}”. Search looks at the action name (such as policy.published), the actor and the target.` : 'Changes made in EasyEAP appear here as they happen.'}</Empty></div>
          : (
            <>
              <div className={cn('hidden gap-x-4 border-b border-[var(--ee-line-2)] px-4 py-2.5 text-[12px] font-medium ee-ink-3 md:grid', scope === 'platform' ? 'md:grid-cols-[180px_minmax(0,1fr)_minmax(0,1.3fr)_minmax(0,1.2fr)_minmax(0,0.8fr)_20px]' : 'md:grid-cols-[180px_minmax(0,1fr)_minmax(0,1.3fr)_minmax(0,1.2fr)_20px]')} aria-hidden>
                <span>Time</span><span>Actor</span><span>Action</span><span>Target</span>{scope === 'platform' && <span>Tenant</span>}<span />
              </div>
              <ul className="ee-divide list-none p-0" aria-label="Audit entries, newest first">
                {items.map((a) => <AuditRow key={a.id} a={a} now={now} scope={scope} tenantName={a.tenant_id ? tenantName.get(a.tenant_id) ?? 'Deleted tenant' : null} />)}
              </ul>
              {audit.hasNextPage && (
                <div className="border-t border-[var(--ee-line)] px-4 py-3">
                  <Btn onClick={() => audit.fetchNextPage()} busy={audit.isFetchingNextPage}>Load older entries</Btn>
                </div>
              )}
            </>
          )}
      </Panel>
    </div>
  )
}

function AuditRow({ a, now, scope, tenantName }: { a: AuditEvent; now: Date; scope: 'tenant' | 'platform'; tenantName: string | null }) {
  const [open, setOpen] = useState(false)
  const tone = actionTone(a.action, a.detail)
  const href = targetHref(a)
  const id = `audit-${a.id}`
  const hasDetail = a.detail && Object.keys(a.detail).length > 0
  return (
    <li>
      <button type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen((v) => !v)}
        className={cn('grid w-full gap-x-4 gap-y-1 px-4 py-3 text-left hover:bg-[var(--ee-hover)]',
          'grid-cols-[minmax(0,1fr)_20px]', scope === 'platform' ? 'md:grid-cols-[180px_minmax(0,1fr)_minmax(0,1.3fr)_minmax(0,1.2fr)_minmax(0,0.8fr)_20px]' : 'md:grid-cols-[180px_minmax(0,1fr)_minmax(0,1.3fr)_minmax(0,1.2fr)_20px]')}>
        <span className="col-start-1 md:col-start-auto">
          <span className="block text-[13px] ee-num">{fmtDateTime(a.at)}</span>
          <span className="block text-[12px] ee-ink-3">{ago(a.at, now)}</span>
        </span>
        <span className="col-start-1 min-w-0 md:col-start-auto">
          <span className="block truncate text-[13px]">{a.actor || '—'}</span>
          {a.actor_type !== 'admin' && <span className="block text-[12px] ee-ink-3">{actorTypeLabel[a.actor_type] ?? a.actor_type}</span>}
        </span>
        <span className="col-start-1 min-w-0 md:col-start-auto">
          {tone ? <Chip tone={tone}>{actionLabel(a.action, a.detail)}</Chip> : <span className="text-[13px] font-medium">{actionLabel(a.action, a.detail)}</span>}
          <span className="block ee-mono text-[12px] ee-ink-3 mt-0.5">{a.action}</span>
        </span>
        <span className="col-start-1 min-w-0 text-[13px] ee-ink-2 md:col-start-auto"><span className="block break-words">{a.target || (typeText(a.target_type) ?? <span className="ee-ink-3">—</span>)}</span></span>
        {scope === 'platform' && <span className="col-start-1 min-w-0 truncate text-[13px] ee-ink-2 md:col-start-auto">{tenantName ?? <span className="ee-ink-3">MSP</span>}</span>}
        <ChevronDown className={cn('col-start-2 row-start-1 mt-0.5 size-4 ee-ink-3 transition-transform md:col-start-auto md:row-start-auto', open && 'rotate-180')} aria-hidden />
      </button>
      {open && (
        <div id={id} className="space-y-3 border-t border-[var(--ee-line)] bg-[rgba(6,9,17,0.3)] px-4 py-4 md:pl-[212px]">
          {hasDetail ? <AuditDetail action={a.action} detail={a.detail} /> : <p className="ee-small ee-ink-3">No further detail was recorded for this entry.</p>}
          <p className="ee-small ee-ink-3 flex flex-wrap gap-x-4 gap-y-1">
            <span>Entry {a.id}</span>
            <span>{actorTypeLabel[a.actor_type] ?? a.actor_type}{a.ip ? ` from ${a.ip}` : ''}</span>
            {a.target_type && <span>Target: {typeText(a.target_type)}</span>}
            {href && <Link to={href} className="underline">Open {a.target_type === 'identity' ? 'user' : a.target_type === 'certificate' ? 'certificate' : 'related page'}</Link>}
          </p>
        </div>
      )}
    </li>
  )
}
