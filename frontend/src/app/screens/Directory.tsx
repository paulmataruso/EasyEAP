// Directory: the Active Directory connection (LDAPS with a read-only service account), connection test, sync status
// and the groups access rules are built from. This is where "Fix directory connection" lands, so a failing sync
// leads the page with what failed, what it affects and how to fix it.
import { useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { BookUser, ChevronRight, CircleCheck, CircleX, FlaskConical, Plus, RefreshCw, Save, ScanSearch, Search } from 'lucide-react'
import { cn } from '@/ui/lib'
import { ApiError } from '../api/client'
import {
  directoryApi, useDirectory, useDirectoryGroups, useLabMode,
  type DirectoryBody, type DirectoryConfig, type DiscoverResult, type SyncResult, type SyncStats, type TestResult, type Transport,
} from '../api/directory'
import { qk } from '../api/keys'
import { useEnforcement, usePolicy } from '../api/policy'
import { useSession } from '../api/session'
import { useTenant } from '../api/tenant'
import { paths } from '../routes'
import { ago, duration, fmtDateTime, plural, relative } from '../lib/format'
import { useNow } from '../lib/useNow'

import {
  Btn, Callout, Chip, Dl, EDialog, Empty, ErrorState, ESwitch, Field, HealthDot, LoadingBlock, PageHeader, Panel, SectionHeader, Seg, SourceTag, errorMessage, toast,
} from '../ui'

// ── Form model ───────────────────────────────────────────────────────────

interface Form {
  hosts: string
  port: string
  transport: Transport
  verify: boolean
  caPem: string
  clearCa: boolean
  domain: string
  baseDn: string
  userBase: string
  groupBase: string
  userFilter: string
  groupFilter: string
  bindDn: string
  password: string
  interval: string
  enabled: boolean
}

const DEFAULT_USER_FILTER = '(&(objectCategory=person)(objectClass=user))'
const DEFAULT_GROUP_FILTER = '(objectClass=group)'
const defaultPort = (t: Transport) => (t === 'ldaps' ? 636 : 389)

/** corp.example.com -> DC=corp,DC=example,DC=com: the usual AD base DN for a domain. */
export function deriveBaseDn(domain: string): string {
  const labels = domain.trim().toLowerCase().replace(/\.$/, '').split('.').filter(Boolean)
  return labels.length >= 2 && labels.every((l) => /^[a-z0-9-]+$/.test(l)) ? labels.map((l) => `DC=${l}`).join(',') : ''
}

/** Stats are {} (or absent) until the first sync finishes; only a complete record is shown. */
export const hasStats = (s: SyncStats | null | undefined): s is SyncStats => !!s && typeof s.users === 'number' && typeof s.groups === 'number'

function formFrom(c: DirectoryConfig | null, tenantDomain: string): Form {
  return {
    hosts: c?.hosts.join(', ') ?? '', port: String(c?.port ?? 636), transport: c?.transport ?? 'ldaps', verify: c?.verify_certificate ?? true,
    caPem: '', clearCa: false, domain: c?.domain ?? tenantDomain ?? '', baseDn: c?.base_dn ?? deriveBaseDn(tenantDomain ?? ''), userBase: c?.user_search_base ?? '', groupBase: c?.group_search_base ?? '',
    userFilter: c?.user_filter ?? DEFAULT_USER_FILTER, groupFilter: c?.group_filter ?? DEFAULT_GROUP_FILTER, bindDn: c?.bind_dn ?? '', password: '',
    interval: String(c?.sync_interval_minutes ?? 15), enabled: c?.enabled ?? true,
  }
}

const DETECT_FIELDS: Array<keyof Form> = ['hosts', 'port', 'caPem']
const hostList = (s: string) => s.split(/[\s,;]+/).map((h) => h.trim()).filter(Boolean)

function validate(f: Form, c: DirectoryConfig | null): Partial<Record<keyof Form, string>> {
  const e: Partial<Record<keyof Form, string>> = {}
  const hosts = hostList(f.hosts)
  if (hosts.length === 0) e.hosts = 'Enter at least one domain controller.'
  else if (hosts.length > 6) e.hosts = 'Enter at most 6 domain controllers.'
  const port = Number(f.port)
  if (!/^\d+$/.test(f.port) || port < 1 || port > 65535) e.port = 'Enter a port from 1 to 65535.'
  if (f.domain.trim().length < 2) e.domain = 'Enter the AD domain, such as corp.example.com.'
  if (f.baseDn.trim().length < 3) e.baseDn = 'Enter the base DN, such as DC=corp,DC=example,DC=com.'
  if (f.bindDn.trim().length < 3) e.bindDn = 'Enter the service account (user@domain or its DN).'
  if (!f.password && !c?.password_set) e.password = 'Enter the service account password.'
  if (f.caPem.trim() && !f.caPem.includes('BEGIN CERTIFICATE')) e.caPem = 'Paste the CA certificate as PEM (-----BEGIN CERTIFICATE-----).'
  const iv = Number(f.interval)
  if (!/^\d+$/.test(f.interval) || iv < 5 || iv > 1440) e.interval = 'Enter 5 to 1440 minutes.'
  return e
}

function bodyFrom(f: Form): DirectoryBody {
  return {
    hosts: hostList(f.hosts), port: Number(f.port), transport: f.transport, verify_certificate: f.verify,
    ca_bundle_pem: f.caPem.trim() ? f.caPem.trim() : null, clear_ca_bundle: f.clearCa && !f.caPem.trim(),
    domain: f.domain.trim(), base_dn: f.baseDn.trim(), user_search_base: f.userBase.trim(), group_search_base: f.groupBase.trim(),
    user_filter: f.userFilter.trim() || DEFAULT_USER_FILTER, group_filter: f.groupFilter.trim() || DEFAULT_GROUP_FILTER,
    bind_dn: f.bindDn.trim(), bind_password: f.password ? f.password : null, sync_interval_minutes: Number(f.interval), enabled: f.enabled,
  }
}

/** What to check, from the words in the stored sync error (the backend already appends its own hint). */
function fixHints(err: string): string[] {
  const m = err.toLowerCase()
  const out: string[] = []
  if (m.includes('safety stop')) out.push('Check the base DN, user search base and user filter below: a narrower search than before makes users look deleted.')
  if (m.includes('certificate') || m.includes('ca bundle') || m.includes('trusted')) out.push('Paste your AD root CA certificate (PEM) under Certificate trust, then test the connection.')
  if (m.includes('hostname') || m.includes('match')) out.push('Use each domain controller’s fully qualified name exactly as it appears in its certificate.')
  if (m.includes('sign in') || m.includes('credentials') || m.includes('password') || m.includes('locked') || m.includes('disabled')) out.push('Re-enter the service account and its password. Check in AD that the account isn’t disabled, locked out or expired.')
  if (m.includes('reach') || m.includes('connect') || m.includes('timed out') || m.includes('refused') || m.includes('dns')) out.push('Check DNS for the domain controller names and that EasyEAP can reach TCP 636 (LDAPS) or 389 (StartTLS).')
  if (!out.length) out.push('Review the connection settings below and use Test connection to see which step fails.')
  return out
}

// ── Screen ───────────────────────────────────────────────────────────────

export default function Directory() {
  const { tid, tenant, can } = useTenant()
  const q = useDirectory(tid)
  const formRef = useRef<HTMLHeadingElement>(null)
  const goToForm = () => { formRef.current?.scrollIntoView({ block: 'start', behavior: 'smooth' }); formRef.current?.focus({ preventScroll: true }) }

  if (q.isLoading) return <><PageHeader title="Directory" /><LoadingBlock rows={8} label="Loading directory" /></>
  if (q.error) return <><PageHeader title="Directory" /><ErrorState error={q.error} onRetry={() => q.refetch()} /></>
  const c = q.data?.config ?? null

  return (
    <div>
      <PageHeader
        title="Directory"
        lede="EasyEAP reads users and groups from Active Directory with a read-only service account. Account state and group membership decide access, so a broken sync means stale decisions."
      />
      <SyncStatus tid={tid} config={c} canSync={can('directory:sync')} onEdit={can('directory:write') ? goToForm : undefined} />
      <div className="mt-10">
        <SectionHeader id="dir-form-h" title={c ? 'Connection' : 'Connect Active Directory'} meta={c ? `${c.domain} · ${c.transport.toUpperCase()}` : undefined} />
        {can('directory:write')
          ? <ConnectionForm key={c ? `${c.domain}:${c.bind_dn}:${c.hosts.join(',')}` : 'new'} tid={tid} config={c} tenantDomain={tenant.domain} headingRef={formRef} />
          : <ReadOnlyConfig config={c} />}
      </div>
      <div className="mt-10">
        <Groups tid={tid} canCreate={can('identities:write')} count={q.data?.group_count ?? 0} />
      </div>
    </div>
  )
}

// ── Sync status ──────────────────────────────────────────────────────────

function statsText(s: SyncStats) {
  return `${plural(s.users, 'user')} and ${plural(s.groups, 'group')} read; ${s.created} created, ${s.updated} updated, ${s.deleted} marked deleted; ${plural(s.decisions, 'access decision')} recomputed in ${s.duration_ms < 1000 ? `${s.duration_ms} ms` : duration(s.duration_ms / 1000)}.`
}

function SyncStatus({ tid, config: c, canSync, onEdit }: { tid: string; config: DirectoryConfig | null; canSync: boolean; onEdit?: () => void }) {
  const qc = useQueryClient()
  const now = useNow()
  const enf = useEnforcement(tid)
  const platformRole = !!useSession().me?.platform_role
  const [result, setResult] = useState<SyncResult | null>(null)
  const [forceOpen, setForceOpen] = useState(false)
  const sync = useMutation({
    mutationFn: (force: boolean) => directoryApi.sync(tid, force),
    onSuccess: (r) => {
      setResult(r)
      setForceOpen(false)
      qc.invalidateQueries({ queryKey: qk.tenantScope(tid) })
      if ('ok' in r && r.ok) toast('Directory synced', statsText(r))
      else if ('ok' in r) toast('Directory sync failed', r.error, 'crit')
      else toast('Sync is turned off', 'Turn on sync for this directory to run it.', 'warn')
    },
    onError: (e) => toast('Sync couldn’t start', errorMessage(e), 'crit'),
  })

  if (!c) {
    return (
      <Panel className="px-5 py-5" risk="warn">
        <Empty icon={<BookUser aria-hidden />} title="No directory connected">
          Without a directory, only local users and local groups can be used in access rules. Connect Active Directory below so account changes (leavers, disabled accounts, group moves) reach RADIUS automatically.
        </Empty>
      </Panel>
    )
  }

  const failed = c.last_sync_status === 'failed'
  const never = !c.last_sync_at
  const due = c.last_sync_at ? new Date(new Date(c.last_sync_at).getTime() + c.sync_interval_minutes * 60_000) : null
  // The worker syncs every interval; allow one missed tick plus a few minutes before calling it overdue.
  const overdue = c.enabled && due && now.getTime() - due.getTime() > (c.sync_interval_minutes + 5) * 60_000
  const safety = failed && !!c.last_sync_error?.startsWith('Safety stop')
  const e = enf.data
  // Scheduled syncs are run by the background worker; the dashboard says whether it is reporting.
  const workerDown = c.enabled && e?.worker_alive === false
  const risk = failed ? 'crit' : !c.enabled || overdue || never || workerDown ? 'warn' : 'valid'

  return (
    <Panel className="px-5 py-5" risk={risk} aria-labelledby="sync-h">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h2 id="sync-h" className="ee-h2">
            {failed ? 'Directory sync is failing' : never ? 'Not synced yet' : !c.enabled ? 'Sync is turned off' : 'Directory sync'}
          </h2>
          <p className="mt-1.5">
            {never ? <HealthDot tone="warn" label="No sync has run yet" />
              : failed ? <HealthDot tone="crit" label={`Last attempt failed ${ago(c.last_sync_at, now)} · ${fmtDateTime(c.last_sync_at)}`} />
              : <HealthDot tone={overdue ? 'warn' : 'valid'} label={`Synced ${ago(c.last_sync_at, now)} · ${fmtDateTime(c.last_sync_at)}`} />}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {failed && onEdit && <Btn onClick={onEdit}>Edit connection</Btn>}
          {canSync && <Btn variant={failed || never ? 'primary' : 'default'} busy={sync.isPending && !forceOpen} onClick={() => { setResult(null); sync.mutate(false) }}><RefreshCw aria-hidden />Sync now</Btn>}
        </div>
      </div>

      {failed && (
        <div className="mt-4 space-y-3">
          <Callout tone="crit" title="What failed">
            <span className="ee-mono text-[12.5px] text-[var(--ee-ink)] break-words">{c.last_sync_error ?? 'No detail was recorded.'}</span>
          </Callout>
          {e && (
            <p className="text-[13px]">
              {e.directory_fresh === false && e.deadline_at
                ? <><span className="font-semibold text-[var(--ee-crit-ink)]">The RADIUS snapshot is no longer refreshed while sync is failing.</span> RADIUS denies everyone from {fmtDateTime(e.deadline_at)} ({relative(e.deadline_at, now)}) unless a sync succeeds before then.</>
                : 'RADIUS keeps deciding from the last good data. Leavers, disabled accounts and group changes in AD don’t reach it until a sync succeeds.'}
            </p>
          )}
          <div>
            <p className="text-[13px] font-semibold">What to check</p>
            <ul className="ee-small ee-ink-2 mt-1 list-disc space-y-1 pl-5">
              {fixHints(c.last_sync_error ?? '').map((h) => <li key={h}>{h}</li>)}
              <li>Then use Test connection, save, and Sync now.</li>
            </ul>
          </div>
          {safety && canSync && (
            <Callout tone="warn" title="Is the change intended?" action={<Btn size="sm" variant="danger" onClick={() => setForceOpen(true)}>Sync anyway</Btn>}>
              If those users really left, run a forced sync. Their accounts are marked deleted and RADIUS rejects them.
            </Callout>
          )}
        </div>
      )}

      {!failed && hasStats(c.last_sync_stats) && <p className="ee-small ee-ink-2 mt-3">{statsText(c.last_sync_stats)}</p>}

      <Dl className="mt-4" cols={3} items={[
        ['Schedule', c.enabled ? `Every ${plural(c.sync_interval_minutes, 'minute')}` : 'Off: syncs run only when you start one'],
        ['Next sync', !c.enabled ? '—' : workerDown
          ? <span className="text-[var(--ee-warn-ink)]">Not running: the background worker {e?.worker_seen_at ? `last reported ${ago(e.worker_seen_at, now)}` : 'isn’t reporting'}, so scheduled syncs don’t happen. Sync now still works.{platformRole && <> <Link to={paths.system()} className="underline">System health</Link></>}</span>
          : !due ? 'As soon as the background worker runs' : overdue
          ? <span className="text-[var(--ee-warn-ink)]">Overdue since {fmtDateTime(due.toISOString())}. The background worker may be stopped.</span>
          : due.getTime() <= now.getTime() ? 'Due now' : `${relative(due.toISOString(), now)} (${fmtDateTime(due.toISOString())})`],
        ['Last good data', failed ? 'From the last successful sync' : hasStats(c.last_sync_stats) ? plural(c.last_sync_stats.users, 'user') : '—'],
      ]} />

      {result && 'ok' in result && !result.ok && <Callout tone="crit" className="mt-4" title="This sync failed">{result.error}</Callout>}
      {result && 'skipped' in result && <Callout tone="warn" className="mt-4" title="Nothing ran">Sync is turned off for this directory. Turn it on under Connection to sync.</Callout>}

      <EDialog open={forceOpen} onOpenChange={setForceOpen} risk="crit" title="Sync anyway?"
        description="The safety stop exists because a wrong search base can make most users look deleted."
        footer={<><Btn onClick={() => setForceOpen(false)}>Cancel</Btn><Btn variant="danger-solid" busy={sync.isPending} onClick={() => sync.mutate(true)}>Run forced sync</Btn></>}>
        <p className="ee-small ee-ink-2">Users missing from the directory search are marked deleted. Deleted accounts are rejected by RADIUS before any rule, whatever certificate they hold. Only continue if those people really left.</p>
      </EDialog>
    </Panel>
  )
}

// ── Connection form ──────────────────────────────────────────────────────

function TestResultView({ r, baseDn, onUseBase }: { r: TestResult; baseDn: string; onUseBase: (base: string, domain: string) => void }) {
  return (
    <div className={cn('rounded-[8px] border px-4 py-3', r.ok ? 'border-[rgba(45,212,191,0.3)]' : 'border-[rgba(244,63,94,0.4)]')} role="status">
      <p className="font-semibold">{r.ok ? 'Connection works' : 'Connection test failed'}</p>
      <ol className="mt-2 space-y-2">
        {r.steps.map((s, i) => (
          <li key={i} className="flex items-start gap-2.5">
            {s.ok ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-[var(--ee-valid)]" aria-hidden /> : <CircleX className="mt-0.5 size-4 shrink-0 text-[var(--ee-crit-ink)]" aria-hidden />}
            <div className="min-w-0">
              <p className="text-[13px]"><span className="sr-only">{s.ok ? 'Passed: ' : 'Failed: '}</span><span className="font-medium">{s.step === 'connect' ? 'Connect and sign in' : s.step === 'search' ? 'Search users and groups' : s.step}</span> · {s.message}</p>
              {s.hint && <p className="ee-small ee-ink-2 mt-0.5">{s.hint}</p>}
              {s.detail && (
                <details className="mt-1">
                  <summary className="ee-small ee-ink-3 cursor-pointer">Technical details</summary>
                  <p className="ee-mono mt-1 break-words text-[12px] ee-ink-2">{s.detail}</p>
                </details>
              )}
            </div>
          </li>
        ))}
      </ol>
      {r.discovered && r.base_dn_outside && r.discovered.base_dn !== baseDn && (
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
          {/* A failed search already names the directory's base DN in its hint. */}
          {r.ok && <p className="ee-small">This directory’s base DN is <span className="ee-mono text-[12.5px]">{r.discovered.base_dn}</span>.</p>}
          <Btn size="sm" onClick={() => onUseBase(r.discovered!.base_dn, r.discovered!.domain)}>{r.ok ? 'Use it' : 'Use the directory’s base DN'}</Btn>
        </div>
      )}
      {!r.ok && <p className="ee-small ee-ink-3 mt-2">Nothing was saved. Fix the field the hint points to and test again.</p>}
    </div>
  )
}

function ConnectionForm({ tid, config: c, tenantDomain, headingRef }: { tid: string; config: DirectoryConfig | null; tenantDomain: string; headingRef: React.RefObject<HTMLHeadingElement | null> }) {
  const qc = useQueryClient()
  const lab = useLabMode(tid)
  const [f, setF] = useState<Form>(() => formFrom(c, tenantDomain))
  const [tried, setTried] = useState(false)
  // Detect needs only the domain controller and TLS fields, so it flags only those.
  const [detectTried, setDetectTried] = useState(false)
  const [test, setTest] = useState<TestResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [detected, setDetected] = useState<DiscoverResult | null>(null)
  const [advanced, setAdvanced] = useState(!!c && (c.user_search_base !== '' || c.group_search_base !== '' || c.user_filter !== DEFAULT_USER_FILTER || c.group_filter !== DEFAULT_GROUP_FILTER))
  const errs = validate(f, c)
  const invalid = Object.keys(errs).length > 0
  const set = <K extends keyof Form>(k: K, v: Form[K]) => { setF((x) => ({ ...x, [k]: v })); setTest(null) }
  const err = (k: keyof Form) => (tried || (detectTried && DETECT_FIELDS.includes(k)) ? errs[k] ?? null : null)
  const plainAllowed = lab.data === true || c?.transport === 'plain'

  const testM = useMutation({
    mutationFn: () => directoryApi.test(tid, bodyFrom(f)),
    onSuccess: (r) => setTest(r),
    onError: (e) => setError(e instanceof ApiError ? e.message : 'The test couldn’t run.'),
  })
  const save = useMutation({
    mutationFn: () => directoryApi.save(tid, bodyFrom(f)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.tenantScope(tid) })
      setF((x) => ({ ...x, password: '', caPem: '', clearCa: false }))
      toast('Directory settings saved', 'A sync has been queued. Its result appears at the top of this page.')
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'The settings couldn’t be saved.'),
  })
  const run = (which: 'test' | 'save') => (e?: FormEvent) => {
    e?.preventDefault()
    setTried(true)
    setError(null)
    if (invalid) return
    if (which === 'test') { setTest(null); testM.mutate() } else save.mutate()
  }
  // The base DN follows the AD domain until someone types their own or detects it.
  const onDomain = (domain: string) => {
    setF((x) => ({ ...x, domain, baseDn: !x.baseDn.trim() || x.baseDn === deriveBaseDn(x.domain) ? deriveBaseDn(domain) : x.baseDn }))
    setTest(null)
  }
  const applyBase = (baseDn: string, domain: string) => {
    setF((x) => ({ ...x, baseDn, domain: domain || x.domain }))
    setTest(null)
  }
  const detect = useMutation({
    mutationFn: () => directoryApi.discover(tid, {
      hosts: hostList(f.hosts), port: Number(f.port), transport: f.transport, verify_certificate: f.verify,
      ca_bundle_pem: f.caPem.trim() ? f.caPem.trim() : null, clear_ca_bundle: f.clearCa && !f.caPem.trim(),
      bind_dn: f.bindDn.trim(), bind_password: f.password ? f.password : null,
    }),
    onSuccess: (r) => {
      setDetected(r)
      if (r.ok) applyBase(r.base_dn, r.domain)
    },
    onError: (e) => setDetected({ ok: false, message: errorMessage(e) }),
  })
  const runDetect = () => {
    setDetectTried(true)
    setDetected(null)
    if (errs.hosts || errs.port || errs.caPem) return
    detect.mutate()
  }
  const onTransport = (t: Transport) => {
    setF((x) => ({ ...x, transport: t, port: Number(x.port) === defaultPort(x.transport) ? String(defaultPort(t)) : x.port }))
    setTest(null)
  }

  return (
    <Panel className="px-5 py-5" aria-labelledby="dir-form-h">
      <h2 ref={headingRef} tabIndex={-1} className="sr-only">Connection settings</h2>
      <form onSubmit={run('save')} noValidate className="max-w-[920px] space-y-7">
        <FormGroup title="Domain controllers">
          <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_120px]">
            <Field label="Hosts" htmlFor="dir-hosts" error={err('hosts')} hint="Fully qualified names, as they appear in each controller’s certificate. Up to 6, tried in order; separate with commas.">
              <input id="dir-hosts" className="ee-input" value={f.hosts} onChange={(e) => set('hosts', e.target.value)} placeholder="dc1.corp.example.com, dc2.corp.example.com" autoComplete="off" spellCheck={false} aria-invalid={!!err('hosts') || undefined} />
            </Field>
            <Field label="Port" htmlFor="dir-port" error={err('port')}>
              <input id="dir-port" className="ee-input ee-num" inputMode="numeric" value={f.port} onChange={(e) => set('port', e.target.value)} aria-invalid={!!err('port') || undefined} />
            </Field>
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="text-[13px] font-semibold">Transport</span>
            <div><Seg label="Transport" value={f.transport} onChange={onTransport} options={[
              { value: 'ldaps', label: 'LDAPS' }, { value: 'starttls', label: 'StartTLS' },
              ...(plainAllowed ? [{ value: 'plain' as Transport, label: 'Plain LDAP' }] : []),
            ]} /></div>
            <p className="ee-small ee-ink-3">{f.transport === 'ldaps' ? 'TLS from the first byte on port 636. Recommended.' : f.transport === 'starttls' ? 'Starts on port 389 and upgrades to TLS before signing in.' : 'No encryption.'}</p>
          </div>
          {f.transport === 'plain' && (
            <Callout tone="crit" title="Plain LDAP sends the password in the clear">
              The service account password and every user and group record cross the network unencrypted. {lab.data ? 'This server runs in lab mode, so EasyEAP accepts it; use it only on an isolated lab network.' : 'EasyEAP refuses plain LDAP outside lab mode, so saving will fail. Choose LDAPS.'}
            </Callout>
          )}
        </FormGroup>

        {f.transport !== 'plain' && (
          <FormGroup title="Certificate trust">
            <div className="flex items-start justify-between gap-4 rounded-[8px] border border-[var(--ee-line)] px-4 py-3">
              <div>
                <label htmlFor="dir-verify" className="text-[13px] font-semibold">Verify the domain controller’s certificate</label>
                <p className="ee-small ee-ink-2 mt-0.5">Proves EasyEAP is talking to your real domain controller before it sends the service account password.</p>
              </div>
              <ESwitch id="dir-verify" checked={f.verify} onChange={(v) => set('verify', v)} label="Verify the domain controller’s certificate" />
            </div>
            {!f.verify && <Callout tone="crit" title="Verification is off">Anyone who can intercept traffic between EasyEAP and the domain controller can pose as it and capture the service account password. Paste your AD root CA below instead.</Callout>}
            <Field label="CA certificate (PEM)" htmlFor="dir-ca" optional error={err('caPem')}
              hint={c?.has_ca_bundle ? 'A CA bundle is saved. Paste a new one to replace it, or leave blank to keep it.' : 'The root CA that signed your domain controllers’ certificates, if it isn’t publicly trusted (usually an AD CS root).'}>
              <textarea id="dir-ca" className="ee-textarea" rows={4} value={f.caPem} onChange={(e) => set('caPem', e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} aria-invalid={!!err('caPem') || undefined} />
            </Field>
            {c?.has_ca_bundle && !f.caPem.trim() && (
              <label className="flex items-center gap-2.5 text-[13px]">
                <input type="checkbox" className="ee-check" checked={f.clearCa} onChange={(e) => set('clearCa', e.target.checked)} />
                Remove the saved CA bundle and rely on the system trust store
              </label>
            )}
          </FormGroup>
        )}

        <FormGroup title="Where to look">
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="AD domain" htmlFor="dir-domain" error={err('domain')}>
              <input id="dir-domain" className="ee-input" value={f.domain} onChange={(e) => onDomain(e.target.value)} placeholder="corp.example.com" autoComplete="off" spellCheck={false} aria-invalid={!!err('domain') || undefined} />
            </Field>
            <Field label="Base DN" htmlFor="dir-base" error={err('baseDn')} hint="Follows the AD domain as you type. Detect reads it from the domain controller.">
              <input id="dir-base" className="ee-input ee-mono text-[13px]" value={f.baseDn} onChange={(e) => set('baseDn', e.target.value)} placeholder="DC=corp,DC=example,DC=com" autoComplete="off" spellCheck={false} aria-invalid={!!err('baseDn') || undefined} />
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <Btn size="sm" onClick={runDetect} busy={detect.isPending}><ScanSearch aria-hidden />Detect from domain controller</Btn>
            {!detected && <span className="ee-small ee-ink-3">Needs only the domain controller above. It reads without signing in where the directory allows it.</span>}
            {detected?.ok && (
              <span className="ee-small ee-ink-2" role="status">
                <CircleCheck className="mr-1 inline size-3.5 align-[-2px] text-[var(--ee-valid)]" aria-hidden />
                Read from {detected.dc_hostname}{detected.signed_in ? ' (signed in as the service account)' : ''}: <span className="ee-mono text-[12.5px]">{detected.base_dn}</span>
              </span>
            )}
          </div>
          {detected && !detected.ok && (
            <Callout tone="crit" title={detected.message}>
              {detected.hint && <p>{detected.hint}</p>}
              {detected.detail && (
                <details className="mt-1">
                  <summary className="ee-small ee-ink-3 cursor-pointer">Technical details</summary>
                  <p className="ee-mono mt-1 break-words text-[12px] ee-ink-2">{detected.detail}</p>
                </details>
              )}
            </Callout>
          )}
          <button type="button" className="ee-small ee-ink-2 inline-flex items-center gap-1 self-start rounded underline-offset-2 hover:underline" aria-expanded={advanced} onClick={() => setAdvanced((v) => !v)}>
            <ChevronRight className={cn('size-3.5 transition-transform', advanced && 'rotate-90')} aria-hidden />Search bases and filters
          </button>
          {advanced && (
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="User search base" htmlFor="dir-ubase" optional hint="Blank searches the whole base DN.">
                <input id="dir-ubase" className="ee-input ee-mono text-[13px]" value={f.userBase} onChange={(e) => set('userBase', e.target.value)} spellCheck={false} />
              </Field>
              <Field label="Group search base" htmlFor="dir-gbase" optional hint="Blank searches the whole base DN.">
                <input id="dir-gbase" className="ee-input ee-mono text-[13px]" value={f.groupBase} onChange={(e) => set('groupBase', e.target.value)} spellCheck={false} />
              </Field>
              <Field label="User filter" htmlFor="dir-ufilter">
                <input id="dir-ufilter" className="ee-input ee-mono text-[13px]" value={f.userFilter} onChange={(e) => set('userFilter', e.target.value)} spellCheck={false} />
              </Field>
              <Field label="Group filter" htmlFor="dir-gfilter">
                <input id="dir-gfilter" className="ee-input ee-mono text-[13px]" value={f.groupFilter} onChange={(e) => set('groupFilter', e.target.value)} spellCheck={false} />
              </Field>
            </div>
          )}
        </FormGroup>

        <FormGroup title="Service account">
          <Callout tone="gold">Use a dedicated, read-only service account. A normal domain user can read users and groups; never use a Domain Admin. EasyEAP only reads from the directory.</Callout>
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="Bind DN or user@domain" htmlFor="dir-bind" error={err('bindDn')}>
              <input id="dir-bind" className="ee-input" value={f.bindDn} onChange={(e) => set('bindDn', e.target.value)} placeholder="svc-easyeap@corp.example.com" autoComplete="off" spellCheck={false} aria-invalid={!!err('bindDn') || undefined} />
            </Field>
            <Field label="Password" htmlFor="dir-pw" error={err('password')} hint={c?.password_set ? 'Leave blank to keep the saved password. It is stored encrypted and never shown again.' : 'Stored encrypted. It can’t be displayed after saving.'}>
              <input id="dir-pw" type="password" className="ee-input" value={f.password} onChange={(e) => set('password', e.target.value)} autoComplete="new-password"
                placeholder={c?.password_set ? 'Saved password kept' : ''} aria-invalid={!!err('password') || undefined} />
            </Field>
          </div>
        </FormGroup>

        <FormGroup title="Sync">
          <div className="flex flex-wrap items-end gap-x-8 gap-y-4">
            <Field label="Sync every" htmlFor="dir-interval" error={err('interval')}>
              <div className="flex items-center gap-2">
                <input id="dir-interval" className="ee-input ee-num w-[100px]" inputMode="numeric" value={f.interval} onChange={(e) => set('interval', e.target.value)} aria-invalid={!!err('interval') || undefined} />
                <span className="ee-small ee-ink-2">minutes</span>
              </div>
            </Field>
            <label className="flex h-[34px] items-center gap-2.5 text-[13px]">
              <ESwitch checked={f.enabled} onChange={(v) => set('enabled', v)} label="Scheduled sync" />
              Scheduled sync {f.enabled ? 'on' : 'off'}
            </label>
          </div>
          {!f.enabled && <p className="ee-small text-[var(--ee-warn-ink)]">With scheduled sync off, leavers and disabled accounts keep their access until someone syncs by hand.</p>}
        </FormGroup>

        {tried && invalid && <Callout tone="crit">Fix the highlighted fields first.</Callout>}
        {error && <Callout tone="crit" title="That didn’t work">{error}</Callout>}
        {test && <TestResultView r={test} baseDn={f.baseDn} onUseBase={applyBase} />}

        <div className="flex flex-wrap items-center gap-2 border-t border-[var(--ee-line)] pt-4">
          <Btn onClick={() => run('test')()} busy={testM.isPending}><FlaskConical aria-hidden />Test connection</Btn>
          <Btn type="submit" variant="primary" busy={save.isPending}><Save aria-hidden />{c ? 'Save and sync' : 'Connect and sync'}</Btn>
          <span className="ee-small ee-ink-3">Testing doesn’t save anything.</span>
        </div>
      </form>
    </Panel>
  )
}

function FormGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className="flex flex-col gap-4">
      <legend className="ee-h3 mb-3">{title}</legend>
      {children}
    </fieldset>
  )
}

function ReadOnlyConfig({ config: c }: { config: DirectoryConfig | null }) {
  if (!c) return <Panel className="px-5 py-5"><p className="ee-small ee-ink-2">No directory is connected. Connecting one needs the Tenant Administrator role.</p></Panel>
  return (
    <Panel className="px-5 py-5">
      <Dl cols={2} items={[
        ['Domain controllers', <span className="break-words">{c.hosts.join(', ')}</span>],
        ['Transport', `${c.transport === 'ldaps' ? 'LDAPS' : c.transport === 'starttls' ? 'StartTLS' : 'Plain LDAP'} on port ${c.port}`],
        ['Certificate verification', c.verify_certificate ? (c.has_ca_bundle ? 'On, with a custom CA bundle' : 'On, system trust store') : <Chip tone="crit">Off</Chip>],
        ['AD domain', c.domain],
        ['Base DN', <span className="ee-mono text-[12.5px]">{c.base_dn}</span>],
        ['Service account', c.bind_dn],
        ['Search bases', c.user_search_base || c.group_search_base ? `Users: ${c.user_search_base || 'base DN'} · Groups: ${c.group_search_base || 'base DN'}` : 'Whole base DN'],
        ['Scheduled sync', c.enabled ? `Every ${plural(c.sync_interval_minutes, 'minute')}` : 'Off'],
      ]} />
      <p className="ee-small ee-ink-3 mt-4">Changing the connection needs the Tenant Administrator role.</p>
    </Panel>
  )
}

// ── Groups ───────────────────────────────────────────────────────────────

const GROUP_COLS = 'md:grid-cols-[minmax(0,1fr)_90px_80px_minmax(140px,0.6fr)]'

function Groups({ tid, canCreate, count }: { tid: string; canCreate: boolean; count: number }) {
  const groups = useDirectoryGroups(tid)
  const policy = usePolicy(tid)
  const [query, setQuery] = useState('')
  const [source, setSource] = useState<'all' | 'ad' | 'local'>('all')
  const [creating, setCreating] = useState(false)
  const usedBy = useMemo(() => {
    const m = new Map<string, string[]>()
    for (const r of policy.data?.rules ?? []) for (const g of r.groups) m.set(g.id, [...(m.get(g.id) ?? []), r.name])
    return m
  }, [policy.data])
  const rows = useMemo(() => {
    const ql = query.trim().toLowerCase()
    return (groups.data?.groups ?? []).filter((g) => (source === 'all' || g.source === source) && (!ql || g.name.toLowerCase().includes(ql) || g.dn.toLowerCase().includes(ql)))
  }, [groups.data, query, source])
  const all = groups.data?.groups ?? []

  return (
    <section aria-labelledby="groups-h">
      <SectionHeader id="groups-h" title="Groups" meta={`${plural(count, 'group')} · access rules match on these`}
        actions={canCreate ? <Btn size="sm" onClick={() => setCreating(true)}><Plus aria-hidden />Local group</Btn> : undefined} />
      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 border-b border-[var(--ee-line)] px-4 py-3">
          <div className="ee-input flex max-w-[360px] flex-1 basis-[220px] items-center gap-2 px-2.5 focus-within:border-[var(--ee-gold)]">
            <Search className="size-4 shrink-0 ee-ink-3" aria-hidden />
            <input aria-label="Filter groups" className="h-full min-w-0 flex-1 bg-transparent outline-none placeholder:text-[var(--ee-ink-3)]" placeholder="Filter by name or DN" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <Seg label="Source" value={source} onChange={setSource} options={[
            { value: 'all', label: 'All', count: all.length }, { value: 'ad', label: 'AD', count: all.filter((g) => g.source === 'ad').length }, { value: 'local', label: 'Local', count: all.filter((g) => g.source === 'local').length },
          ]} />
        </div>
        {groups.isLoading ? <div className="px-4 py-3"><LoadingBlock rows={5} label="Loading groups" /></div>
          : groups.error ? <div className="p-4"><ErrorState error={groups.error} onRetry={() => groups.refetch()} /></div>
          : all.length === 0 ? <div className="p-4"><Empty title="No groups yet">Groups appear after the first successful sync. Local groups you create here can be used in rules straight away.</Empty></div>
          : rows.length === 0 ? <p className="px-4 py-4 ee-small ee-ink-2">No group matches that filter.</p>
          : (
            <div className="max-h-[560px] overflow-auto">
              <div className={cn('sticky top-0 z-[1] hidden gap-x-4 border-b border-[var(--ee-line-2)] bg-[var(--ee-panel-solid)] px-4 py-2.5 text-[12px] font-medium ee-ink-3 md:grid', GROUP_COLS)} aria-hidden>
                <span>Group</span><span>Source</span><span className="text-right">Members</span><span>Used in rules</span>
              </div>
              <ul className="ee-divide list-none p-0" aria-label="Directory groups">
                {rows.map((g) => {
                  const used = usedBy.get(g.id)
                  return (
                    <li key={g.id} className={cn('grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-4 gap-y-1 px-4 py-2.5', GROUP_COLS)}>
                      <div className="min-w-0">
                        <span className="block font-medium">{g.name}</span>
                        <span className="block truncate text-[12px] ee-ink-3" title={g.dn}>{g.source === 'local' ? 'Local group in EasyEAP' : g.dn}</span>
                      </div>
                      <div className="md:pt-0.5"><SourceTag source={g.source} /></div>
                      <div className="col-span-2 flex flex-wrap gap-x-4 gap-y-1 text-[13px] md:contents">
                        <span className="ee-num md:pt-0.5 md:text-right">{g.members}<span className="md:sr-only"> {g.members === 1 ? 'member' : 'members'}</span></span>
                        <span className="ee-ink-2 md:pt-0.5">
                          <span className="md:sr-only">{used ? 'Used in ' : ''}</span>
                          {used ? used.map((n) => `“${n}”`).join(', ') : <><span className="ee-ink-3 max-md:hidden" aria-hidden>—</span><span className="ee-ink-3 md:sr-only">Not used in any rule</span></>}
                        </span>
                      </div>
                    </li>
                  )
                })}
              </ul>
            </div>
          )}
      </Panel>
      <CreateGroupDialog tid={tid} open={creating} onOpenChange={setCreating} />
    </section>
  )
}

function CreateGroupDialog({ tid, open, onOpenChange }: { tid: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [tried, setTried] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: () => directoryApi.createLocalGroup(tid, name.trim()),
    onSuccess: (g) => { qc.invalidateQueries({ queryKey: qk.directoryGroups(tid) }); qc.invalidateQueries({ queryKey: qk.directory(tid) }); toast(`Local group “${g.name}” created`, 'Add local users to it from their user record, then use it in a rule.'); setName(''); setTried(false); onOpenChange(false) },
    onError: (e) => setError(errorMessage(e)),
  })
  const nameErr = !name.trim() ? 'Enter a name.' : null
  return (
    <EDialog open={open} onOpenChange={(o) => { if (!o) { setError(null); setTried(false) } onOpenChange(o) }} title="Create a local group"
      description="Local groups live only in EasyEAP and hold local users, such as people who aren’t in Active Directory. Directory users get their groups from AD."
      footer={<><Btn onClick={() => onOpenChange(false)}>Cancel</Btn><Btn variant="primary" busy={create.isPending} onClick={() => { setTried(true); setError(null); if (!nameErr) create.mutate() }}>Create group</Btn></>}>
      <form onSubmit={(e) => { e.preventDefault(); setTried(true); if (!nameErr) create.mutate() }} className="space-y-3">
        <Field label="Name" htmlFor="grp-name" error={tried ? nameErr : null}>
          <input id="grp-name" className="ee-input" value={name} maxLength={256} onChange={(e) => setName(e.target.value)} autoComplete="off" aria-invalid={(tried && !!nameErr) || undefined} />
        </Field>
        {error && <Callout tone="crit" title="Not created">{error}</Callout>}
      </form>
    </EDialog>
  )
}
