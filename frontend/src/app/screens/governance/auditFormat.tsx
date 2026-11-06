// Human labels for audit actions and a readable rendering of each entry's detail JSON. Unknown actions and keys
// fall back to a tidied version of the raw name, so nothing recorded is ever hidden.
import { useState, type ReactNode } from 'react'
import { cn } from '@/ui/lib'
import { fmtDateTime, plural } from '../../lib/format'
import { Chip, type Tone } from '../../ui'

export const actionLabels: Record<string, string> = {
  'admin.created': 'Administrator created',
  'admin.deleted': 'Administrator deleted',
  'admin.mfa_reset': 'Administrator’s two-factor reset',
  'admin.updated': 'Administrator access changed',
  'auth.login': 'Signed in',
  'auth.login_failed': 'Sign-in failed',
  'auth.logout': 'Signed out',
  'auth.mfa_disabled': 'Two-factor authentication turned off',
  'auth.mfa_enabled': 'Two-factor authentication turned on',
  'auth.mfa_reset_cli': 'Two-factor reset from the server command line',
  'auth.password_changed': 'Password changed',
  'auth.profile_updated': 'Own profile updated',
  'certificate.revoked': 'Certificate revoked',
  'directory.saved': 'Directory connection saved',
  'directory.sync_failed': 'Scheduled directory sync failed',
  'directory.synced': 'Directory synced',
  'enrollment.cancelled': 'Enrollment cancelled',
  'enrollment.completed': 'Enrollment completed',
  'enrollment.link_created': 'Enrollment link created',
  'enrollment.package_downloaded': 'Certificate package downloaded',
  'enrollment.server_package_created': 'Server-generated certificate package created',
  'group.created': 'Local group created',
  'identity.created': 'Local user created',
  'identity.disconnected': 'User’s sessions disconnected',
  'identity.updated': 'User updated',
  'pki.crl_rotated': 'Revocation list reissued',
  'pki.initialized': 'Certificate authority initialized',
  'policy.published': 'Access policy published',
  'policy.settings_updated': 'Policy settings changed',
  'radius.client_created': 'Controller added',
  'radius.client_deleted': 'Controller removed',
  'radius.client_secret_rotated': 'Controller shared secret rotated',
  'radius.client_updated': 'Controller updated',
  'radius.server_certificate_rotated': 'RADIUS server certificate rotated',
  'radius.settings_saved': 'RADIUS settings saved',
  'rule.created': 'Access rule created',
  'rule.deleted': 'Access rule deleted',
  'rule.reordered': 'Access rules reordered',
  'rule.updated': 'Access rule changed',
  'setup.first_admin_created': 'First administrator created',
  'auth.reauth_failed': 'Password re-entry failed',
  'system.backup_created': 'Backup created',
  'system.backup_deleted': 'Backup deleted from the server',
  'system.backup_downloaded': 'Backup downloaded',
  'system.backup_restored': 'Backup restored',
  'system.restore_started': 'Restore started',
  'system.syslog_added': 'Syslog destination added',
  'system.syslog_removed': 'Syslog destination removed',
  'system.syslog_updated': 'Syslog destination changed',
  'template.created': 'Certificate template created',
  'template.updated': 'Certificate template changed',
  'tenant.created': 'Tenant created',
  'tenant.deleted': 'Tenant deleted',
  'tenant.updated': 'Tenant updated',
  'vlan.created': 'VLAN created',
  'vlan.deleted': 'VLAN deleted',
  'vlan.updated': 'VLAN changed',
}

const tidy = (s: string) => {
  const t = s.replace(/[._]+/g, ' ').trim()
  return t.charAt(0).toUpperCase() + t.slice(1)
}

export function actionLabel(action: string, detail?: Record<string, unknown>): string {
  if (action === 'directory.synced' && detail && detail.ok === false) return 'Directory sync failed'
  return actionLabels[action] ?? tidy(action)
}

export function actionTone(action: string, detail?: Record<string, unknown>): Tone | null {
  if (action === 'directory.synced' && detail?.ok === false) return 'crit'
  if (/(revoked|deleted|failed|disabled|mfa_reset)/.test(action)) return 'crit'
  if (action === 'policy.published' || action === 'system.backup_restored' || action === 'system.restore_started' || /rotated|settings/.test(action)) return 'gold'
  return null
}

export const actorTypeLabel: Record<string, string> = { admin: 'Administrator', system: 'EasyEAP', enrollee: 'Enrollee', agent: 'RADIUS agent' }

// ── Detail rendering ─────────────────────────────────────────────────────

const keyLabels: Record<string, string> = {
  vlan_ref: 'VLAN', group_ids: 'Groups (ids)', default_vlan_ref: 'Default VLAN', max_snapshot_age_seconds: 'Fail closed after',
  expiry_warning_days: 'Expiry warning', allow_server_keygen: 'Server-generated keys', default_action: 'Default action', bind_dn: 'Service account',
  verify_certificate: 'Verify certificate', password_changed: 'Password changed', duration_ms: 'Duration', decisions: 'Decisions recomputed',
  platform_role: 'Platform role', is_active: 'Active', clear_platform_role: 'Remove platform role', with_certificates: 'Hold certificates',
  newly_allowed: 'Newly allowed', newly_denied: 'Newly denied', vlan_changed: 'VLAN changes', rule_only: 'Decided by a different rule',
  key_origin: 'Key generated by', expires_at: 'Expires', enrollment_id: 'Enrollment', tenant_id: 'Tenant', ip: 'IP address',
  from_revision: 'From revision', to_revision: 'To revision', extra_attributes: 'Reply attributes', purposes: 'Certificate types',
}
export const humanKey = (k: string) => keyLabels[k] ?? tidy(k)

const isoRe = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/

function Value({ k, v }: { k?: string; v: unknown }): ReactNode {
  if (v === null || v === undefined || v === '') return <span className="ee-ink-3">—</span>
  if (v === '[withheld]') return <Chip tone="neutral">Withheld (secret)</Chip>
  if (typeof v === 'boolean') return v ? 'Yes' : 'No'
  if (typeof v === 'number') {
    if (k === 'duration_ms') return <span className="ee-num">{v} ms</span>
    if (k === 'max_snapshot_age_seconds') return <span className="ee-num">{plural(Math.round(v / 3600), 'hour')}</span>
    if (k === 'expiry_warning_days') return <span className="ee-num">{plural(v, 'day')}</span>
    return <span className="ee-num">{v.toLocaleString('en-GB')}</span>
  }
  if (typeof v === 'string') {
    if (isoRe.test(v)) return fmtDateTime(v)
    if (/^[0-9a-f-]{36}$/i.test(v) || /^[0-9A-F]{32,}$/.test(v)) return <span className="ee-mono text-[12px] break-all">{v}</span>
    return <span className="break-words">{v}</span>
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="ee-ink-3">None</span>
    if (v.every((x) => typeof x !== 'object' || x === null)) return <span className="break-words">{v.map((x) => String(x)).join(', ')}</span>
    return <ul className="space-y-1.5">{v.map((x, i) => <li key={i} className="rounded-[6px] border border-[var(--ee-line)] px-2.5 py-1.5"><Value v={x} /></li>)}</ul>
  }
  if (typeof v === 'object') return <KeyValues obj={v as Record<string, unknown>} nested />
  return String(v)
}

export function KeyValues({ obj, nested }: { obj: Record<string, unknown>; nested?: boolean }) {
  const entries = Object.entries(obj)
  if (entries.length === 0) return <span className="ee-ink-3">No detail recorded.</span>
  return (
    <dl className={cn('grid gap-x-4 gap-y-1.5', nested ? 'grid-cols-[minmax(90px,auto)_minmax(0,1fr)]' : 'grid-cols-1 sm:grid-cols-[minmax(140px,auto)_minmax(0,1fr)]')}>
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="ee-small ee-ink-3">{humanKey(k)}</dt>
          <dd className="min-w-0 text-[13px]"><Value k={k} v={v} /></dd>
        </div>
      ))}
    </dl>
  )
}

function names(v: unknown): string[] { return Array.isArray(v) ? v.map(String) : [] }

function PolicyPublished({ d }: { d: Record<string, unknown> }) {
  const impact = (d.impact ?? {}) as Record<string, number>
  const created = names(d.created), updated = names(d.updated), deleted = names(d.deleted), order = names(d.order)
  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-4">
        {([['newly_allowed', 'Newly allowed'], ['newly_denied', 'Newly denied'], ['vlan_changed', 'VLAN changes'], ['unchanged', 'Unchanged']] as const).map(([k, l]) => (
          <div key={k} className="rounded-[7px] border border-[var(--ee-line)] px-3 py-2">
            <p className="ee-small ee-ink-3">{l}</p>
            <p className={cn('ee-num text-[16px] font-semibold', k === 'newly_denied' && (impact[k] ?? 0) > 0 && 'text-[var(--ee-crit-ink)]')}>{(impact[k] ?? 0) + (k === 'unchanged' ? impact.rule_only ?? 0 : 0)}</p>
          </div>
        ))}
      </div>
      <p className="ee-small ee-ink-2">
        Evaluated {plural(impact.evaluated ?? 0, 'person', 'people')}; {impact.with_certificates ?? 0} held an active certificate. Default when no rule matches: {d.default_action === 'allow' ? 'Allow' : 'Deny'}.
      </p>
      <dl className="grid gap-x-4 gap-y-1.5 sm:grid-cols-[140px_minmax(0,1fr)]">
        <dt className="ee-small ee-ink-3">Added</dt><dd className="text-[13px]">{created.length ? created.map((n) => `“${n}”`).join(', ') : <span className="ee-ink-3">None</span>}</dd>
        <dt className="ee-small ee-ink-3">Changed</dt><dd className="text-[13px]">{updated.length ? updated.map((n) => `“${n}”`).join(', ') : <span className="ee-ink-3">None</span>}</dd>
        <dt className="ee-small ee-ink-3">Removed</dt><dd className="text-[13px]">{deleted.length ? deleted.map((n) => `“${n}”`).join(', ') : <span className="ee-ink-3">None</span>}</dd>
        <dt className="ee-small ee-ink-3">Rule order</dt><dd className="text-[13px]">{order.length ? <ol className="list-decimal pl-5">{order.map((n, i) => <li key={i}>{n}</li>)}</ol> : <span className="ee-ink-3">No rules</span>}</dd>
        <dt className="ee-small ee-ink-3">Revision</dt><dd className="ee-mono text-[12px]">{String(d.from_revision ?? '—').slice(0, 8)} → {String(d.to_revision ?? '—').slice(0, 8)}</dd>
      </dl>
    </div>
  )
}

function BeforeAfter({ before, after }: { before: Record<string, unknown>; after: Record<string, unknown> }) {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])]
  const changed = keys.filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k]))
  return (
    <div className="overflow-x-auto">
      <table className="ee-table">
        <caption className="sr-only">Settings before and after</caption>
        <thead><tr><th>Setting</th><th>Before</th><th>After</th></tr></thead>
        <tbody>
          {changed.length === 0 ? <tr><td colSpan={3} className="ee-ink-3">Saved without changes.</td></tr> : changed.map((k) => (
            <tr key={k}><td className="ee-ink-2">{humanKey(k)}</td><td><Value k={k} v={before[k]} /></td><td><Value k={k} v={after[k]} /></td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function AuditDetail({ action, detail }: { action: string; detail: Record<string, unknown> }) {
  const [raw, setRaw] = useState(false)
  let body: ReactNode
  if (action === 'policy.published') body = <PolicyPublished d={detail} />
  else if (detail && typeof detail.before === 'object' && typeof detail.after === 'object' && detail.before && detail.after) {
    body = <BeforeAfter before={detail.before as Record<string, unknown>} after={detail.after as Record<string, unknown>} />
  } else body = <KeyValues obj={detail ?? {}} />
  return (
    <div className="space-y-3">
      {body}
      <div>
        <button type="button" className="ee-small ee-ink-3 rounded underline-offset-2 hover:underline" aria-expanded={raw} onClick={() => setRaw((v) => !v)}>{raw ? 'Hide recorded JSON' : 'Show recorded JSON'}</button>
        {raw && <pre className="ee-code mt-2 max-h-[320px] overflow-auto whitespace-pre-wrap break-words">{JSON.stringify(detail, null, 2)}</pre>}
      </div>
    </div>
  )
}
