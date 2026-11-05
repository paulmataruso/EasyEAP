// Administrator dialogs: create (with a generated temporary password shown once), edit access, deactivate and
// delete. Every change goes through a review step that states exactly what will change.
import { useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, UserPlus } from 'lucide-react'
import { qk } from '../../api/keys'
import { adminsApi, type Admin, type AdminGrant, type AdminsResponse } from '../../api/governance'
import type { TenantListItem } from '../../api/types'
import { Btn, Callout, ConfirmText, EDialog, ESelect, Field, OneTimeSecret, errorMessage, toast } from '../../ui'

const NONE = 'none'

export function roleLabel(roles: AdminsResponse['roles'], id: string | null | undefined): string {
  if (!id) return 'None'
  return [...roles.platform, ...roles.tenant].find((r) => r.id === id)?.label ?? id
}

/** 4×4 groups from an unambiguous alphabet: ~80 bits, meets the API's password policy. */
function generatePassword(): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = new Uint32Array(16)
  crypto.getRandomValues(bytes)
  const chars = Array.from(bytes, (b) => alphabet[b % alphabet.length])
  return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join('')).join('-')
}

function passwordProblems(pw: string, email: string): string[] {
  const p: string[] = []
  if (pw.length < 12) p.push('Use at least 12 characters.')
  const local = email.split('@')[0]?.toLowerCase()
  if (local && pw.toLowerCase().includes(local)) p.push('Don’t include the email name in the password.')
  if (new Set(pw).size < 6) p.push('Use a less repetitive password.')
  return p
}

// ── Access editor (platform role + tenant grants) ────────────────────────

interface Access { platformRole: string; grants: Record<string, string> }
const accessOf = (a: Admin | null): Access => ({ platformRole: a?.platform_role ?? NONE, grants: Object.fromEntries((a?.grants ?? []).map((g) => [g.tenant_id, g.role])) })
const grantsList = (x: Access): AdminGrant[] => Object.entries(x.grants).filter(([, r]) => r && r !== NONE).map(([tenant_id, role]) => ({ tenant_id, role }))

function AccessEditor({ value, onChange, roles, tenants, lockPlatform }: { value: Access; onChange: (v: Access) => void; roles: AdminsResponse['roles']; tenants: TenantListItem[]; lockPlatform?: boolean }) {
  const platformAll = value.platformRole !== NONE
  return (
    <div className="space-y-4">
      <Field label="Platform role" htmlFor="adm-prole" hint={lockPlatform ? 'You can’t remove your own Super Administrator role.' : 'Platform roles apply to every tenant, including tenants created later.'}>
        <ESelect id="adm-prole" label="Platform role" value={value.platformRole} onChange={(v) => onChange({ ...value, platformRole: v })} disabled={lockPlatform} className="w-full"
          options={[{ value: NONE, label: 'None: only the tenants granted below' }, ...roles.platform.map((r) => ({ value: r.id, label: r.label }))]} />
      </Field>
      <div>
        <p className="text-[13px] font-semibold">Tenant roles</p>
        <p className="ee-small ee-ink-3 mt-0.5">{platformAll ? 'The platform role already covers every tenant. A tenant role adds nothing unless the platform role is removed.' : 'Grant a role per tenant. Tenants without a role are invisible to this administrator.'}</p>
        {tenants.length === 0 ? <p className="ee-small ee-ink-3 mt-2">No tenants exist yet.</p> : (
          <ul className="mt-2 divide-y divide-[var(--ee-line)] rounded-[8px] border border-[var(--ee-line)]">
            {tenants.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                <span className="min-w-0 text-[13px] font-medium">{t.name}</span>
                <ESelect label={`Role in ${t.name}`} value={value.grants[t.id] ?? NONE} onChange={(v) => onChange({ ...value, grants: { ...value.grants, [t.id]: v } })} className="min-w-[210px]"
                  options={[{ value: NONE, label: 'No access' }, ...roles.tenant.map((r) => ({ value: r.id, label: r.label }))]} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function accessChanges(before: Access, after: Access, roles: AdminsResponse['roles'], tenants: TenantListItem[]) {
  const lines: Array<{ what: string; from: string; to: string }> = []
  const lbl = (id: string) => (id === NONE ? 'None' : roleLabel(roles, id))
  if (before.platformRole !== after.platformRole) lines.push({ what: 'Platform role', from: lbl(before.platformRole), to: lbl(after.platformRole) })
  for (const t of tenants) {
    const b = before.grants[t.id] ?? NONE, a = after.grants[t.id] ?? NONE
    if (b !== a) lines.push({ what: t.name, from: b === NONE ? 'No access' : lbl(b), to: a === NONE ? 'No access' : lbl(a) })
  }
  return lines
}

function ChangeTable({ lines }: { lines: Array<{ what: string; from: string; to: string }> }) {
  return (
    <ul className="divide-y divide-[var(--ee-line)] rounded-[8px] border border-[var(--ee-line)]">
      {lines.map((l) => (
        <li key={l.what} className="grid gap-1 px-3 py-2 sm:grid-cols-[150px_minmax(0,1fr)]">
          <span className="ee-small ee-ink-3">{l.what}</span>
          <span className="flex flex-wrap items-center gap-1.5 text-[13px]"><span className="ee-ink-2">{l.from}</span><ArrowRight className="size-3.5 ee-ink-3" aria-label="to" /><span className="font-medium">{l.to}</span></span>
        </li>
      ))}
    </ul>
  )
}

// ── Create ───────────────────────────────────────────────────────────────

export function CreateAdminDialog({ open, onOpenChange, data, tenants }: { open: boolean; onOpenChange: (o: boolean) => void; data: AdminsResponse; tenants: TenantListItem[] }) {
  const [secret, setSecret] = useState<{ email: string; password: string } | null>(null)
  const [ack, setAck] = useState(false)
  const block = !!secret && !ack
  return (
    <EDialog open={open} onOpenChange={(o) => { if (!o) { setSecret(null); setAck(false) } onOpenChange(o) }} blockDismiss={block} wide
      title={secret ? 'Temporary password' : 'Add an administrator'}
      description={secret ? `Give this to ${secret.email} through a separate channel.` : 'They sign in with this email and the password you set here.'}
      footer={secret ? <Btn variant="primary" disabled={!ack} onClick={() => { setSecret(null); setAck(false); onOpenChange(false) }}>Done</Btn> : undefined}>
      {secret ? (
        <div className="space-y-3">
          <OneTimeSecret value={secret.password} what="temporary password" acknowledged={ack} onAcknowledge={setAck}
            note="EasyEAP shows this temporary password once and stores only a hash of it. Ask them to change it under Account after signing in and to turn on two-factor authentication." />
        </div>
      ) : open ? (
        <CreateForm data={data} tenants={tenants} onDone={(r) => { if (r) setSecret(r); else onOpenChange(false) }} onCancel={() => onOpenChange(false)} />
      ) : null}
    </EDialog>
  )
}

function CreateForm({ data, tenants, onDone, onCancel }: { data: AdminsResponse; tenants: TenantListItem[]; onDone: (secret: { email: string; password: string } | null) => void; onCancel: () => void }) {
  const qc = useQueryClient()
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [mode, setMode] = useState<'generate' | 'set'>('generate')
  const [pw, setPw] = useState('')
  const [access, setAccess] = useState<Access>(accessOf(null))
  const [step, setStep] = useState<'form' | 'review'>('form')
  const [tried, setTried] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const generated = useMemo(() => generatePassword(), [])
  const emailErr = !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim()) ? 'Enter a valid email address.' : data.admins.some((a) => a.email === email.trim().toLowerCase()) ? 'An administrator with this email already exists.' : null
  const nameErr = !name.trim() ? 'Enter their name.' : null
  const pwProblems = mode === 'set' ? passwordProblems(pw, email) : []
  const noAccess = access.platformRole === NONE && grantsList(access).length === 0
  const invalid = !!(emailErr || nameErr || pwProblems.length)
  const lines = accessChanges(accessOf(null), access, data.roles, tenants)

  const create = useMutation({
    mutationFn: () => adminsApi.create({
      email: email.trim(), display_name: name.trim(), password: mode === 'generate' ? generated : pw,
      platform_role: access.platformRole === NONE ? null : access.platformRole, grants: grantsList(access),
    }),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: qk.admins() })
      toast('Administrator added', `${a.email} can now sign in.`)
      onDone(mode === 'generate' ? { email: a.email, password: generated } : null)
    },
    onError: (e) => { setError(errorMessage(e)); setStep('form') },
  })

  if (step === 'review') {
    return (
      <div className="space-y-4">
        <p className="text-[13.5px]">Create <span className="font-semibold">{name.trim()}</span> ({email.trim().toLowerCase()}) with:</p>
        {lines.length ? <ChangeTable lines={lines} /> : <Callout tone="warn">No role yet: they can sign in but see no tenants until you grant one.</Callout>}
        <p className="ee-small ee-ink-2">{mode === 'generate' ? 'A temporary password is generated and shown once on the next screen.' : 'They sign in with the password you set.'}</p>
        <div className="-mx-6 -mb-5 flex flex-wrap justify-end gap-2 border-t border-[var(--ee-line)] px-6 py-4">
          <Btn onClick={() => setStep('form')} disabled={create.isPending}>Back</Btn>
          <Btn variant="primary" busy={create.isPending} onClick={() => create.mutate()}><UserPlus aria-hidden />Create administrator</Btn>
        </div>
      </div>
    )
  }

  return (
    <form className="space-y-5" noValidate onSubmit={(e) => { e.preventDefault(); setTried(true); setError(null); if (!invalid) setStep('review') }}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Email" htmlFor="adm-email" error={tried ? emailErr : null}>
          <input id="adm-email" type="email" className="ee-input" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" aria-invalid={(tried && !!emailErr) || undefined} />
        </Field>
        <Field label="Name" htmlFor="adm-name" error={tried ? nameErr : null}>
          <input id="adm-name" className="ee-input" value={name} maxLength={120} onChange={(e) => setName(e.target.value)} autoComplete="off" aria-invalid={(tried && !!nameErr) || undefined} />
        </Field>
      </div>
      <fieldset>
        <legend className="mb-1.5 text-[13px] font-semibold">Initial password</legend>
        <div className="flex flex-col gap-2">
          <label className="flex items-start gap-2.5 text-[13px]"><input type="radio" name="pwmode" className="ee-check mt-0.5" checked={mode === 'generate'} onChange={() => setMode('generate')} />
            <span>Generate a temporary password <span className="ee-small block ee-ink-3">Shown once after creating, for you to pass on.</span></span></label>
          <label className="flex items-start gap-2.5 text-[13px]"><input type="radio" name="pwmode" className="ee-check mt-0.5" checked={mode === 'set'} onChange={() => setMode('set')} />
            <span>Set a password now</span></label>
        </div>
        {mode === 'set' && (
          <div className="mt-3">
            <Field label="Password" htmlFor="adm-pw" error={tried && pwProblems.length ? pwProblems.join(' ') : null} hint="At least 12 characters, not repetitive, without the email name.">
              <input id="adm-pw" type="password" className="ee-input" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" aria-invalid={(tried && pwProblems.length > 0) || undefined} />
            </Field>
          </div>
        )}
      </fieldset>
      <AccessEditor value={access} onChange={setAccess} roles={data.roles} tenants={tenants} />
      {noAccess && <p className="ee-small text-[var(--ee-warn-ink)]">With no platform or tenant role they can sign in but see nothing.</p>}
      {error && <Callout tone="crit" title="Not created">{error}</Callout>}
      <div className="-mx-6 -mb-5 flex flex-wrap justify-end gap-2 border-t border-[var(--ee-line)] px-6 py-4">
        <Btn onClick={onCancel}>Cancel</Btn>
        <Btn type="submit" variant="primary">Review</Btn>
      </div>
    </form>
  )
}

// ── Edit access ──────────────────────────────────────────────────────────

export function EditAdminDialog({ admin, onClose, data, tenants, self }: { admin: Admin | null; onClose: () => void; data: AdminsResponse; tenants: TenantListItem[]; self: boolean }) {
  return (
    <EDialog open={!!admin} onOpenChange={(o) => { if (!o) onClose() }} wide title={admin ? `Edit ${admin.display_name}` : 'Edit administrator'}
      description={admin ? `${admin.email}. Changes apply at their next request; they don’t need to sign in again.` : undefined}>
      {admin && <EditForm key={admin.id} admin={admin} data={data} tenants={tenants} self={self} onClose={onClose} />}
    </EDialog>
  )
}

function EditForm({ admin, data, tenants, self, onClose }: { admin: Admin; data: AdminsResponse; tenants: TenantListItem[]; self: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const before = useMemo(() => accessOf(admin), [admin])
  const [name, setName] = useState(admin.display_name)
  const [access, setAccess] = useState<Access>(before)
  const [step, setStep] = useState<'form' | 'review'>('form')
  const [error, setError] = useState<string | null>(null)
  const lines = accessChanges(before, access, data.roles, tenants)
  if (name.trim() !== admin.display_name && name.trim()) lines.unshift({ what: 'Name', from: admin.display_name, to: name.trim() })
  const grantsChanged = JSON.stringify(grantsList(before).sort((a, b) => a.tenant_id.localeCompare(b.tenant_id))) !== JSON.stringify(grantsList(access).sort((a, b) => a.tenant_id.localeCompare(b.tenant_id)))
  const save = useMutation({
    mutationFn: () => adminsApi.update(admin.id, {
      ...(name.trim() && name.trim() !== admin.display_name ? { display_name: name.trim() } : {}),
      ...(access.platformRole !== before.platformRole ? (access.platformRole === NONE ? { clear_platform_role: true } : { platform_role: access.platformRole }) : {}),
      ...(grantsChanged ? { grants: grantsList(access) } : {}),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: qk.admins() }); toast('Administrator updated', `${admin.email}: ${lines.length === 1 ? '1 change' : `${lines.length} changes`} applied.`); onClose() },
    onError: (e) => { setError(errorMessage(e)); setStep('form') },
  })

  if (step === 'review') {
    return (
      <div className="space-y-4">
        <p className="text-[13.5px]">Apply these changes to {admin.email}?</p>
        <ChangeTable lines={lines} />
        <div className="-mx-6 -mb-5 flex flex-wrap justify-end gap-2 border-t border-[var(--ee-line)] px-6 py-4">
          <Btn onClick={() => setStep('form')} disabled={save.isPending}>Back</Btn>
          <Btn variant="primary" busy={save.isPending} onClick={() => save.mutate()}>Apply {lines.length === 1 ? 'change' : `${lines.length} changes`}</Btn>
        </div>
      </div>
    )
  }
  return (
    <form className="space-y-5" noValidate onSubmit={(e) => { e.preventDefault(); setError(null); if (lines.length) setStep('review') }}>
      <Field label="Name" htmlFor="adm-edit-name" error={!name.trim() ? 'Enter their name.' : null}>
        <input id="adm-edit-name" className="ee-input" value={name} maxLength={120} onChange={(e) => setName(e.target.value)} autoComplete="off" />
      </Field>
      <AccessEditor value={access} onChange={setAccess} roles={data.roles} tenants={tenants} lockPlatform={self} />
      {error && <Callout tone="crit" title="Not saved">{error}</Callout>}
      <div className="-mx-6 -mb-5 flex flex-wrap items-center justify-end gap-2 border-t border-[var(--ee-line)] px-6 py-4">
        {!lines.length && <span className="ee-small ee-ink-3 mr-auto">No changes yet.</span>}
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn type="submit" variant="primary" disabled={!lines.length || !name.trim()}>Review</Btn>
      </div>
    </form>
  )
}

// ── Deactivate / reactivate / delete ────────────────────────────────────

export function ActiveDialog({ admin, onClose }: { admin: Admin | null; onClose: () => void }) {
  const qc = useQueryClient()
  const deactivate = !!admin?.is_active
  const m = useMutation({
    mutationFn: () => adminsApi.update(admin!.id, { is_active: !admin!.is_active }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: qk.admins() }); toast(deactivate ? 'Administrator deactivated' : 'Administrator reactivated', deactivate ? `${admin!.email} was signed out and can’t sign in.` : `${admin!.email} can sign in again.`); onClose() },
    onError: (e) => toast('Not changed', errorMessage(e), 'crit'),
  })
  return (
    <EDialog open={!!admin} onOpenChange={(o) => { if (!o) onClose() }} risk={deactivate ? 'warn' : undefined}
      title={admin ? `${deactivate ? 'Deactivate' : 'Reactivate'} ${admin.display_name}?` : ''}
      description={admin?.email}
      footer={<><Btn onClick={onClose} disabled={m.isPending}>Cancel</Btn><Btn variant={deactivate ? 'danger-solid' : 'primary'} busy={m.isPending} onClick={() => m.mutate()}>{deactivate ? 'Deactivate' : 'Reactivate'}</Btn></>}>
      <p className="ee-small ee-ink-2">{deactivate
        ? 'Their sessions end now and they can’t sign in. Their roles are kept, so reactivating restores the same access. Changes they made stay in the audit log.'
        : 'They can sign in again with their existing password and keep the roles they had.'}</p>
    </EDialog>
  )
}

export function DeleteAdminDialog({ admin, onClose }: { admin: Admin | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [typed, setTyped] = useState('')
  const m = useMutation({
    mutationFn: () => adminsApi.remove(admin!.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: qk.admins() }); toast('Administrator deleted', `${admin!.email} no longer exists. Their past actions stay in the audit log.`); setTyped(''); onClose() },
    onError: (e) => toast('Not deleted', errorMessage(e), 'crit'),
  })
  return (
    <EDialog open={!!admin} onOpenChange={(o) => { if (!o) { setTyped(''); onClose() } }} risk="crit" title={admin ? `Delete ${admin.display_name}?` : ''}
      description="This can’t be undone. Deactivating keeps the account if you might need it again."
      footer={<><Btn onClick={onClose} disabled={m.isPending}>Cancel</Btn><Btn variant="danger-solid" busy={m.isPending} disabled={typed.trim().toLowerCase() !== admin?.email} onClick={() => m.mutate()}>Delete administrator</Btn></>}>
      {admin && <ConfirmText expected={admin.email} value={typed} onChange={setTyped} label="Email" />}
    </EDialog>
  )
}

export function ResetMfaDialog({ admin, onClose }: { admin: Admin | null; onClose: () => void }) {
  const qc = useQueryClient()
  const m = useMutation({
    mutationFn: () => adminsApi.resetMfa(admin!.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: qk.admins() }); toast('Two-factor reset', `${admin!.email} was signed out. They sign in with their password and set up two-factor again.`); onClose() },
    onError: (e) => toast('Not reset', errorMessage(e), 'crit'),
  })
  return (
    <EDialog open={!!admin} onOpenChange={(o) => { if (!o) onClose() }} risk="warn"
      title={admin ? `Reset two-factor for ${admin.display_name}?` : ''}
      description={admin?.email}
      footer={<><Btn onClick={onClose} disabled={m.isPending}>Cancel</Btn><Btn variant="danger-solid" busy={m.isPending} onClick={() => m.mutate()}>Reset two-factor</Btn></>}>
      <p className="ee-small ee-ink-2">Use this when they’ve lost their authenticator. Their two-factor is turned off and their sessions end now. Until they set it up again, their password alone signs them in, so confirm who is asking before you reset it.</p>
    </EDialog>
  )
}

