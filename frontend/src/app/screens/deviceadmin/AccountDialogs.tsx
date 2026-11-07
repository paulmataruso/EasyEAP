// Local device-admin accounts: create, edit, password, authenticator code, unlock, delete. Passwords follow the
// backend's rule (app/admin/passwords.py): length, not composition; 8 characters is enough with an authenticator code.
import { useEffect, useId, useState, type FormEvent } from 'react'
import { KeyRound, LockOpen, ShieldCheck, ShieldOff, Trash2 } from 'lucide-react'
import { errorField } from '../../api/client'
import { groupSecret } from '../../api/account'
import {
  parseSites, passwordProblem, privLabel, statusLabels, useCreateAccount, useDeleteAccount, useSetAccountPassword, useTotpConfirm, useTotpRemove,
  useTotpSetup, useUnlockAccount, useUpdateAccount, usernameProblem, type AccountStatus, type AdminAccount, type AdminRole,
} from '../../api/deviceAdmin'
import { useTenant } from '../../api/tenant'
import { fmtDateTime } from '../../lib/format'
import { Btn, Callout, Chip, CopyButton, EDialog, ESelect, ESwitch, Field, SectionHeader, errorMessage, toast, type Tone } from '../../ui'
import { QrCode } from '../account/QrCode'

export const statusTone: Record<AccountStatus, Tone> = { active: 'valid', disabled: 'neutral', expired: 'warn', locked: 'crit', no_password: 'warn' }

/** The date part, local time, for <input type="date">. */
const dateInput = (iso: string | null) => {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}
/** The end of that day, local time. */
const dateOut = (v: string) => (v ? new Date(`${v}T23:59:59`).toISOString() : null)

type Err = { field: string; message: string } | null

function RoleSelect({ id, roles, value, onChange, error }: { id: string; roles: AdminRole[]; value: string; onChange: (v: string) => void; error?: string | null }) {
  return (
    <Field label="Role" htmlFor={id} error={error} hint="The role’s privilege level is what the device gives at login (15 is full access).">
      <ESelect id={id} label="Role" className="w-full" value={value} onChange={onChange} placeholder="Choose a role"
        options={roles.map((r) => ({ value: r.id, label: <>{r.name}<span className="ee-ink-3 ml-1.5">level {privLabel(r.priv_lvl)}</span></> }))} />
    </Field>
  )
}

function PasswordFields({ id, password, confirm, setPassword, setConfirm, error, totp, label = 'Password' }: {
  id: string; password: string; confirm: string; setPassword: (v: string) => void; setConfirm: (v: string) => void; error?: string | null; totp: boolean; label?: string
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label={label} htmlFor={`${id}-pw`} error={error} hint={totp ? 'At least 8 characters: the account also needs an authenticator code.' : 'At least 15 characters. A phrase of several words works well.'}>
        <input id={`${id}-pw`} type="password" className="ee-input" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" maxLength={128} />
      </Field>
      <Field label="Confirm" htmlFor={`${id}-pc`}>
        <input id={`${id}-pc`} type="password" className="ee-input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" maxLength={128} />
      </Field>
    </div>
  )
}

function checkPassword(password: string, confirm: string, username: string, totp: boolean): string | null {
  return passwordProblem(password, username, totp) ?? (password !== confirm ? 'The passwords don’t match.' : null)
}

// ── Create ──────────────────────────────────────────────────────────────

export function NewAccountDialog({ open, roles, onClose, onCreated }: { open: boolean; roles: AdminRole[]; onClose: () => void; onCreated: (a: AdminAccount) => void }) {
  const { tid } = useTenant()
  const id = useId()
  const create = useCreateAccount(tid)
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [roleId, setRoleId] = useState('')
  const [sites, setSites] = useState('')
  const [expires, setExpires] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<Err>(null)
  useEffect(() => {
    if (!open) return
    setUsername(''); setDisplayName(''); setEmail(''); setSites(''); setExpires(''); setPassword(''); setConfirm(''); setError(null)
    setRoleId(roles.find((r) => r.builtin && r.priv_lvl === 1)?.id ?? roles[0]?.id ?? '')
  }, [open, roles])
  const err = (f: string) => (error?.field === f ? error.message : null)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    const name = username.trim().toLowerCase()
    const bad = usernameProblem(name)
    if (bad) return setError({ field: 'username', message: bad })
    if (!roleId) return setError({ field: 'role_id', message: 'Choose a role.' })
    if (password || confirm) {
      const p = checkPassword(password, confirm, name, false)
      if (p) return setError({ field: 'password', message: p })
    }
    create.mutate({ username: name, display_name: displayName.trim(), email: email.trim(), role_id: roleId, sites: parseSites(sites), expires_at: dateOut(expires), password: password || undefined }, {
      onSuccess: (r) => { toast('Account created', password ? 'It can log in to devices within about 15 seconds.' : 'Set a password before it can log in.'); onCreated(r.user) },
      onError: (e2) => setError({ field: errorField(e2) ?? '', message: errorMessage(e2) }),
    })
  }
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} wide title="New device admin account"
      description="An EasyEAP account for logging in to switches and controllers, for people or contractors who aren’t in the directory."
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" type="submit" form={`${id}-f`} busy={create.isPending}>Create account</Btn></>}>
      <form id={`${id}-f`} noValidate className="space-y-4" onSubmit={submit}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Username" htmlFor={`${id}-u`} error={err('username')} hint="What they type at the device’s login prompt.">
            <input id={`${id}-u`} className="ee-input ee-mono" value={username} onChange={(e) => setUsername(e.target.value)} maxLength={64} autoComplete="off" spellCheck={false} placeholder="jsmith-net" />
          </Field>
          <Field label="Name" htmlFor={`${id}-n`} optional>
            <input id={`${id}-n`} className="ee-input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={120} autoComplete="off" />
          </Field>
          <Field label="Email" htmlFor={`${id}-e`} optional>
            <input id={`${id}-e`} type="email" className="ee-input" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} autoComplete="off" />
          </Field>
          <RoleSelect id={`${id}-r`} roles={roles} value={roleId} onChange={setRoleId} error={err('role_id')} />
          <Field label="Sites" htmlFor={`${id}-s`} optional error={err('sites')} hint="Comma-separated. Empty: every device. Otherwise only devices at these sites.">
            <input id={`${id}-s`} className="ee-input" value={sites} onChange={(e) => setSites(e.target.value)} autoComplete="off" placeholder="hq, branch-1" />
          </Field>
          <Field label="Expires" htmlFor={`${id}-x`} optional error={err('expires_at')} hint="For contractors: logins stop at the end of this day.">
            <input id={`${id}-x`} type="date" className="ee-input" value={expires} onChange={(e) => setExpires(e.target.value)} />
          </Field>
        </div>
        <PasswordFields id={id} password={password} confirm={confirm} setPassword={setPassword} setConfirm={setConfirm} error={err('password')} totp={false} label="Password (optional)" />
        <p className="ee-small ee-ink-3">Leave the password empty to add an authenticator code first: with a code, 8 characters is enough.</p>
        {error && !['username', 'role_id', 'password', 'sites', 'expires_at'].includes(error.field) && <Callout tone="crit" title="The account wasn’t created">{error.message}</Callout>}
      </form>
    </EDialog>
  )
}

// ── Manage ──────────────────────────────────────────────────────────────

export function AccountDialog({ account, roles, onClose }: { account: AdminAccount | null; roles: AdminRole[]; onClose: () => void }) {
  return (
    <EDialog open={!!account} onOpenChange={(o) => !o && onClose()} wide
      title={account ? <span className="flex flex-wrap items-center gap-2"><span className="ee-mono">{account.username}</span><Chip tone={statusTone[account.status]}>{statusLabels[account.status]}</Chip></span> : ''}
      description={account ? [account.display_name, account.email].filter(Boolean).join(' · ') || 'Local device admin account' : undefined}
      footer={<Btn onClick={onClose}>Close</Btn>}>
      {account && <AccountBody key={account.id} account={account} roles={roles} onDeleted={onClose} />}
    </EDialog>
  )
}

function AccountBody({ account, roles, onDeleted }: { account: AdminAccount; roles: AdminRole[]; onDeleted: () => void }) {
  const { tid, can } = useTenant()
  const write = can('admin:write')
  return (
    <div className="space-y-6">
      {account.status === 'locked' && <UnlockCallout account={account} write={write} />}
      {account.clashes_with_directory && (
        <Callout tone="warn">A directory user with the same name can log in through a group mapping. On devices this local account wins: rename one of them so it’s clear who logged in.</Callout>
      )}
      <DetailsSection account={account} roles={roles} write={write} />
      {write && <PasswordSection account={account} />}
      {write && <TotpSection account={account} />}
      <p className="ee-small ee-ink-3">Created {fmtDateTime(account.created_at)}{account.created_by ? ` by ${account.created_by}` : ''} · last login {account.last_login_at ? fmtDateTime(account.last_login_at) : 'never'}</p>
      {write && <DeleteSection account={account} onDeleted={onDeleted} tid={tid} />}
    </div>
  )
}

function UnlockCallout({ account, write }: { account: AdminAccount; write: boolean }) {
  const { tid } = useTenant()
  const unlock = useUnlockAccount(tid)
  return (
    <Callout tone="crit" title="Locked after too many failed logins"
      action={write ? <Btn size="sm" busy={unlock.isPending} onClick={() => unlock.mutate(account.id, {
        onSuccess: () => toast('Account unlocked', 'Devices accept it again within about 15 seconds.'),
        onError: (e) => toast('It wasn’t unlocked', errorMessage(e), 'crit'),
      })}><LockOpen aria-hidden />Unlock</Btn> : undefined}>
      Ten failures in 15 minutes lock the account{account.locked_until ? ` until ${fmtDateTime(account.locked_until)}` : ''}. Check the Admin log for where the attempts came from before you unlock it.
    </Callout>
  )
}

function DetailsSection({ account, roles, write }: { account: AdminAccount; roles: AdminRole[]; write: boolean }) {
  const { tid } = useTenant()
  const id = useId()
  const update = useUpdateAccount(tid)
  const [displayName, setDisplayName] = useState(account.display_name)
  const [email, setEmail] = useState(account.email)
  const [roleId, setRoleId] = useState(account.role_id)
  const [sites, setSites] = useState(account.sites.join(', '))
  const [expires, setExpires] = useState(dateInput(account.expires_at))
  const [enabled, setEnabled] = useState(account.enabled)
  const [error, setError] = useState<Err>(null)
  const err = (f: string) => (error?.field === f ? error.message : null)
  const save = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    update.mutate({ id: account.id, body: { display_name: displayName.trim(), email: email.trim(), role_id: roleId, sites: parseSites(sites), enabled, expires_at: dateOut(expires) } }, {
      onSuccess: () => toast('Account saved', 'Devices use the change within about 15 seconds.'),
      onError: (e2) => setError({ field: errorField(e2) ?? '', message: errorMessage(e2) }),
    })
  }
  return (
    <section aria-labelledby={`${id}-h`}>
      <SectionHeader id={`${id}-h`} level={3} title="Details" />
      <form noValidate className="space-y-4" onSubmit={save}>
        <fieldset disabled={!write} className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" htmlFor={`${id}-n`} optional>
            <input id={`${id}-n`} className="ee-input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={120} autoComplete="off" />
          </Field>
          <Field label="Email" htmlFor={`${id}-e`} optional>
            <input id={`${id}-e`} type="email" className="ee-input" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} autoComplete="off" />
          </Field>
          <RoleSelect id={`${id}-r`} roles={roles} value={roleId} onChange={setRoleId} error={err('role_id')} />
          <Field label="Sites" htmlFor={`${id}-s`} optional hint="Comma-separated. Empty: every device.">
            <input id={`${id}-s`} className="ee-input" value={sites} onChange={(e) => setSites(e.target.value)} autoComplete="off" />
          </Field>
          <Field label="Expires" htmlFor={`${id}-x`} optional>
            <input id={`${id}-x`} type="date" className="ee-input" value={expires} onChange={(e) => setExpires(e.target.value)} />
          </Field>
          <div className="flex items-start justify-between gap-6 sm:pt-6">
            <div className="min-w-0">
              <p className="text-[13px] font-semibold">Can log in</p>
              <p className="ee-small ee-ink-3 mt-0.5">{enabled ? 'Devices accept this account.' : 'Devices refuse this account.'}</p>
            </div>
            <ESwitch checked={enabled} onChange={setEnabled} label="Can log in" disabled={!write} />
          </div>
        </fieldset>
        {error && error.field !== 'role_id' && <Callout tone="crit" title="The account wasn’t saved">{error.message}</Callout>}
        {write && <Btn type="submit" variant="primary" size="sm" busy={update.isPending}>Save details</Btn>}
      </form>
    </section>
  )
}

function PasswordSection({ account }: { account: AdminAccount }) {
  const { tid } = useTenant()
  const id = useId()
  const set = useSetAccountPassword(tid)
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    const p = checkPassword(password, confirm, account.username, account.totp_enabled)
    if (p) return setError(p)
    set.mutate({ id: account.id, password }, {
      onSuccess: () => { setPassword(''); setConfirm(''); toast('Password set', 'Devices accept it within about 15 seconds.') },
      onError: (e2) => setError(errorMessage(e2)),
    })
  }
  return (
    <section aria-labelledby={`${id}-h`} className="border-t border-[var(--ee-line)] pt-5">
      <SectionHeader id={`${id}-h`} level={3} title="Password" meta={account.password_set_at ? `Set ${fmtDateTime(account.password_set_at)}` : 'Not set: the account can’t log in yet'} />
      <form noValidate className="space-y-3" onSubmit={submit}>
        <PasswordFields id={id} password={password} confirm={confirm} setPassword={setPassword} setConfirm={setConfirm} error={error} totp={account.totp_enabled}
          label={account.has_password ? 'New password' : 'Password'} />
        <Btn type="submit" size="sm" busy={set.isPending}><KeyRound aria-hidden />{account.has_password ? 'Change password' : 'Set password'}</Btn>
      </form>
    </section>
  )
}

function TotpSection({ account }: { account: AdminAccount }) {
  const { tid } = useTenant()
  const id = useId()
  const setup = useTotpSetup(tid)
  const confirmCode = useTotpConfirm(tid)
  const remove = useTotpRemove(tid)
  const [pending, setPending] = useState<{ secret: string; otpauth_uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [removing, setRemoving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const turnOn = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!/^\d{6}$/.test(code.replace(/\s/g, ''))) return setError('Enter the 6-digit code the authenticator app shows.')
    confirmCode.mutate({ id: account.id, code: code.replace(/\s/g, '') }, {
      onSuccess: () => { setPending(null); setCode(''); toast('Authenticator code on', 'At the device’s password prompt, type the password followed by the current code.') },
      onError: (e2) => setError(errorMessage(e2)),
    })
  }
  const turnOff = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    const p = checkPassword(password, confirm, account.username, false)
    if (p) return setError(p)
    remove.mutate({ id: account.id, password }, {
      onSuccess: () => { setRemoving(false); setPassword(''); setConfirm(''); toast('Authenticator code removed', 'The account now logs in with the new password alone.', 'warn') },
      onError: (e2) => setError(errorMessage(e2)),
    })
  }
  return (
    <section aria-labelledby={`${id}-h`} className="border-t border-[var(--ee-line)] pt-5">
      <SectionHeader id={`${id}-h`} level={3} title="Authenticator code"
        actions={account.totp_enabled ? <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>On</Chip> : <Chip tone="neutral" icon={<ShieldOff aria-hidden />}>Off</Chip>} />
      {account.totp_enabled ? (
        removing ? (
          <form noValidate className="space-y-3" onSubmit={turnOff}>
            <p className="text-[13.5px] ee-ink-2">Without a code the password must be at least 15 characters, so set a new one.</p>
            <PasswordFields id={`${id}-r`} password={password} confirm={confirm} setPassword={setPassword} setConfirm={setConfirm} error={error} totp={false} label="New password" />
            <div className="flex flex-wrap gap-2">
              <Btn type="submit" size="sm" variant="danger" busy={remove.isPending}><ShieldOff aria-hidden />Remove the code</Btn>
              <Btn size="sm" variant="ghost" onClick={() => { setRemoving(false); setError(null) }}>Cancel</Btn>
            </div>
          </form>
        ) : (
          <div className="space-y-3">
            <p className="text-[13.5px] ee-ink-2">At the device’s password prompt, type the password and then the 6-digit code with nothing between them. Each code works once.</p>
            <Btn size="sm" onClick={() => setRemoving(true)}><ShieldOff aria-hidden />Remove…</Btn>
          </div>
        )
      ) : !pending ? (
        <div className="space-y-3">
          <p className="text-[13.5px] ee-ink-2 max-w-[65ch]">Add a code from an authenticator app to this account’s logins. Devices see one password field, so the code is typed straight after the password.</p>
          {error && <Callout tone="crit">{error}</Callout>}
          <Btn size="sm" busy={setup.isPending} onClick={() => { setError(null); setup.mutate(account.id, { onSuccess: (r) => { setPending(r); setCode('') }, onError: (e) => setError(errorMessage(e)) }) }}>
            <ShieldCheck aria-hidden />Set up an authenticator code
          </Btn>
        </div>
      ) : (
        <form noValidate className="space-y-4" onSubmit={turnOn}>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
            <QrCode text={pending.otpauth_uri} label={`QR code for ${account.username}’s authenticator app`} />
            <div className="min-w-0 flex-1 space-y-3">
              <p className="ee-small ee-ink-2">Have {account.display_name || account.username} scan the code, or enter this key as a time-based (TOTP) account.</p>
              <div className="flex flex-wrap items-center gap-2">
                <code className="ee-mono rounded-[7px] border border-[var(--ee-line-2)] bg-[rgba(6,9,17,0.6)] px-3 py-2 text-[14px] tracking-[0.06em] break-all" aria-label="Setup key">{groupSecret(pending.secret)}</code>
                <CopyButton text={pending.secret} what="setup key" />
              </div>
              <Field label="6-digit code" htmlFor={`${id}-c`}>
                <input id={`${id}-c`} className="ee-input ee-num w-[160px] tracking-[0.2em]" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ''))} />
              </Field>
            </div>
          </div>
          {error && <Callout tone="crit">{error}</Callout>}
          <div className="flex flex-wrap gap-2">
            <Btn type="submit" size="sm" variant="primary" busy={confirmCode.isPending}><ShieldCheck aria-hidden />Turn on</Btn>
            <Btn size="sm" variant="ghost" onClick={() => { setPending(null); setError(null) }}>Cancel</Btn>
          </div>
        </form>
      )}
    </section>
  )
}

function DeleteSection({ account, onDeleted, tid }: { account: AdminAccount; onDeleted: () => void; tid: string }) {
  const del = useDeleteAccount(tid)
  const [asking, setAsking] = useState(false)
  return (
    <section aria-label="Delete" className="border-t border-[var(--ee-line)] pt-5">
      {!asking ? <Btn size="sm" variant="danger" onClick={() => setAsking(true)}><Trash2 aria-hidden />Delete account…</Btn> : (
        <Callout tone="crit" title={`Delete ${account.username}?`}
          action={<div className="flex gap-2">
            <Btn size="sm" variant="ghost" onClick={() => setAsking(false)}>Cancel</Btn>
            <Btn size="sm" variant="danger" busy={del.isPending} onClick={() => del.mutate(account.id, {
              onSuccess: () => { toast('Account deleted'); onDeleted() },
              onError: (e) => toast('It wasn’t deleted', errorMessage(e), 'crit'),
            })}><Trash2 aria-hidden />Delete</Btn>
          </div>}>
          Devices refuse it within about 15 seconds. Its entries in the Admin log stay. To stop logins for a while, turn off “Can log in” instead.
        </Callout>
      )}
    </section>
  )
}
