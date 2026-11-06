// The signed-in administrator's account: profile and session, password change, two-factor authentication.
import { useId, useMemo, useState, type FormEvent } from 'react'
import { Check, KeyRound, ShieldCheck, ShieldOff, X } from 'lucide-react'
import { PASSWORD_MIN, groupSecret, passwordProblems, useChangePassword, useMfaDisable, useMfaEnable, useMfaSetup, type MfaSetup } from '../api/account'
import { useSession } from '../api/session'
import { fmtDateTime, relative } from '../lib/format'
import { useNow } from '../lib/useNow'
import { Btn, Callout, Chip, CopyButton, Dl, Field, PageHeader, Panel, SectionHeader, errorMessage, toast } from '../ui'
import { qrMatrix, qrPath } from './account/qr'

export default function Account() {
  const { me } = useSession()
  const now = useNow()
  if (!me) return null
  const role = me.platform_role_label
    ?? (me.grants.length ? me.grants.map((g) => `${g.role_label}, ${g.tenant_name}`).join('; ') : 'No role assigned')
  return (
    <div>
      <PageHeader title="Your account" lede={me.email} />
      <div className="grid max-w-[1180px] items-start gap-6 xl:grid-cols-2">
        <div className="space-y-6">
          <Panel className="p-5 sm:p-6" aria-labelledby="acc-prof-h">
            <SectionHeader id="acc-prof-h" title="Profile" />
            <Dl cols={2} items={[
              ['Name', me.display_name],
              ['Email', <span className="break-all">{me.email}</span>],
              ['Role', role, 'wide'],
              ['Two-factor authentication', me.mfa_enabled ? <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>On</Chip> : <Chip tone={me.platform_role === 'platform_owner' ? 'crit' : 'warn'} icon={<ShieldOff aria-hidden />}>Off</Chip>],
              ['This session ends', <span title={fmtDateTime(me.session_expires_at)}>{fmtDateTime(me.session_expires_at)} <span className="ee-ink-3">({relative(me.session_expires_at, now)})</span></span>],
            ]} />
            <p className="ee-small ee-ink-3 mt-4">To change your name or email, ask a Super Administrator. Sessions end at the time shown; sign in again after that.</p>
          </Panel>
          <PasswordPanel email={me.email} />
        </div>
        <TwoFactorPanel enabled={me.mfa_enabled} email={me.email} />
      </div>
    </div>
  )
}

function PasswordPanel({ email }: { email: string }) {
  const id = useId()
  const change = useChangePassword()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const problems = passwordProblems(next, email)
  const mismatch = confirm.length > 0 && confirm !== next
  const rules = [
    { ok: next.length >= PASSWORD_MIN, label: `At least ${PASSWORD_MIN} characters` },
    { ok: next.length > 0 && !problems.some((p) => p.includes('email')), label: 'Doesn’t contain your email name' },
    { ok: next.length > 0 && new Set(next).size >= 6, label: 'At least 6 different characters' },
  ]
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    setError(null)
    if (!current || problems.length || next !== confirm) return
    change.mutate({ current_password: current, new_password: next }, {
      onSuccess: () => {
        setCurrent(''); setNext(''); setConfirm(''); setTouched(false)
        toast('Password changed', 'Your other sessions were signed out. This one stays signed in.')
      },
      onError: (err) => setError(errorMessage(err)),
    })
  }
  return (
    <Panel className="p-5 sm:p-6" aria-labelledby="acc-pw-h">
      <SectionHeader id="acc-pw-h" title="Change password" />
      <form onSubmit={submit} noValidate className="space-y-4">
        <input type="email" autoComplete="username" value={email} readOnly hidden />
        <Field label="Current password" htmlFor={`${id}-cur`} error={touched && !current ? 'Enter your current password.' : null}>
          <input id={`${id}-cur`} type="password" className="ee-input" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} aria-invalid={(touched && !current) || undefined} />
        </Field>
        <Field label="New password" htmlFor={`${id}-new`} error={touched && problems.length ? problems.join(' ') : null}>
          <input id={`${id}-new`} type="password" className="ee-input" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} aria-invalid={(touched && problems.length > 0) || undefined} aria-describedby={`${id}-rules`} />
        </Field>
        <ul id={`${id}-rules`} className="space-y-1 text-[12.5px]" aria-label="Password requirements">
          {rules.map((r) => (
            <li key={r.label} className={r.ok ? 'flex items-center gap-1.5 text-[var(--ee-valid-ink)]' : 'flex items-center gap-1.5 ee-ink-3'}>
              {r.ok ? <Check className="size-3.5" aria-hidden /> : <X className="size-3.5" aria-hidden />}{r.label}<span className="sr-only">{r.ok ? ': met' : ': not met'}</span>
            </li>
          ))}
        </ul>
        <Field label="Confirm new password" htmlFor={`${id}-conf`} error={(touched || mismatch) && confirm !== next ? 'The passwords don’t match.' : null}>
          <input id={`${id}-conf`} type="password" className="ee-input" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} aria-invalid={((touched || mismatch) && confirm !== next) || undefined} />
        </Field>
        {error && <Callout tone="crit" title="Your password wasn’t changed">{error}</Callout>}
        <div className="flex flex-wrap items-center gap-3">
          <Btn type="submit" variant="primary" busy={change.isPending}><KeyRound aria-hidden />Change password</Btn>
          <p className="ee-small ee-ink-3">Signs out your other sessions; this one stays signed in.</p>
        </div>
      </form>
    </Panel>
  )
}

function Qr({ text }: { text: string }) {
  const qr = useMemo(() => { const m = qrMatrix(text); return m ? qrPath(m) : null }, [text])
  if (!qr) return null
  return (
    <svg viewBox={`0 0 ${qr.size} ${qr.size}`} className="size-[184px] shrink-0 rounded-[8px]" role="img" aria-label="QR code for your authenticator app" shapeRendering="crispEdges">
      <rect width={qr.size} height={qr.size} fill="#ffffff" />
      <path d={qr.d} fill="#0b0f1a" />
    </svg>
  )
}

function TwoFactorPanel({ enabled, email }: { enabled: boolean; email: string }) {
  const id = useId()
  const setup = useMfaSetup()
  const enable = useMfaEnable()
  const disable = useMfaDisable()
  const [pending, setPending] = useState<MfaSetup | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const codeOk = /^\d{6}$/.test(code.replace(/\s/g, ''))

  const start = () => {
    setError(null)
    setup.mutate(undefined, { onSuccess: (r) => { setPending(r); setCode('') }, onError: (e) => setError(errorMessage(e)) })
  }
  const turnOn = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!codeOk) { setError('Enter the 6-digit code your authenticator app shows.'); return }
    enable.mutate(code.replace(/\s/g, ''), {
      onSuccess: () => { setPending(null); setCode(''); toast('Two-factor authentication is on', 'You’ll enter a code from your authenticator app each time you sign in.') },
      onError: (err) => setError(errorMessage(err)),
    })
  }
  const turnOff = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!codeOk) { setError('Enter the 6-digit code your authenticator app shows.'); return }
    disable.mutate(code.replace(/\s/g, ''), {
      onSuccess: () => { setCode(''); toast('Two-factor authentication is off', 'Sign-in now needs only your password. Turn it back on soon.', 'warn') },
      onError: (err) => setError(errorMessage(err)),
    })
  }

  return (
    <Panel className="p-5 sm:p-6" risk={enabled ? undefined : 'warn'} aria-labelledby="acc-mfa-h">
      <SectionHeader id="acc-mfa-h" title="Two-factor authentication"
        actions={enabled ? <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>On</Chip> : <Chip tone="warn" icon={<ShieldOff aria-hidden />}>Off</Chip>} />
      {enabled ? (
        <form onSubmit={turnOff} noValidate className="space-y-4">
          <p className="text-[13.5px] ee-ink-2">Each sign-in asks for a code from your authenticator app. To turn it off, enter a current code.</p>
          <Field label="Code from your authenticator app" htmlFor={`${id}-off`}>
            <input id={`${id}-off`} className="ee-input ee-num w-[160px] tracking-[0.2em]" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ''))} />
          </Field>
          {error && <Callout tone="crit">{error}</Callout>}
          <Btn type="submit" variant="danger" busy={disable.isPending}><ShieldOff aria-hidden />Turn off two-factor</Btn>
        </form>
      ) : !pending ? (
        <div className="space-y-4">
          <p className="text-[13.5px] ee-ink-2 max-w-[65ch]">Your account can issue certificates and change who gets on the network. Add a time-based code from an authenticator app (1Password, Microsoft Authenticator, Google Authenticator and others) to every sign-in.</p>
          {error && <Callout tone="crit">{error}</Callout>}
          <Btn variant="primary" busy={setup.isPending} onClick={start}><ShieldCheck aria-hidden />Set up two-factor</Btn>
        </div>
      ) : (
        <form onSubmit={turnOn} noValidate className="space-y-5">
          <section aria-labelledby={`${id}-s1`} className="space-y-3">
            <h3 id={`${id}-s1`} className="ee-h3">1. Add EasyEAP to your authenticator app</h3>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
              <Qr text={pending.otpauth_uri} />
              <div className="min-w-0 flex-1 space-y-3">
                <p className="ee-small ee-ink-2">Scan the code, or enter this key manually as a time-based (TOTP) account named {email}.</p>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="ee-mono rounded-[7px] border border-[var(--ee-line-2)] bg-[rgba(6,9,17,0.6)] px-3 py-2 text-[14px] tracking-[0.06em] break-all" aria-label="Setup key">{groupSecret(pending.secret)}</code>
                  <CopyButton text={pending.secret} what="setup key" />
                </div>
                <details className="ee-small">
                  <summary className="cursor-pointer ee-ink-2 hover:text-[var(--ee-ink)]">Setup link (otpauth URI)</summary>
                  <div className="mt-2 flex flex-wrap items-start gap-2">
                    <code className="ee-mono min-w-0 flex-1 break-all text-[12px] ee-ink-2">{pending.otpauth_uri}</code>
                    <CopyButton text={pending.otpauth_uri} what="setup link" />
                  </div>
                </details>
              </div>
            </div>
          </section>
          <section aria-labelledby={`${id}-s2`} className="space-y-3 border-t border-[var(--ee-line)] pt-4">
            <h3 id={`${id}-s2`} className="ee-h3">2. Confirm with a code</h3>
            <Field label="6-digit code" htmlFor={`${id}-on`}>
              <input id={`${id}-on`} className="ee-input ee-num w-[160px] tracking-[0.2em]" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ''))} autoFocus />
            </Field>
            <Callout tone="warn">EasyEAP has no recovery codes. If you lose the device, an operator must run <code className="ee-mono text-[12.5px]">easyeap reset-admin-mfa {email}</code> on the server.</Callout>
            {error && <Callout tone="crit">{error}</Callout>}
            <div className="flex flex-wrap gap-2">
              <Btn type="submit" variant="primary" busy={enable.isPending}><ShieldCheck aria-hidden />Turn on two-factor</Btn>
              <Btn variant="ghost" onClick={() => { setPending(null); setCode(''); setError(null) }}>Cancel</Btn>
            </div>
          </section>
        </form>
      )}
    </Panel>
  )
}
