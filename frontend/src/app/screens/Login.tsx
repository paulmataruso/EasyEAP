import { useState, type FormEvent } from 'react'
import { useNavigate, useLocation } from 'react-router'
import { KeyRound, LogIn } from 'lucide-react'
import { Wordmark } from '@/ui/Logo'
import { api, ApiError } from '../api/client'
import { useSession } from '../api/session'
import type { Me } from '../api/types'
import { Btn, Callout, Field, Panel } from '../ui'

export function AuthFrame({ title, lede, children, wide }: { title: string; lede?: string; children: React.ReactNode; wide?: boolean }) {
  return (
    <div className="grid min-h-screen place-items-center px-4 py-10">
      <div className={wide ? 'w-full max-w-[580px]' : 'w-full max-w-[420px]'}>
        <div className="mb-6 flex justify-center"><Wordmark className="gap-3 text-[22px] text-[var(--ee-ink)]" markClassName="size-11" /></div>
        <Panel className="px-6 py-6" risk="gold">
          <h1 className="ee-h1 text-[22px]" tabIndex={-1} data-page-heading>{title}</h1>
          {lede && <p className="ee-lede mt-1.5">{lede}</p>}
          <div className="mt-5">{children}</div>
        </Panel>
        <p className="mt-4 text-center text-[12px] ee-ink-3">EasyEAP · Enterprise Wi-Fi Authentication, Simplified</p>
      </div>
    </div>
  )
}

export function Login() {
  const { signIn } = useSession()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needTotp, setNeedTotp] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const res = await api.post<Me | { mfa_required: true }>('/api/auth/login', { email, password, totp: needTotp ? totp : undefined })
      if ('mfa_required' in res) { setNeedTotp(true); setBusy(false); return }
      signIn(res)
      const from = (location.state as { from?: string } | null)?.from
      navigate(from && from !== '/login' ? from : '/', { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed.')
      setBusy(false)
    }
  }

  return (
    <AuthFrame title="Sign in" lede="Administrators only. Users enroll their devices from the link they're sent.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {error && <Callout tone="crit">{error}</Callout>}
        {!needTotp ? (
          <>
            <Field label="Email" htmlFor="email">
              <input id="email" className="ee-input" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
            </Field>
            <Field label="Password" htmlFor="password">
              <input id="password" className="ee-input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
          </>
        ) : (
          <Field label="Verification code" htmlFor="totp" hint="The 6-digit code from your authenticator app.">
            <input id="totp" className="ee-input ee-mono tracking-[0.2em]" inputMode="numeric" autoComplete="one-time-code" maxLength={10} value={totp} onChange={(e) => setTotp(e.target.value)} autoFocus />
          </Field>
        )}
        <Btn type="submit" variant="primary" size="lg" className="w-full" busy={busy} disabled={!email || !password || (needTotp && totp.length < 6)}>
          {needTotp ? <KeyRound aria-hidden /> : <LogIn aria-hidden />}
          {needTotp ? 'Verify and sign in' : 'Sign in'}
        </Btn>
      </form>
    </AuthFrame>
  )
}
