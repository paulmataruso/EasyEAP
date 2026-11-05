// First run: there is no default account. The first Super Administrator is created with the one-time setup token
// printed by `docker compose exec easyeap-api easyeap setup-token`.
import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../api/client'
import { useSession } from '../api/session'
import type { Me } from '../api/types'
import { paths } from '../routes'
import { Btn, Callout, Field } from '../ui'
import { AuthFrame } from './Login'

export function FirstRun() {
  const { signIn } = useSession()
  const navigate = useNavigate()
  const [form, setForm] = useState({ setup_token: '', display_name: '', email: '', password: '', confirm: '' })
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }))
  const mismatch = form.confirm.length > 0 && form.confirm !== form.password
  const short = form.password.length > 0 && form.password.length < 12

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const me = await api.post<Me>('/api/setup/admin', { setup_token: form.setup_token.trim(), display_name: form.display_name, email: form.email, password: form.password })
      signIn(me)
      navigate(paths.newTenant(), { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Setup failed.')
      setBusy(false)
    }
  }

  return (
    <AuthFrame title="Set up EasyEAP" lede="Create the first Super Administrator. There is no default account.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        <Callout tone="gold" title="Get the one-time setup token">
          On the server, run <code className="ee-mono text-[12.5px]">docker compose exec easyeap-api easyeap setup-token</code>. The token stops working once this account exists.
        </Callout>
        {error && <Callout tone="crit">{error}</Callout>}
        <Field label="Setup token" htmlFor="token">
          <input id="token" className="ee-input ee-mono" autoComplete="off" spellCheck={false} value={form.setup_token} onChange={set('setup_token')} autoFocus />
        </Field>
        <Field label="Your name" htmlFor="name">
          <input id="name" className="ee-input" autoComplete="name" value={form.display_name} onChange={set('display_name')} />
        </Field>
        <Field label="Email" htmlFor="email">
          <input id="email" className="ee-input" type="email" autoComplete="username" value={form.email} onChange={set('email')} />
        </Field>
        <Field label="Password" htmlFor="pw" hint="At least 12 characters. Use a password manager." error={short ? 'Use at least 12 characters.' : null}>
          <input id="pw" className="ee-input" type="password" autoComplete="new-password" aria-invalid={short || undefined} value={form.password} onChange={set('password')} />
        </Field>
        <Field label="Confirm password" htmlFor="pw2" error={mismatch ? 'The passwords don’t match.' : null}>
          <input id="pw2" className="ee-input" type="password" autoComplete="new-password" aria-invalid={mismatch || undefined} value={form.confirm} onChange={set('confirm')} />
        </Field>
        <Btn type="submit" variant="primary" size="lg" className="w-full" busy={busy}
          disabled={!form.setup_token || !form.display_name || !form.email || form.password.length < 12 || form.password !== form.confirm}>
          <ShieldCheck aria-hidden />Create administrator
        </Btn>
        <p className="ee-small ee-ink-3">Next you’ll create the first tenant and run its certificate authority ceremony. Turn on two-factor authentication from your account page afterwards.</p>
      </form>
    </AuthFrame>
  )
}
