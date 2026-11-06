// First run: there is no default account. The one-time setup token printed by the installer (and by
// `docker compose exec easyeap-api easyeap setup-token`) either creates the first Super Administrator or restores a
// backup onto this fresh server. Either way the token stops working afterwards.
import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { RadioGroup } from 'radix-ui'
import { LockOpen, RotateCcw, ShieldCheck } from 'lucide-react'
import { backupApi, type BackupInspection, type UploadedBackup } from '../api/backup'
import { api, ApiError, notifyMaintenance } from '../api/client'
import { useSession } from '../api/session'
import type { Me } from '../api/types'
import { fmtDateTime } from '../lib/format'
import { paths } from '../routes'
import { Btn, Callout, errorMessage, Field } from '../ui'
import { AuthFrame } from './Login'
import { fmtBytes } from './events/bytes'
import { BackupFilePicker, BackupSummary } from './system/restoreParts'

type Mode = 'new' | 'restore'

export function FirstRun() {
  const [mode, setMode] = useState<Mode>('new')
  const [token, setToken] = useState('')
  return (
    <AuthFrame title="Set up EasyEAP" lede="Start a new installation, or bring back one you backed up." wide={mode === 'restore'}>
      <div className="space-y-4">
        <RadioGroup.Root value={mode} onValueChange={(v) => setMode(v as Mode)} className="grid gap-2 sm:grid-cols-2" aria-label="How to set up">
          <RadioGroup.Item value="new" className="ee-radio-card">
            <span className="ee-radio-dot" aria-hidden />
            <span><span className="block text-[13.5px] font-semibold">Set up new</span><span className="ee-small ee-ink-2">Create the first administrator, then your first tenant.</span></span>
          </RadioGroup.Item>
          <RadioGroup.Item value="restore" className="ee-radio-card">
            <span className="ee-radio-dot" aria-hidden />
            <span><span className="block text-[13.5px] font-semibold">Restore a backup</span><span className="ee-small ee-ink-2">Upload an .easyeap file to get everything back as it was.</span></span>
          </RadioGroup.Item>
        </RadioGroup.Root>
        <Callout tone="gold" title="You need the one-time setup token">
          The installer printed it when it finished. To print it again, run <code className="ee-mono text-[12.5px]">docker compose exec easyeap-api easyeap setup-token</code> on the server.
        </Callout>
        <Field label="Setup token" htmlFor="token">
          <input id="token" className="ee-input ee-mono" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} autoFocus />
        </Field>
        {mode === 'new' ? <NewAdmin token={token} /> : <RestoreBackup token={token} />}
      </div>
    </AuthFrame>
  )
}

function NewAdmin({ token }: { token: string }) {
  const { signIn } = useSession()
  const navigate = useNavigate()
  const [form, setForm] = useState({ display_name: '', email: '', password: '', confirm: '' })
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
      const me = await api.post<Me>('/api/setup/admin', { setup_token: token.trim(), display_name: form.display_name, email: form.email, password: form.password })
      signIn(me)
      navigate(paths.newTenant(), { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Setup failed.')
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      {error && <Callout tone="crit">{error}</Callout>}
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
        disabled={!token || !form.display_name || !form.email || form.password.length < 12 || form.password !== form.confirm}>
        <ShieldCheck aria-hidden />Create administrator
      </Btn>
      <p className="ee-small ee-ink-3">Next you’ll create the first tenant and run its certificate authority ceremony. Turn on two-factor authentication from your account page afterwards.</p>
    </form>
  )
}

function RestoreBackup({ token }: { token: string }) {
  const [upload, setUpload] = useState<{ u: UploadedBackup; name: string } | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [info, setInfo] = useState<BackupInspection | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const tokenOk = token.trim().length >= 10

  const unlock = async (e: FormEvent) => {
    e.preventDefault()
    if (!upload || !passphrase) return
    setBusy(true)
    setError(null)
    try {
      setInfo(await backupApi.setupInspect(upload.u.id, { setup_token: token.trim(), passphrase }))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  const restore = async () => {
    if (!upload) return
    setBusy(true)
    setError(null)
    try {
      notifyMaintenance(await backupApi.setupStart(upload.u.id, { setup_token: token.trim(), passphrase }))
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }
  const startOver = () => { setUpload(null); setInfo(null); setPassphrase(''); setError(null) }

  if (!upload) {
    return (
      <div className="space-y-3">
        <BackupFilePicker setupToken={token} disabled={!tokenOk} onUploaded={(u, f) => setUpload({ u, name: f.name })} />
        {!tokenOk && <p className="ee-small ee-ink-3">Enter the setup token first.</p>}
      </div>
    )
  }
  if (!info) {
    return (
      <form className="space-y-4" onSubmit={unlock}>
        <Callout tone="neutral" title={upload.name}>
          {fmtBytes(upload.u.size)} · made {fmtDateTime(upload.u.created_at)} by EasyEAP {upload.u.product_version ?? '(unknown version)'}
        </Callout>
        <Field label="Backup passphrase" htmlFor="fr-pass" hint="The passphrase chosen when the backup was made.">
          <input id="fr-pass" className="ee-input" type="password" autoComplete="off" autoFocus value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
        </Field>
        {error && <Callout tone="crit">{error}</Callout>}
        <div className="flex flex-wrap gap-2">
          <Btn type="submit" variant="primary" size="lg" className="flex-1" busy={busy} disabled={!passphrase || !tokenOk}><LockOpen aria-hidden />Unlock backup</Btn>
          <Btn size="lg" onClick={startOver}>Choose another file</Btn>
        </div>
      </form>
    )
  }
  return (
    <div className="space-y-4">
      <BackupSummary info={info} />
      {error && <Callout tone="crit">{error}</Callout>}
      {info.restorable && (
        <p className="ee-small ee-ink-2">Afterwards, sign in with an administrator account from the backup. Certificates issued after the backup was made aren’t in it.</p>
      )}
      <div className="flex flex-wrap gap-2">
        <Btn variant="primary" size="lg" className="flex-1" busy={busy} disabled={!info.restorable || !tokenOk} onClick={restore}><RotateCcw aria-hidden />Restore this backup</Btn>
        <Btn size="lg" onClick={startOver}>Choose another file</Btn>
      </div>
    </div>
  )
}
