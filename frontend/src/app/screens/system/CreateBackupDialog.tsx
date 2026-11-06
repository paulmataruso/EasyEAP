// Make a full encrypted backup from the console: choose the passphrase, confirm it's you, watch it being made, then
// download it. The passphrase stays in this dialog's state and is sent once; EasyEAP never stores it.
import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { RadioGroup } from 'radix-ui'
import { Archive, Download, RotateCcw } from 'lucide-react'
import { backupApi, backupDownloadUrl, useBackup } from '../../api/backup'
import { qk } from '../../api/keys'
import { generatePassphrase } from '../../api/pki'
import { useSession } from '../../api/session'
import { fmtDateTime, relative } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { Btn, Callout, CopyButton, Dl, EDialog, errorMessage, Field, OneTimeSecret } from '../../ui'
import { RunSteps } from '../../ui/RunSteps'
import { fmtBytes } from '../events/bytes'

/** Mirrors backend/app/backup/bundle.py passphrase_problem(). */
export function passphraseProblem(p: string): string | null {
  if (p.length < 12) return 'Use at least 12 characters.'
  if (new Set(p).size < 5) return 'That passphrase is too repetitive.'
  return null
}

export function CreateBackupDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { me } = useSession()
  const qc = useQueryClient()
  const now = useNow(30_000)
  const [mode, setMode] = useState<'generated' | 'own'>('generated')
  const [generated, setGenerated] = useState(generatePassphrase)
  const [own, setOwn] = useState('')
  const [ownConfirm, setOwnConfirm] = useState('')
  const [saved, setSaved] = useState(false)
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [id, setId] = useState<string | null>(null)
  const rec = useBackup(id)
  // Each opening starts a new backup with a new passphrase; closing drops the password and passphrases from memory.
  useEffect(() => {
    if (open) { setMode('generated'); setGenerated(generatePassphrase()); setSaved(false); setError(null); setBusy(false); setId(null) }
    else { setPassword(''); setTotp(''); setOwn(''); setOwnConfirm('') }
  }, [open])

  const passphrase = mode === 'generated' ? generated : own
  const ownProblem = mode === 'own' && own ? passphraseProblem(own) : null
  const mismatch = mode === 'own' && ownConfirm.length > 0 && ownConfirm !== own
  const ready = !passphraseProblem(passphrase) && (mode === 'generated' || own === ownConfirm) && saved && !!password && (!me?.mfa_enabled || totp.replace(/\s/g, '').length >= 6)

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      const r = await backupApi.create({ passphrase, password, totp: me?.mfa_enabled ? totp : undefined })
      qc.setQueryData(qk.backup(r.id), r)
      void qc.invalidateQueries({ queryKey: qk.backups() })
      setPassword('')
      setTotp('')
      setId(r.id)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const r = rec.data
  if (id) {
    const failed = r?.status === 'failed'
    const done = r?.status === 'done'
    return (
      <EDialog open={open} onOpenChange={onOpenChange} risk={failed ? 'crit' : done ? 'valid' : undefined}
        title={done ? 'Backup ready' : failed ? 'The backup failed' : 'Making the backup'}
        description={done ? 'Download it now and store it somewhere other than this server.' : failed ? undefined : 'You can close this dialog. The backup carries on and appears in the list.'}
        footer={
          done ? (
            <>
              <Btn onClick={() => onOpenChange(false)}>Close</Btn>
              <a className="ee-btn ee-btn-primary" href={backupDownloadUrl(r.id)} download={r.file_name}
                onClick={() => setTimeout(() => { void qc.invalidateQueries({ queryKey: qk.backups() }); void qc.invalidateQueries({ queryKey: qk.systemHealth() }) }, 1500)}>
                <Download aria-hidden />Download backup
              </a>
            </>
          ) : failed ? (
            <>
              <Btn onClick={() => onOpenChange(false)}>Close</Btn>
              <Btn variant="primary" onClick={() => { setId(null); setError(null) }}><RotateCcw aria-hidden />Try again</Btn>
            </>
          ) : <Btn onClick={() => onOpenChange(false)}>Close</Btn>
        }>
        {rec.error && !r ? <Callout tone="crit">{errorMessage(rec.error)}</Callout>
          : failed ? <Callout tone="crit" title="Nothing was saved">{r.error ?? 'The backup failed.'}</Callout>
          : done ? (
            <div className="space-y-4">
              <Dl
                items={[
                  ['File', <span className="ee-mono text-[12.5px] break-all">{r.file_name}</span>, 'wide'],
                  ['Size', <span className="ee-num">{fmtBytes(r.size)}</span>],
                  ['Made', fmtDateTime(r.created_at)],
                  ['SHA-256', <span className="flex items-start gap-2"><span className="ee-mono text-[12px] break-all ee-ink-2">{r.sha256}</span>{r.sha256 && <CopyButton text={r.sha256} what="checksum" label="Copy" />}</span>, 'wide'],
                ]}
              />
              <Callout tone="neutral">
                The server deletes its copy {r.expires_at ? relative(r.expires_at, now) : 'after a day'}. You’ll need the passphrase to restore it.
              </Callout>
              {r.pki_access && !r.pki_access.recovery_keys && r.pki_access.restore_before && (
                <Callout tone="warn" title={`Restore it before ${fmtDateTime(r.pki_access.restore_before)}`}>
                  This installation predates PKI recovery keys, so the CA credentials in this backup expire then. Make a new backup before that date.
                </Callout>
              )}
            </div>
          ) : <RunSteps steps={r?.steps ?? []} label="Backup steps" />}
      </EDialog>
    )
  }

  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide title="Create a backup"
      description="A full backup of this EasyEAP server: every tenant, CA key, certificate, policy, setting, administrator and the audit trail."
      footer={
        <>
          <Btn onClick={() => onOpenChange(false)}>Cancel</Btn>
          <Btn variant="primary" busy={busy} disabled={!ready} onClick={submit}><Archive aria-hidden />Create backup</Btn>
        </>
      }>
      <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (ready) void submit() }}>
        <fieldset className="space-y-3">
          <legend className="mb-1.5 text-[13px] font-semibold">Passphrase</legend>
          <p className="ee-small ee-ink-2 -mt-1">The backup is encrypted with this passphrase. Without it nobody can restore the backup, including you: EasyEAP doesn’t keep a copy.</p>
          <RadioGroup.Root value={mode} onValueChange={(v) => { setMode(v as 'generated' | 'own'); setSaved(false) }} className="grid gap-2 sm:grid-cols-2" aria-label="Passphrase">
            <RadioGroup.Item value="generated" className="ee-radio-card">
              <span className="ee-radio-dot" aria-hidden />
              <span><span className="block text-[13.5px] font-semibold">Generate one</span><span className="ee-small ee-ink-2">Recommended. 30 random characters to store in your password manager.</span></span>
            </RadioGroup.Item>
            <RadioGroup.Item value="own" className="ee-radio-card">
              <span className="ee-radio-dot" aria-hidden />
              <span><span className="block text-[13.5px] font-semibold">Use my own</span><span className="ee-small ee-ink-2">At least 12 characters. Use a long phrase, not a password you use elsewhere.</span></span>
            </RadioGroup.Item>
          </RadioGroup.Root>
          {mode === 'generated' ? (
            <OneTimeSecret value={generated} what="backup passphrase" acknowledged={saved} onAcknowledge={setSaved}
              note="EasyEAP doesn’t keep this passphrase. If it’s lost, the backup can’t be opened." />
          ) : (
            <div className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Passphrase" htmlFor="bk-pass" error={ownProblem}>
                  <input id="bk-pass" className="ee-input" type="password" autoComplete="new-password" value={own} onChange={(e) => setOwn(e.target.value)} aria-invalid={!!ownProblem || undefined} />
                </Field>
                <Field label="Confirm passphrase" htmlFor="bk-pass2" error={mismatch ? 'The passphrases don’t match.' : null}>
                  <input id="bk-pass2" className="ee-input" type="password" autoComplete="new-password" value={ownConfirm} onChange={(e) => setOwnConfirm(e.target.value)} aria-invalid={mismatch || undefined} />
                </Field>
              </div>
              <label className="flex items-center gap-2.5 text-[13px]">
                <input type="checkbox" className="ee-check" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                I’ve saved the backup passphrase somewhere safe
              </label>
            </div>
          )}
        </fieldset>

        <fieldset className="space-y-3 border-t border-[var(--ee-line)] pt-4">
          <legend className="sr-only">Confirm it’s you</legend>
          <p className="text-[13px] font-semibold">Confirm it’s you</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Your password" htmlFor="bk-pw">
              <input id="bk-pw" className="ee-input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            {me?.mfa_enabled && (
              <Field label="Verification code" htmlFor="bk-totp" hint="From your authenticator app.">
                <input id="bk-totp" className="ee-input ee-mono tracking-[0.2em]" inputMode="numeric" autoComplete="one-time-code" maxLength={10} value={totp} onChange={(e) => setTotp(e.target.value)} />
              </Field>
            )}
          </div>
        </fieldset>
        {error && <Callout tone="crit">{error}</Callout>}
        <p className="ee-small ee-ink-3">The CA service pauses for a few seconds while its data is copied. RADIUS keeps authenticating throughout.</p>
        <button type="submit" hidden aria-hidden tabIndex={-1} />
      </form>
    </EDialog>
  )
}
