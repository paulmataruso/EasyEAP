// Restore a backup over this running server: upload, unlock with the passphrase, review what it holds, then confirm
// with RESTORE and the administrator's password. Once the server accepts, the whole console switches to the restore
// progress page (MaintenanceGate).
import { useEffect, useRef, useState } from 'react'
import { ArrowLeft, LockOpen, RotateCcw } from 'lucide-react'
import { backupApi, type BackupInspection, type UploadedBackup } from '../../api/backup'
import { notifyMaintenance } from '../../api/client'
import { useSession } from '../../api/session'
import { fmtDateTime } from '../../lib/format'
import { Btn, Callout, ConfirmText, EDialog, errorMessage, Field } from '../../ui'
import { fmtBytes } from '../events/bytes'
import { BackupFilePicker, BackupSummary } from './restoreParts'

type Phase = 'file' | 'unlock' | 'review'

export function RestoreDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { me } = useSession()
  const [phase, setPhase] = useState<Phase>('file')
  const [upload, setUpload] = useState<{ u: UploadedBackup; name: string } | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [info, setInfo] = useState<BackupInspection | null>(null)
  const [typed, setTyped] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const started = useRef(false)

  // Closing (or leaving) without restoring deletes the uploaded file from the server and drops every secret typed here.
  const uploadId = upload?.u.id
  useEffect(() => {
    if (open) return
    if (uploadId && !started.current) void backupApi.discard(uploadId).catch(() => undefined)
    setPhase('file'); setUpload(null); setPassphrase(''); setInfo(null); setTyped(''); setPassword(''); setTotp(''); setError(null); setBusy(false)
    started.current = false
  }, [open, uploadId])

  const unlock = async () => {
    if (!upload) return
    setBusy(true)
    setError(null)
    try {
      setInfo(await backupApi.inspect(upload.u.id, passphrase))
      setPhase('review')
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const restore = async () => {
    if (!upload) return
    setBusy(true)
    setError(null)
    try {
      const st = await backupApi.start(upload.u.id, { passphrase, password, totp: me?.mfa_enabled ? totp : undefined, confirm: typed })
      started.current = true
      notifyMaintenance(st)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(false)
    }
  }

  const ready = !!info?.restorable && typed.trim() === 'RESTORE' && !!password && (!me?.mfa_enabled || totp.replace(/\s/g, '').length >= 6)

  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide risk={phase === 'review' ? 'crit' : undefined}
      title={phase === 'review' ? 'Restore this backup?' : 'Restore from a backup'}
      description={phase === 'review' ? 'Everything on this server is replaced by the backup.' : 'Replace everything on this server with the contents of an EasyEAP backup.'}
      footer={
        phase === 'file' ? <Btn onClick={() => onOpenChange(false)}>Cancel</Btn>
        : phase === 'unlock' ? (
          <>
            <Btn onClick={() => onOpenChange(false)}>Cancel</Btn>
            <Btn variant="primary" busy={busy} disabled={!passphrase} onClick={unlock}><LockOpen aria-hidden />Unlock</Btn>
          </>
        ) : (
          <>
            <Btn onClick={() => { setPhase('unlock'); setError(null) }}><ArrowLeft aria-hidden />Back</Btn>
            <Btn variant="danger-solid" busy={busy} disabled={!ready} onClick={restore}><RotateCcw aria-hidden />Restore and sign everyone out</Btn>
          </>
        )
      }>
      {phase === 'file' && (
        <div className="space-y-4">
          <BackupFilePicker onUploaded={(u, f) => { setUpload({ u, name: f.name }); setPhase('unlock') }} />
          <p className="ee-small ee-ink-3">The file is checked before anything changes. Nothing on this server is touched until you confirm the restore.</p>
        </div>
      )}

      {phase === 'unlock' && upload && (
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (passphrase) void unlock() }}>
          <Callout tone="neutral" title={upload.name}>
            {fmtBytes(upload.u.size)} · made {fmtDateTime(upload.u.created_at)} by EasyEAP {upload.u.product_version ?? '(unknown version)'}
          </Callout>
          <Field label="Backup passphrase" htmlFor="rs-pass" hint="The passphrase chosen when the backup was made.">
            <input id="rs-pass" className="ee-input" type="password" autoComplete="off" autoFocus value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
          </Field>
          {error && <Callout tone="crit">{error}</Callout>}
        </form>
      )}

      {phase === 'review' && info && (
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (ready) void restore() }}>
          <BackupSummary info={info} />
          {info.restorable && (
            <>
              <div className="rounded-[10px] border border-[var(--ee-line-2)] p-4">
                <h3 className="text-[13px] font-semibold">What happens</h3>
                <ul className="ee-small ee-ink-2 mt-2 list-disc space-y-1.5 pl-5">
                  <li>Every tenant, certificate authority, certificate, policy, setting and administrator on this server is replaced by the backup’s. Anything created since the backup was made is lost.</li>
                  <li>Everyone is signed out. Sign in afterwards with an account from the backup.</li>
                  <li>The console is unavailable for a few minutes. RADIUS keeps authenticating with its current configuration, then switches to the restored one.</li>
                  <li>Certificates issued after the backup was made aren’t in it, so RADIUS rejects them as unknown. Re-issue them.</li>
                  <li>If any step fails, EasyEAP puts everything back as it was.</li>
                </ul>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <ConfirmText expected="RESTORE" value={typed} onChange={setTyped} label="Confirm" />
                <Field label="Your password" htmlFor="rs-pw">
                  <input id="rs-pw" className="ee-input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </Field>
                {me?.mfa_enabled && (
                  <Field label="Verification code" htmlFor="rs-totp" hint="From your authenticator app.">
                    <input id="rs-totp" className="ee-input ee-mono tracking-[0.2em]" inputMode="numeric" autoComplete="one-time-code" maxLength={10} value={totp} onChange={(e) => setTotp(e.target.value)} />
                  </Field>
                )}
              </div>
            </>
          )}
          {error && <Callout tone="crit">{error}</Callout>}
          <button type="submit" hidden aria-hidden tabIndex={-1} />
        </form>
      )}
    </EDialog>
  )
}
