// System → Backup and restore. The Super Administrator makes, downloads and restores full backups here; MSP
// Auditors see when the last backup was taken. No server shell is needed for any of it.
import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Archive, Download, RotateCcw, Trash2 } from 'lucide-react'
import { backupApi, backupDownloadUrl, useBackups, type BackupRecord } from '../../api/backup'
import { qk } from '../../api/keys'
import { useSession } from '../../api/session'
import type { SystemHealth } from '../../api/system'
import { ago, fmtDateTime, relative } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { Btn, Callout, Dl, EDialog, ErrorState, HealthDot, LoadingBlock, Panel, SectionHeader, toast, toastError } from '../../ui'
import { fmtBytes } from '../events/bytes'
import { CreateBackupDialog } from './CreateBackupDialog'
import { RestoreDialog } from './RestoreDialog'

/** Same threshold as the platform needs-action queue (dashboard.py BACKUP_MAX_AGE). */
export const backupOverdue = (at: string, now: Date) => now.getTime() - new Date(at).getTime() > 7 * 864e5

export function BackupPanel({ health }: { health: SystemHealth | undefined }) {
  const { me } = useSession()
  const now = useNow()
  const owner = me?.platform_role === 'platform_owner'
  const list = useBackups(owner)
  const [creating, setCreating] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const last = health?.backup ?? null
  const overdue = !!last && backupOverdue(last.at, now)
  const data = list.data

  return (
    <Panel risk={health && (!last || overdue) ? 'warn' : undefined} aria-labelledby="sys-backup">
      <div className="p-5">
        <SectionHeader id="sys-backup" title="Backup and restore"
          actions={owner && data?.supervisor ? (
            <>
              <Btn size="sm" onClick={() => setRestoring(true)}><RotateCcw aria-hidden />Restore</Btn>
              <Btn size="sm" variant="primary" onClick={() => setCreating(true)}><Archive aria-hidden />Create backup</Btn>
            </>
          ) : undefined} />

        {health && (last ? (
          <>
            {overdue && <Callout tone="warn" title={`Last backup ${ago(last.at, now)}`} className="mb-4">Anything changed since then can’t be restored. Make a backup at least weekly and keep it off this server.</Callout>}
            <Dl
              className="mb-4"
              items={[
                ['Last backup', <span title={fmtDateTime(last.at)}>{ago(last.at, now)}</span>],
                ['Size', <span className="ee-num">{fmtBytes(last.size)} · encrypted</span>],
                ['File', <span className="ee-mono text-[12.5px] break-all">{last.file}</span>, 'wide'],
              ]}
            />
          </>
        ) : (
          <Callout tone="warn" title="No backup yet" className="mb-4">Without one, losing this server means losing every tenant’s certificate authority and issued certificates.{owner ? ' Create a backup and download it.' : ''}</Callout>
        ))}

        {!owner ? (
          <p className="ee-small ee-ink-2">Making and restoring backups needs the Super Administrator role.</p>
        ) : list.isLoading ? <LoadingBlock rows={3} label="Loading backups" />
          : list.error || !data ? <ErrorState error={list.error} onRetry={() => list.refetch()} title="Backups couldn’t be loaded" />
          : (
            <>
              {!data.supervisor && (
                <Callout tone="crit" title="Backups need the updated CA service" className="mb-4">
                  The certificate authority container is still running its previous start-up configuration. Update this installation with the installer to turn on backup and restore.
                </Callout>
              )}
              {!data.recovery_keys && (
                <Callout tone="warn" title="Restore each backup within 32 days" className="mb-4">
                  This installation was set up before EasyEAP kept PKI recovery keys. A backup’s CA credentials stay valid for 32 days after it’s made, so restore from a recent one. Each backup shows its own date.
                </Callout>
              )}
              {data.backups.length > 0 && (
                <>
                  <h3 className="ee-h3 mb-1">On this server</h3>
                  <p className="ee-small ee-ink-3 mb-2">Kept for {data.retention_hours} hours so you can download them, then deleted.</p>
                  <ul className="ee-divide mb-4">
                    {data.backups.map((b) => <BackupRow key={b.id} b={b} now={now} />)}
                  </ul>
                </>
              )}
              {data.last_restore && data.last_restore.finished_at && (
                <p className="ee-small ee-ink-2 mb-3">
                  {data.last_restore.status === 'done' ? 'Restored' : 'Restore failed'} {ago(data.last_restore.finished_at, now)}
                  {data.last_restore.backup_created_at && <> from the backup made {fmtDateTime(data.last_restore.backup_created_at)}</>}.
                </p>
              )}
            </>
          )}

        <ul className="ee-small ee-ink-2 list-disc space-y-1.5 pl-5">
          <li>A backup holds everything on this server, including every CA key. It’s encrypted with the passphrase you choose; protect the file and the passphrase like the CAs themselves.</li>
          <li>Making a backup pauses the CA service for a few seconds. RADIUS keeps authenticating throughout.</li>
          <li>Restoring replaces everything on this server and signs everyone out. Certificates issued after the backup was made aren’t in it: re-issue them.</li>
          <li>A new installation can be restored from its first-run page, with the setup token from the installer.</li>
        </ul>
      </div>
      {owner && <CreateBackupDialog open={creating} onOpenChange={setCreating} />}
      {owner && <RestoreDialog open={restoring} onOpenChange={setRestoring} />}
    </Panel>
  )
}

function BackupRow({ b, now }: { b: BackupRecord; now: Date }) {
  const qc = useQueryClient()
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const remove = async () => {
    setBusy(true)
    try {
      await backupApi.remove(b.id)
      toast('Server copy deleted', b.downloaded_at ? 'Your downloaded copy isn’t affected.' : undefined)
      setConfirm(false)
      void qc.invalidateQueries({ queryKey: qk.backups() })
    } catch (e) {
      toastError('Couldn’t delete the backup')(e)
    } finally {
      setBusy(false)
    }
  }
  const refreshSoon = () => setTimeout(() => { void qc.invalidateQueries({ queryKey: qk.backups() }); void qc.invalidateQueries({ queryKey: qk.systemHealth() }) }, 1500)
  const current = b.steps?.find((s) => s.current)?.label

  return (
    <li className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 py-3 first:pt-0 last:pb-0">
      <div className="min-w-0 flex-1">
        <p className="ee-mono text-[12.5px] break-all">{b.file_name ?? (b.status === 'running' ? 'Backup in progress' : 'Backup')}</p>
        <p className="ee-small ee-ink-3 mt-0.5">
          <span title={fmtDateTime(b.created_at)}>Started {ago(b.created_at, now)}</span>
          {b.created_by && <> by {b.created_by}</>}
          {b.size !== undefined && <> · <span className="ee-num">{fmtBytes(b.size)}</span></>}
        </p>
        <div className="mt-1">
          {b.status === 'running' ? <HealthDot tone="neutral" label={current ? `${current}…` : 'Working…'} />
            : b.status === 'failed' ? <p className="ee-small text-[var(--ee-crit-ink)]">Failed: {b.error ?? 'unknown error'}</p>
            : b.downloaded_at ? <HealthDot tone="valid" label={`Downloaded ${ago(b.downloaded_at, now)}`} />
            : <HealthDot tone="warn" label={`Not downloaded · deleted ${b.expires_at ? relative(b.expires_at, now) : 'soon'}`} />}
        </div>
        {b.status === 'done' && b.pki_access && !b.pki_access.recovery_keys && b.pki_access.restore_before && (
          <p className="ee-small ee-ink-2 mt-1">Restore before {fmtDateTime(b.pki_access.restore_before)}.</p>
        )}
      </div>
      {b.status !== 'running' && (
        <div className="flex shrink-0 items-center gap-1.5">
          {b.status === 'done' && (
            <a className="ee-btn ee-btn-sm" href={backupDownloadUrl(b.id)} download={b.file_name} onClick={refreshSoon} aria-label={`Download ${b.file_name}`}>
              <Download aria-hidden />Download
            </a>
          )}
          <Btn size="sm" variant="ghost" icon aria-label={`Delete the server copy of ${b.file_name ?? 'this backup'}`} onClick={() => setConfirm(true)}><Trash2 aria-hidden /></Btn>
        </div>
      )}
      <EDialog open={confirm} onOpenChange={setConfirm} title="Delete the server copy?"
        description={b.status === 'failed' ? 'This failed backup holds nothing usable.' : b.downloaded_at ? 'The copy you downloaded isn’t affected.' : 'This backup hasn’t been downloaded. Once it’s deleted it can’t be recovered.'}
        risk={b.status === 'done' && !b.downloaded_at ? 'crit' : undefined}
        footer={<><Btn onClick={() => setConfirm(false)}>Cancel</Btn><Btn variant="danger-solid" busy={busy} onClick={remove}><Trash2 aria-hidden />Delete</Btn></>}>
        <p className="ee-mono text-[12.5px] break-all">{b.file_name ?? b.id}</p>
      </EDialog>
    </li>
  )
}
