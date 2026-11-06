// Pieces shared by the console restore dialog and the first-run restore: choosing and uploading the file, and the
// summary of what an unlocked backup holds.
import { useEffect, useRef, useState, type DragEvent } from 'react'
import { FileArchive, Upload, X } from 'lucide-react'
import { uploadBackup, type BackupInspection, type UploadedBackup } from '../../api/backup'
import { fmtCount, fmtDateTime, plural } from '../../lib/format'
import { Btn, Callout, Chip, Dl, errorMessage } from '../../ui'
import { UploadProgress } from '../../ui/RunSteps'
import { fmtBytes } from '../events/bytes'

/** Choose a .easyeap file (button or drop) and upload it at once, with progress and cancel. */
export function BackupFilePicker({ setupToken, onUploaded, disabled }: { setupToken?: string; onUploaded: (u: UploadedBackup, file: File) => void; disabled?: boolean }) {
  const [file, setFile] = useState<File | null>(null)
  const [sent, setSent] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [over, setOver] = useState(false)
  const abort = useRef<AbortController | null>(null)
  useEffect(() => () => abort.current?.abort(), [])

  const start = async (f: File) => {
    setError(null)
    if (!/\.easyeap$/i.test(f.name)) {
      setError('Choose an EasyEAP backup file (it ends in .easyeap).')
      return
    }
    setFile(f)
    setSent(0)
    const ctl = new AbortController()
    abort.current = ctl
    try {
      const u = await uploadBackup(f, { setupToken, signal: ctl.signal, onProgress: (s) => setSent(s) })
      onUploaded(u, f)
    } catch (e) {
      if ((e as Error).name !== 'AbortError') setError(errorMessage(e))
      setFile(null)
    } finally {
      abort.current = null
    }
  }
  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setOver(false)
    const f = e.dataTransfer.files?.[0]
    if (f && !disabled && !file) void start(f)
  }

  if (file) {
    return (
      <div className="space-y-3 rounded-[10px] border border-[var(--ee-line-2)] p-4">
        <p className="flex min-w-0 items-center gap-2 text-[13px]"><FileArchive className="size-4 shrink-0 ee-ink-3" aria-hidden /><span className="truncate ee-mono">{file.name}</span><span className="ee-ink-3 shrink-0">{fmtBytes(file.size)}</span></p>
        <UploadProgress sent={sent} total={file.size} label={sent >= file.size ? 'Checking the file…' : 'Uploading'} />
        <Btn size="sm" onClick={() => abort.current?.abort()}><X aria-hidden />Cancel upload</Btn>
      </div>
    )
  }
  return (
    <div className="space-y-3">
      {error && <Callout tone="crit">{error}</Callout>}
      <label className="ee-drop" data-over={over || undefined} onDragOver={(e) => { e.preventDefault(); setOver(true) }} onDragLeave={() => setOver(false)} onDrop={onDrop}>
        <Upload className="size-5 ee-ink-3" aria-hidden />
        <span className="text-[13.5px] font-semibold">Choose a backup file</span>
        <span className="ee-small ee-ink-3">or drop it here. EasyEAP backups end in .easyeap.</span>
        <input type="file" accept=".easyeap" className="sr-only" disabled={disabled} aria-label="Backup file"
          onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void start(f) }} />
      </label>
    </div>
  )
}

const COUNT_LABELS: Array<[keyof BackupInspection['counts'], string]> = [
  ['tenants', 'Tenants'], ['administrators', 'Administrators'], ['identities', 'Users'],
  ['active_certificates', 'Active certificates'], ['radius_clients', 'Wi-Fi controllers'], ['audit_events', 'Audit entries'],
]

/** What an unlocked backup holds, and whether it can be restored here. */
export function BackupSummary({ info }: { info: BackupInspection }) {
  return (
    <div className="space-y-4">
      {info.problems.map((p) => <Callout key={p} tone="crit" title="This backup can’t be restored here">{p}</Callout>)}
      {info.warnings.map((w) => <Callout key={w} tone="warn">{w}</Callout>)}
      <Dl
        items={[
          ['Made', fmtDateTime(info.created_at)],
          ['By', info.created_by ?? '—'],
          ['On server', <span className="ee-mono text-[12.5px] break-all">{info.source_host ?? '—'}</span>],
          ['EasyEAP version', <span className="ee-num">{info.product_version ?? '—'}</span>],
        ]}
      />
      <div>
        <h3 className="ee-label mb-2">Contents</h3>
        <ul className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-[13px] sm:grid-cols-3">
          {COUNT_LABELS.map(([k, label]) => (
            <li key={k} className="flex items-baseline justify-between gap-2 border-b border-[var(--ee-line)] pb-1.5">
              <span className="ee-ink-2">{label}</span><span className="ee-num font-semibold">{fmtCount(info.counts[k] ?? 0)}</span>
            </li>
          ))}
        </ul>
      </div>
      {info.tenants.length > 0 && (
        <div>
          <h3 className="ee-label mb-2">{plural(info.tenants.length, 'tenant')}</h3>
          <ul className="flex flex-wrap gap-1.5">
            {info.tenants.map((t) => (
              <li key={t.slug}>
                <Chip tone={t.status === 'active' ? 'valid' : t.status === 'suspended' ? 'crit' : 'neutral'}>
                  {t.name}{t.status !== 'active' && <span className="font-normal opacity-80">· {t.status === 'suspended' ? 'suspended' : 'in setup'}</span>}
                </Chip>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
