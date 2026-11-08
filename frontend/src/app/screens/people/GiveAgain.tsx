// Giving a waiting enrollment again, without making a new one (routers/enrollments.py show_link and
// windows_setup_again): a link is shown to copy, a Windows setup file is downloaded again with the same one-time codes.
// Each time is in the audit log; nothing is cached here. Used on a user's page and in the Users list.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { Download, Hourglass, Link2 } from 'lucide-react'
import { saveBlob } from '../../api/client'
import { downloadSetupAgain, showEnrollmentLink, type IdentityListItem, type WaitingEnrollment } from '../../api/people'
import { useTenant } from '../../api/tenant'
import { paths } from '../../routes'
import { Btn, Callout, CopyButton, EDialog, LoadingBlock, errorMessage, toast } from '../../ui'
import { fmtDateTime } from '../../lib/format'

/** What the dialog and the download need of a waiting enrollment. */
export interface Waiting { id: string; device_name: string; expires_at: string }

/** A pending link, shown again: fetched when the dialog opens (each showing is audited) and dropped when it closes. */
export function ShowLinkDialog({ tid, identityName, e, onClose }: { tid: string; identityName: string; e: Waiting | null; onClose: () => void }) {
  const [link, setLink] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const id = e?.id
  useEffect(() => {
    setLink(null); setError(null)
    if (!id) return
    let live = true
    showEnrollmentLink(tid, id).then((r) => { if (live) setLink(r.link) }, (err) => { if (live) setError(errorMessage(err)) })
    return () => { live = false }
  }, [tid, id])
  return (
    <EDialog open={!!e} onOpenChange={(o) => { if (!o) onClose() }} title={`Enrollment link for ${e?.device_name ?? ''}`}
      description={<>Send it to {identityName} again. It still works once, on the device itself, until {e ? fmtDateTime(e.expires_at) : ''}.</>}
      footer={<Btn onClick={onClose}>Done</Btn>}>
      {error ? <Callout tone="crit" title="The link can’t be shown">{error}</Callout>
        : link ? (
          <div className="flex items-center gap-2">
            <code className="ee-secret min-w-0 flex-1 break-all text-[13px]" aria-label="Enrollment link">{link}</code>
            <CopyButton text={link} what="enrollment link" />
          </div>
        ) : <LoadingBlock label="Getting the link" />}
    </EDialog>
  )
}

/** Saves the waiting Windows setup file again. The file goes straight to the browser's downloads. */
export async function saveSetupAgain(tid: string, e: Waiting, identityName: string): Promise<boolean> {
  try {
    const res = await downloadSetupAgain(tid, e.id)
    saveBlob(new Blob([res.content], { type: 'application/octet-stream' }), res.filename)
    toast('Setup file downloaded again', `For ${identityName}: the same one-time codes, which still work once, until ${fmtDateTime(res.expires_at)}.`)
    return true
  } catch (err) {
    toast('The setup file can’t be downloaded again', errorMessage(err), 'crit')
    return false
  }
}

const waitingWhat: Record<WaitingEnrollment['method'], string> = { link: 'Link', 'windows-setup': 'Setup file', server: 'Package' }

/** Links, Windows setup files and packages waiting for a device: give a link or setup file again from here. */
export function WaitingList({ u, onShow, align }: { u: IdentityListItem; onShow: (w: WaitingEnrollment) => void; align?: 'end' }) {
  const { tid, can } = useTenant()
  const [busy, setBusy] = useState<string | null>(null)
  if (!u.waiting?.length) return null
  // A disabled account's codes can't be used (they stay, and work again once it's enabled): its page says so.
  const manage = can('enrollment:manage') && u.account_state === 'enabled'
  return (
    <span className={`mt-1 flex flex-wrap gap-1.5 ${align === 'end' ? 'justify-end' : ''}`}>
      {u.waiting.map((w) => {
        const label = `${waitingWhat[w.method] ?? 'Link'} waiting`
        const until = `until ${fmtDateTime(w.expires_at)}`
        const title = `${w.device_name} · expires ${fmtDateTime(w.expires_at)}`
        if (manage && w.available && w.method === 'link') {
          return <Btn key={w.id} size="sm" variant="ghost" title={title} aria-label={`${label} for ${w.device_name} ${until}: show it`} onClick={() => onShow(w)}><Link2 aria-hidden />{label}</Btn>
        }
        if (manage && w.available && w.method === 'windows-setup') {
          return (
            <Btn key={w.id} size="sm" variant="ghost" title={title} aria-label={`${label} for ${u.display_name} ${until}: download it again`} busy={busy === w.id}
              onClick={async () => { setBusy(w.id); await saveSetupAgain(tid, w, u.display_name); setBusy(null) }}>
              <Download aria-hidden />{label}
            </Btn>
          )
        }
        return (
          <Link key={w.id} to={paths.user(tid, u.id)} title={title} aria-label={`${label} for ${w.device_name} ${until}: open ${u.display_name}’s page`}
            className="ee-small ee-ink-2 inline-flex items-center gap-1 hover:underline"><Hourglass aria-hidden className="size-3.5" />{label}</Link>
        )
      })}
    </span>
  )
}
