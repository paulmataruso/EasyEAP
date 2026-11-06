// System → Remote syslog: where the audit trail, authentication events and system log are forwarded, and whether
// each destination is keeping up.
import { useState } from 'react'
import { Link } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { Pencil, Plus, ScrollText, Send, Trash2 } from 'lucide-react'
import { categoryLabels, syslogApi, syslogKey, transportLabels, useSyslog, type SyslogDestination } from '../../api/logs'
import { useSession } from '../../api/session'
import { ago, fmtCount, fmtDateTime } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { Btn, EDialog, Empty, ErrorState, HealthDot, LoadingBlock, Panel, SectionHeader, toast, toastError } from '../../ui'
import { SyslogDialog } from './SyslogDialog'

export function SyslogPanel() {
  const { me } = useSession()
  const owner = me?.platform_role === 'platform_owner'
  const q = useSyslog()
  const now = useNow()
  const [dialog, setDialog] = useState<{ open: boolean; editing: SyslogDestination | null }>({ open: false, editing: null })
  const data = q.data
  const failing = data?.destinations.filter((d) => d.status.state === 'failing') ?? []
  const workerStale = !!data?.worker_seen_at && now.getTime() - new Date(data.worker_seen_at).getTime() > 3 * 60_000

  return (
    <Panel risk={failing.length ? 'crit' : undefined} aria-labelledby="sys-syslog">
      <div className="p-5">
        <SectionHeader id="sys-syslog" title="Remote syslog"
          meta={data && data.destinations.length > 0 ? (failing.length ? `${failing.length} failing` : `${data.destinations.filter((d) => d.enabled).length} sending`) : undefined}
          actions={
            <>
              <Link to={paths.systemLog()} className="ee-btn ee-btn-sm"><ScrollText aria-hidden />System log</Link>
              {owner && data && data.destinations.length < data.max_destinations && (
                <Btn size="sm" variant="primary" onClick={() => setDialog({ open: true, editing: null })}><Plus aria-hidden />Add destination</Btn>
              )}
            </>
          } />
        {q.isLoading ? <LoadingBlock rows={3} label="Loading syslog destinations" />
          : q.error || !data ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="Syslog settings couldn’t be loaded" />
          : data.destinations.length === 0 ? (
            <Empty icon={<Send />} title="Nothing is forwarded yet">
              Send the audit trail, every authentication and the system log to your syslog server or SIEM, over TLS, TCP or UDP. EasyEAP keeps its own copy either way.
            </Empty>
          ) : (
            <>
              {workerStale && <p className="ee-small mb-3 text-[var(--ee-warn-ink)]">The background worker isn’t running, so nothing is being forwarded. Messages wait and are sent once it’s back.</p>}
              <ul className="ee-divide">
                {data.destinations.map((d) => <DestinationRow key={d.id} d={d} now={now} owner={owner} onEdit={() => setDialog({ open: true, editing: d })} />)}
              </ul>
              <p className="ee-small ee-ink-3 mt-3">Messages carry the host name <span className="ee-mono">{data.hostname}</span>. TCP and TLS deliver every message at least once; after an outage, delivery resumes where it stopped.</p>
            </>
          )}
      </div>
      {owner && data && <SyslogDialog open={dialog.open} onOpenChange={(o) => setDialog((cur) => ({ ...cur, open: o }))} editing={dialog.editing} facilities={data.facilities} />}
    </Panel>
  )
}

function DestinationRow({ d, now, owner, onEdit }: { d: SyslogDestination; now: Date; owner: boolean; onEdit: () => void }) {
  const qc = useQueryClient()
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState<'test' | 'delete' | null>(null)
  const st = d.status
  const status = {
    delivering: <HealthDot tone="valid" label={st.last_sent_at ? `Delivering · last message ${ago(st.last_sent_at, now)}` : 'Delivering'} />,
    waiting: <HealthDot tone="neutral" label="Waiting for the first message" />,
    failing: <HealthDot tone="crit" label="Failing" />,
    disabled: <HealthDot tone="neutral" label="Paused" />,
  }[st.state]

  const test = async () => {
    setBusy('test')
    try {
      const r = await syslogApi.test(d)
      toast('Test message sent', r.detail)
    } catch (e) {
      toastError('Test message failed')(e)
    } finally {
      setBusy(null)
    }
  }
  const remove = async () => {
    setBusy('delete')
    try {
      await syslogApi.remove(d.id)
      toast('Destination removed')
      setConfirm(false)
      void qc.invalidateQueries({ queryKey: syslogKey })
    } catch (e) {
      toastError('Couldn’t remove the destination')(e)
    } finally {
      setBusy(null)
    }
  }

  return (
    <li className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 py-3 first:pt-0 last:pb-0">
      <div className="min-w-0 flex-1">
        <p className="font-medium">{d.name}</p>
        <p className="ee-small ee-ink-2 mt-0.5"><span className="ee-mono">{d.host}:{d.port}</span> · {transportLabels[d.transport]} · {d.format === 'rfc5424' ? 'RFC 5424' : 'RFC 3164'} · {d.body === 'json' ? 'JSON' : 'text'}</p>
        <p className="ee-small ee-ink-3 mt-0.5">{d.categories.map((c) => categoryLabels[c]).join(', ')}{d.categories.includes('system') && d.system_level !== 'info' ? ` (${d.system_level === 'error' ? 'errors only' : 'warnings and errors'})` : ''}</p>
        <div className="mt-1.5">{status}</div>
        {st.state === 'failing' && st.error && (
          <p className="ee-small mt-1 text-[var(--ee-crit-ink)]">{st.error}{st.error_at && <span className="ee-ink-3" title={fmtDateTime(st.error_at)}> · since {ago(st.error_at, now)}</span>}</p>
        )}
        <p className="ee-small ee-ink-3 mt-1">
          <span className="ee-num">{fmtCount(st.sent)}</span> sent
          {st.backlog !== null && st.backlog > 0 && <> · <span className="ee-num">about {fmtCount(st.backlog)}</span> waiting</>}
        </p>
      </div>
      {owner && (
        <div className="flex shrink-0 items-center gap-1.5">
          <Btn size="sm" busy={busy === 'test'} onClick={test}><Send aria-hidden />Test</Btn>
          <Btn size="sm" variant="ghost" icon aria-label={`Edit ${d.name}`} onClick={onEdit}><Pencil aria-hidden /></Btn>
          <Btn size="sm" variant="ghost" icon aria-label={`Remove ${d.name}`} onClick={() => setConfirm(true)}><Trash2 aria-hidden /></Btn>
        </div>
      )}
      <EDialog open={confirm} onOpenChange={setConfirm} title={`Remove ${d.name}?`} description="EasyEAP stops forwarding to it at once. Its own system log and audit trail are unaffected."
        footer={<><Btn onClick={() => setConfirm(false)}>Cancel</Btn><Btn variant="danger-solid" busy={busy === 'delete'} onClick={remove}><Trash2 aria-hidden />Remove</Btn></>}>
        <p className="ee-mono text-[12.5px]">{d.host}:{d.port}</p>
      </EDialog>
    </li>
  )
}
