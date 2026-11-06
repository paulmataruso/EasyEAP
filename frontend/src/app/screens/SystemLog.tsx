// System log (/system/logs): operational messages from the API, worker, RADIUS agent and FreeRADIUS, newest first.
// Kept 30 days; forwarded to remote syslog with the audit trail and authentication events.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ArrowLeft, Search } from 'lucide-react'
import { sourceLabels, useSystemLogs, type LogLevel, type LogSource, type SystemLogEntry } from '../api/logs'
import { useSession } from '../api/session'
import { ago, fmtDateTime, plural } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Btn, Chip, Empty, ErrorState, ESelect, LoadingBlock, PageHeader, Panel, Seg, type Tone } from '../ui'

function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value)
  useEffect(() => { const id = setTimeout(() => setV(value), ms); return () => clearTimeout(id) }, [value, ms])
  return v
}

const levelTone: Record<LogLevel, Tone> = { debug: 'neutral', info: 'neutral', warning: 'warn', error: 'crit', critical: 'crit' }
const levelText: Record<LogLevel, string> = { debug: 'Debug', info: 'Info', warning: 'Warning', error: 'Error', critical: 'Critical' }

export default function SystemLog() {
  const { me } = useSession()
  const canRead = me?.platform_role === 'platform_owner' || me?.platform_role === 'platform_auditor'
  const [level, setLevel] = useState<LogLevel>('info')
  const [source, setSource] = useState('')
  const [query, setQuery] = useState('')
  const q = useDebounced(query.trim())
  const logs = useSystemLogs({ level, source, q })
  const now = useNow()

  if (!canRead) {
    return (
      <div>
        <PageHeader title="System log" />
        <Empty title="You don’t have access to the system log">It’s available to the Super Administrator and MSP Auditors.</Empty>
      </div>
    )
  }
  const items = logs.data?.pages.flatMap((p) => p.logs) ?? []

  return (
    <div>
      <PageHeader title="System log"
        lede="Messages from the API, background worker, RADIUS agent and FreeRADIUS, newest first. Kept for 30 days, and forwarded to remote syslog if you set it up."
        actions={<Link to={paths.system()} className="ee-btn"><ArrowLeft aria-hidden />System health</Link>} />
      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 border-b border-[var(--ee-line)] px-4 py-3">
          <Seg value={level} onChange={setLevel} label="Level" options={[{ value: 'info', label: 'All' }, { value: 'warning', label: 'Warnings and errors' }, { value: 'error', label: 'Errors' }]} />
          <ESelect className="w-[170px]" label="Source" value={source || 'all'} onChange={(v) => setSource(v === 'all' ? '' : v)}
            options={[{ value: 'all', label: 'All sources' }, ...(Object.keys(sourceLabels) as LogSource[]).map((s) => ({ value: s, label: sourceLabels[s] }))]} />
          <div className="ee-input flex min-w-[200px] max-w-[360px] flex-1 items-center gap-2 px-2.5 focus-within:border-[var(--ee-gold)]">
            <Search className="size-4 shrink-0 ee-ink-3" aria-hidden />
            <input aria-label="Search messages" className="h-full min-w-0 flex-1 bg-transparent outline-none placeholder:text-[var(--ee-ink-3)]"
              placeholder="Search messages" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <span className="ee-small ee-ink-3 ml-auto" aria-live="polite">{logs.isFetching && !logs.isFetchingNextPage ? 'Loading…' : `${plural(items.length, 'message')} shown${logs.hasNextPage ? ', more available' : ''}`}</span>
        </div>
        {logs.isLoading ? <div className="p-4"><LoadingBlock rows={8} label="Loading the system log" /></div>
          : logs.error ? <div className="p-4"><ErrorState error={logs.error} onRetry={() => logs.refetch()} /></div>
          : items.length === 0 ? <div className="p-4"><Empty title={q || source || level !== 'info' ? 'No messages match' : 'Nothing logged yet'}>{q || source || level !== 'info' ? 'Try a lower level, another source or a different search.' : 'Messages appear here as EasyEAP runs.'}</Empty></div>
          : (
            <>
              <ul className="ee-divide list-none p-0" aria-label="System log, newest first">
                {items.map((e) => <LogRow key={e.id} e={e} now={now} />)}
              </ul>
              {logs.hasNextPage && (
                <div className="border-t border-[var(--ee-line)] px-4 py-3">
                  <Btn onClick={() => logs.fetchNextPage()} busy={logs.isFetchingNextPage}>Load older messages</Btn>
                </div>
              )}
            </>
          )}
      </Panel>
    </div>
  )
}

function LogRow({ e, now }: { e: SystemLogEntry; now: Date }) {
  const [first, ...rest] = e.message.split('\n')
  const [open, setOpen] = useState(false)
  return (
    <li className="grid gap-x-4 gap-y-1 px-4 py-2.5 text-[13px] md:grid-cols-[150px_86px_110px_minmax(0,1fr)]">
      <span className="ee-small ee-ink-3 ee-num" title={fmtDateTime(e.at)}>{ago(e.at, now)}</span>
      <span><Chip tone={levelTone[e.level]}>{levelText[e.level]}</Chip></span>
      <span className="ee-small ee-ink-2">{sourceLabels[e.source] ?? e.source}</span>
      <div className="min-w-0">
        <p className="ee-mono text-[12.5px] break-words whitespace-pre-wrap">{first}</p>
        {e.logger && <p className="ee-small ee-ink-3">{e.logger}</p>}
        {rest.length > 0 && (
          <>
            <button type="button" className="ee-small underline-offset-2 hover:underline ee-ink-2" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
              {open ? 'Hide details' : `Show ${plural(rest.length, 'more line')}`}
            </button>
            {open && <pre className="ee-code mt-1.5 whitespace-pre-wrap break-words text-[12px]">{rest.join('\n')}</pre>}
          </>
        )}
      </div>
    </li>
  )
}
