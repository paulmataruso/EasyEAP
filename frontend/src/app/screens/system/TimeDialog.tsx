// Edit the NTP servers the host's chronyd uses. Each can be tested from the server before saving; the time service
// applies a saved change within seconds.
import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Plus, Save, Timer, Trash2 } from 'lucide-react'
import { fmtOffset, fmtSeconds, timeApi, timeKey, type TimeServer, type TimeSettings } from '../../api/time'
import { Btn, Callout, EDialog, ESelect, ESwitch, errorMessage, toast } from '../../ui'

const blank = (): TimeServer => ({ address: '', kind: 'server', iburst: true, nts: false, prefer: false })
const SUGGESTED: Array<{ label: string; server: TimeServer }> = [
  { label: 'time.cloudflare.com (NTS)', server: { address: 'time.cloudflare.com', kind: 'server', iburst: true, nts: true, prefer: false } },
  { label: 'pool.ntp.org', server: { address: 'pool.ntp.org', kind: 'pool', iburst: true, nts: false, prefer: false } },
]

type TestResult = { ok: true; text: string } | { ok: false; text: string }

export function TimeDialog({ open, onOpenChange, settings, max }: { open: boolean; onOpenChange: (o: boolean) => void; settings: TimeSettings; max: number }) {
  const qc = useQueryClient()
  const [servers, setServers] = useState<TimeServer[]>([])
  const [onlyThese, setOnlyThese] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tests, setTests] = useState<Record<number, TestResult>>({})

  useEffect(() => {
    if (!open) return
    setServers(settings.servers.length ? settings.servers.map((s) => ({ ...s })) : [blank()])
    // A first setup uses only the servers entered: the host's own are usually marked prefer and would win otherwise.
    setOnlyThese(settings.servers.length ? settings.only_these : true)
    setError(null)
    setTests({})
    setBusy(null)
  }, [open, settings])

  const set = (i: number, patch: Partial<TimeServer>) => {
    setServers((cur) => cur.map((s, j) => (j === i ? { ...s, ...patch } : s)))
    setTests(({ [i]: _gone, ...rest }) => rest)
  }
  const remove = (i: number) => { setServers((cur) => cur.filter((_, j) => j !== i)); setTests({}) }
  const add = (s: TimeServer = blank()) => setServers((cur) => {
    const empty = cur.findIndex((x) => !x.address.trim())
    if (empty >= 0 && s.address) return cur.map((x, j) => (j === empty ? s : x))
    return [...cur, s]
  })
  const filled = servers.filter((s) => s.address.trim())
  const isIp = (v: string) => /^[\d.]+$/.test(v) || v.includes(':')
  const valid = filled.length > 0 || settings.servers.length > 0

  const test = async (i: number) => {
    setBusy(`test-${i}`)
    try {
      const r = await timeApi.test(servers[i].address.trim())
      setTests((t) => ({ ...t, [i]: { ok: true, text: `Answered from ${r.address}: this server’s clock is ${fmtOffset(r.offset)}, round trip ${fmtSeconds(r.delay)}, stratum ${r.stratum}.${servers[i].nts ? ' NTS is checked by chronyd once saved.' : ''}` } }))
    } catch (e) {
      setTests((t) => ({ ...t, [i]: { ok: false, text: errorMessage(e) } }))
    } finally {
      setBusy(null)
    }
  }
  const save = async () => {
    setBusy('save')
    setError(null)
    try {
      await timeApi.save({ servers: filled.map((s) => ({ ...s, address: s.address.trim() })), only_these: filled.length > 0 && onlyThese })
      toast('NTP servers saved', 'The host’s chronyd uses them within a few seconds. The Time panel shows when they answer.')
      void qc.invalidateQueries({ queryKey: timeKey })
      onOpenChange(false)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(null)
    }
  }

  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide title="NTP servers"
      description="The servers the host’s clock follows. Every EasyEAP log, certificate and session takes its time from that clock."
      footer={
        <>
          <Btn onClick={() => onOpenChange(false)}>Cancel</Btn>
          <Btn variant="primary" busy={busy === 'save'} disabled={!valid || !!busy} onClick={save}><Save aria-hidden />Save</Btn>
        </>
      }>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid) void save() }}>
        <ul className="space-y-3">
          {servers.map((s, i) => (
            <li key={i} className="rounded-[10px] border border-[var(--ee-line-2)] p-3">
              <fieldset>
              <legend className="sr-only">Server {i + 1}</legend>
              <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_130px_auto]">
                <input aria-label={`Server ${i + 1} address`} className="ee-input ee-mono" maxLength={253} spellCheck={false} autoFocus={i === 0}
                  value={s.address} placeholder="ntp.example.net or 192.0.2.10" onChange={(e) => set(i, { address: e.target.value, kind: isIp(e.target.value.trim()) ? 'server' : s.kind })} />
                <ESelect label={`Server ${i + 1} type`} value={s.kind} onChange={(v) => set(i, { kind: v as TimeServer['kind'] })}
                  options={[{ value: 'server', label: 'Server' }, { value: 'pool', label: 'Pool', disabled: isIp(s.address.trim()) }]} />
                <div className="flex items-center gap-1">
                  <Btn size="sm" busy={busy === `test-${i}`} disabled={!s.address.trim() || !!busy} onClick={() => test(i)}><Timer aria-hidden />Test</Btn>
                  <Btn size="sm" variant="ghost" icon aria-label={`Remove server ${i + 1}`} onClick={() => remove(i)}><Trash2 aria-hidden /></Btn>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1.5 text-[13px]">
                <label className="flex items-center gap-2"><input type="checkbox" className="ee-check" checked={s.nts} onChange={(e) => set(i, { nts: e.target.checked })} />NTS (authenticated time)</label>
                <label className="flex items-center gap-2"><input type="checkbox" className="ee-check" checked={s.prefer} onChange={(e) => set(i, { prefer: e.target.checked })} />Prefer</label>
                <label className="flex items-center gap-2"><input type="checkbox" className="ee-check" checked={s.iburst} onChange={(e) => set(i, { iburst: e.target.checked })} />Quick start (iburst)</label>
              </div>
              <p role="status" className={`ee-small ${tests[i] ? 'mt-2' : ''} ${tests[i]?.ok === false ? 'text-[var(--ee-crit-ink)]' : 'ee-ink-2'}`}>{tests[i]?.text}</p>
              </fieldset>
            </li>
          ))}
        </ul>
        <div className="flex flex-wrap items-center gap-2">
          <Btn size="sm" disabled={servers.length >= max} onClick={() => add()}><Plus aria-hidden />Add a server</Btn>
          {SUGGESTED.filter((x) => !servers.some((s) => s.address.trim().toLowerCase() === x.server.address)).map((x) => (
            <Btn key={x.label} size="sm" variant="ghost" disabled={servers.length >= max && servers.every((s) => s.address.trim())} onClick={() => add({ ...x.server })}><Plus aria-hidden />{x.label}</Btn>
          ))}
        </div>
        <p className="ee-small ee-ink-3">A pool is a name that stands for several servers (pool.ntp.org): chronyd uses up to four of them. NTS needs the server to support it, and TCP 4460 open to it as well as UDP 123. Test asks once over plain NTP from this server.</p>
        {filled.some((s) => s.nts) && filled.some((s) => !s.nts) && (
          <Callout tone="neutral">With an NTS server listed, chronyd sets the clock only while an NTS server answers; the servers without NTS just refine it when they agree. If no NTS server can be reached, the clock isn’t corrected (with “Use only these servers”, EasyEAP brings the host’s own servers back after 10 minutes).</Callout>
        )}

        <div className="flex items-center justify-between gap-4 rounded-[10px] border border-[var(--ee-line-2)] px-4 py-3">
          <span className="text-[13px]">
            <span className="font-medium">Use only these servers</span>
            <span className="block ee-small ee-ink-2">The host’s own servers stay configured but aren’t used while one of these answers. If none does, they keep the clock until one is back.</span>
          </span>
          <ESwitch checked={onlyThese && filled.length > 0} disabled={filled.length === 0} onChange={setOnlyThese} label="Use only these servers" />
        </div>
        {filled.length === 0 && settings.servers.length > 0 && <Callout tone="neutral">Saving with no servers removes EasyEAP’s, and the host’s own servers keep the clock.</Callout>}
        {error && <Callout tone="crit">{error}</Callout>}
        <button type="submit" hidden aria-hidden tabIndex={-1} />
      </form>
    </EDialog>
  )
}
