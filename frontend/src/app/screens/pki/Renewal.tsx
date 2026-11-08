// Certificate renewal (docs/plans/cert-renewal.md §15a): what renews by itself, at what share of each certificate's
// life, the template days that follow, and the CA dates to plan for. Group Policy keeps its own schedule.
import { useEffect, useId, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { Save } from 'lucide-react'
import { derivedDays, renewAfterDays, useRenewal, useSaveRenewal, type RenewalIn, type RenewalOverview } from '../../api/renewal'
import { useTenant } from '../../api/tenant'
import { fmtDate, relative } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { Btn, Callout, ESwitch, ErrorState, LoadingBlock, Panel, SectionHeader, Seg, errorMessage, toast } from '../../ui'

const PRESETS = [50, 60, 70, 80, 90]

const fromData = (d: RenewalOverview): RenewalIn => ({
  user_certs: d.settings.user_certs, machine_certs: d.settings.machine_certs, server_cert: d.settings.server_cert, renew_at_percent: d.settings.renew_at_percent,
})

function SwitchRow({ id, label, hint, checked, onChange, disabled }: { id: string; label: string; hint: ReactNode; checked: boolean; onChange: (v: boolean) => void; disabled: boolean }) {
  return (
    <div className="flex items-start justify-between gap-6 py-3">
      <div className="min-w-0">
        <label htmlFor={id} className="text-[13.5px] font-semibold">{label}</label>
        <p className="ee-small ee-ink-3 mt-0.5 max-w-[70ch]">{hint}</p>
      </div>
      <ESwitch id={id} checked={checked} onChange={onChange} label={label} disabled={disabled} />
    </div>
  )
}

export function RenewalPanel() {
  const { tid, can } = useTenant()
  const q = useRenewal(tid)
  const save = useSaveRenewal(tid)
  const id = useId()
  const now = useNow(60_000)
  const [v, setV] = useState<RenewalIn | null>(null)
  const d = q.data
  useEffect(() => { if (d) setV(fromData(d)) }, [d])

  if (q.isLoading || (d && !v)) return <Panel className="p-5 sm:p-6"><LoadingBlock rows={4} label="Loading renewal settings" /></Panel>
  if (q.error || !d || !v) return <Panel className="p-5 sm:p-6"><ErrorState error={q.error} onRetry={() => q.refetch()} /></Panel>
  const write = can('ca:manage')
  const saved = fromData(d)
  const dirty = (Object.keys(saved) as (keyof RenewalIn)[]).some((k) => saved[k] !== v[k])
  const p = v.renew_at_percent
  const set = <K extends keyof RenewalIn>(k: K, x: RenewalIn[K]) => setV((o) => (o ? { ...o, [k]: x } : o))
  const own = d.templates.filter((t) => !t.group_policy && t.purpose !== 'radius-server')
  const gp = d.templates.filter((t) => t.group_policy)
  const sc = d.server_certificate
  const sched = d.ca_schedule
  // When the current server certificate rotates at the percentage shown (saved or not): not_before + p % of its life.
  const dueAt = sc ? new Date(Date.parse(sc.not_before) + ((Date.parse(sc.not_after) - Date.parse(sc.not_before)) * p) / 100) : null
  const presets = PRESETS.includes(p) ? PRESETS : [...PRESETS, p].sort((a, b) => a - b)
  const submit = () => save.mutate(v, {
    onSuccess: () => toast('Renewal settings saved', saved.renew_at_percent !== p ? 'Templates take the new renewal period; setup files and scripts made from now on use it.' : undefined),
    onError: (e) => toast('Renewal settings weren’t saved', errorMessage(e), 'crit'),
  })

  return (
    <Panel className="p-5 sm:p-6" aria-labelledby={`${id}-h`}>
      <SectionHeader id={`${id}-h`} title="Renewal"
        meta={d.settings.updated_at ? `Changed ${fmtDate(d.settings.updated_at)}${d.settings.updated_by ? ` by ${d.settings.updated_by}` : ''}` : undefined} />
      <p className="ee-small ee-ink-2 max-w-[80ch]">
        Certificates renew by themselves wherever something on the device can ask: the Windows setup file’s daily task, the Linux script’s timer,
        and Group Policy. Each asks with the certificate’s own key, so nobody signs in. Apple and Android profiles can’t renew themselves:
        those users need a new link before the certificate expires, and the dashboard lists them.
      </p>

      <div className="mt-2 divide-y divide-[var(--ee-line)]">
        <SwitchRow id={`${id}-u`} label="User certificates" checked={v.user_certs} onChange={(x) => set('user_certs', x)} disabled={!write}
          hint="Wi-Fi certificates issued to people, through the Windows setup file and the Linux script." />
        <SwitchRow id={`${id}-m`} label="Device certificates" checked={v.machine_certs} onChange={(x) => set('machine_certs', x)} disabled={!write}
          hint="Computer and device certificates, including the Windows setup file’s computer certificate (Wi-Fi before sign-in)." />
        <SwitchRow id={`${id}-s`} label="RADIUS server certificate" checked={v.server_cert} onChange={(x) => set('server_cert', x)} disabled={!write}
          hint={<>EasyEAP issues a new one by itself (checked every 6 hours) and keeps the previous one for {d.limits.rollback_days} days so it can be put back.
            {dueAt && v.server_cert && (dueAt > now ? <> Next: {fmtDate(dueAt.toISOString())}.</>
              : sc?.ca_too_short ? <> The current one is past {p} % of its life, but the issuing CA expires too soon to give a new one 30 days: it waits for a new issuing CA.</>
                : <> The current one is past {p} % of its life: it rotates within 6 hours{dirty ? ' of saving' : ''}.</>)}
          </>} />
      </div>

      <div className="mt-3 space-y-2">
        <p className="text-[13.5px] font-semibold" id={`${id}-p`}>Renew once this much of a certificate’s life has passed</p>
        <div className="flex flex-wrap items-center gap-3">
          {write ? <Seg label="Renew at" value={String(p)} onChange={(x) => set('renew_at_percent', Number(x))} options={presets.map((n) => ({ value: String(n), label: `${n} %` }))} />
            : <span className="ee-num text-[13.5px]">{p} %</span>}
        </div>
        <p className="ee-small ee-ink-2">
          A 365-day certificate renews from day {renewAfterDays(365, p)}, {derivedDays(365, p)} days before it expires. A device that’s off or away
          then has that long to come back. Shorter certificates (an issuing CA that expires sooner) renew at the same share of their life.
        </p>
        {own.length > 0 && (
          <p className="ee-small ee-ink-3">
            Templates: {own.map((t) => `${t.name} renews ${derivedDays(t.validity_days, p)} days before expiry`).join('; ')}.
          </p>
        )}
        {gp.length > 0 && (
          <p className="ee-small ee-ink-3">
            Group Policy certificates keep Windows’ own schedule (from 80 % of their life, inside their renewal period), set on the{' '}
            <Link className="underline" to={paths.autoenroll(tid)}>Autoenroll page</Link>.
          </p>
        )}
      </div>

      {write && (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Btn variant="primary" size="sm" onClick={submit} busy={save.isPending} disabled={!dirty}><Save aria-hidden />Save renewal settings</Btn>
          {dirty && <Btn size="sm" variant="ghost" onClick={() => setV(saved)}>Discard changes</Btn>}
        </div>
      )}
      {!write && <p className="ee-small ee-ink-3 mt-3">Changing renewal needs the PKI Administrator or Tenant Administrator role.</p>}

      {sched && (
        <div className="mt-5 border-t border-[var(--ee-line)] pt-4">
          <p className="text-[13.5px] font-semibold">Certificate authority dates</p>
          {sched.issuing.shortening && (
            <Callout tone="warn" className="mt-2" title="New certificates are shorter than their templates say">
              Certificates can’t outlive the issuing CA, so those issued now end on {fmtDate(sched.issuing.expires)} and renew sooner in proportion.
            </Callout>
          )}
          <dl className="mt-2 grid gap-x-6 gap-y-1.5 text-[13px] sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]">
            <dt className="ee-ink-2">Prepare the next issuing CA by</dt><dd>{fmtDate(sched.issuing.prepare_by)} <span className="ee-ink-3">({relative(sched.issuing.prepare_by, now)})</span></dd>
            <dt className="ee-ink-2">Switch to it by</dt><dd>{fmtDate(sched.issuing.switch_by)} <span className="ee-ink-3">({relative(sched.issuing.switch_by, now)})</span></dd>
            <dt className="ee-ink-2">{sched.issuing.common_name} expires</dt><dd>{fmtDate(sched.issuing.expires)}</dd>
            {sched.root && <><dt className="ee-ink-2">{sched.root.common_name} expires</dt><dd>{fmtDate(sched.root.expires)}</dd></>}
            {sched.root?.crl_next_update && <><dt className="ee-ink-2">Root revocation list valid until</dt><dd>{fmtDate(sched.root.crl_next_update)}</dd></>}
          </dl>
          <p className="ee-small ee-ink-3 mt-2 max-w-[80ch]">
            Switching by then lets every {sched.longest_validity_days}-day certificate be issued at full length with 90 days to spare. A new issuing CA
            is signed with the offline root key; the console doesn’t make one yet, so these are the dates to plan for.
          </p>
        </div>
      )}
    </Panel>
  )
}
