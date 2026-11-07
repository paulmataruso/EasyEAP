// Group Policy autoenrollment (docs/plans/gpo-autoenrollment.md, docs/autoenrollment.md): domain PCs and their users
// get certificates from EasyEAP through Group Policy, as from AD CS. PCs authenticate with Kerberos; EasyEAP checks
// every computer and user in Active Directory.
// Intents: ?tab=settings|log
import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { CheckCircle2, CircleAlert, Download, FileBadge, FlaskConical, RefreshCw, Trash2, TriangleAlert, Upload } from 'lucide-react'
import {
  codeLabels, fetchScript, useAutoenroll, useAutoenrollEvents, useDeleteKeytab, useReenroll, useSaveAutoenroll, useTestKeytab,
  useUploadKeytab, type AutoenrollEvent, type AutoenrollStatus, type AutoenrollTemplate, type EventOutcome, type ReadinessItem,
  type ResponseFormat,
} from '../api/autoenroll'
import { errorField, saveBlob } from '../api/client'
import { useDirectoryGroups } from '../api/directory'
import { useTenant } from '../api/tenant'
import { ago, fmtDateTime, plural } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import {
  Btn, Callout, Chip, CopyButton, Dl, EDialog, ESelect, ESwitch, Empty, ErrorState, Field, LoadingBlock, PageHeader, Panel, SectionHeader,
  Seg, errorMessage, toast, type Tone,
} from '../ui'
import { useUrlState } from './people/shared'

type Tab = 'setup' | 'settings' | 'log'
const TABS: Tab[] = ['setup', 'settings', 'log']

export default function Autoenroll() {
  const { tid, tenant, can } = useTenant()
  const write = can('directory:write')
  const { values, set } = useUrlState(['tab'] as const)
  const tab: Tab = (TABS as string[]).includes(values.tab) ? (values.tab as Tab) : 'setup'
  const q = useAutoenroll(tid)
  const data = q.data
  return (
    <div>
      <PageHeader
        title={<span className="inline-flex flex-wrap items-center gap-2">Group Policy autoenrollment <Chip tone="gold">Preview</Chip></span>}
        lede={<>Domain PCs in {tenant.name}, and the people who sign in to them, get certificates from EasyEAP through Group Policy, the way they would from AD CS: nothing to download or click, renewed by Windows. PCs prove who they are with Kerberos, and EasyEAP checks every computer and user in Active Directory.</>}
      />
      {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="Autoenrollment couldn’t be loaded" /> : !data ? <LoadingBlock rows={6} label="Loading autoenrollment" /> : (
        <>
          <Summary data={data} />
          <div className="mb-4 max-w-full overflow-x-auto">
            <Seg label="View" value={tab} onChange={(v) => set({ tab: v === 'setup' ? null : v })} options={[
              { value: 'setup', label: 'Set up' },
              { value: 'settings', label: 'Settings' },
              { value: 'log', label: 'Request log' },
            ]} />
          </div>
          {tab === 'setup' && <SetupTab data={data} write={write} onSettings={() => set({ tab: 'settings' })} />}
          {tab === 'settings' && <SettingsTab data={data} write={write} />}
          {tab === 'log' && <LogTab />}
        </>
      )}
    </div>
  )
}

function Summary({ data }: { data: AutoenrollStatus }) {
  const now = useNow(60_000)
  const c = data.config
  const state: [Tone, string] = !c.enabled ? ['neutral', 'Off'] : data.ready ? ['valid', 'On'] : ['warn', 'On, not ready']
  return (
    <Panel className="mb-4 px-4 py-3 sm:px-5" aria-label="Autoenrollment status">
      <Dl cols={3} items={[
        ['Status', <Chip tone={state[0]}>{state[1]}</Chip>],
        ['Issued to', c.enabled ? [c.computers && 'computers', c.users && 'users'].filter(Boolean).join(' and ') || 'nobody (both off)' : '—'],
        ['Certificates from Group Policy', <span className="ee-num">{data.counts.certificates.toLocaleString('en-GB')}</span>],
        ['Computers known', <span className="ee-num">{data.counts.computers.toLocaleString('en-GB')}</span>],
        ['Last request handled', c.last_success_at ? <span title={fmtDateTime(c.last_success_at)}>{ago(c.last_success_at, now)}</span> : 'Never'],
        ['Last problem', c.last_error_at ? <span title={c.last_error ?? ''}>{ago(c.last_error_at, now)}</span> : 'None'],
      ]} />
    </Panel>
  )
}

// ── Set up ───────────────────────────────────────────────────────────────

const levelTone: Record<ReadinessItem['level'], Tone> = { ok: 'valid', warning: 'warn', error: 'crit' }
const readinessTitle: Record<string, string> = {
  host: 'Console host name', directory: 'Active Directory', pki: 'Certificate authority', keytab: 'Keytab', keytab_test: 'Keytab test',
  binding: 'Channel binding', policy: 'Access policy', quota: 'Who can add computers',
}

function Readiness({ items }: { items: ReadinessItem[] }) {
  return (
    <ul className="ee-divide" aria-label="Readiness">
      {items.map((i) => (
        <li key={i.key} className="flex items-start gap-3 py-2.5">
          <span className="mt-0.5 shrink-0" style={{ color: `var(--ee-${levelTone[i.level]})` }}>
            {i.level === 'ok' ? <CheckCircle2 aria-label="Ready" size={16} /> : i.level === 'warning' ? <TriangleAlert aria-label="Warning" size={16} /> : <CircleAlert aria-label="Not ready" size={16} />}
          </span>
          <div className="min-w-0">
            <p className="text-[13px] font-semibold">{readinessTitle[i.key] ?? i.key}</p>
            <p className="ee-small ee-ink-2 max-w-[80ch]">{i.message}</p>
          </div>
        </li>
      ))}
    </ul>
  )
}

function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(s)
}

function SetupTab({ data, write, onSettings }: { data: AutoenrollStatus; write: boolean; onSettings: () => void }) {
  const { tid, can } = useTenant()
  const now = useNow(60_000)
  const upload = useUploadKeytab(tid)
  const remove = useDeleteKeytab(tid)
  const test = useTestKeytab(tid)
  const file = useRef<HTMLInputElement>(null)
  const [scriptBusy, setScriptBusy] = useState<string | null>(null)
  const k = data.config.keytab
  const t = data.config.keytab_test

  const download = async (flavor: 'windows' | 'samba') => {
    setScriptBusy(flavor)
    try {
      const s = await fetchScript(tid, flavor)
      saveBlob(new Blob([s.content], { type: 'text/plain' }), s.filename)
    } catch (e) {
      toast('The script wasn’t made', errorMessage(e), 'crit')
    } finally {
      setScriptBusy(null)
    }
  }
  const onFile = async (f: File | undefined) => {
    if (!f) return
    if (f.size > 100_000) return toast('That file is too large for a keytab', undefined, 'crit')
    upload.mutate(toBase64(await f.arrayBuffer()), {
      onSuccess: (d) => toast('Keytab uploaded', d.config.keytab?.problems.length ? 'It has problems: see Readiness.' : 'Now test it.'),
      onError: (e) => toast('The keytab wasn’t uploaded', errorMessage(e), 'crit'),
    })
    if (file.current) file.current.value = ''
  }

  return (
    <div className="space-y-4">
      <Panel className="px-4 py-3 sm:px-5" aria-labelledby="ae-ready-h">
        <SectionHeader id="ae-ready-h" title="Readiness" meta={data.ready ? 'Nothing blocks autoenrollment.' : 'Fix the red items before PCs can enroll.'} />
        <Readiness items={data.readiness} />
      </Panel>

      <Panel className="p-5" aria-labelledby="ae-steps-h">
        <SectionHeader id="ae-steps-h" title="Set it up" />
        <ol className="space-y-6">
          <Step n={1} title="Create the service account">
            <p>Run the script on a domain controller, as a Domain Admin. It creates <code className="ee-mono">{data.config.service_account}</code>, registers <code className="ee-mono">HTTP/{data.host}</code> on it (Kerberos tickets for EasyEAP are made for that name) and writes <code className="ee-mono">easyeap-cep.keytab</code>. Running it again sets a new password, so upload the new keytab afterwards.</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <Btn size="sm" busy={scriptBusy === 'windows'} onClick={() => download('windows')}><Download aria-hidden />Script for Windows AD (.ps1)</Btn>
              <Btn size="sm" busy={scriptBusy === 'samba'} onClick={() => download('samba')}><Download aria-hidden />Script for Samba AD (.sh)</Btn>
            </div>
          </Step>
          <Step n={2} title="Upload and test the keytab">
            {k ? (
              <Dl items={[
                ['Principal', <span className="ee-mono text-[12.5px] break-all">{k.principal ?? '—'}</span>, 'wide'],
                ['Key version', <span className="ee-num">{k.kvno}</span>],
                ['Encryption', k.enctypes.join(', ') || '—'],
                ['Uploaded', k.uploaded_at ? <span title={fmtDateTime(k.uploaded_at)}>{ago(k.uploaded_at, now)}</span> : '—'],
                ['Test', t ? <span className="inline-flex flex-wrap items-center gap-2"><Chip tone={t.ok ? 'valid' : 'crit'}>{t.ok ? 'Passed' : 'Failed'}</Chip><span className="ee-small ee-ink-3">{ago(t.at, now)}</span></span> : 'Not run'],
              ]} />
            ) : <p>Upload the keytab the script wrote, then delete the file. EasyEAP keeps it encrypted.</p>}
            {t && !t.ok && <Callout tone="crit" className="mt-2" title="The test failed">{t.message}</Callout>}
            {k && k.problems.length > 0 && <Callout tone="crit" className="mt-2" title="This keytab won’t work">{k.problems.join(' ')}</Callout>}
            {write && (
              <div className="mt-2 flex flex-wrap gap-2">
                <input ref={file} type="file" accept=".keytab,application/octet-stream" className="sr-only" id="ae-keytab" onChange={(e) => onFile(e.target.files?.[0])} />
                <Btn size="sm" variant={k ? 'default' : 'primary'} busy={upload.isPending} onClick={() => file.current?.click()}><Upload aria-hidden />{k ? 'Replace keytab' : 'Upload keytab'}</Btn>
                {k && <Btn size="sm" busy={test.isPending} onClick={() => test.mutate(undefined, {
                  onSuccess: (d) => toast(d.config.keytab_test?.ok ? 'The keytab works' : 'The test failed', d.config.keytab_test?.message, d.config.keytab_test?.ok ? 'valid' : 'crit'),
                  onError: (e) => toast('The test didn’t run', errorMessage(e), 'crit'),
                })}><FlaskConical aria-hidden />Test</Btn>}
                {k && <Btn size="sm" variant="ghost" busy={remove.isPending} onClick={() => remove.mutate(undefined, { onSuccess: () => toast('Keytab removed'), onError: (e) => toast('It wasn’t removed', errorMessage(e), 'crit') })}><Trash2 aria-hidden />Remove</Btn>}
              </div>
            )}
            <p className="ee-small ee-ink-3 mt-2">The test asks your domain controller for a ticket to <span className="ee-mono">HTTP/{data.host}</span> with the directory’s bind account, as a PC would, and opens it with the keytab. It needs Kerberos (88/tcp) from EasyEAP to the domain controller; enrollment itself doesn’t.</p>
          </Step>
          <Step n={3} title="Turn it on">
            <p>{data.config.enabled ? <>Autoenrollment is on for {[data.config.computers && 'computers', data.config.users && 'users'].filter(Boolean).join(' and ') || 'nobody'}.</> : 'Choose who gets certificates and turn autoenrollment on.'}</p>
            <div className="mt-2"><Btn size="sm" onClick={onSettings}>Open settings</Btn></div>
          </Step>
          <Step n={4} title="Point Group Policy at EasyEAP">
            <p className="mb-2">In a GPO linked to the PCs’ OU, under <b>Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies</b>:</p>
            <ol className="list-decimal space-y-1.5 pl-5 marker:text-[var(--ee-ink-3)]">
              <li className="pl-1"><b>Certificate Services Client – Certificate Enrollment Policy</b>: Enabled. Add a server: paste the URL below, authentication <b>Windows integrated</b>, <b>Validate Server</b>, <b>Add</b>. Tick <b>Default</b> on it.</li>
              <li className="pl-1"><b>Certificate Services Client – Auto-Enrollment</b>: Enabled, with both boxes ticked (renew and remove; update certificates that use templates).</li>
              <li className="pl-1">For user certificates, the same two policies under <b>User Configuration</b>.</li>
              <li className="pl-1">The Wi-Fi and wired policies from the Group Policy guide (RADIUS → Group Policy) connect with these certificates. Computer certificates connect at the sign-in screen, so people can sign in without cached credentials.</li>
            </ol>
            <div className="mt-3 flex flex-wrap items-center gap-2 rounded-[var(--ee-r-2)] border border-[var(--ee-line)] px-3 py-2">
              <span className="ee-small ee-ink-3">Policy server URL</span>
              <span className="ee-mono break-all text-[12.5px]">{data.urls.policy}</span>
              <CopyButton text={data.urls.policy} what="policy server URL" />
            </div>
            {can('radius:read') && <p className="ee-small ee-ink-3 mt-2"><Link className="underline" to={paths.radius(tid)}>RADIUS → Group Policy</Link> has the Wi-Fi and wired policies and the root CA for trusted roots.</p>}
          </Step>
          <Step n={5} title="Try one PC">
            <ol className="list-decimal space-y-1.5 pl-5 marker:text-[var(--ee-ink-3)]">
              <li className="pl-1">On the PC: <code className="ee-mono">gpupdate /force</code>, then <code className="ee-mono">certutil -pulse</code>. <b>certlm.msc → Personal</b> shows a certificate from the “{data.templates.find((x) => x.kind === 'computer')?.common_name ?? 'EasyEAP-Computer'}” template within a minute.</li>
              <li className="pl-1">Signed in as a user (when user certificates are on): <code className="ee-mono">certutil -user -pulse</code>; <b>certmgr.msc → Personal</b>.</li>
              <li className="pl-1">Run <code className="ee-mono">certutil -pulse</code> again: nothing new is issued.</li>
              <li className="pl-1">Sign out: the PC connects at the sign-in screen with its certificate. The Request log here and the Authentication log show each step.</li>
            </ol>
            <p className="ee-small ee-ink-3 mt-2">If nothing arrives: Event Viewer → Applications and Services Logs → Microsoft → Windows → CertificateServicesClient-AutoEnrollment (and -CertEnroll), and the Request log tab here.</p>
          </Step>
        </ol>
      </Panel>
    </div>
  )
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <li className="grid grid-cols-[28px_1fr] gap-3">
      <span className="ee-num grid h-7 w-7 place-items-center rounded-full border border-[var(--ee-line)] text-[13px] font-semibold" aria-hidden>{n}</span>
      <div className="min-w-0 text-[13px]">
        <h3 className="ee-h3 mb-1.5">{title}</h3>
        {children}
      </div>
    </li>
  )
}

// ── Settings ─────────────────────────────────────────────────────────────

const formatLabels: Record<ResponseFormat, string> = {
  unsigned: 'Standard (recommended)',
  signed: 'Signed by an enrollment-service certificate',
  pkcs7: 'Certificates only (PKCS #7)',
}

function SettingsTab({ data, write }: { data: AutoenrollStatus; write: boolean }) {
  const { tid } = useTenant()
  const id = useId()
  const save = useSaveAutoenroll(tid)
  const groups = useDirectoryGroups(tid)
  const c = data.config
  const tpl = (k: 'computer' | 'user') => data.templates.find((x) => x.kind === k)
  const init = () => ({
    enabled: c.enabled, computers: c.computers, users: c.users, group: c.computer_group?.id ?? '', binding: c.require_channel_binding,
    format: c.response_format, cDays: String(tpl('computer')?.validity_days ?? 365), cRenew: String(tpl('computer')?.renew_before_days ?? 42),
    uDays: String(tpl('user')?.validity_days ?? 365), uRenew: String(tpl('user')?.renew_before_days ?? 42),
  })
  const [v, setV] = useState(init)
  const [error, setError] = useState<string | null>(null)
  const [reenroll, setReenroll] = useState<AutoenrollTemplate | null>(null)
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reset the form when the saved settings change
  useEffect(() => setV(init()), [data])
  const put = <K extends keyof ReturnType<typeof init>>(k: K, x: ReturnType<typeof init>[K]) => setV((o) => ({ ...o, [k]: x }))

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    const n = (s: string) => Number(s)
    const days = [n(v.cDays), n(v.cRenew), n(v.uDays), n(v.uRenew)]
    if (days.some((d) => !Number.isInteger(d))) return setError('Use whole numbers of days.')
    const hasTemplates = data.templates.length > 0
    save.mutate({
      enabled: v.enabled, computers: v.computers, users: v.users, computer_group_id: v.group || null, require_channel_binding: v.binding,
      response_format: v.format,
      ...(hasTemplates || v.enabled ? { computer_validity_days: days[0], computer_renew_before_days: days[1], user_validity_days: days[2], user_renew_before_days: days[3] } : {}),
    }, {
      onSuccess: () => toast('Settings saved', v.enabled ? 'PCs pick up changes at their next policy refresh (about every 8 hours, or gpupdate).' : undefined),
      onError: (e2) => setError(errorField(e2) ? `${errorField(e2)}: ${errorMessage(e2)}` : errorMessage(e2)),
    })
  }

  const groupOptions = [{ value: '', label: 'Every computer in the directory' },
    ...(groups.data?.groups ?? []).filter((g) => g.source === 'ad').map((g) => ({ value: g.id, label: g.name }))]
  return (
    <div className="space-y-4">
      <Panel className="p-5" aria-labelledby="ae-set-h">
        <SectionHeader id="ae-set-h" title="Who gets certificates" />
        <form noValidate className="space-y-4" onSubmit={submit} id={`${id}-f`}>
          <fieldset disabled={!write} className="space-y-4">
            <Row label="Autoenrollment" hint="Off: EasyEAP answers no Group Policy requests. Certificates already issued keep working until they expire or you revoke them.">
              <ESwitch label="Autoenrollment" checked={v.enabled} onChange={(x) => put('enabled', x)} />
            </Row>
            <Row label="Computers" hint="Each domain PC gets a certificate for its DNS name. It connects at the sign-in screen, as the computer: rules use the computer’s AD groups.">
              <ESwitch label="Computers" checked={v.computers} onChange={(x) => put('computers', x)} />
            </Row>
            {v.computers && (
              <Field label="Only computers in" htmlFor={`${id}-g`} hint={c.machine_account_quota ? `Any domain user can add up to ${c.machine_account_quota} computers to the domain (ms-DS-MachineAccountQuota). Limit autoenrollment to a group of corporate PCs, or set the quota to 0.` : 'Optional: limit computer certificates to one AD group.'}>
                <ESelect id={`${id}-g`} label="Computer group" className="w-full max-w-[420px]" value={v.group} onChange={(x) => put('group', x)} options={groupOptions} />
              </Field>
            )}
            <Row label="Users" hint="Each person who signs in to a domain PC gets a certificate for their UPN on that PC (one per PC).">
              <ESwitch label="Users" checked={v.users} onChange={(x) => put('users', x)} />
            </Row>
          </fieldset>
        </form>
      </Panel>

      <Panel className="p-5" aria-labelledby="ae-tpl-h">
        <SectionHeader id="ae-tpl-h" title="Certificates" />
        {data.templates.length === 0 ? <p className="ee-small ee-ink-2">The computer and user templates are made when you first turn autoenrollment on.</p> : (
          <div className="overflow-x-auto">
            <table className="ee-table">
              <caption className="sr-only">Autoenrollment templates</caption>
              <thead><tr><th className="pt-1.5">Template</th><th className="pt-1.5">Valid for</th><th className="pt-1.5">Renew when</th><th className="pt-1.5">Revision</th>{write && <th className="pt-1.5"><span className="sr-only">Actions</span></th>}</tr></thead>
              <tbody>
                {(['computer', 'user'] as const).map((k) => {
                  const x = tpl(k)
                  if (!x) return null
                  const [d, r] = k === 'computer' ? ['cDays', 'cRenew'] as const : ['uDays', 'uRenew'] as const
                  return (
                    <tr key={k}>
                      <td className="min-w-[180px]"><span className="font-medium">{x.name}</span><span className="ee-small ee-ink-3 block ee-mono break-all">{x.common_name} · {x.oid}</span></td>
                      <td><span className="flex items-center gap-1.5"><input aria-label={`${x.name}: days valid`} className="ee-input ee-num w-[80px]" inputMode="numeric" disabled={!write} value={v[d]} onChange={(e) => put(d, e.target.value.replace(/\D/g, ''))} /><span className="ee-small ee-ink-2">days</span></span></td>
                      <td><span className="flex items-center gap-1.5"><input aria-label={`${x.name}: days before expiry to renew`} className="ee-input ee-num w-[70px]" inputMode="numeric" disabled={!write} value={v[r]} onChange={(e) => put(r, e.target.value.replace(/\D/g, ''))} /><span className="ee-small ee-ink-2">days before</span></span></td>
                      <td className="ee-num">{x.revision}</td>
                      {write && <td><Btn size="sm" variant="ghost" onClick={() => setReenroll(x)}><RefreshCw aria-hidden />Re-enroll everyone</Btn></td>}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="ee-small ee-ink-3 mt-2">Keys are RSA 2048, made by Windows in the TPM where the PC has one, or in software (PCs without a TPM, or installed with the TPM check bypassed). The private key never leaves the PC.</p>
      </Panel>

      <Panel className="p-5" aria-labelledby="ae-sec-h">
        <SectionHeader id="ae-sec-h" title="Security" />
        <fieldset disabled={!write} className="space-y-4">
          <Row label="Require channel binding" hint="A Kerberos ticket must be bound to the PC’s own TLS connection to EasyEAP (Extended Protection), so a ticket relayed through another server is refused. Windows sends bindings by default. Turn off only if a TLS-inspecting proxy sits between PCs and EasyEAP.">
            <ESwitch label="Require channel binding" checked={v.binding} onChange={(x) => put('binding', x)} />
          </Row>
          <Field label="Response format" htmlFor={`${id}-r`} hint="How the issued certificate is packaged for Windows. Change it only if a PC logs that it can’t read EasyEAP’s response.">
            <ESelect id={`${id}-r`} label="Response format" className="w-full max-w-[420px]" value={v.format} onChange={(x) => put('format', x as ResponseFormat)}
              options={(Object.keys(formatLabels) as ResponseFormat[]).map((f) => ({ value: f, label: formatLabels[f] }))} />
          </Field>
        </fieldset>
      </Panel>

      {error && <Callout tone="crit" title="Settings weren’t saved">{error}</Callout>}
      {write && <Btn type="submit" form={`${id}-f`} variant="primary" busy={save.isPending}>Save settings</Btn>}
      <ReenrollDialog template={reenroll} onClose={() => setReenroll(null)} />
    </div>
  )
}

function Row({ label, hint, children }: { label: string; hint: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0"><p className="text-[13px] font-semibold">{label}</p><p className="ee-small ee-ink-2 max-w-[70ch]">{hint}</p></div>
      <div className="shrink-0 pt-0.5">{children}</div>
    </div>
  )
}

function ReenrollDialog({ template, onClose }: { template: AutoenrollTemplate | null; onClose: () => void }) {
  const { tid } = useTenant()
  const run = useReenroll(tid)
  const who = template?.kind === 'computer' ? 'every PC' : 'every user'
  return (
    <EDialog open={!!template} onOpenChange={(o) => !o && onClose()} title={`Re-enroll ${who}?`} risk="warn"
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" busy={run.isPending} onClick={() => template && run.mutate(template.kind, {
        onSuccess: () => { toast('New revision published', `${who[0].toUpperCase()}${who.slice(1)} gets a new certificate at its next refresh.`); onClose() },
        onError: (e) => toast('Nothing changed', errorMessage(e), 'crit'),
      })}>Re-enroll {who}</Btn></>}>
      <p className="text-[13px]">EasyEAP publishes a new major revision of “{template?.name}”. At its next policy refresh (about every 8 hours, or <code className="ee-mono">gpupdate</code>), {who} requests a new certificate and Windows removes the old one. Use it after changing what goes into the certificates, or when you suspect keys were copied. Old certificates stay valid until they expire or you revoke them.</p>
    </EDialog>
  )
}

// ── Request log ──────────────────────────────────────────────────────────

const outcomeTone: Record<EventOutcome, Tone> = { ok: 'valid', denied: 'warn', error: 'crit' }
const outcomeLabel = (e: AutoenrollEvent) => (e.outcome === 'ok' ? (e.service === 'ces' ? 'Issued' : e.code === 'none' ? 'Nothing offered' : 'Policy sent') : e.outcome === 'denied' ? 'Refused' : 'Failed')

function LogTab() {
  const { tid } = useTenant()
  const now = useNow(30_000)
  const [outcome, setOutcome] = useState<'' | EventOutcome>('')
  const q = useAutoenrollEvents(tid, outcome)
  const items = q.data?.events ?? []
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2.5" role="search" aria-label="Filter the request log">
        <Seg label="Result" value={outcome || 'all'} onChange={(x) => setOutcome(x === 'all' ? '' : (x as EventOutcome))}
          options={[{ value: 'all', label: 'Everything' }, { value: 'ok', label: 'Handled' }, { value: 'denied', label: 'Refused' }, { value: 'error', label: 'Failed' }]} />
      </div>
      {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : q.isLoading ? <LoadingBlock rows={5} label="Loading the request log" /> : items.length === 0 ? (
        <Empty icon={<FileBadge aria-hidden />} title={outcome ? 'Nothing matches' : 'No requests yet'}>
          Each policy request and certificate request from a PC appears here: who asked, from which PC, what EasyEAP answered and why. A PC’s routine policy refresh is logged once every few hours.
        </Empty>
      ) : (
        <Panel className="px-4 py-3 sm:px-5" aria-label="Request log">
          <div className="overflow-x-auto">
            <table className="ee-table">
              <caption className="sr-only">Group Policy requests, newest first</caption>
              <thead><tr><th className="pt-1.5">When</th><th className="pt-1.5">Who</th><th className="pt-1.5">Request</th><th className="pt-1.5">Result</th><th className="pt-1.5">Detail</th></tr></thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap"><span title={fmtDateTime(e.at)}>{ago(e.at, now)}</span></td>
                    <td className="min-w-[140px]">
                      <span className="ee-mono text-[12.5px] break-all">{e.caller || <span className="ee-ink-3">Unknown</span>}</span>
                      <span className="ee-small ee-ink-3 block">{e.kind === 'computer' ? 'Computer' : e.kind === 'user' ? `User${e.machine ? ` on ${e.machine}` : ''}` : ''}{e.ip ? `${e.kind ? ' · ' : ''}${e.ip}` : ''}</span>
                    </td>
                    <td className="whitespace-nowrap">{e.service === 'cep' ? 'Policy' : 'Certificate'}{e.template && <span className="ee-small ee-ink-3 block">{e.template}</span>}</td>
                    <td className="whitespace-nowrap">
                      <span className="flex flex-wrap items-center gap-1.5"><Chip tone={outcomeTone[e.outcome]}>{outcomeLabel(e)}</Chip>{e.outcome !== 'ok' && e.code && <span className="ee-small ee-ink-3">{codeLabels[e.code] ?? e.code}</span>}</span>
                    </td>
                    <td className="min-w-[260px] ee-small">
                      {e.message}
                      {e.certificate_id && <> <Link className="underline" to={paths.certificate(tid, e.certificate_id)}>Open certificate</Link></>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="ee-small ee-ink-3 pt-3">{plural(items.length, 'request')}{q.data?.more ? ' (the latest 200)' : ''}. The last 2,000 requests are kept.</p>
        </Panel>
      )}
    </div>
  )
}
