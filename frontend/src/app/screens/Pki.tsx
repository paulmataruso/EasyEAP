// Certificate authority: the ceremony (when not initialised), root and issuing CA, chain and public URLs, the CRL,
// and certificate templates.
import { useEffect, useId, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, FileKey, Pencil, Plus, RefreshCw } from 'lucide-react'
import { api, saveBlob } from '../api/client'
import { qk } from '../api/keys'
import {
  KEY_ALGORITHMS, TEMPLATE_FIELDS, chainUrl, keyAlgorithmLabels, purposeLabels, usePki, useRotateCrl, useSaveTemplate,
  type CertificateAuthority, type CertificateTemplate, type IssuingCrl, type PkiOverview, type TemplateIn,
} from '../api/pki'
import { useTenant } from '../api/tenant'
import { ago, fmtDate, fmtDateTime, fmtFingerprint, fmtSerial, plural, relative, remaining } from '../lib/format'
import { useNow } from '../lib/useNow'
import {
  Btn, Callout, Chip, CopyButton, EDialog, ESelect, ESwitch, ErrorState, Field, LoadingBlock, PageHeader, Panel, SectionHeader, Seg,
  errorMessage, toast,
} from '../ui'
import { CeremonyForm } from './setup/Ceremony'

export default function Pki() {
  const { tid, tenant } = useTenant()
  const q = usePki(tid)
  if (q.isLoading) return <><PageHeader title="Certificate authority" /><LoadingBlock rows={8} label="Loading the certificate authority" /></>
  if (q.error || !q.data) return <><PageHeader title="Certificate authority" /><ErrorState error={q.error} onRetry={() => q.refetch()} /></>
  const d = q.data
  if (!d.initialized) {
    return (
      <div>
        <PageHeader title="Certificate authority" lede={`${tenant.name} has no certificate authority yet. Create one to issue device and RADIUS server certificates.`} />
        <Panel className="max-w-[1100px] p-5 sm:p-6" risk="gold" aria-labelledby="pki-cer-h">
          <SectionHeader id="pki-cer-h" title="Run the CA ceremony" meta="About a minute" />
          <CeremonyForm labMode={d.lab_mode} />
        </Panel>
      </div>
    )
  }
  return <Initialized d={d} />
}

function Initialized({ d }: { d: PkiOverview }) {
  const { tenant } = useTenant()
  const root = d.authorities.find((a) => a.role === 'root')
  const issuing = d.authorities.find((a) => a.role === 'issuing')
  return (
    <div>
      <PageHeader title="Certificate authority" lede={`${tenant.name} issues certificates from ${issuing?.common_name ?? 'its issuing CA'}${root ? `, signed by ${root.common_name}` : ''}.`} />
      <div className="space-y-6">
        <div className="grid gap-6 xl:grid-cols-2">
          {root && <CaPanel ca={root} />}
          {issuing && <CaPanel ca={issuing} />}
        </div>
        <div className="grid items-start gap-6 xl:grid-cols-12">
          <Distribution d={d} />
          <Crl root={root} crl={d.crl} crlUrl={d.urls.crl} />
        </div>
        <Templates templates={d.templates} />
      </div>
    </div>
  )
}

const Row = ({ k, children }: { k: string; children: ReactNode }) => (
  <div className="grid gap-x-4 gap-y-0.5 py-2 sm:grid-cols-[minmax(0,7.5rem)_minmax(0,1fr)] sm:items-baseline">
    <dt className="ee-label">{k}</dt>
    <dd className="min-w-0 text-[13.5px]">{children}</dd>
  </div>
)

function CaPanel({ ca }: { ca: CertificateAuthority }) {
  const now = useNow(60_000)
  const isRoot = ca.role === 'root'
  const days = (new Date(ca.not_after).getTime() - now.getTime()) / 864e5
  const tone = days < 0 ? 'crit' : days < 180 ? 'warn' : undefined
  return (
    <Panel className="min-w-0 p-5 sm:p-6" risk={tone} aria-labelledby={`ca-${ca.id}`}>
      <SectionHeader id={`ca-${ca.id}`} title={isRoot ? 'Root CA' : 'Issuing CA'}
        actions={isRoot
          ? (ca.offline ? <Chip tone="gold" icon={<FileKey aria-hidden />}>Offline</Chip> : <Chip tone="warn">Online (lab mode)</Chip>)
          : <Chip tone="valid">Online · signs certificates</Chip>} />
      <dl className="ee-divide">
        <Row k="Name"><span className="font-semibold">{ca.common_name}</span></Row>
        <Row k="Subject"><span className="ee-mono text-[12.5px] [overflow-wrap:anywhere]">{ca.subject}</span></Row>
        <Row k="Key">{keyAlgorithmLabels[ca.key_algorithm] ?? ca.key_algorithm}</Row>
        <Row k="Valid">
          <span className="flex flex-wrap items-baseline justify-between gap-x-3">
            <span>{fmtDate(ca.not_before)} to {fmtDate(ca.not_after)}</span>
            <span className={tone === 'warn' ? 'ee-remaining text-[var(--ee-warn-ink)]' : tone === 'crit' ? 'ee-remaining text-[var(--ee-crit-ink)]' : 'ee-remaining ee-ink-2'}>{remaining(ca.not_after, now)}</span>
          </span>
        </Row>
        <Row k="Serial"><span className="ee-mono text-[12.5px] break-all">{fmtSerial(ca.serial)}</span></Row>
        <Row k="SHA-256"><span className="ee-mono text-[12px] leading-[1.6] break-all ee-ink-2">{fmtFingerprint(ca.fingerprint_sha256)}</span></Row>
      </dl>
      <p className="ee-small ee-ink-3 mt-3">
        {isRoot
          ? ca.offline ? 'Its private key exists only in the encrypted file downloaded during the ceremony. EasyEAP can’t sign with it.' : 'Its private key is kept in OpenBao because the ceremony ran in lab mode.'
          : 'Its private key never leaves OpenBao. Certificates it issues can’t outlive it.'}
      </p>
    </Panel>
  )
}

function UrlRow({ label, url, note }: { label: string; url: string; note?: string }) {
  return (
    <div className="py-2.5">
      <div className="flex items-center justify-between gap-3">
        <p className="text-[13px] font-semibold">{label}</p>
        <CopyButton text={url} what={`${label} URL`} label="Copy URL" />
      </div>
      <a href={url} className="ee-mono mt-0.5 block text-[12.5px] ee-ink-2 break-all hover:text-[var(--ee-ink)]" target="_blank" rel="noreferrer">{url}</a>
      {note && <p className="ee-small ee-ink-3 mt-0.5">{note}</p>}
    </div>
  )
}

function Distribution({ d }: { d: PkiOverview }) {
  const { tid, tenant } = useTenant()
  const [busy, setBusy] = useState(false)
  const download = async () => {
    setBusy(true)
    try {
      const pem = await api.get<string>(chainUrl(tid))
      saveBlob(new Blob([pem], { type: 'application/x-pem-file' }), `${tenant.slug}-ca-chain.pem`)
    } catch (e) {
      toast('The chain wasn’t downloaded', errorMessage(e), 'crit')
    } finally { setBusy(false) }
  }
  return (
    <Panel className="min-w-0 p-5 sm:p-6 xl:col-span-7" aria-labelledby="pki-dist-h">
      <SectionHeader id="pki-dist-h" title="Distribution" actions={<Btn size="sm" busy={busy} onClick={download}><Download aria-hidden />CA chain (PEM)</Btn>} />
      <p className="ee-small ee-ink-2 mb-2 max-w-[75ch]">The chain holds the issuing and root CA certificates. Enrollment profiles install it on devices automatically; controllers and other relying parties can use it too. These public URLs are served over plain HTTP, as certificate clients expect.</p>
      <div className="ee-divide">
        <UrlRow label="Issuing CA certificate" url={d.urls.ca} />
        <UrlRow label="Root CA certificate" url={d.urls.root_ca} />
        <UrlRow label="Certificate revocation list" url={d.urls.crl} note="Published in every certificate EasyEAP issues." />
        <UrlRow label="Root revocation list" url={d.urls.root_crl} />
        <UrlRow label="OCSP responder" url={d.urls.ocsp} />
      </div>
    </Panel>
  )
}

interface AuditLite { items: Array<{ at: string; actor: string; action: string }> }

/** Edge light: crit once the list has expired (RADIUS rejects everything), warn inside its last 12 hours or when unreadable. */
function crlRisk(crl: IssuingCrl | null, now: Date): 'crit' | 'warn' | undefined {
  if (!crl) return undefined
  if (!crl.available) return 'warn'
  if (!crl.next_update) return undefined
  const left = new Date(crl.next_update).getTime() - now.getTime()
  return left <= 0 ? 'crit' : left < 12 * 3600_000 ? 'warn' : undefined
}

function Crl({ root, crl, crlUrl }: { root?: CertificateAuthority; crl: IssuingCrl | null; crlUrl: string }) {
  const { tid, can } = useTenant()
  const now = useNow()
  const rotate = useRotateCrl(tid)
  const auditParams = { q: 'pki.crl_rotated', page_size: 1 }
  const last = useQuery({
    queryKey: qk.tenantAudit(tid, auditParams),
    queryFn: ({ signal }) => api.get<AuditLite>(`/api/tenants/${tid}/audit?q=pki.crl_rotated&page_size=1`, signal),
    enabled: can('audit:read'),
  })
  const lastManual = last.data?.items[0]
  return (
    <Panel className="min-w-0 p-5 sm:p-6 xl:col-span-5" aria-labelledby="pki-crl-h" risk={crlRisk(crl, now)}>
      <SectionHeader id="pki-crl-h" title="Revocation list"
        actions={can('ca:manage') ? <Btn size="sm" busy={rotate.isPending} onClick={() => rotate.mutate(undefined, {
          onSuccess: () => toast('Revocation list rebuilt', 'RADIUS loads it with its next configuration refresh, usually within seconds.'),
          onError: (e) => toast('The revocation list wasn’t rebuilt', errorMessage(e), 'crit'),
        })}><RefreshCw aria-hidden />Rebuild now</Btn> : undefined} />
      <div className="space-y-3 text-[13.5px]">
        <p className="ee-ink-2">EasyEAP rebuilds the issuing CA’s revocation list after every revocation and every 24 hours. Each list is valid for 72 hours, and RADIUS checks devices against it on every full handshake.</p>
        {crl && !crl.available && <Callout tone="warn" title="The current revocation list couldn’t be read">The certificate authority didn’t answer. RADIUS keeps the last list it loaded; check System health.</Callout>}
        {crl?.next_update && new Date(crl.next_update).getTime() <= now.getTime() && (
          <Callout tone="crit" title="The revocation list has expired">RADIUS rejects every certificate from this CA until a new list is published. Rebuild it now (Tenant or PKI Administrator), then check System health for the worker.</Callout>
        )}
        <dl className="ee-divide border-y border-[var(--ee-line)]">
          {crl?.this_update && (
            <Row k="Published"><span title={fmtDateTime(crl.this_update)}>{ago(crl.this_update, now)}</span>{crl.revoked_count !== null && <span className="ee-ink-3"> · {plural(crl.revoked_count, 'revoked certificate')}</span>}</Row>
          )}
          {crl?.next_update && (
            <Row k="Valid until">{fmtDateTime(crl.next_update)} <span className="ee-ink-3">({relative(crl.next_update, now)})</span></Row>
          )}
          <Row k="Last manual rebuild">
            {!can('audit:read') ? <span className="ee-ink-3">Needs audit access</span>
              : last.isLoading ? <span className="ee-ink-3">Loading…</span>
                : lastManual ? <span title={fmtDateTime(lastManual.at)}>{ago(lastManual.at, now)} by {lastManual.actor}</span>
                  : <span className="ee-ink-3">None from the console</span>}
          </Row>
          {root?.crl_next_update && (
            <Row k="Root CRL valid until">{fmtDate(root.crl_next_update)} <span className="ee-ink-3">({relative(root.crl_next_update, now)})</span></Row>
          )}
          <Row k="Published at"><span className="ee-mono text-[12.5px] break-all">{crlUrl}</span></Row>
        </dl>
      </div>
    </Panel>
  )
}

// ── Templates ───────────────────────────────────────────────────────────
function Templates({ templates }: { templates: CertificateTemplate[] }) {
  const { can } = useTenant()
  const [editing, setEditing] = useState<CertificateTemplate | 'new' | null>(null)
  const canWrite = can('templates:write')
  const keygen = (t: CertificateTemplate) => [t.allow_client_keygen && 'On device', t.allow_server_keygen && 'By EasyEAP'].filter(Boolean).join(', ') || '—'
  return (
    <Panel className="p-5 sm:p-6" aria-labelledby="pki-tpl-h">
      <SectionHeader id="pki-tpl-h" title="Certificate templates" meta={`${templates.length} templates`}
        actions={canWrite ? <Btn size="sm" onClick={() => setEditing('new')}><Plus aria-hidden />New template</Btn> : undefined} />
      <p className="ee-small ee-ink-2 mb-4 max-w-[75ch]">Templates set the key type, lifetime and names of the certificates EasyEAP issues. Names come from directory data; a device can’t request a certificate for anyone else. Changes apply to certificates issued afterwards.</p>
      <div className="hidden lg:block">
        <table className="ee-table">
          <caption className="sr-only">Certificate templates</caption>
          <thead><tr><th>Template</th><th>Key</th><th className="text-right">Lifetime</th><th className="text-right">Renew before</th><th>Subject and names</th><th>Key generated</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {templates.map((t) => (
              <tr key={t.id}>
                <td><span className="font-semibold">{t.name}</span><span className="ee-small ee-ink-3 block">{purposeLabels[t.purpose] ?? t.purpose}</span></td>
                <td className="whitespace-nowrap">{keyAlgorithmLabels[t.key_algorithm] ?? t.key_algorithm}</td>
                <td className="ee-num whitespace-nowrap text-right">{t.validity_days} days</td>
                <td className="ee-num whitespace-nowrap text-right">{t.renew_before_days} days</td>
                <td className="ee-mono text-[12.5px]"><span className="block">{t.subject_pattern}</span><span className="ee-ink-3 block">{t.san_patterns.join(', ')}</span></td>
                <td className="ee-ink-2">{keygen(t)}</td>
                <td className="text-right">
                  {t.purpose === 'radius-server' ? <span className="ee-small ee-ink-3 whitespace-nowrap">Managed by EasyEAP</span>
                    : canWrite ? <Btn size="sm" variant="ghost" onClick={() => setEditing(t)} aria-label={`Edit ${t.name}`}><Pencil aria-hidden />Edit</Btn> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="lg:hidden divide-y divide-[var(--ee-line)] border-y border-[var(--ee-line)]" aria-label="Certificate templates">
        {templates.map((t) => (
          <li key={t.id} className="py-3 text-[13px]">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0"><p className="font-semibold">{t.name}</p><p className="ee-small ee-ink-3">{purposeLabels[t.purpose] ?? t.purpose} · {keyAlgorithmLabels[t.key_algorithm] ?? t.key_algorithm}</p></div>
              {t.purpose !== 'radius-server' && canWrite && <Btn size="sm" variant="ghost" onClick={() => setEditing(t)} aria-label={`Edit ${t.name}`}><Pencil aria-hidden />Edit</Btn>}
            </div>
            <p className="mt-1.5 ee-num">{t.validity_days} days · renew {t.renew_before_days} days before expiry</p>
            <p className="ee-mono text-[12.5px] ee-ink-2 break-all mt-1">{t.subject_pattern} · {t.san_patterns.join(', ')}</p>
          </li>
        ))}
      </ul>
      {!canWrite && <p className="ee-small ee-ink-3 mt-3">Editing templates needs the PKI Administrator or Tenant Administrator role.</p>}
      <TemplateDialog editing={editing} onClose={() => setEditing(null)} />
    </Panel>
  )
}

const emptyTemplate: TemplateIn = {
  name: '', purpose: 'user', key_algorithm: 'ecdsa-p256', validity_days: 365, renew_before_days: 30, subject_pattern: 'CN={upn}',
  san_patterns: ['upn:{upn}', 'email:{email}'], allow_client_keygen: true, allow_server_keygen: false,
}

function templateErrors(v: TemplateIn, sans: string) {
  const fields = (p: string) => [...p.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).filter((f) => !(TEMPLATE_FIELDS as readonly string[]).includes(f))
  const lines = sans.split('\n').map((s) => s.trim()).filter(Boolean)
  const badField = [v.subject_pattern, ...lines].flatMap(fields)[0]
  return {
    name: v.name.trim().length < 2 ? 'Name the template, for example “Laptop Wi-Fi”.' : null,
    validity_days: !Number.isInteger(v.validity_days) || v.validity_days < 1 || v.validity_days > 825 ? 'Choose 1 to 825 days.' : null,
    renew_before_days: !Number.isInteger(v.renew_before_days) || v.renew_before_days < 1 || v.renew_before_days > 180 ? 'Choose 1 to 180 days.'
      : v.renew_before_days >= v.validity_days ? 'Renewal must start before the certificate expires.' : null,
    subject_pattern: !v.subject_pattern.startsWith('CN=') ? 'The subject must start with CN=, for example CN={upn}.' : badField ? `Unknown field {${badField}}. Use one of: ${TEMPLATE_FIELDS.join(', ')}.` : null,
    san_patterns: lines.some((l) => !/^(upn|email|dns):/.test(l)) ? 'Start each name with upn:, email: or dns:.' : null,
    keygen: !v.allow_client_keygen && !v.allow_server_keygen ? 'Allow at least one way to generate the key.' : null,
  }
}

function TemplateDialog({ editing, onClose }: { editing: CertificateTemplate | 'new' | null; onClose: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const save = useSaveTemplate(tid)
  const [v, setV] = useState<TemplateIn>(emptyTemplate)
  const [sans, setSans] = useState('')
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (!editing) return
    const t: TemplateIn = editing === 'new' ? emptyTemplate : {
      name: editing.name, purpose: editing.purpose === 'device' ? 'device' : 'user', key_algorithm: editing.key_algorithm, validity_days: editing.validity_days,
      renew_before_days: editing.renew_before_days, subject_pattern: editing.subject_pattern, san_patterns: editing.san_patterns,
      allow_client_keygen: editing.allow_client_keygen, allow_server_keygen: editing.allow_server_keygen,
    }
    setV(t)
    setSans(t.san_patterns.join('\n'))
    setTouched(false)
    setError(null)
  }, [editing])
  const set = <K extends keyof TemplateIn>(k: K, val: TemplateIn[K]) => setV((p) => ({ ...p, [k]: val }))
  const errors = templateErrors(v, sans)
  const err = (k: keyof typeof errors) => (touched ? errors[k] : null)
  const num = (s: string) => (s === '' ? NaN : Number(s.replace(/[^0-9]/g, '')))
  const submit = () => {
    setTouched(true)
    setError(null)
    if (Object.values(errors).some(Boolean)) return
    const body = { ...v, name: v.name.trim(), subject_pattern: v.subject_pattern.trim(), san_patterns: sans.split('\n').map((s) => s.trim()).filter(Boolean) }
    save.mutate({ id: editing && editing !== 'new' ? editing.id : undefined, body }, {
      onSuccess: () => { toast(editing === 'new' ? 'Template created' : 'Template saved', `${body.name}. It applies to certificates issued from now on.`); onClose() },
      onError: (e) => setError(errorMessage(e)),
    })
  }
  return (
    <EDialog open={!!editing} onOpenChange={(o) => !o && onClose()} wide title={editing === 'new' ? 'New certificate template' : `Edit ${editing?.name ?? 'template'}`}
      description="Existing certificates keep the settings they were issued with."
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" busy={save.isPending} onClick={submit}>{editing === 'new' ? 'Create template' : 'Save template'}</Btn></>}>
      <form className="space-y-4" noValidate onSubmit={(e) => { e.preventDefault(); submit() }}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" htmlFor={`${id}-n`} error={err('name')}>
            <input id={`${id}-n`} className="ee-input" maxLength={80} value={v.name} onChange={(e) => set('name', e.target.value)} aria-invalid={!!err('name') || undefined} autoFocus />
          </Field>
          <Field label="Issued to" hint="User certificates follow a person to any device; device certificates name one device.">
            <Seg label="Issued to" value={v.purpose} onChange={(x) => set('purpose', x)} options={[{ value: 'user', label: 'Users' }, { value: 'device', label: 'Devices' }]} />
          </Field>
          <Field label="Key algorithm" htmlFor={`${id}-k`}>
            <ESelect id={`${id}-k`} label="Key algorithm" value={v.key_algorithm} onChange={(x) => set('key_algorithm', x)} className="w-full" options={KEY_ALGORITHMS.map((a) => ({ value: a, label: keyAlgorithmLabels[a] }))} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Lifetime (days)" htmlFor={`${id}-v`} error={err('validity_days')}>
              <input id={`${id}-v`} className="ee-input ee-num" inputMode="numeric" value={Number.isNaN(v.validity_days) ? '' : v.validity_days} onChange={(e) => set('validity_days', num(e.target.value))} aria-invalid={!!err('validity_days') || undefined} />
            </Field>
            <Field label="Renew before (days)" htmlFor={`${id}-r`} error={err('renew_before_days')}>
              <input id={`${id}-r`} className="ee-input ee-num" inputMode="numeric" value={Number.isNaN(v.renew_before_days) ? '' : v.renew_before_days} onChange={(e) => set('renew_before_days', num(e.target.value))} aria-invalid={!!err('renew_before_days') || undefined} />
            </Field>
          </div>
        </div>
        <Field label="Subject" htmlFor={`${id}-s`} error={err('subject_pattern')} hint={<>Fields: {TEMPLATE_FIELDS.map((f) => `{${f}}`).join(' ')}</>}>
          <input id={`${id}-s`} className="ee-input ee-mono" maxLength={200} value={v.subject_pattern} onChange={(e) => set('subject_pattern', e.target.value)} spellCheck={false} aria-invalid={!!err('subject_pattern') || undefined} />
        </Field>
        <Field label="Subject alternative names" htmlFor={`${id}-san`} error={err('san_patterns')} hint="One per line, starting with upn:, email: or dns:. A name whose field is empty for a user is skipped.">
          <textarea id={`${id}-san`} className="ee-textarea" rows={3} value={sans} onChange={(e) => setSans(e.target.value)} spellCheck={false} aria-invalid={!!err('san_patterns') || undefined} />
        </Field>
        <div className="space-y-3">
          <div className="flex items-start justify-between gap-6">
            <div><p className="text-[13px] font-semibold">Device generates its key</p><p className="ee-small ee-ink-3">The enrollment portal creates the key on the device and sends only a certificate request.</p></div>
            <ESwitch checked={v.allow_client_keygen} onChange={(x) => set('allow_client_keygen', x)} label="Device generates its key" />
          </div>
          <div className="flex items-start justify-between gap-6">
            <div><p className="text-[13px] font-semibold">EasyEAP may generate the key</p><p className="ee-small ee-ink-3">For devices that can’t create a request: EasyEAP builds a password-protected PKCS#12 file.</p></div>
            <ESwitch checked={v.allow_server_keygen} onChange={(x) => set('allow_server_keygen', x)} label="EasyEAP may generate the key" />
          </div>
          {err('keygen') && <p className="ee-field-error" role="alert">{err('keygen')}</p>}
        </div>
        {error && <Callout tone="crit" title="The template wasn’t saved">{error}</Callout>}
      </form>
    </EDialog>
  )
}
