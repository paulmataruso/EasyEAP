// The certificate authority ceremony: an offline root CA and an online issuing CA per tenant.
// The root key is generated inside OpenBao, used once to sign the issuing CA and the root CRL, returned once encrypted
// under a passphrase, and destroyed on the server. The result dialog can't close until the key file is downloaded and
// the administrator confirms it (and any generated passphrase) is stored.
import { useEffect, useId, useState, type FormEvent } from 'react'
import { Check, Download, KeyRound, ShieldCheck } from 'lucide-react'
import { saveBlob } from '../../api/client'
import {
  KEY_ALGORITHMS, fileBlob, generatePassphrase, keyAlgorithmLabels, useInitializePki, useInvalidatePki,
  type CeremonyIn, type CeremonyOut,
} from '../../api/pki'
import { useTenant } from '../../api/tenant'
import { fmtDate, fmtFingerprint } from '../../lib/format'
import { Btn, Callout, EDialog, ESelect, ESwitch, Field, OneTimeSecret, Seg, errorMessage, toast } from '../../ui'

type Protect = 'generate' | 'own'

function validate(v: CeremonyIn, protect: Protect, own: string, confirm: string) {
  const years = (n: number, lo: number, hi: number) => (!Number.isInteger(n) || n < lo || n > hi ? `Choose ${lo} to ${hi} years.` : null)
  return {
    organization: v.organization.trim().length < 2 ? 'Enter the organisation name that appears in the CA certificates.' : null,
    country: v.country && !/^[A-Za-z]{2}$/.test(v.country) ? 'Use the two-letter country code, for example US or GB.' : null,
    root_common_name: v.root_common_name.trim().length < 3 ? 'Name the root CA, for example “Contoso Root CA”.' : null,
    issuing_common_name: v.issuing_common_name.trim().length < 3 ? 'Name the issuing CA, for example “Contoso Issuing CA 1”.' : null,
    root_validity_years: years(v.root_validity_years, 5, 30),
    issuing_validity_years: years(v.issuing_validity_years, 1, 15) ?? (v.issuing_validity_years >= v.root_validity_years ? 'The issuing CA must expire before the root CA.' : null),
    own: !v.keep_root_online && protect === 'own' && own.length < 12 ? 'Use at least 12 characters.' : null,
    confirm: !v.keep_root_online && protect === 'own' && confirm !== own ? 'The passphrases don’t match.' : null,
  }
}

/** Inline ceremony form plus its one-time result dialog. `onDone` runs after the result dialog closes. */
export function CeremonyForm({ labMode, onDone }: { labMode: boolean; onDone?: () => void }) {
  const { tid, tenant, can } = useTenant()
  const id = useId()
  const run = useInitializePki(tid)
  const invalidate = useInvalidatePki(tid)
  const [v, setV] = useState<CeremonyIn>(() => ({
    organization: tenant.name, country: '', state: '', locality: '',
    root_common_name: `${tenant.name} Root CA`.slice(0, 64), issuing_common_name: `${tenant.name} Issuing CA 1`.slice(0, 64),
    key_algorithm: 'ecdsa-p384', root_validity_years: 20, issuing_validity_years: 8, root_passphrase: null, keep_root_online: false,
  }))
  const [protect, setProtect] = useState<Protect>('generate')
  const [own, setOwn] = useState('')
  const [confirm, setConfirm] = useState('')
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<{ out: CeremonyOut; passphrase: string | null } | null>(null)
  const set = <K extends keyof CeremonyIn>(k: K, val: CeremonyIn[K]) => setV((p) => ({ ...p, [k]: val }))
  const errors = validate(v, protect, own, confirm)
  const err = (k: keyof typeof errors) => (touched ? errors[k] : null)

  if (!can('ca:manage')) {
    return <Callout tone="neutral" title="A PKI Administrator or Tenant Administrator runs the ceremony">Your role can view the certificate authority but not create it.</Callout>
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    setError(null)
    if (Object.values(errors).some(Boolean)) return
    const generated = !v.keep_root_online && protect === 'generate' ? generatePassphrase() : null
    const body: CeremonyIn = {
      ...v, organization: v.organization.trim(), country: v.country.trim().toUpperCase(), state: v.state.trim(), locality: v.locality.trim(),
      root_common_name: v.root_common_name.trim(), issuing_common_name: v.issuing_common_name.trim(),
      root_passphrase: v.keep_root_online ? null : generated ?? own,
    }
    run.mutate(body, {
      onSuccess: (out) => { setResult({ out, passphrase: generated }); setOwn(''); setConfirm('') },
      onError: (e2) => setError(errorMessage(e2)),
    })
  }

  return (
    <>
      <form onSubmit={submit} noValidate className="space-y-6">
        <ol className="grid gap-3 text-[13.5px] md:grid-cols-3">
          {[
            ['Root CA, offline', 'OpenBao generates the root key, signs the issuing CA and the root revocation list with it, then destroys it on the server.'],
            ['You keep the root key', 'You download the root key once, encrypted under a passphrase. You need it only to create a new issuing CA.'],
            ['Issuing CA, online', 'Signs device and RADIUS server certificates. Its key never leaves OpenBao.'],
          ].map(([t, d], i) => (
            <li key={t} className="rounded-[8px] border border-[var(--ee-line)] bg-[rgba(6,9,17,0.3)] px-3.5 py-3">
              <p className="font-semibold"><span className="ee-num ee-ink-3 mr-1.5">{i + 1}</span>{t}</p>
              <p className="ee-small ee-ink-2 mt-1">{d}</p>
            </li>
          ))}
        </ol>

        <fieldset className="space-y-4">
          <legend className="ee-h3 mb-3">Names</legend>
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="Root CA name" htmlFor={`${id}-root`} error={err('root_common_name')}>
              <input id={`${id}-root`} className="ee-input" maxLength={64} value={v.root_common_name} onChange={(e) => set('root_common_name', e.target.value)} aria-invalid={!!err('root_common_name') || undefined} />
            </Field>
            <Field label="Issuing CA name" htmlFor={`${id}-iss`} error={err('issuing_common_name')}>
              <input id={`${id}-iss`} className="ee-input" maxLength={64} value={v.issuing_common_name} onChange={(e) => set('issuing_common_name', e.target.value)} aria-invalid={!!err('issuing_common_name') || undefined} />
            </Field>
            <Field label="Organisation" htmlFor={`${id}-org`} error={err('organization')}>
              <input id={`${id}-org`} className="ee-input" maxLength={64} value={v.organization} onChange={(e) => set('organization', e.target.value)} aria-invalid={!!err('organization') || undefined} />
            </Field>
            <div className="grid grid-cols-[112px_minmax(0,1fr)_minmax(0,1fr)] gap-3">
              <Field label="Country" htmlFor={`${id}-c`} error={err('country')} optional>
                <input id={`${id}-c`} className="ee-input uppercase" maxLength={2} value={v.country} onChange={(e) => set('country', e.target.value.replace(/[^A-Za-z]/g, ''))} aria-invalid={!!err('country') || undefined} autoComplete="off" />
              </Field>
              <Field label="State or region" htmlFor={`${id}-st`} optional>
                <input id={`${id}-st`} className="ee-input" maxLength={64} value={v.state} onChange={(e) => set('state', e.target.value)} />
              </Field>
              <Field label="City" htmlFor={`${id}-l`} optional>
                <input id={`${id}-l`} className="ee-input" maxLength={64} value={v.locality} onChange={(e) => set('locality', e.target.value)} />
              </Field>
            </div>
          </div>
        </fieldset>

        <fieldset className="space-y-4">
          <legend className="ee-h3 mb-3">Keys and lifetime</legend>
          <div className="grid gap-4 md:grid-cols-3">
            <Field label="Key algorithm" htmlFor={`${id}-alg`} hint="ECDSA P-384 suits current devices. Choose RSA only for equipment that can’t use ECDSA.">
              <ESelect id={`${id}-alg`} label="Key algorithm" value={v.key_algorithm} onChange={(x) => set('key_algorithm', x)} className="w-full"
                options={KEY_ALGORITHMS.map((a) => ({ value: a, label: keyAlgorithmLabels[a] }))} />
            </Field>
            <Field label="Root CA lifetime (years)" htmlFor={`${id}-ry`} error={err('root_validity_years')} hint="5 to 30 years.">
              <input id={`${id}-ry`} className="ee-input ee-num" inputMode="numeric" value={Number.isNaN(v.root_validity_years) ? '' : v.root_validity_years}
                onChange={(e) => set('root_validity_years', e.target.value === '' ? NaN : Number(e.target.value.replace(/[^0-9]/g, '')))} aria-invalid={!!err('root_validity_years') || undefined} />
            </Field>
            <Field label="Issuing CA lifetime (years)" htmlFor={`${id}-iy`} error={err('issuing_validity_years')} hint="1 to 15 years. Certificates can’t outlive it.">
              <input id={`${id}-iy`} className="ee-input ee-num" inputMode="numeric" value={Number.isNaN(v.issuing_validity_years) ? '' : v.issuing_validity_years}
                onChange={(e) => set('issuing_validity_years', e.target.value === '' ? NaN : Number(e.target.value.replace(/[^0-9]/g, '')))} aria-invalid={!!err('issuing_validity_years') || undefined} />
            </Field>
          </div>
        </fieldset>

        <fieldset className="space-y-4">
          <legend className="ee-h3 mb-1">Root key protection</legend>
          {labMode && (
            <div className="flex items-start justify-between gap-6 rounded-[8px] border border-[rgba(245,165,36,0.35)] px-3.5 py-3">
              <div>
                <p className="text-[13px] font-semibold">Keep the root CA online (lab mode)</p>
                <p className="ee-small ee-ink-2 mt-0.5">The root key stays in OpenBao and nothing is downloaded. Use this only on a lab install; anyone with OpenBao access could sign a new issuing CA.</p>
              </div>
              <ESwitch checked={v.keep_root_online} onChange={(x) => set('keep_root_online', x)} label="Keep the root CA online" />
            </div>
          )}
          {!v.keep_root_online && (
            <>
              <Seg label="Passphrase" value={protect} onChange={setProtect} options={[{ value: 'generate', label: 'Generate a passphrase' }, { value: 'own', label: 'Use my own passphrase' }]} />
              {protect === 'generate' ? (
                <p className="ee-small ee-ink-2 max-w-[75ch]">This browser generates a random passphrase (six groups of five characters) and sends it with the request. EasyEAP encrypts the root key with it and shows it to you once, next to the download.</p>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  <Field label="Passphrase" htmlFor={`${id}-pw`} error={err('own')} hint="At least 12 characters. EasyEAP doesn’t keep it.">
                    <input id={`${id}-pw`} type="password" className="ee-input" autoComplete="new-password" value={own} onChange={(e) => setOwn(e.target.value)} aria-invalid={!!err('own') || undefined} />
                  </Field>
                  <Field label="Confirm passphrase" htmlFor={`${id}-pw2`} error={err('confirm')}>
                    <input id={`${id}-pw2`} type="password" className="ee-input" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} aria-invalid={!!err('confirm') || undefined} />
                  </Field>
                </div>
              )}
            </>
          )}
        </fieldset>

        {error && <Callout tone="crit" title="The ceremony didn’t complete">{error}</Callout>}
        <div className="flex flex-wrap items-center gap-3">
          <Btn type="submit" variant="primary" size="lg" busy={run.isPending}><ShieldCheck aria-hidden />Create certificate authority</Btn>
          <p className="ee-small ee-ink-3">This can be done once per tenant.</p>
        </div>
      </form>
      <CeremonyResultDialog result={result} onClose={() => { setResult(null); void invalidate(); toast('Certificate authority ready', `${tenant.name} can now issue certificates.`); onDone?.() }} />
    </>
  )
}

function CeremonyResultDialog({ result, onClose }: { result: { out: CeremonyOut; passphrase: string | null } | null; onClose: () => void }) {
  const [downloaded, setDownloaded] = useState(false)
  const [acked, setAcked] = useState(false)
  const out = result?.out
  const keyFile = out?.root_key_file
  const needsKey = !!keyFile

  useEffect(() => {
    if (!result) { setDownloaded(false); setAcked(false); return }
    // The key file exists only in this page's memory: warn before a reload or tab close loses it.
    if (!needsKey) return
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault() }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [result, needsKey])

  const ready = !needsKey || (downloaded && acked)
  const download = () => {
    if (!keyFile) return
    saveBlob(fileBlob(keyFile), keyFile.filename)
    setDownloaded(true)
  }

  return (
    <EDialog open={!!result} onOpenChange={(o) => { if (!o && ready) onClose() }} wide blockDismiss={!ready} risk="gold"
      title="Certificate authority created"
      description={needsKey ? 'The root CA is now offline. EasyEAP kept no copy of its private key: this is the only chance to save it.' : 'The root CA key stays online in OpenBao (lab mode).'}
      footer={<>
        {!ready && <span className="ee-small ee-ink-3 mr-auto">{!downloaded ? 'Download the root key to continue.' : 'Confirm you’ve stored it to continue.'}</span>}
        <Btn variant="primary" disabled={!ready} onClick={onClose}>Done</Btn>
      </>}>
      {out && (
        <div className="space-y-5">
          {needsKey && keyFile && (
            <section className="space-y-3" aria-labelledby="cer-key-h">
              <h3 id="cer-key-h" className="ee-h3">1. Download the encrypted root key</h3>
              <div className="flex flex-wrap items-center gap-3">
                <Btn variant={downloaded ? 'default' : 'primary'} onClick={download}>{downloaded ? <Check aria-hidden /> : <Download aria-hidden />}{downloaded ? 'Downloaded' : 'Download root key'}</Btn>
                <span className="ee-mono text-[12.5px] ee-ink-2 break-all">{keyFile.filename}</span>
              </div>
              <p className="ee-small ee-ink-2">A PKCS#8 file encrypted with the passphrase. Keep it offline, for example on encrypted removable media in a safe. You need it only to create a new issuing CA.</p>
              {out.root_cert_file && (
                <Btn size="sm" variant="ghost" onClick={() => out.root_cert_file && saveBlob(fileBlob(out.root_cert_file), out.root_cert_file.filename)}><Download aria-hidden />Root certificate (public)</Btn>
              )}
            </section>
          )}
          {needsKey && (
            <section className="space-y-3 border-t border-[var(--ee-line)] pt-4" aria-labelledby="cer-pass-h">
              <h3 id="cer-pass-h" className="ee-h3">2. {result?.passphrase ? 'Save the passphrase' : 'Confirm'}</h3>
              {result?.passphrase ? (
                <OneTimeSecret value={result.passphrase} what="root key passphrase" acknowledged={acked} onAcknowledge={setAcked}
                  note={<>EasyEAP shows this passphrase once and keeps no copy. Store it apart from the key file, for example in your password manager. Without both, nobody can create a new issuing CA for this tenant.</>} />
              ) : (
                <>
                  <p className="ee-small ee-ink-2">The key file is encrypted with the passphrase you entered. EasyEAP keeps no copy of either.</p>
                  <label className="flex items-center gap-2.5 text-[13px]">
                    <input type="checkbox" className="ee-check" checked={acked} onChange={(e) => setAcked(e.target.checked)} />
                    I’ve stored the root key file and its passphrase somewhere safe
                  </label>
                </>
              )}
              {!downloaded && acked && <p className="ee-small text-[var(--ee-warn-ink)]">Download the root key file too: it can’t be downloaded later.</p>}
            </section>
          )}
          <section className="space-y-2 border-t border-[var(--ee-line)] pt-4" aria-labelledby="cer-fp-h">
            <h3 id="cer-fp-h" className="ee-h3 flex items-center gap-2"><KeyRound className="size-4 ee-ink-3" aria-hidden />For your records</h3>
            {[out.root, out.issuing].map((ca) => (
              <div key={ca.id} className="text-[13px]">
                <p><span className="font-semibold">{ca.common_name}</span> <span className="ee-ink-3">· valid until {fmtDate(ca.not_after)}{ca.offline ? ' · offline' : ''}</span></p>
                <p className="ee-mono text-[12px] ee-ink-2 break-all">SHA-256 {fmtFingerprint(ca.fingerprint_sha256)}</p>
              </div>
            ))}
          </section>
        </div>
      )}
    </EDialog>
  )
}
