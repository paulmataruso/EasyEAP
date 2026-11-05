// Tenant policy settings (PUT /policy/settings). Applies immediately. The endpoint also carries the tenant default
// action/VLAN, which belong to the draft: this form always sends the *live* values from the server, so it can never
// publish part of a draft.
import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api/client'
import { qk } from '../../api/keys'
import { policyApi, type PolicyResponse } from '../../api/policy'
import type { Enforcement } from '../../api/types'
import { fmtDateTime } from '../../lib/format'
import { Btn, Callout, ESwitch, Field, Panel, SectionHeader, toast } from '../../ui'

export function SettingsSection({ tid, live, canWrite, canKeygen, enforcement }: { tid: string; live: PolicyResponse; canWrite: boolean; canKeygen: boolean; enforcement: Enforcement | undefined }) {
  // Remount when the server values change, so the form never holds stale numbers after a save elsewhere.
  const s = live.settings
  return <SettingsForm key={`${s.max_snapshot_age_seconds}:${s.expiry_warning_days}:${s.allow_server_keygen}`} tid={tid} live={live} canWrite={canWrite} canKeygen={canKeygen} enforcement={enforcement} />
}

function SettingsForm({ tid, live, canWrite, canKeygen, enforcement }: { tid: string; live: PolicyResponse; canWrite: boolean; canKeygen: boolean; enforcement: Enforcement | undefined }) {
  const qc = useQueryClient()
  const s = live.settings
  const [hours, setHours] = useState(String(Math.round(s.max_snapshot_age_seconds / 3600)))
  const [days, setDays] = useState(String(s.expiry_warning_days))
  const [keygen, setKeygen] = useState(s.allow_server_keygen)
  const [error, setError] = useState<string | null>(null)
  const h = Number(hours), d = Number(days)
  const hoursErr = !/^\d+$/.test(hours) || h < 1 || h > 168 ? 'Enter 1 to 168 hours (7 days).' : null
  const daysErr = !/^\d+$/.test(days) || d < 1 || d > 180 ? 'Enter 1 to 180 days.' : null
  const dirty = h * 3600 !== s.max_snapshot_age_seconds || d !== s.expiry_warning_days || keygen !== s.allow_server_keygen

  const save = useMutation({
    mutationFn: async () => {
      // The default action and VLAN aren't settings: they change only through a published draft. The live keygen value
      // is re-read so a role that can't change it sends it back unchanged.
      const latest = (await qc.fetchQuery({ queryKey: qk.policy(tid), queryFn: () => api.get<PolicyResponse>(`/api/tenants/${tid}/policy`), staleTime: 0 })).settings
      return policyApi.updateSettings(tid, {
        max_snapshot_age_seconds: h * 3600, expiry_warning_days: d, allow_server_keygen: canKeygen ? keygen : latest.allow_server_keygen,
      })
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: qk.tenantScope(tid) }); toast('Policy settings saved', 'Applied immediately.') },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'The settings couldn’t be saved.'),
  })
  const submit = (e: FormEvent) => { e.preventDefault(); setError(null); if (!hoursErr && !daysErr) save.mutate() }
  const disabled = !canWrite

  const deadline = enforcement?.snapshot_built_at && !hoursErr ? new Date(new Date(enforcement.snapshot_built_at).getTime() + h * 3600_000).toISOString() : null

  return (
    <section aria-labelledby="settings-h">
      <SectionHeader id="settings-h" title="Policy settings" meta="Not part of the draft. Saving applies immediately." />
      <Panel className="px-5 py-5">
        <form onSubmit={submit} noValidate className="space-y-5">
          <div className="grid gap-5 md:grid-cols-2">
            <Field label="Fail closed after" htmlFor="set-age" error={hoursErr}
              hint={<>Hours RADIUS keeps deciding from its last snapshot if EasyEAP stops refreshing it. After that it denies everyone.{deadline && <> With the current snapshot that would be {fmtDateTime(deadline)}.</>}</>}>
              <div className="flex items-center gap-2">
                <input id="set-age" className="ee-input ee-num w-[110px]" inputMode="numeric" value={hours} onChange={(e) => setHours(e.target.value)} disabled={disabled} aria-invalid={!!hoursErr || undefined} />
                <span className="ee-small ee-ink-2">hours</span>
              </div>
            </Field>
            <Field label="Warn before certificates expire" htmlFor="set-warn" error={daysErr}
              hint="Certificates inside this window show as Expiring and appear in the needs-action queue.">
              <div className="flex items-center gap-2">
                <input id="set-warn" className="ee-input ee-num w-[110px]" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} disabled={disabled} aria-invalid={!!daysErr || undefined} />
                <span className="ee-small ee-ink-2">days</span>
              </div>
            </Field>
          </div>

          <div className="rounded-[8px] border border-[var(--ee-line)] px-4 py-3.5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <label htmlFor="set-keygen" className="text-[13.5px] font-semibold">Allow server-generated keys</label>
                <p className="ee-small ee-ink-2 mt-1 max-w-[70ch]">
                  For devices that can’t run the enrollment page, EasyEAP can create the private key itself and hand it over in a password-protected PKCS#12 file.
                  The trade-off: the key exists outside the device while it’s generated and delivered, so anyone who gets the file and its password can impersonate the device. Leave this off unless you need it.
                </p>
                {!canKeygen && <p className="ee-small ee-ink-3 mt-1.5">Only a Tenant Administrator can change this.</p>}
              </div>
              <ESwitch id="set-keygen" checked={keygen} onChange={setKeygen} label="Allow server-generated keys" disabled={!canWrite || !canKeygen} />
            </div>
          </div>

          {canWrite && !canKeygen && (
            <p className="ee-small ee-ink-3">Only a Tenant Administrator can change whether server-generated keys are allowed. You can change the other settings.</p>
          )}
          {!canWrite && <p className="ee-small ee-ink-3">Your role can view these settings. Changing them needs the Wi-Fi Administrator or Tenant Administrator role.</p>}
          {error && <Callout tone="crit" title="Not saved">{error}</Callout>}
          {canWrite && (
            <div className="flex flex-wrap items-center gap-3">
              <Btn type="submit" variant="primary" busy={save.isPending} disabled={!dirty}>Save settings</Btn>
              {dirty ? <span className="ee-small ee-ink-2">Unsaved. Saving applies immediately.</span> : <span className="ee-small ee-ink-3">No unsaved changes.</span>}
            </div>
          )}
        </form>
      </Panel>
    </section>
  )
}
