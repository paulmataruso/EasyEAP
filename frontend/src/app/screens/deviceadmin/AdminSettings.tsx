// Device administration settings: roles (a name and a Cisco privilege level), break-glass local-only usernames, and
// how long the Admin log is kept.
import { useEffect, useId, useState, type FormEvent } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import { errorField } from '../../api/client'
import { privLabel, useDeleteRole, useSaveAdminSettings, useSaveRole, type AdminRole, type DeviceAdminOverview } from '../../api/deviceAdmin'
import { useTenant } from '../../api/tenant'
import { plural } from '../../lib/format'
import { Btn, Callout, Chip, EDialog, Field, Panel, SectionHeader, Tip, errorMessage, toast } from '../../ui'

export function AdminSettings({ data, write }: { data: DeviceAdminOverview; write: boolean }) {
  const { tid } = useTenant()
  const id = useId()
  const save = useSaveAdminSettings(tid)
  const del = useDeleteRole(tid)
  const [role, setRole] = useState<AdminRole | 'new' | null>(null)
  const [names, setNames] = useState(data.settings.local_only_usernames.join(', '))
  const [days, setDays] = useState(String(data.settings.retention_days))
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  useEffect(() => { setNames(data.settings.local_only_usernames.join(', ')); setDays(String(data.settings.retention_days)) }, [data.settings])
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    const n = Number(days)
    if (!Number.isInteger(n) || n < 30 || n > 730) return setError({ field: 'retention_days', message: 'Keep the log between 30 and 730 days.' })
    save.mutate({ local_only_usernames: names.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean), retention_days: n }, {
      onSuccess: () => toast('Settings saved', 'Devices use the change within about 15 seconds.'),
      onError: (e2) => setError({ field: errorField(e2) ?? '', message: errorMessage(e2) }),
    })
  }
  return (
    <div className="space-y-4">
      <Panel className="px-4 py-3 sm:px-5" aria-labelledby="da-roles-h">
        <SectionHeader id="da-roles-h" title="Roles" actions={write ? <Btn size="sm" onClick={() => setRole('new')}><Plus aria-hidden />New role</Btn> : undefined} />
        <p className="ee-small ee-ink-2 mb-2 max-w-[75ch]">A role is a privilege level on the device: 15 can change the configuration, 1 can only look. Levels in between need the device to assign commands to them (privilege exec level …).</p>
        <ul className="ee-divide">
          {data.roles.map((r) => (
            <li key={r.id} className="flex flex-wrap items-start justify-between gap-3 py-3">
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-[14px] font-semibold">{r.name}{r.builtin && <Chip tone="neutral">Built-in</Chip>}</p>
                <p className="ee-small ee-ink-2 mt-0.5">Level {privLabel(r.priv_lvl)} · {plural(r.used, 'account or group', 'accounts and groups')}{r.description ? ` · ${r.description}` : ''}</p>
              </div>
              {write && (
                <div className="flex gap-2">
                  <Btn size="sm" onClick={() => setRole(r)}>Edit</Btn>
                  {!r.builtin && (
                    <Tip content={r.used ? 'Give its accounts and groups another role first' : 'Delete role'}>
                      <span><Btn size="sm" variant="danger" icon className="w-7" disabled={r.used > 0 || del.isPending} aria-label={`Delete role ${r.name}`}
                        onClick={() => del.mutate(r.id, { onSuccess: () => toast('Role deleted'), onError: (e) => toast('It wasn’t deleted', errorMessage(e), 'crit') })}><Trash2 aria-hidden /></Btn></span>
                    </Tip>
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      </Panel>

      <Panel className="p-5" aria-labelledby="da-set-h">
        <SectionHeader id="da-set-h" title="Break-glass and log" />
        <form noValidate className="space-y-4" onSubmit={submit}>
          <fieldset disabled={!write} className="space-y-4">
            <Field label="Local-only usernames" htmlFor={`${id}-l`} error={error?.field === 'local_only_usernames' ? error.message : null}
              hint="Names EasyEAP always refuses so the device uses its own local account, for example your break-glass account. Separate with commas.">
              <input id={`${id}-l`} className="ee-input ee-mono" value={names} onChange={(e) => setNames(e.target.value)} autoComplete="off" spellCheck={false} placeholder="breakglass, netadmin" />
            </Field>
            <Field label="Keep the Admin log for" htmlFor={`${id}-d`} error={error?.field === 'retention_days' ? error.message : null} hint="30 to 730 days. Older entries are deleted each night.">
              <div className="flex items-center gap-2">
                <input id={`${id}-d`} className="ee-input ee-num w-[110px]" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value.replace(/\D/g, ''))} />
                <span className="ee-small ee-ink-2">days</span>
              </div>
            </Field>
          </fieldset>
          {error && !['local_only_usernames', 'retention_days'].includes(error.field) && <Callout tone="crit" title="Settings weren’t saved">{error.message}</Callout>}
          {write && <Btn type="submit" variant="primary" size="sm" busy={save.isPending}>Save</Btn>}
        </form>
      </Panel>

      <RoleDialog role={role} onClose={() => setRole(null)} />
    </div>
  )
}

function RoleDialog({ role, onClose }: { role: AdminRole | 'new' | null; onClose: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const save = useSaveRole(tid)
  const existing = role && role !== 'new' ? role : null
  const [name, setName] = useState('')
  const [level, setLevel] = useState('1')
  const [description, setDescription] = useState('')
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  useEffect(() => {
    if (!role) return
    setName(existing?.name ?? ''); setLevel(String(existing?.priv_lvl ?? 1)); setDescription(existing?.description ?? ''); setError(null)
  }, [role, existing])
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    const n = Number(level)
    if (!name.trim()) return setError({ field: 'name', message: 'Name the role.' })
    if (!Number.isInteger(n) || n < 0 || n > 15) return setError({ field: 'priv_lvl', message: 'Use a level from 0 to 15.' })
    save.mutate({ id: existing?.id, body: { name: name.trim(), priv_lvl: n, description: description.trim() } }, {
      onSuccess: () => { toast(existing ? 'Role saved' : 'Role created'); onClose() },
      onError: (e2) => setError({ field: errorField(e2) ?? '', message: errorMessage(e2) }),
    })
  }
  const err = (f: string) => (error?.field === f ? error.message : null)
  return (
    <EDialog open={!!role} onOpenChange={(o) => !o && onClose()} title={existing ? `Edit ${existing.name}` : 'New role'}
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" type="submit" form={`${id}-f`} busy={save.isPending}>{existing ? 'Save role' : 'Create role'}</Btn></>}>
      <form id={`${id}-f`} noValidate className="space-y-4" onSubmit={submit}>
        {existing?.builtin && <Callout tone="neutral">Built-in roles keep their name and level. You can change the description.</Callout>}
        <Field label="Name" htmlFor={`${id}-n`} error={err('name')}>
          <input id={`${id}-n`} className="ee-input" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} disabled={existing?.builtin} autoComplete="off" placeholder="Helpdesk" />
        </Field>
        <Field label="Privilege level" htmlFor={`${id}-l`} error={err('priv_lvl')} hint="0–15. 15 is full access, 1 is read-only.">
          <input id={`${id}-l`} className="ee-input ee-num w-[90px]" inputMode="numeric" value={level} onChange={(e) => setLevel(e.target.value.replace(/\D/g, '').slice(0, 2))} disabled={existing?.builtin} />
        </Field>
        <Field label="Description" htmlFor={`${id}-d`} optional>
          <input id={`${id}-d`} className="ee-input" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={300} autoComplete="off" />
        </Field>
        {error && !['name', 'priv_lvl'].includes(error.field) && <Callout tone="crit" title="The role wasn’t saved">{error.message}</Callout>}
      </form>
    </EDialog>
  )
}
