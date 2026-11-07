// Directory access: which AD groups may log in to devices, with which role. The first mapping that matches a user's
// groups (checked in AD at login, nested groups included) decides the role, so order matters.
import { useEffect, useId, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { ArrowDown, ArrowUp, BookUser, Plus, Trash2 } from 'lucide-react'
import { errorField } from '../../api/client'
import { useDirectoryGroups } from '../../api/directory'
import { lockoutNote, parseSites, privLabel, useCreateMap, useDeleteMap, useOrderMaps, useUpdateMap, type DeviceAdminOverview, type GroupMap } from '../../api/deviceAdmin'
import { useTenant } from '../../api/tenant'
import { plural } from '../../lib/format'
import { paths } from '../../routes'
import { Btn, Callout, Chip, EDialog, ESelect, Empty, Field, Panel, SectionHeader, Tip, errorMessage, toast } from '../../ui'
import { SearchBox } from '../people/shared'

export function DirectoryAccess({ data, write }: { data: DeviceAdminOverview; write: boolean }) {
  const { tid, can } = useTenant()
  const [editing, setEditing] = useState<GroupMap | 'new' | null>(null)
  const [removing, setRemoving] = useState<GroupMap | null>(null)
  const [q, setQ] = useState('')
  const order = useOrderMaps(tid)
  const del = useDeleteMap(tid)
  const dir = data.directory
  const maps = data.maps
  const move = (i: number, by: -1 | 1) => {
    const ids = maps.map((m) => m.id)
    ;[ids[i], ids[i + by]] = [ids[i + by], ids[i]]
    order.mutate(ids, { onError: (e) => toast('The order wasn’t saved', errorMessage(e), 'crit') })
  }
  const admits = useMemo(() => {
    const ql = q.trim().toLowerCase()
    return data.admits.filter((a) => !ql || [a.username, a.upn, a.display_name, a.group].some((x) => x?.toLowerCase().includes(ql)))
  }, [data.admits, q])

  if (!dir.connected) {
    return (
      <Empty icon={<BookUser aria-hidden />} title="No directory connected"
        action={can('directory:read') ? <Link to={paths.directory(tid)} className="ee-btn ee-btn-sm">Open Directory</Link> : undefined}>
        Connect Active Directory to let AD groups log in to devices. Until then, use EasyEAP accounts.
      </Empty>
    )
  }
  return (
    <div className="space-y-4">
      {!dir.usable && (
        <Callout tone="warn" title="The directory can’t be used for admin logins yet">
          {dir.problem ?? 'Check the directory connection.'} Until it can, AD users can’t log in to devices; EasyEAP accounts still work.
        </Callout>
      )}
      <Panel className="px-4 py-3 sm:px-5" aria-labelledby="da-maps-h">
        <SectionHeader id="da-maps-h" title="Groups that may log in" meta={dir.domain ?? undefined}
          actions={write ? <Btn size="sm" onClick={() => setEditing('new')}><Plus aria-hidden />Add a group</Btn> : undefined} />
        <p className="ee-small ee-ink-2 mb-3 max-w-[75ch]">
          At login EasyEAP checks the user’s groups in AD itself, nested groups included, so removing someone from a group takes effect at their next login.
          The first group in this list that matches decides the role. Someone just added to a group in AD can log in after the next directory sync.
          {dir.connected ? ` ${lockoutNote(dir)}` : ''}
        </p>
        {maps.length === 0 ? (
          <p className="ee-small ee-ink-3 py-3">No groups yet: only EasyEAP accounts can log in to devices.</p>
        ) : (
          <ol className="ee-divide">
            {maps.map((mp, i) => (
              <li key={mp.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="flex min-w-0 items-start gap-3">
                  <span className="ee-num ee-ink-3 w-5 pt-0.5 text-right text-[12.5px]" aria-hidden>{i + 1}</span>
                  <div className="min-w-0">
                    <p className="flex flex-wrap items-center gap-2 text-[14px] font-semibold">
                      {mp.group ?? 'Deleted group'}
                      {mp.group_deleted && <Chip tone="crit">Not in the directory any more</Chip>}
                    </p>
                    <p className="ee-small ee-ink-2 mt-0.5">
                      {mp.role ?? '—'} · level {privLabel(mp.priv_lvl)} · {mp.sites.length ? `sites ${mp.sites.join(', ')}` : 'every site'} · {plural(mp.admits, 'user')} by this group
                    </p>
                  </div>
                </div>
                {write && (
                  <div className="flex gap-1.5">
                    <Btn size="sm" variant="ghost" icon className="w-7" disabled={i === 0 || order.isPending} onClick={() => move(i, -1)} aria-label={`Move ${mp.group} up`}><ArrowUp aria-hidden /></Btn>
                    <Btn size="sm" variant="ghost" icon className="w-7" disabled={i === maps.length - 1 || order.isPending} onClick={() => move(i, 1)} aria-label={`Move ${mp.group} down`}><ArrowDown aria-hidden /></Btn>
                    <Btn size="sm" onClick={() => setEditing(mp)}>Edit</Btn>
                    <Tip content="Remove"><span><Btn size="sm" variant="danger" icon className="w-7" onClick={() => setRemoving(mp)} aria-label={`Remove ${mp.group}`}><Trash2 aria-hidden /></Btn></span></Tip>
                  </div>
                )}
              </li>
            ))}
          </ol>
        )}
      </Panel>

      {maps.length > 0 && (
        <Panel className="px-4 py-3 sm:px-5" aria-labelledby="da-admits-h">
          <SectionHeader id="da-admits-h" title="Who can log in" meta={`${plural(data.admits.length, 'directory user')} from the last sync`} />
          {data.admits.length === 0 ? <p className="ee-small ee-ink-3 py-2">Nobody yet: the groups have no enabled members in the last sync.</p> : (
            <>
              <SearchBox className="mb-3 w-full sm:w-[280px]" value={q} onChange={setQ} label="Search who can log in" placeholder="Name, username or group" />
              <div className="overflow-x-auto">
                <table className="ee-table">
                  <caption className="sr-only">Directory users the groups admit, with the role the first matching group gives</caption>
                  <thead><tr><th className="pt-1.5">User</th><th className="pt-1.5">Logs in as</th><th className="pt-1.5">Role</th><th className="pt-1.5">Through</th></tr></thead>
                  <tbody>
                    {admits.slice(0, 200).map((a) => (
                      <tr key={a.id}>
                        <td>{a.display_name || a.username}</td>
                        <td className="ee-mono text-[12.5px]">{a.username}{a.upn && a.upn !== a.username && <span className="ee-ink-3 block">{a.upn}</span>}</td>
                        <td className="whitespace-nowrap">{a.role} <span className="ee-ink-3">· {privLabel(a.priv_lvl)}</span>{a.sites.length > 0 && <span className="ee-small ee-ink-3 block">{a.sites.join(', ')}</span>}</td>
                        <td>{a.group}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="ee-small ee-ink-3 pt-3">{admits.length > 200 ? `The first 200 of ${admits.length}. ` : ''}Local accounts with the same name win on devices.</p>
            </>
          )}
        </Panel>
      )}

      <MapDialog open={editing !== null} map={editing === 'new' ? null : editing} data={data} onClose={() => setEditing(null)} />
      <EDialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)} risk="crit" title={`Remove ${removing?.group ?? 'this group'}?`}
        footer={<><Btn variant="ghost" onClick={() => setRemoving(null)}>Cancel</Btn>
          <Btn variant="danger" busy={del.isPending} onClick={() => removing && del.mutate(removing.id, {
            onSuccess: () => { toast('Group removed', 'Its members can’t log in to devices within about 15 seconds, unless another group admits them.'); setRemoving(null) },
            onError: (e) => toast('It wasn’t removed', errorMessage(e), 'crit'),
          })}><Trash2 aria-hidden />Remove</Btn></>}>
        <p className="text-[13.5px] ee-ink-2">Its members lose device logins unless another group in the list admits them. Sessions already open stay open.</p>
      </EDialog>
    </div>
  )
}

function MapDialog({ open, map, data, onClose }: { open: boolean; map: GroupMap | null; data: DeviceAdminOverview; onClose: () => void }) {
  const { tid } = useTenant()
  const id = useId()
  const groups = useDirectoryGroups(tid, open && !map)
  const create = useCreateMap(tid)
  const update = useUpdateMap(tid)
  const [groupId, setGroupId] = useState('')
  const [find, setFind] = useState('')
  const [roleId, setRoleId] = useState('')
  const [sites, setSites] = useState('')
  const [error, setError] = useState<{ field: string; message: string } | null>(null)
  useEffect(() => {
    if (!open) return
    setGroupId(map?.group_id ?? ''); setFind(''); setError(null)
    setRoleId(map?.role_id ?? data.roles.find((r) => r.builtin && r.priv_lvl === 1)?.id ?? data.roles[0]?.id ?? '')
    setSites(map?.sites.join(', ') ?? '')
  }, [open, map, data.roles])
  const mapped = new Set(data.maps.map((m) => m.group_id))
  const candidates = (groups.data?.groups ?? []).filter((g) => g.source === 'ad' && !mapped.has(g.id))
  const shown = candidates.filter((g) => !find.trim() || g.name.toLowerCase().includes(find.trim().toLowerCase())).slice(0, 8)
  const chosen = candidates.find((g) => g.id === groupId)
  const err = (f: string) => (error?.field === f ? error.message : null)
  const submit = () => {
    setError(null)
    if (!map && !groupId) return setError({ field: 'group_id', message: 'Choose a group.' })
    if (!roleId) return setError({ field: 'role_id', message: 'Choose a role.' })
    const done = () => { toast(map ? 'Group saved' : 'Group added', 'Devices use the change within about 15 seconds.'); onClose() }
    const fail = (e: unknown) => setError({ field: errorField(e) ?? '', message: errorMessage(e) })
    if (map) update.mutate({ id: map.id, body: { role_id: roleId, sites: parseSites(sites) } }, { onSuccess: done, onError: fail })
    else create.mutate({ group_id: groupId, role_id: roleId, sites: parseSites(sites) }, { onSuccess: done, onError: fail })
  }
  return (
    <EDialog open={open} onOpenChange={(o) => !o && onClose()} title={map ? `Edit ${map.group ?? 'group'}` : 'Let a directory group log in'}
      description="Members of this AD group may log in to devices with their AD username and password."
      footer={<><Btn variant="ghost" onClick={onClose}>Cancel</Btn><Btn variant="primary" type="submit" form={`${id}-f`} busy={create.isPending || update.isPending}>{map ? 'Save' : 'Add group'}</Btn></>}>
      <form id={`${id}-f`} noValidate className="space-y-4" onSubmit={(e) => { e.preventDefault(); submit() }}>
        {!map && (
          <Field label="Group" htmlFor={`${id}-g`} error={err('group_id')} hint="Active Directory groups from the last sync. Groups created in EasyEAP can’t be used: logins check AD itself.">
            <div className="space-y-2">
              <input id={`${id}-g`} className="ee-input" value={find} onChange={(e) => setFind(e.target.value)} placeholder="Find a group" autoComplete="off" />
              {groups.isLoading ? <p className="ee-small ee-ink-3">Loading groups…</p> : shown.length === 0 ? (
                <p className="ee-small ee-ink-3">{candidates.length === 0 ? 'No unmapped AD groups. Sync the directory if a group is missing.' : 'No group matches.'}</p>
              ) : (
                <ul className="rounded-[8px] border border-[var(--ee-line)]" role="radiogroup" aria-label="Group">
                  {shown.map((g) => (
                    <li key={g.id}>
                      <label className="flex cursor-pointer items-center gap-2.5 px-3 py-2 text-[13.5px] hover:bg-[var(--ee-hover)]">
                        <input type="radio" name={`${id}-grp`} className="ee-check" checked={groupId === g.id} onChange={() => setGroupId(g.id)} />
                        <span className="min-w-0 flex-1 truncate">{g.name}</span>
                        <span className="ee-small ee-ink-3">{plural(g.members, 'member')}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              )}
              {chosen && !shown.includes(chosen) && <p className="ee-small ee-ink-2">Chosen: {chosen.name}</p>}
            </div>
          </Field>
        )}
        <Field label="Role" htmlFor={`${id}-r`} error={err('role_id')} hint="The privilege level members get at login.">
          <ESelect id={`${id}-r`} label="Role" className="w-full" value={roleId} onChange={setRoleId} placeholder="Choose a role"
            options={data.roles.map((r) => ({ value: r.id, label: <>{r.name}<span className="ee-ink-3 ml-1.5">level {privLabel(r.priv_lvl)}</span></> }))} />
        </Field>
        <Field label="Sites" htmlFor={`${id}-s`} optional hint="Comma-separated. Empty: every device. Otherwise only devices at these sites (each device’s Site on the RADIUS page).">
          <input id={`${id}-s`} className="ee-input" value={sites} onChange={(e) => setSites(e.target.value)} autoComplete="off" placeholder="hq, branch-1" />
        </Field>
        {error && !['group_id', 'role_id'].includes(error.field) && <Callout tone="crit" title="It wasn’t saved">{error.message}</Callout>}
      </form>
    </EDialog>
  )
}
