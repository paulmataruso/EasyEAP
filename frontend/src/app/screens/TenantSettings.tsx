// Tenant settings: name and domain, status (activate or suspend, with consequences), and deletion (crypto-shredding).
import { useEffect, useId, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Pause, Play, Save, Trash2 } from 'lucide-react'
import { api, ApiError } from '../api/client'
import { qk } from '../api/keys'
import { useSession } from '../api/session'
import { useTenant } from '../api/tenant'
import type { Tenant } from '../api/types'
import { fmtDate } from '../lib/format'
import { paths } from '../routes'
import { Btn, Callout, Chip, ConfirmText, Dl, EDialog, Field, PageHeader, Panel, SectionHeader, errorMessage, toast } from '../ui'

function usePatchTenant(tid: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<Pick<Tenant, 'name' | 'domain' | 'status'>>) => api.patch<Tenant>(`/api/tenants/${tid}`, body),
    onSuccess: () => Promise.all([qc.invalidateQueries({ queryKey: qk.tenantScope(tid) }), qc.invalidateQueries({ queryKey: qk.tenants() }), qc.invalidateQueries({ queryKey: qk.overview() })]),
  })
}

const statusChip = (s: string) => (s === 'active' ? <Chip tone="valid">Active</Chip> : s === 'suspended' ? <Chip tone="crit">Suspended</Chip> : <Chip tone="neutral">In setup</Chip>)

export default function TenantSettings() {
  const { tenant, can } = useTenant()
  const { canManageAdmins } = useSession()
  const canWrite = can('tenant:write')
  const canDelete = can('tenants:delete') || canManageAdmins
  return (
    <div>
      <PageHeader title="Tenant settings" lede={`${tenant.name} · ${tenant.slug}`} />
      <div className="max-w-[960px] space-y-6">
        <General canWrite={canWrite} />
        <Panel className="p-5 sm:p-6" risk={tenant.status === 'suspended' ? 'crit' : undefined} aria-labelledby="ts-status-h">
          <SectionHeader id="ts-status-h" title="Status" actions={statusChip(tenant.status)} />
          <StatusSection canWrite={canWrite} />
        </Panel>
        {canDelete && <DeleteSection />}
      </div>
    </div>
  )
}

function General({ canWrite }: { canWrite: boolean }) {
  const { tid, tenant } = useTenant()
  const id = useId()
  const patch = usePatchTenant(tid)
  const [name, setName] = useState(tenant.name)
  const [domain, setDomain] = useState(tenant.domain)
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { setName(tenant.name); setDomain(tenant.domain) }, [tenant.name, tenant.domain])
  const nameErr = name.trim().length < 2 ? 'Use at least 2 characters.' : null
  const domainErr = domain.trim() && !/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(domain.trim()) ? 'Enter a domain such as contoso.com, or leave it blank.' : null
  const dirty = name.trim() !== tenant.name || domain.trim().toLowerCase() !== tenant.domain
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    setError(null)
    if (nameErr || domainErr) return
    patch.mutate({ name: name.trim(), domain: domain.trim().toLowerCase() }, {
      onSuccess: () => toast('Tenant updated', name.trim()),
      onError: (err) => setError(errorMessage(err)),
    })
  }
  return (
    <Panel className="p-5 sm:p-6" aria-labelledby="ts-gen-h">
      <SectionHeader id="ts-gen-h" title="General" />
      <form onSubmit={submit} noValidate className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="Name" htmlFor={`${id}-n`} error={touched ? nameErr : null}>
            <input id={`${id}-n`} className="ee-input" maxLength={160} value={name} onChange={(e) => setName(e.target.value)} disabled={!canWrite} aria-invalid={(touched && !!nameErr) || undefined} />
          </Field>
          <Field label="Domain" htmlFor={`${id}-d`} error={touched ? domainErr : null} hint="Used to build user principal names for local users. Saving a directory fills it in when blank.">
            <input id={`${id}-d`} className="ee-input ee-mono" maxLength={253} value={domain} onChange={(e) => setDomain(e.target.value)} disabled={!canWrite} spellCheck={false} aria-invalid={(touched && !!domainErr) || undefined} />
          </Field>
        </div>
        <Dl items={[
          ['Short name', <span className="ee-mono text-[13px]">{tenant.slug}</span>],
          ['Created', fmtDate(tenant.created_at)],
          ['Tenant ID', <span className="ee-mono text-[12.5px] break-all">{tenant.id}</span>, 'wide'],
        ]} />
        <p className="ee-small ee-ink-3">The short name appears in certificate file names and RADIUS server names and can’t be changed.</p>
        {error && <Callout tone="crit" title="Changes weren’t saved">{error}</Callout>}
        {canWrite ? <Btn type="submit" variant="primary" busy={patch.isPending} disabled={!dirty}><Save aria-hidden />Save changes</Btn>
          : <p className="ee-small ee-ink-3">Changing tenant details needs the Tenant Administrator role.</p>}
      </form>
    </Panel>
  )
}

function StatusSection({ canWrite }: { canWrite: boolean }) {
  const { tid, tenant } = useTenant()
  const patch = usePatchTenant(tid)
  const [confirm, setConfirm] = useState<'suspend' | 'activate' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const run = (status: 'active' | 'suspended') => {
    setError(null)
    patch.mutate({ status }, {
      onSuccess: () => {
        setConfirm(null)
        toast(status === 'active' ? `${tenant.name} is active` : `${tenant.name} is suspended`,
          status === 'active' ? 'RADIUS starts serving it with its next configuration refresh, usually within seconds.' : 'RADIUS stops serving it with its next configuration refresh, usually within seconds.',
          status === 'active' ? 'valid' : 'warn')
      },
      onError: (e) => setError(errorMessage(e)),
    })
  }
  return (
    <div className="space-y-4 text-[13.5px]">
      {tenant.status === 'setup' && (
        <>
          <p className="ee-ink-2">This tenant is still being set up. RADIUS doesn’t serve it, so nobody can connect yet.</p>
          <Link to={paths.setup(tid)} className="ee-btn ee-btn-primary">Continue setup</Link>
        </>
      )}
      {tenant.status === 'active' && (
        <>
          <p className="ee-ink-2">RADIUS serves this tenant. Suspend it to stop all Wi-Fi access without deleting anything, for example when a contract is paused.</p>
          {canWrite && <Btn variant="danger" onClick={() => setConfirm('suspend')}><Pause aria-hidden />Suspend tenant</Btn>}
        </>
      )}
      {tenant.status === 'suspended' && (
        <>
          <Callout tone="crit" title="Nobody in this tenant can connect">RADIUS has removed this tenant. Every authentication through its controllers is rejected until you reactivate it.</Callout>
          {canWrite && <Btn variant="primary" onClick={() => setConfirm('activate')}><Play aria-hidden />Reactivate tenant</Btn>}
        </>
      )}
      {!canWrite && tenant.status !== 'setup' && <p className="ee-small ee-ink-3">Changing the status needs the Tenant Administrator role.</p>}
      {error && !confirm && <Callout tone="crit">{error}</Callout>}

      <EDialog open={confirm === 'suspend'} onOpenChange={(o) => !o && setConfirm(null)} risk="crit" title={`Suspend ${tenant.name}?`}
        description="Nothing is deleted, and you can reactivate it at any time."
        footer={<><Btn variant="ghost" onClick={() => setConfirm(null)}>Cancel</Btn><Btn variant="danger-solid" busy={patch.isPending} onClick={() => run('suspended')}><Pause aria-hidden />Suspend tenant</Btn></>}>
        <ul className="list-disc space-y-1.5 pl-5 text-[13.5px] ee-ink-2">
          <li>RADIUS removes this tenant with its next configuration refresh, usually within seconds. From then on <strong className="text-[var(--ee-ink)]">nobody in the tenant can connect</strong>.</li>
          <li>Devices already on the network stay connected until they next re-authenticate, at most the RADIUS session timeout.</li>
          <li>Directory sync pauses. Certificates aren’t revoked and keep working after reactivation.</li>
        </ul>
        {error && <Callout tone="crit" className="mt-4">{error}</Callout>}
      </EDialog>
      <EDialog open={confirm === 'activate'} onOpenChange={(o) => !o && setConfirm(null)} risk="gold" title={`Reactivate ${tenant.name}?`}
        footer={<><Btn variant="ghost" onClick={() => setConfirm(null)}>Cancel</Btn><Btn variant="primary" busy={patch.isPending} onClick={() => run('active')}><Play aria-hidden />Reactivate</Btn></>}>
        <p className="text-[13.5px] ee-ink-2">RADIUS serves the tenant again with its next configuration refresh. Devices with a valid certificate that the access policy allows can connect.</p>
        {error && <Callout tone="crit" className="mt-4">{error}</Callout>}
      </EDialog>
    </div>
  )
}

function DeleteSection() {
  const { tid, tenant } = useTenant()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState('')
  const [error, setError] = useState<string | null>(null)
  const del = useMutation({ mutationFn: () => api.del<{ ok: boolean }>(`/api/tenants/${tid}`, { confirm_slug: typed }) })
  useEffect(() => { if (!open) { setTyped(''); setError(null) } }, [open])
  const go = () => {
    setError(null)
    del.mutate(undefined, {
      onSuccess: () => {
        setOpen(false)
        toast(`${tenant.name} deleted`, 'Its keys were destroyed; its secrets can’t be recovered.')
        qc.removeQueries({ queryKey: qk.tenantScope(tid) })
        void qc.invalidateQueries({ queryKey: qk.tenants() })
        void qc.invalidateQueries({ queryKey: qk.overview() })
        navigate(paths.tenants(), { replace: true })
      },
      onError: (e) => setError(e instanceof ApiError && e.status === 403 ? 'Only the Super Administrator can delete tenants.' : errorMessage(e)),
    })
  }
  return (
    <Panel className="p-5 sm:p-6" risk="crit" aria-labelledby="ts-del-h">
      <SectionHeader id="ts-del-h" title="Delete tenant" />
      <div className="space-y-3 text-[13.5px]">
        <p className="ee-ink-2 max-w-[75ch]">Deleting destroys the tenant’s certificate authority and its encryption key in OpenBao. Every stored secret (shared secrets, the directory password, escrowed keys) becomes unrecoverable, and RADIUS stops serving the tenant. This can’t be undone.</p>
        <Btn variant="danger" onClick={() => setOpen(true)}><Trash2 aria-hidden />Delete {tenant.name}</Btn>
      </div>
      <EDialog open={open} onOpenChange={setOpen} risk="crit" title={`Delete ${tenant.name} permanently?`} description="This is crypto-shredding: there is no backup EasyEAP can restore from."
        footer={<><Btn variant="ghost" onClick={() => setOpen(false)}>Cancel</Btn><Btn variant="danger-solid" busy={del.isPending} disabled={typed !== tenant.slug} onClick={go}><Trash2 aria-hidden />Delete permanently</Btn></>}>
        <div className="space-y-4">
          <ul className="list-disc space-y-1.5 pl-5 text-[13.5px] ee-ink-2">
            <li>The tenant’s transit key is destroyed, so every secret encrypted with it (RADIUS shared secrets, the directory bind password, escrowed device keys, the RADIUS server key) becomes unrecoverable.</li>
            <li>The issuing CA is destroyed. RADIUS stops serving the tenant and nobody can connect.</li>
            <li>Users, certificates, rules, controllers and authentication logs for this tenant are deleted. Audit log entries are kept, with a record of the deletion.</li>
          </ul>
          <ConfirmText expected={tenant.slug} value={typed} onChange={setTyped} label="Tenant short name" />
          {error && <Callout tone="crit" title="The tenant wasn’t deleted">{error}</Callout>}
        </div>
      </EDialog>
    </Panel>
  )
}
