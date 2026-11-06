// Administrators (Super Administrator only): accounts, platform roles, per-tenant grants, MFA status. Every change
// goes through a confirmation that states what changes; nobody can remove their own access here.
import { useState } from 'react'
import { cn } from '@/ui/lib'
import { DropdownMenu } from 'radix-ui'
import { KeyRound, MoreHorizontal, PencilLine, ShieldCheck, ShieldOff, Trash2, UserCheck, UserPlus, UserX } from 'lucide-react'
import { useAdmins, type Admin } from '../api/governance'
import { useSession } from '../api/session'
import { useTenantList } from '../api/tenant'
import { useNow } from '../lib/useNow'
import { Btn, Chip, Empty, ErrorState, LoadingBlock, PageHeader, Panel } from '../ui'
import { ago } from '../lib/format'

import { ActiveDialog, CreateAdminDialog, DeleteAdminDialog, EditAdminDialog, ResetMfaDialog, roleLabel } from './governance/AdminDialogs'

const COLS = 'md:grid-cols-[minmax(0,1.1fr)_minmax(0,1.4fr)_130px_150px_32px]'

// What each role id allows (backend/app/security/rbac.py). Labels always come from the API.
const roleHelp: Record<string, string> = {
  platform_owner: 'Everything in every tenant, plus administrators, tenant creation and deletion.',
  platform_operator: 'Runs every tenant and can create tenants. Can’t manage administrators.',
  platform_auditor: 'Read-only across every tenant, including the platform audit.',
  tenant_admin: 'Everything in one tenant: directory, policy, RADIUS secrets, certificate authorities, server-generated keys.',
  pki_admin: 'Certificate authorities, templates, issuing and revoking certificates.',
  wifi_admin: 'Users, access policy, RADIUS controllers, issuing and revoking certificates, directory sync.',
  auditor: 'Read-only view of one tenant, including its audit log.',
}

export default function Admins() {
  const { me, canManageAdmins } = useSession()
  const q = useAdmins(canManageAdmins)
  const tenants = useTenantList()
  const now = useNow()
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<Admin | null>(null)
  const [toggling, setToggling] = useState<Admin | null>(null)
  const [deleting, setDeleting] = useState<Admin | null>(null)
  const [resetting, setResetting] = useState<Admin | null>(null)

  if (!canManageAdmins) {
    return (
      <div>
        <PageHeader title="Administrators" />
        <Empty title="Only the Super Administrator manages administrators">
          Your role doesn’t include adding administrators or changing their access. Ask the MSP owner if someone needs access or a different role.
        </Empty>
      </div>
    )
  }

  const data = q.data
  const tenantList = tenants.data ?? []
  const tenantName = (id: string) => tenantList.find((t) => t.id === id)?.name ?? 'Deleted tenant'
  const withoutMfa = data?.admins.filter((a) => a.is_active && !a.mfa_enabled).length ?? 0

  return (
    <div>
      <PageHeader
        title="Administrators"
        lede="Who can sign in to EasyEAP and what they can do. Platform roles cover every tenant; tenant roles are granted one tenant at a time."
        actions={data ? <Btn variant="primary" onClick={() => setCreating(true)}><UserPlus aria-hidden />Add administrator</Btn> : undefined}
      />

      {q.isLoading ? <LoadingBlock rows={6} label="Loading administrators" />
        : q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} />
        : data && (
          <>
            {withoutMfa > 0 && (
              <p className="ee-small mb-4 text-[var(--ee-warn-ink)]">
                {withoutMfa === 1 ? '1 active administrator has' : `${withoutMfa} active administrators have`} no two-factor authentication. Each person turns it on under Account. If someone loses their authenticator, reset it from their actions menu.
              </p>
            )}
            <Panel className="overflow-hidden">
              <div className={cn('hidden gap-x-4 border-b border-[var(--ee-line-2)] px-4 py-2.5 text-[12px] font-medium ee-ink-3 md:grid', COLS)} aria-hidden>
                <span>Administrator</span><span>Access</span><span>Two-factor</span><span>Last sign-in</span><span />
              </div>
              <ul className="ee-divide list-none p-0" aria-label="Administrators">
                {data.admins.map((a) => {
                  const self = a.id === me?.id
                  return (
                    <li key={a.id} className={cn('grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-4 gap-y-2 px-4 py-3', COLS, !a.is_active && 'opacity-75')}>
                      <div className="min-w-0">
                        <p className="flex flex-wrap items-center gap-2 font-medium">{a.display_name}{self && <Chip tone="gold">You</Chip>}{!a.is_active && <Chip tone="neutral" icon={<UserX aria-hidden />}>Deactivated</Chip>}</p>
                        <p className="truncate text-[12.5px] ee-ink-3">{a.email}</p>
                      </div>
                      <div className="col-span-2 col-start-1 row-start-2 min-w-0 md:col-span-1 md:col-start-auto md:row-start-auto">
                        <span className="sr-only">Access: </span>
                        {a.platform_role && <span className="block text-[13px]">{roleLabel(data.roles, a.platform_role)}</span>}
                        {a.grants.length > 0 && (
                          <ul className="ee-small ee-ink-2 mt-0.5 space-y-0.5">
                            {a.grants.map((g) => <li key={g.tenant_id}>{tenantName(g.tenant_id)} · {roleLabel(data.roles, g.role)}</li>)}
                          </ul>
                        )}
                        {!a.platform_role && a.grants.length === 0 && <span className="text-[13px] text-[var(--ee-warn-ink)]">No role: sees no tenants</span>}
                      </div>
                      <div className="col-span-2 col-start-1 row-start-3 flex flex-wrap items-center gap-x-4 gap-y-1 md:contents">
                        <span><span className="sr-only">Two-factor: </span>{a.mfa_enabled ? <Chip tone="valid" icon={<ShieldCheck aria-hidden />}>Two-factor on</Chip> : <Chip tone={a.platform_role === 'platform_owner' ? 'crit' : 'warn'} icon={<ShieldOff aria-hidden />}>Two-factor off</Chip>}</span>
                        <span className="text-[13px] ee-ink-2"><span className="md:sr-only">Last sign-in </span>{a.last_login_at ? ago(a.last_login_at, now) : 'never'}</span>
                      </div>
                      <div className="col-start-2 row-start-1 text-right md:col-start-auto md:row-start-auto">
                        <DropdownMenu.Root modal={false}>
                          <DropdownMenu.Trigger asChild>
                            <Btn variant="ghost" size="sm" icon className="w-7" aria-label={`Actions for ${a.email}`}><MoreHorizontal aria-hidden /></Btn>
                          </DropdownMenu.Trigger>
                          <DropdownMenu.Portal>
                            <DropdownMenu.Content className="ee-menu" align="end" sideOffset={4}>
                              <DropdownMenu.Item className="ee-menu-item" onSelect={() => setEditing(a)}><PencilLine className="size-4 ee-ink-3" aria-hidden />Edit name and access</DropdownMenu.Item>
                              <DropdownMenu.Separator className="ee-menu-sep" />
                              {self ? (
                                <DropdownMenu.Label className="ee-menu-label max-w-[240px]">You can’t deactivate or delete your own account. Manage your own two-factor under Account.</DropdownMenu.Label>
                              ) : (
                                <>
                                  {a.mfa_enabled && <DropdownMenu.Item className="ee-menu-item" onSelect={() => setResetting(a)}><KeyRound className="size-4 ee-ink-3" aria-hidden />Reset two-factor</DropdownMenu.Item>}
                                  <DropdownMenu.Item className="ee-menu-item" onSelect={() => setToggling(a)}>
                                    {a.is_active ? <><UserX className="size-4 ee-ink-3" aria-hidden />Deactivate</> : <><UserCheck className="size-4 ee-ink-3" aria-hidden />Reactivate</>}
                                  </DropdownMenu.Item>
                                  <DropdownMenu.Item className="ee-menu-item text-[var(--ee-crit-ink)]" onSelect={() => setDeleting(a)}><Trash2 className="size-4" aria-hidden />Delete</DropdownMenu.Item>
                                </>
                              )}
                            </DropdownMenu.Content>
                          </DropdownMenu.Portal>
                        </DropdownMenu.Root>
                      </div>
                    </li>
                  )
                })}
              </ul>
            </Panel>
            <details className="mt-4 max-w-[80ch]">
              <summary className="ee-small ee-ink-2 cursor-pointer">What each role can do</summary>
              <dl className="ee-small mt-2 grid gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(200px,auto)_minmax(0,1fr)]">
                {[...data.roles.platform, ...data.roles.tenant].map((r) => (
                  <div key={r.id} className="contents"><dt className="font-medium">{r.label}</dt><dd className="ee-ink-2">{roleHelp[r.id] ?? '—'}</dd></div>
                ))}
              </dl>
            </details>

            <CreateAdminDialog open={creating} onOpenChange={setCreating} data={data} tenants={tenantList} />
            <EditAdminDialog admin={editing} onClose={() => setEditing(null)} data={data} tenants={tenantList} self={editing?.id === me?.id} />
            <ActiveDialog admin={toggling} onClose={() => setToggling(null)} />
            <DeleteAdminDialog admin={deleting} onClose={() => setDeleting(null)} />
            <ResetMfaDialog admin={resetting} onClose={() => setResetting(null)} />
          </>
        )}
    </div>
  )
}
