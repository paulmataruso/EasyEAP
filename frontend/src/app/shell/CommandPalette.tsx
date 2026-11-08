// ⌘K command palette that acts: navigate, switch tenant, and start entity actions ("Issue certificate for…",
// "Revoke…", "Rotate secret for…", "Test a user…"). Entity actions open the owning screen with an intent parameter,
// so the real dialog (with its confirmations) does the work.
import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Dialog } from 'radix-ui'
import { useNavigate } from 'react-router'
import {
  ArrowLeft, Building, CornerDownLeft, EthernetPort, FileBadge, FilePlus, FileX, FlaskConical, KeyRound, LayoutDashboard, ListOrdered, LogOut, RefreshCw, Router,
  Logs, ScrollText, Search, ServerCog, ShieldCheck, SquareTerminal, Users,
} from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { cn } from '@/ui/lib'
import { api } from '../api/client'
import { qk } from '../api/keys'
import { useSession } from '../api/session'
import { useOptionalTenant, useTenantList } from '../api/tenant'
import { paths } from '../routes'
import { toast, errorMessage } from '../ui'
import { useEntitySearch, type HitKind } from './search'

type Mode = { kind: 'root' } | { kind: 'pick'; title: string; placeholder: string; kinds: HitKind[]; filter?: (status?: string) => boolean; onPick: (id: string) => void } | { kind: 'tenant' }

interface Cmd { id: string; label: string; hint?: string; icon: ReactNode; keywords?: string; run: () => void; perm?: string }

export function CommandPalette({ open, onOpenChange, start }: { open: boolean; onOpenChange: (o: boolean) => void; start?: 'issue' }) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { signOut, isPlatform, canManageAdmins } = useSession()
  const tctx = useOptionalTenant()
  const tid = tctx?.tid ?? null
  const tenants = useTenantList()
  const [mode, setMode] = useState<Mode>({ kind: 'root' })
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => { if (!open) { setMode({ kind: 'root' }); setQuery(''); setActive(0) } }, [open])
  useEffect(() => { setActive(0) }, [query, mode])

  const close = () => onOpenChange(false)
  const go = (to: string) => { close(); navigate(to) }
  const pick = (m: Extract<Mode, { kind: 'pick' }>) => { setMode(m); setQuery(''); setTimeout(() => inputRef.current?.focus(), 0) }

  const commands = useMemo<Cmd[]>(() => {
    const out: Cmd[] = []
    if (tid && tctx) {
      out.push(
        { id: 'issue', label: 'Issue certificate for…', icon: <FilePlus aria-hidden />, keywords: 'enroll new device wifi', perm: 'certificates:issue',
          run: () => pick({ kind: 'pick', title: 'Issue certificate for…', placeholder: 'Find a user by name, username or email', kinds: ['user'], filter: (s) => s === 'enabled', onPick: (id) => go(paths.user(tid, id, { issue: true })) }) },
        { id: 'revoke', label: 'Revoke certificate…', icon: <FileX aria-hidden />, keywords: 'serial lost stolen', perm: 'certificates:revoke',
          run: () => pick({ kind: 'pick', title: 'Revoke certificate…', placeholder: 'Find by serial, user or device', kinds: ['certificate'], filter: (s) => s === 'active' || s === 'expiring', onPick: (id) => go(paths.certificates(tid, { revoke: id })) }) },
        { id: 'rotate', label: 'Rotate shared secret for…', icon: <KeyRound aria-hidden />, keywords: 'controller nas radius client', perm: 'radius:secrets',
          run: () => pick({ kind: 'pick', title: 'Rotate shared secret for…', placeholder: 'Find a controller by name, address or site', kinds: ['controller'], onPick: (id) => go(paths.radius(tid, { rotate: id })) }) },
        { id: 'add-switch', label: 'Add switch (wired 802.1X)', icon: <EthernetPort aria-hidden />, keywords: 'catalyst unifi port dot1x wired ethernet nas', perm: 'radius:write',
          run: () => go(paths.radius(tid, { add: 'switch' })) },
        { id: 'add-controller', label: 'Add wireless controller', icon: <Router aria-hidden />, keywords: 'wlc 9800 aireos unifi nas radius client', perm: 'radius:write',
          run: () => go(paths.radius(tid, { add: true })) },
        { id: 'test', label: 'Test a user against the policy…', icon: <FlaskConical aria-hidden />, keywords: 'why vlan simulate decision', perm: 'policy:read',
          run: () => pick({ kind: 'pick', title: 'Test a user…', placeholder: 'Find a user', kinds: ['user'], onPick: (id) => go(paths.policy(tid, { test: id })) }) },
        { id: 'sync', label: 'Sync directory now', icon: <RefreshCw aria-hidden />, keywords: 'active directory ldap', perm: 'directory:sync',
          run: async () => {
            close()
            try { await api.post(`/api/tenants/${tid}/directory/sync`); toast('Directory sync queued', 'Results appear on the Directory page within a minute.'); qc.invalidateQueries({ queryKey: qk.directory(tid) }) }
            catch (e) { toast('Sync couldn’t start', errorMessage(e), 'crit') }
          } },
        { id: 'go-dashboard', label: 'Dashboard', hint: 'Go to', icon: <LayoutDashboard aria-hidden />, run: () => go(paths.dashboard(tid)) },
        { id: 'go-users', label: 'Users', hint: 'Go to', icon: <Users aria-hidden />, run: () => go(paths.users(tid)) },
        { id: 'go-certs', label: 'Certificates', hint: 'Go to', icon: <ShieldCheck aria-hidden />, run: () => go(paths.certificates(tid)) },
        { id: 'go-events', label: 'Authentication log', hint: 'Go to', icon: <ScrollText aria-hidden />, keywords: 'radius events rejects', run: () => go(paths.events(tid)) },
        { id: 'go-syslog', label: 'Device syslog', hint: 'Go to', icon: <Logs aria-hidden />, keywords: 'live log switch controller messages diagnose', perm: 'radius:read', run: () => go(paths.syslog(tid)) },
        { id: 'go-policy', label: 'Access policy', hint: 'Go to', icon: <ListOrdered aria-hidden />, keywords: 'vlan rules', run: () => go(paths.policy(tid)) },
        { id: 'go-radius', label: 'RADIUS, controllers and switches', hint: 'Go to', icon: <Router aria-hidden />, keywords: 'nas wired', run: () => go(paths.radius(tid)) },
        { id: 'go-device-admin', label: 'Device administration', hint: 'Go to', icon: <SquareTerminal aria-hidden />, keywords: 'tacacs aaa switch login admin accounts', perm: 'admin:read', run: () => go(paths.deviceAdmin(tid)) },
        { id: 'go-directory', label: 'Directory', hint: 'Go to', icon: <Building aria-hidden />, keywords: 'active directory ldaps', run: () => go(paths.directory(tid)) },
        { id: 'go-autoenroll', label: 'Group Policy autoenrollment', hint: 'Go to', icon: <FileBadge aria-hidden />, keywords: 'gpo cep ces kerberos keytab computer certificate windows domain', perm: 'directory:read', run: () => go(paths.autoenroll(tid)) },
        { id: 'go-pki', label: 'Certificate authority', hint: 'Go to', icon: <KeyRound aria-hidden />, keywords: 'pki ca crl', run: () => go(paths.pki(tid)) },
      )
    }
    out.push({ id: 'tenant', label: 'Switch tenant…', icon: <Building aria-hidden />, keywords: 'customer organisation', run: () => { setMode({ kind: 'tenant' }); setQuery('') } })
    if (isPlatform) out.push({ id: 'go-tenants', label: 'All tenants', hint: 'Go to', icon: <Building aria-hidden />, run: () => go(paths.tenants()) })
    if (canManageAdmins) out.push({ id: 'go-admins', label: 'Administrators', hint: 'Go to', icon: <Users aria-hidden />, run: () => go(paths.admins()) })
    if (isPlatform) out.push({ id: 'go-system', label: 'System health', hint: 'Go to', icon: <ServerCog aria-hidden />, run: () => go(paths.system()) })
    if (isPlatform) out.push({ id: 'go-system-log', label: 'System log', hint: 'Go to', icon: <ScrollText aria-hidden />, run: () => go(paths.systemLog()) })
    out.push({ id: 'signout', label: 'Sign out', icon: <LogOut aria-hidden />, run: async () => { close(); await signOut(); navigate(paths.login()) } })
    return out.filter((c) => !c.perm || tctx?.can(c.perm))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tid, tctx, isPlatform, canManageAdmins])

  // Opened from "Issue certificate" in the sidebar: go straight to picking the user.
  const started = useRef(false)
  useEffect(() => {
    if (!open) { started.current = false; return }
    if (start === 'issue' && !started.current) { started.current = true; commands.find((c) => c.id === 'issue')?.run() }
  }, [open, start, commands])

  const pickMode = mode.kind === 'pick' ? mode : null
  const search = useEntitySearch(tid, mode.kind === 'root' || pickMode ? query : '', pickMode ? pickMode.kinds : ['user', 'certificate', 'controller', 'mac', 'admin'], { mac: tctx?.can('mac:read') ?? false, admin: tctx?.can('admin:read') ?? false })

  type Row = { key: string; label: string; sub?: string; icon?: ReactNode; group: string; run: () => void }
  const rows: Row[] = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (mode.kind === 'tenant') {
      return (tenants.data ?? []).filter((t) => !q || t.name.toLowerCase().includes(q) || t.slug.includes(q))
        .map((t) => ({ key: t.id, label: t.name, sub: t.domain || t.slug, group: 'Tenants', run: () => go(paths.dashboard(t.id)) }))
    }
    if (pickMode) {
      return search.hits.filter((h) => !pickMode.filter || pickMode.filter(h.status)).map((h) => ({ key: h.key, label: h.label, sub: h.sub, group: h.group, run: () => pickMode.onPick(h.id) }))
    }
    const cmds = commands.filter((c) => !q || `${c.label} ${c.keywords ?? ''}`.toLowerCase().includes(q))
      .map((c) => ({ key: c.id, label: c.label, sub: c.hint, icon: c.icon, group: c.hint ? 'Go to' : 'Actions', run: c.run }))
    const ents = tid ? search.hits.map((h) => ({
      key: h.key, label: h.label, sub: h.sub, group: h.group,
      run: () => go(h.kind === 'user' ? paths.user(tid, h.id) : h.kind === 'certificate' ? paths.certificate(tid, h.id) : h.kind === 'controller' ? paths.radius(tid, { client: h.id }) : h.kind === 'mac' ? paths.mac(tid, { device: h.id }) : h.kind === 'admin' ? paths.deviceAdmin(tid, { account: h.id }) : paths.policy(tid)),
    })) : []
    const actions = cmds.filter((c) => c.group === 'Actions'), gotos = cmds.filter((c) => c.group === 'Go to')
    return [...actions, ...ents, ...gotos]
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, query, commands, search.hits, tenants.data, tid])

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(rows.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(0, i - 1)) }
    else if (e.key === 'Enter') { e.preventDefault(); rows[active]?.run() }
    else if (e.key === 'Backspace' && !query && mode.kind !== 'root') { e.preventDefault(); setMode({ kind: 'root' }) }
  }

  const title = mode.kind === 'pick' ? mode.title : mode.kind === 'tenant' ? 'Switch tenant' : 'Command palette'
  const placeholder = mode.kind === 'pick' ? mode.placeholder : mode.kind === 'tenant' ? 'Find a tenant' : tid ? `Search ${tctx?.tenant.name} or type a command` : 'Type a command'

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="ee-backdrop" />
        <Dialog.Content className="ee-dialog ee-dialog-wide ee-palette p-0" aria-describedby={undefined} onOpenAutoFocus={(e) => { e.preventDefault(); inputRef.current?.focus() }}>
          <Dialog.Title className="sr-only">{title}</Dialog.Title>
          <div className="flex items-center gap-2.5 border-b border-[var(--ee-line)] px-4 py-3">
            {mode.kind !== 'root' ? (
              <button type="button" className="rounded ee-ink-3 hover:text-[var(--ee-ink)]" aria-label="Back to all commands" onClick={() => { setMode({ kind: 'root' }); inputRef.current?.focus() }}>
                <ArrowLeft className="size-4" aria-hidden />
              </button>
            ) : <Search className="size-4 ee-ink-3" aria-hidden />}
            {mode.kind !== 'root' && <span className="ee-chip shrink-0" data-tone="gold">{title}</span>}
            <input
              ref={inputRef}
              className="min-w-0 flex-1 bg-transparent text-[15px] outline-none placeholder:text-[var(--ee-ink-3)]"
              role="combobox"
              aria-expanded
              aria-controls="ee-palette-list"
              aria-activedescendant={rows[active] ? `ee-pal-${active}` : undefined}
              aria-label={placeholder}
              placeholder={placeholder}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onKey}
            />
            <kbd className="ee-kbd" aria-hidden>esc</kbd>
          </div>
          <div id="ee-palette-list" role="listbox" aria-label={title} className="max-h-[min(60vh,480px)] overflow-y-auto p-1.5">
            {rows.length === 0 ? (
              <p className="px-3 py-4 ee-small ee-ink-2">
                {search.loading ? 'Searching…' : pickMode && !query ? 'Start typing to search.' : 'No matches.'}
              </p>
            ) : rows.map((r, i) => (
              <div key={r.key}>
                {(i === 0 || rows[i - 1].group !== r.group) && <p className="ee-menu-label" aria-hidden>{r.group}</p>}
                <div
                  id={`ee-pal-${i}`}
                  role="option"
                  aria-selected={i === active}
                  className={cn('ee-menu-item', '[&_svg]:size-4 [&_svg]:text-[var(--ee-ink-3)]')}
                  onMouseEnter={() => setActive(i)}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => r.run()}
                >
                  {r.icon}
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-medium">{r.label}</span>
                    {r.sub && r.group !== 'Go to' && r.group !== 'Actions' && <span className="block truncate text-[12px] ee-ink-3">{r.sub}</span>}
                  </span>
                  {i === active && <CornerDownLeft className="size-3.5" aria-hidden />}
                </div>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-[var(--ee-line)] px-4 py-2.5 text-[12px] ee-ink-3">
            <span><kbd className="ee-kbd">↑</kbd> <kbd className="ee-kbd">↓</kbd> move</span>
            <span><kbd className="ee-kbd">↵</kbd> choose</span>
            {mode.kind !== 'root' && <span><kbd className="ee-kbd">⌫</kbd> back</span>}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
