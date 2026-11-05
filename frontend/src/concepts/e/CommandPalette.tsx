import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Dialog } from 'radix-ui'
import { ArrowRight, FileKey, LayoutDashboard, Network, Plus, Router, Route, Search, ShieldCheck, User, Users, Waypoints, Building } from 'lucide-react'
import { useTenants, useTenantData } from '@/prototype/store'
import { formatSerial } from '@/ui/lib'
import { vendorLabels } from '@/domain/explain'
import type { ScreenId } from '../contract'
import { HealthBullets, LineBullet, useE, type Intent } from './ui'
import { userKey } from './bits'

interface Cmd { id: string; group: string; label: string; hint?: string; icon: ReactNode; keywords?: string; run: () => void }

export const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
export const PALETTE_KEY = isMac ? 'Cmd K' : 'Ctrl K'

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { go, container } = useE()
  const { tenants, current, switchTenant } = useTenants()
  const d = useTenantData()
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const listId = useId()
  const listRef = useRef<HTMLDivElement>(null)

  const run = (s: ScreenId, opts?: { entityId?: string; intent?: Intent }) => () => go(s, opts)
  const all = useMemo<Cmd[]>(() => {
    const screens: Cmd[] = [
      { id: 'go-dash', group: 'Go to', label: 'Dashboard', hint: 'Route map and service health', icon: <LayoutDashboard />, run: run('dashboard'), keywords: 'overview home map' },
      { id: 'go-users', group: 'Go to', label: 'Users', hint: 'Directory and local accounts', icon: <Users />, run: run('users'), keywords: 'identity people ad' },
      { id: 'go-certs', group: 'Go to', label: 'Certificates', hint: 'PKI, CA status and revocation', icon: <FileKey />, run: run('certificates'), keywords: 'pki crl ocsp revoke' },
      { id: 'go-radius', group: 'Go to', label: 'RADIUS', hint: 'Server settings and wireless controllers', icon: <Router />, run: run('radius'), keywords: 'nas wlc controller freeradius' },
      { id: 'go-pol', group: 'Go to', label: 'VLAN policies', hint: 'VLANs and access rules', icon: <Route />, run: run('policies'), keywords: 'rules deny allow vlan' },
      { id: 'go-ten', group: 'Go to', label: 'Tenants', hint: 'MSP portfolio', icon: <Building />, run: run('tenants'), keywords: 'msp customers portfolio networks' },
    ]
    const actions: Cmd[] = [
      { id: 'a-add', group: 'Actions', label: 'Register a wireless controller', hint: 'Generates a shared secret', icon: <Plus />, run: run('radius', { entityId: 'new' }), keywords: 'add nas controller wlc' },
      { id: 'a-test', group: 'Actions', label: 'Test a user against policy', hint: 'Shows the decision route and VLAN', icon: <Waypoints />, run: run('policies', { intent: { kind: 'policies.test' } }), keywords: 'trace decision' },
      { id: 'a-issue', group: 'Actions', label: 'Issue a Wi-Fi certificate', hint: 'Pick a user, then Issue Wi-Fi certificate', icon: <ShieldCheck />, run: run('users'), keywords: 'enroll enrollment new certificate' },
      { id: 'a-denied', group: 'Actions', label: 'Show denied users', icon: <Users />, run: run('users', { intent: { kind: 'users.filter', access: 'deny' } }), keywords: 'unauthorized' },
      { id: 'a-exp', group: 'Actions', label: 'Show expiring certificates', icon: <FileKey />, run: run('certificates', { intent: { kind: 'certs.filter', status: 'expiring' } }), keywords: 'renew' },
    ]
    const nets: Cmd[] = tenants.map((t) => ({
      id: `t-${t.id}`, group: 'Switch network', label: t.name, hint: t.id === current.id ? `${t.domain} · current` : t.domain,
      icon: <HealthBullets radius={t.health.radius} pki={t.health.pki} directory={t.health.directory} />,
      run: () => { switchTenant(t.id); go('dashboard') }, keywords: `${t.slug} tenant`,
    }))
    const users: Cmd[] = d.identities.map((i) => ({ id: `u-${i.id}-${i.objectGuid}`, group: 'Users', label: i.displayName, hint: i.upn ?? i.username, icon: <User />, run: run('user', { entityId: userKey(i, d.identities) }), keywords: `${i.username} ${i.department ?? ''} ${i.email ?? ''}` }))
    const certs: Cmd[] = d.certificates.map((c) => ({ id: `c-${c.id}`, group: 'Certificates', label: c.commonName, hint: formatSerial(c.serial), icon: <FileKey />, run: run('certificates', { entityId: c.id }), keywords: `${c.serial} ${c.status}` }))
    const nas: Cmd[] = d.radiusClients.map((c) => ({ id: `n-${c.id}`, group: 'Controllers', label: c.name, hint: `${c.address} · ${vendorLabels[c.vendor]}`, icon: <Router />, run: run('radius', { entityId: c.id }), keywords: `${c.site} ${c.address}` }))
    const vlans: Cmd[] = d.vlans.map((v) => ({ id: `v-${v.id}`, group: 'VLANs', label: `VLAN ${v.vlanId} ${v.name}`, hint: v.description, icon: <LineBullet vlan={v} size={18} />, run: run('policies'), keywords: 'vlan' }))
    return [...screens, ...actions, ...nets, ...users, ...certs, ...nas, ...vlans]
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenants, current.id, d])

  const results = useMemo(() => {
    const tokens = q.trim().toLowerCase().split(/\s+/).filter(Boolean)
    if (!tokens.length) return all.filter((c) => ['Go to', 'Actions', 'Switch network'].includes(c.group))
    const hit = all.filter((c) => { const hay = `${c.label} ${c.hint ?? ''} ${c.keywords ?? ''} ${c.group}`.toLowerCase(); return tokens.every((t) => hay.includes(t)) })
    const perGroup = new Map<string, number>()
    return hit.filter((c) => { const n = perGroup.get(c.group) ?? 0; perGroup.set(c.group, n + 1); return n < 6 })
  }, [q, all])

  useEffect(() => { setActive(0) }, [q, open])
  useEffect(() => { listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' }) }, [active])

  const exec = (c: Cmd | undefined) => { if (!c) return; onOpenChange(false); setQ(''); c.run() }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(results.length - 1, a + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)) }
    else if (e.key === 'Home') { e.preventDefault(); setActive(0) }
    else if (e.key === 'End') { e.preventDefault(); setActive(results.length - 1) }
    else if (e.key === 'Enter') { e.preventDefault(); exec(results[active]) }
  }

  const groups = [...new Set(results.map((r) => r.group))]
  let idx = -1
  return (
    <Dialog.Root open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) setQ('') }}>
      <Dialog.Portal container={container}>
        <Dialog.Overlay className="e-overlay" />
        <Dialog.Content className="e-modal e-palette" aria-describedby={undefined}>
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <div className="flex items-center gap-3 border-b border-[var(--e-hair)] px-4">
            <Search size={18} className="t2 shrink-0" aria-hidden />
            <input
              autoFocus
              className="h-14 min-w-0 flex-1 bg-transparent text-[15px] text-[var(--e-text)] outline-none placeholder:text-[var(--e-text-3)]"
              placeholder={`Search ${current.name}: users, serials, controllers, VLANs…`}
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={onKey}
              role="combobox"
              aria-expanded="true"
              aria-controls={listId}
              aria-activedescendant={results[active] ? `${listId}-${results[active].id}` : undefined}
              aria-autocomplete="list"
              aria-label="Search commands"
            />
            <span className="e-kbd" aria-hidden>Esc</span>
          </div>
          <div ref={listRef} id={listId} role="listbox" aria-label="Results" className="e-palette-list">
            {results.length === 0 && (
              <div className="px-4 py-10 text-center">
                <p className="font-semibold">Nothing matches “{q}”</p>
                <p className="t2 mt-1 text-[13px]">Search by name, UPN, certificate serial, controller IP or VLAN number. Results cover {current.name} only; switch network to search another tenant.</p>
              </div>
            )}
            {groups.map((g) => (
              <div key={g} role="group" aria-label={g} className="pb-1">
                <p className="t2 px-2.5 pb-1 pt-2 text-[12px] font-semibold" aria-hidden>{g}</p>
                {results.filter((r) => r.group === g).map((c) => {
                  idx++
                  const i = idx
                  return (
                    <div
                      key={c.id}
                      id={`${listId}-${c.id}`}
                      role="option"
                      aria-selected={i === active}
                      data-index={i}
                      className="e-palette-item"
                      onPointerMove={() => setActive(i)}
                      onClick={() => exec(c)}
                    >
                      <span className="grid w-[54px] shrink-0 place-items-center [&>svg]:size-4">{c.icon}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[13.5px] font-semibold">{c.label}</span>
                        {c.hint && <span className="t2 block truncate text-[12px]">{c.hint}</span>}
                      </span>
                      {i === active && <ArrowRight size={15} aria-hidden />}
                    </div>
                  )
                })}
              </div>
            ))}
          </div>
          <div className="t2 flex flex-wrap gap-x-4 gap-y-1 border-t border-[var(--e-hair)] px-4 py-2.5 text-[12px]">
            <span><span className="e-kbd">Up</span> <span className="e-kbd">Down</span> to move</span>
            <span><span className="e-kbd">Enter</span> to open</span>
            <span className="ml-auto inline-flex items-center gap-1.5"><Network size={13} aria-hidden />{current.name}</span>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
