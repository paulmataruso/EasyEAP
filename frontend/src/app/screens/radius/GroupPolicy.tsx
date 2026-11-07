// Group Policy for domain PCs (docs/windows-group-policy.md): the tenant's values and files, and the steps. Certificates
// come from Group Policy autoenrollment (screens/Autoenroll.tsx), the Windows setup file or the portal; this sets up
// everything around them.
import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { api, saveBlob } from '../../api/client'
import { qk } from '../../api/keys'
import { useTenant } from '../../api/tenant'
import { Btn, CopyButton, Dl, EDialog, ErrorState, LoadingBlock } from '../../ui'

export interface GroupPolicyGuide {
  server_name: string; ssid: string; wpa3: boolean; root_cn: string; issuing_cn: string; root_thumbprint: string
  files: Array<{ name: string; type: string; content: string }>
  sections: Array<{ title: string; steps: string[] }>
}

export function useGroupPolicy(tid: string, enabled: boolean) {
  return useQuery({
    queryKey: [...qk.radius(tid), 'group-policy'] as const,
    queryFn: ({ signal }) => api.get<GroupPolicyGuide>(`/api/tenants/${tid}/radius/group-policy`, signal),
    enabled,
    staleTime: 60_000,
  })
}

export function GroupPolicyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { tid } = useTenant()
  const q = useGroupPolicy(tid, open)
  const g = q.data
  return (
    <EDialog open={open} onOpenChange={onOpenChange} wide title="Windows Group Policy"
      description="Trust, services and the Wi-Fi and wired policies for domain PCs. Certificates come from Group Policy autoenrollment, the Windows setup file on a user’s page, or the EasyEAP portal.">
      {q.isLoading ? <LoadingBlock rows={6} label="Building the guide" /> : q.error || !g ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : (
        <div className="space-y-5">
          <Dl items={[
            ['RADIUS server name', <span className="ee-mono text-[12.5px] break-all">{g.server_name}</span>],
            ['Wi-Fi network', <span>{g.ssid} · {g.wpa3 ? 'WPA3-Enterprise' : 'WPA2-Enterprise'}</span>],
            ['Root CA', <span>{g.root_cn}</span>],
            ['Root CA SHA-1 thumbprint', <span className="flex flex-wrap items-center gap-2"><span className="ee-mono text-[12px] break-all">{g.root_thumbprint}</span><CopyButton text={g.root_thumbprint.replace(/ /g, '')} what="root CA thumbprint" /></span>, 'wide'],
          ]} />
          <div className="flex flex-wrap gap-2">
            {g.files.map((f) => <Btn key={f.name} size="sm" onClick={() => saveBlob(new Blob([f.content], { type: f.type }), f.name)}><Download aria-hidden />{f.name}</Btn>)}
          </div>
          {g.sections.map((s) => (
            <section key={s.title} aria-label={s.title}>
              <h3 className="ee-h3 mb-2">{s.title}</h3>
              <ol className="list-decimal space-y-1.5 pl-5 text-[13px] marker:text-[var(--ee-ink-3)] marker:tabular-nums">
                {s.steps.map((x) => <li key={x} className="pl-1">{x}</li>)}
              </ol>
            </section>
          ))}
        </div>
      )}
    </EDialog>
  )
}
