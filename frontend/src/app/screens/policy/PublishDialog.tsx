// Publish confirmation: what changes, who it affects (from the preview just seen) and what "live" means for RADIUS.
import { Upload } from 'lucide-react'
import type { PreviewResponse } from '../../api/policy'
import { plural } from '../../lib/format'
import { Btn, Callout, EDialog } from '../../ui'
import type { ChangeLine } from './draft'
import { holders } from './PreviewPanel'

const holdText = (n: number) => (n === 1 ? '1 holds a certificate' : `${n} hold certificates`)

export function PublishDialog({ open, onOpenChange, lines, preview, busy, error, onConfirm, tenantName, enforceable }: {
  open: boolean
  onOpenChange: (o: boolean) => void
  lines: ChangeLine[]
  preview: PreviewResponse | null
  busy: boolean
  error: string | null
  onConfirm: () => void
  tenantName: string
  enforceable: boolean | undefined
}) {
  const s = preview?.summary
  const h = preview ? holders(preview.changes) : null
  return (
    <EDialog open={open} onOpenChange={(o) => { if (!busy) onOpenChange(o) }} wide risk={s && s.newly_denied > 0 ? 'crit' : 'gold'}
      title={`Publish ${plural(lines.length, 'change')}`}
      description={`The access policy for ${tenantName} is replaced in one step.`}
      footer={<>
        <Btn onClick={() => onOpenChange(false)} disabled={busy}>Keep editing</Btn>
        <Btn variant="primary" onClick={onConfirm} busy={busy}><Upload aria-hidden />Publish {plural(lines.length, 'change')}</Btn>
      </>}
    >
      <div className="space-y-4">
        <div>
          <h3 className="ee-h3 mb-1.5">Rule changes</h3>
          <ul className="ee-small list-disc space-y-1 pl-5 ee-ink-2">
            {lines.map((l) => <li key={l.key}>{l.text}</li>)}
          </ul>
        </div>
        {s && h && (
          <div>
            <h3 className="ee-h3 mb-1.5">Impact</h3>
            <ul className="ee-small list-disc space-y-1 pl-5 ee-ink-2">
              <li><span className="font-semibold text-[var(--ee-ink)]">{plural(s.newly_allowed, 'newly allowed', 'newly allowed')}</span>{s.newly_allowed > 0 && <>; {holdText(h.newly_allowed)} and can connect after publishing</>}</li>
              <li><span className={s.newly_denied ? 'font-semibold text-[var(--ee-crit-ink)]' : 'font-semibold text-[var(--ee-ink)]'}>{plural(s.newly_denied, 'newly denied', 'newly denied')}</span>{s.newly_denied > 0 && <>; {holdText(h.newly_denied)} and will be rejected at their next connection</>}</li>
              <li><span className="font-semibold text-[var(--ee-ink)]">{plural(s.vlan_changed, 'VLAN change')}</span></li>
              <li>{s.unchanged + s.rule_only} unchanged</li>
            </ul>
          </div>
        )}
        <Callout tone="neutral" title="When it takes effect">
          {enforceable === false
            ? 'This tenant isn’t enforceable yet, so RADIUS doesn’t use its policy. The new rules apply once setup is finished.'
            : 'RADIUS applies the new snapshot within seconds of publishing; this page shows when it has. People already connected keep their current session and VLAN until they reconnect or the session times out.'}
        </Callout>
        {error && <Callout tone="crit" title="Publishing failed">{error}</Callout>}
      </div>
    </EDialog>
  )
}
