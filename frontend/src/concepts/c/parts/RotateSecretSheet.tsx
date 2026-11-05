import { useState } from 'react'
import { AlertDialog } from 'radix-ui'
import { EyeOff, TriangleAlert } from 'lucide-react'
import { useActions } from '@/prototype/store'
import type { RadiusClient } from '@/domain/types'
import { Button } from '../ui/Button'
import { ConfirmSheet, Sheet } from '../ui/Sheet'
import { SecretOnce } from '../ui/Code'
import { Note } from '../ui/Layout'
import { useConcept } from '../app/context'
import { generateSecret } from '../lib/snippets'

/** Confirm → rotate → show the new secret once. Closing discards it from memory. */
export function RotateSecretSheet({ client, onClose }: { client: RadiusClient | null; onClose: () => void }) {
  const { rotateSecret } = useActions()
  const { toast } = useConcept()
  const [secret, setSecret] = useState<string | null>(null)
  if (!client) return null

  const finish = () => {
    setSecret(null)
    onClose()
  }

  if (secret) {
    return (
      <Sheet
        open
        onOpenChange={(o) => !o && finish()}
        wide
        title={`New secret for ${client.name}`}
        description="Paste it into the controller’s RADIUS server entry now. Requests from this controller fail until it matches."
        actions={<Button variant="primary" onClick={finish}>I’ve stored the secret</Button>}
      >
        <SecretOnce secret={secret} />
        <Note icon={EyeOff} tone="warn">
          <strong>Shown once.</strong> After you close this sheet EasyEAP never displays the secret again.
        </Note>
      </Sheet>
    )
  }

  return (
    <ConfirmSheet
      open
      onOpenChange={(o) => !o && finish()}
      title={`Rotate the shared secret for ${client.name}?`}
      description="The current secret stops working immediately."
      confirm={
        <AlertDialog.Action asChild>
          <button
            type="button"
            className="c-btn is-primary"
            onClick={(e) => {
              e.preventDefault()
              rotateSecret(client.id)
              setSecret(generateSecret())
              toast(`Secret rotated for ${client.name}`, 'Recorded in the audit trail. The secret itself is never logged.')
            }}
          >
            Rotate secret
          </button>
        </AlertDialog.Action>
      }
    >
      <Note icon={TriangleAlert} tone="warn">
        People connecting through <strong>{client.site}</strong> are rejected from the moment you rotate until the new secret is entered on the controller. Rotate during a quiet period, with controller access at hand.
      </Note>
    </ConfirmSheet>
  )
}
