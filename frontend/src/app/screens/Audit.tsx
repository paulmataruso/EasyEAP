import { PageHeader } from '../ui'

export default function Audit({ scope }: { scope: 'tenant' | 'platform' }) {
  return <PageHeader title={scope === 'tenant' ? 'Audit log' : 'Platform audit'} lede="Not built yet." />
}
