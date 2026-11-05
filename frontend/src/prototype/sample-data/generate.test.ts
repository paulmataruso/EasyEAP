import { generateSampleData } from '@/prototype/sample-data/generate'
import { expect, test } from 'vitest'
test('sample data is unique, consistent and contains the contract sample entity', () => {
  const d = generateSampleData()
  for (const k of ['identities', 'devices', 'certificates', 'authEvents'] as const) {
    const ids = d[k].map((x) => x.id); expect(new Set(ids).size).toBe(ids.length)
  }
  expect(d.identities.some((i) => i.id === 't-harborview:u-pnatarajan')).toBe(true)
  expect(d.identities.some((i) => i.displayName === 'Owen Doyle')).toBe(true)
  for (const i of d.identities) { const last = d.authEvents.find((e) => e.identityId === i.id); expect(i.lastAuthAt).toBe(last?.at ?? null) }

})
