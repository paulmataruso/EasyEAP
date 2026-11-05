import { lazy } from 'react'
import type { ConceptModule } from './contract'

export const CONCEPTS: Array<{ id: ConceptModule['id']; name: string; skill: ConceptModule['skill'] }> = [
  { id: 'a', name: 'Dark Glass Enterprise', skill: 'UI/UX Pro Max' },
  { id: 'b', name: 'Modern Network Operations', skill: 'UI/UX Pro Max' },
  { id: 'c', name: 'Premium Minimalist Glass', skill: 'UI/UX Pro Max' },
  { id: 'd', name: 'Refined Enterprise Administration', skill: 'Impeccable' },
  { id: 'e', name: 'Advanced Network Operations Center', skill: 'Impeccable' },
  { id: 'f', name: 'Modern Security Management', skill: 'Impeccable' },
]

const loaders = {
  a: () => import('./a'),
  b: () => import('./b'),
  c: () => import('./c'),
  d: () => import('./d'),
  e: () => import('./e'),
  f: () => import('./f'),
} as const

export const lazyConceptRoot = Object.fromEntries(
  Object.entries(loaders).map(([id, load]) => [id, lazy(async () => ({ default: (await load()).default.Root }))]),
) as Record<ConceptModule['id'], ReturnType<typeof lazy<ConceptModule['Root']>>>
