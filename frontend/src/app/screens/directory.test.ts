import { describe, expect, it } from 'vitest'
import { deriveBaseDn, hasStats } from './Directory'

describe('directory form helpers', () => {
  it('derives the usual AD base DN from the domain', () => {
    expect(deriveBaseDn('corp.example.com')).toBe('DC=corp,DC=example,DC=com')
    expect(deriveBaseDn(' Corp.Example.COM. ')).toBe('DC=corp,DC=example,DC=com')
    expect(deriveBaseDn('corp')).toBe('')
    expect(deriveBaseDn('bad domain.com')).toBe('')
  })

  it('shows sync stats only once a sync has recorded them', () => {
    // A configuration saved but never synced carries {} (older servers) or null.
    expect(hasStats({} as never)).toBe(false)
    expect(hasStats(null)).toBe(false)
    expect(hasStats({ users: 3, groups: 2, created: 3, updated: 0, deleted: 0, decisions: 0, duration_ms: 40 })).toBe(true)
  })
})
