import { describe, expect, it } from 'vitest'
import { purposeLabel } from './shared'

describe('purposeLabel', () => {
  it('names what a rule applies to; computers are their own kind', () => {
    expect(purposeLabel([])).toBe('any certificate')
    expect(purposeLabel(['user', 'device', 'computer'])).toBe('any certificate')
    expect(purposeLabel(['user'])).toBe('user certificates only')
    expect(purposeLabel(['computer'])).toBe('domain computer certificates only')
    // A rule for users and their devices doesn't reach domain computers (Group Policy autoenrollment).
    expect(purposeLabel(['user', 'device'])).toBe('user and device certificates only')
  })
})
