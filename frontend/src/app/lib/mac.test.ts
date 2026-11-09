import { describe, expect, it } from 'vitest'
import { checkMac, coaSummary, formatMac, isRandomized } from '../api/mac'

describe('checkMac (mirrors backend app/mac.py)', () => {
  it('accepts the notations switches and admins use', () => {
    for (const v of ['b4:96:91:22:67:d1', 'B4-96-91-22-67-D1', 'b496.9122.67d1', 'B496912267D1', '  b496912267d1 ']) expect(checkMac(v)).toEqual({ mac: 'B496912267D1' })
  })
  it('refuses mixed separators, wrong lengths, group and zero addresses', () => {
    for (const v of ['b4:96-91:22:67:d1', 'b49691226', 'b4:96:91:22:67:d1:00', 'printer', '01:00:5e:00:00:01', 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']) expect(checkMac(v)).toHaveProperty('error')
  })
  it('formats and flags randomised addresses', () => {
    expect(formatMac('B496912267D1')).toBe('B4:96:91:22:67:D1')
    expect(isRandomized('DA0000000001')).toBe(true)
    expect(isRandomized('B496912267D1')).toBe(false)
  })
})

describe('coaSummary', () => {
  it('says nothing without a live session', () => {
    expect(coaSummary(null)).toBeNull()
    expect(coaSummary({ sessions: 0, queued: 0, without_coa: 0 })).toBeNull()
  })
  it('counts switches told now and sessions that change later', () => {
    expect(coaSummary({ sessions: 2, queued: 1, without_coa: 1 })).toBe('1 switch was told to apply it now; 1 session on switches without CoA change at their next re-authentication.')
  })
})
