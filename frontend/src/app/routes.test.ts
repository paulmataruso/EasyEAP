import { describe, expect, it } from 'vitest'
import { paths, targetPath } from './routes'

describe('targetPath', () => {
  const tid = 't-1'
  it('maps every backend action target to a screen that exists', () => {
    expect(targetPath(tid, 'directory')).toBe(paths.directory(tid))
    expect(targetPath(tid, 'autoenroll')).toBe('/t/t-1/autoenroll')
    expect(paths.autoenroll(tid, { tab: 'log' })).toBe('/t/t-1/autoenroll?tab=log')
    expect(targetPath(tid, 'radius')).toBe('/t/t-1/radius')
    expect(targetPath(tid, 'pki')).toBe('/t/t-1/pki')
    expect(targetPath(tid, 'setup')).toBe('/t/t-1/setup')
    expect(targetPath(tid, 'system')).toBe('/system')
    expect(targetPath(tid, 'tenant')).toBe('/t/t-1/settings')
    expect(targetPath(tid, 'certificates:expiring')).toBe('/t/t-1/certificates?status=expiring')
    expect(targetPath(tid, 'events:unknown_ca')).toBe('/t/t-1/events?reason=unknown_ca')
    expect(targetPath(tid, 'radius:client:c-9')).toBe('/t/t-1/radius?client=c-9')
    expect(targetPath(tid, 'mac:seen')).toBe('/t/t-1/mac?tab=seen')
  })
  it('falls back to the dashboard for unknown targets', () => {
    expect(targetPath(tid, 'something-new')).toBe('/t/t-1/dashboard')
  })
  it('builds intent links', () => {
    expect(paths.user(tid, 'u1', { issue: true })).toBe('/t/t-1/users/u1?issue=1')
    expect(paths.certificates(tid, { revoke: 'c1' })).toBe('/t/t-1/certificates?revoke=c1')
    expect(paths.radius(tid, { rotate: 'n1' })).toBe('/t/t-1/radius?rotate=n1')
    expect(paths.radius(tid, { add: true })).toBe('/t/t-1/radius?add=1')
    expect(paths.radius(tid, { add: 'switch' })).toBe('/t/t-1/radius?add=switch')
    expect(paths.events(tid, { network: 'wired' })).toBe('/t/t-1/events?network=wired')
    expect(paths.policy(tid, { test: 'u1' })).toBe('/t/t-1/policy?test=u1')
    expect(paths.mac(tid, { device: 'd1' })).toBe('/t/t-1/mac?device=d1')
    expect(paths.deviceAdmin(tid)).toBe('/t/t-1/device-admin')
    expect(paths.syslog(tid)).toBe('/t/t-1/syslog')
    expect(paths.syslog(tid, { device: 'c 1' })).toBe('/t/t-1/syslog?device=c%201')
    expect(paths.deviceAdmin(tid, { tab: 'log' })).toBe('/t/t-1/device-admin?tab=log')
    expect(paths.deviceAdmin(tid, { account: 'a1' })).toBe('/t/t-1/device-admin?account=a1')
    expect(paths.mac(tid, { allow: 'AA:BB:CC:DD:EE:FF' })).toBe('/t/t-1/mac?allow=AA%3ABB%3ACC%3ADD%3AEE%3AFF')
  })
})
