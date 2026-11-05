// Input validation for RADIUS client registration. Messages name the problem and the fix.

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function ipv4ToInt(ip: string): number | null {
  const m = IPV4.exec(ip)
  if (!m) return null
  const parts = m.slice(1).map(Number)
  if (parts.some((p) => p > 255)) return null
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
}

const intToIpv4 = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.')

/** Validates an IPv4 address or CIDR range a controller will send RADIUS from. */
export function validateAddress(raw: string, existing: Array<{ name: string; address: string }>): string | null {
  const value = raw.trim()
  if (!value) return 'Enter the address the controller sends RADIUS from, for example 10.20.0.10 or a range like 10.20.0.0/28.'
  const [ip, prefixRaw, extra] = value.split('/')
  if (extra !== undefined) return `“${value}” has more than one slash. Use an address (10.20.0.10) or one CIDR range (10.20.0.0/28).`
  if (ip.includes(':')) return 'IPv6 RADIUS clients are not supported yet. Use the controller’s IPv4 management address.'
  const n = ipv4ToInt(ip)
  if (n === null) return `“${ip}” is not a valid IPv4 address. Each of the four numbers must be between 0 and 255, for example 10.20.0.10.`
  if (prefixRaw !== undefined) {
    if (!/^\d{1,2}$/.test(prefixRaw) || Number(prefixRaw) > 32) return `“/${prefixRaw}” is not a valid prefix length. Use a number from 8 to 32.`
    const prefix = Number(prefixRaw)
    if (prefix < 8) return `A /${prefix} range would accept RADIUS from ${(2 ** (32 - prefix)).toLocaleString('en-US')} addresses. Use the controller’s own address or a range of /8 or narrower.`
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
    if (((n & mask) >>> 0) !== n) return `${value} has host bits set. Did you mean ${intToIpv4((n & mask) >>> 0)}/${prefix}?`
  }
  if (n === 0) return '0.0.0.0 cannot be a RADIUS client. Use the controller’s management address.'
  const clash = existing.find((c) => c.address === value || c.address === `${ip}/32` || `${value}/32` === c.address)
  if (clash) return `${value} is already registered to ${clash.name}. Each address can belong to one controller.`
  return null
}

export function validateName(raw: string, existing: Array<{ name: string }>): string | null {
  const value = raw.trim()
  if (!value) return 'Enter a name your team will recognise, for example “Riverside branch WLC”.'
  if (value.length > 64) return `Keep the name to 64 characters or fewer (currently ${value.length}).`
  if (existing.some((c) => c.name.toLowerCase() === value.toLowerCase())) return `A controller called “${value}” already exists. Add the site or model to tell them apart.`
  return null
}

export function validatePort(raw: string): string | null {
  if (!/^\d+$/.test(raw.trim())) return 'Enter the CoA port as a number, usually 3799 (1700 on Catalyst 9800).'
  const n = Number(raw)
  if (n < 1 || n > 65535) return 'Ports run from 1 to 65535. The CoA default is 3799, or 1700 on Catalyst 9800.'
  if (n === 1812 || n === 1813) return `UDP ${n} is the RADIUS ${n === 1812 ? 'authentication' : 'accounting'} port. CoA needs its own port, usually 3799.`
  return null
}
