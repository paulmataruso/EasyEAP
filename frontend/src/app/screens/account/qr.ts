// Minimal QR code encoder (ISO/IEC 18004): byte mode, error correction level M, versions 1–10, automatic mask.
// Enough for an otpauth:// URI; written here so the console needs no QR dependency. Follows the reference algorithm
// published by Project Nayuki (MIT).

const ECC_M_PER_BLOCK = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26]
const BLOCKS_M = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5]
const MAX_VERSION = 10

function rawDataModules(ver: number): number {
  let r = (16 * ver + 128) * ver + 64
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2
    r -= (25 * n - 10) * n - 55
    if (ver >= 7) r -= 36
  }
  return r
}
const dataCodewords = (ver: number) => Math.floor(rawDataModules(ver) / 8) - ECC_M_PER_BLOCK[ver] * BLOCKS_M[ver]

function gfMul(x: number, y: number): number {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z
}

function rsDivisor(degree: number): number[] {
  const r: number[] = new Array(degree).fill(0)
  r[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < r.length; j++) {
      r[j] = gfMul(r[j], root)
      if (j + 1 < r.length) r[j] ^= r[j + 1]
    }
    root = gfMul(root, 0x02)
  }
  return r
}

function rsRemainder(data: number[], divisor: number[]): number[] {
  const r: number[] = divisor.map(() => 0)
  for (const b of data) {
    const factor = b ^ (r.shift() as number)
    r.push(0)
    divisor.forEach((coef, i) => { r[i] ^= gfMul(coef, factor) })
  }
  return r
}

const bit = (x: number, i: number) => ((x >>> i) & 1) !== 0

/** Encode text as a QR matrix (true = dark), or null if it doesn't fit version 10-M. */
export function qrMatrix(text: string): boolean[][] | null {
  const bytes = Array.from(new TextEncoder().encode(text))
  let ver = 1
  for (; ver <= MAX_VERSION; ver++) {
    const ccBits = ver <= 9 ? 8 : 16
    if (4 + ccBits + bytes.length * 8 <= dataCodewords(ver) * 8) break
  }
  if (ver > MAX_VERSION) return null
  const cap = dataCodewords(ver) * 8

  // Data bits
  const bb: number[] = []
  const push = (val: number, len: number) => { for (let i = len - 1; i >= 0; i--) bb.push((val >>> i) & 1) }
  push(0b0100, 4)
  push(bytes.length, ver <= 9 ? 8 : 16)
  bytes.forEach((b) => push(b, 8))
  push(0, Math.min(4, cap - bb.length))
  push(0, (8 - (bb.length % 8)) % 8)
  for (let pad = 0xec; bb.length < cap; pad ^= 0xec ^ 0x11) push(pad, 8)
  const data: number[] = []
  for (let i = 0; i < bb.length; i += 8) data.push(bb.slice(i, i + 8).reduce((a, b2) => (a << 1) | b2, 0))

  // Error correction and interleaving
  const numBlocks = BLOCKS_M[ver]
  const eccLen = ECC_M_PER_BLOCK[ver]
  const raw = Math.floor(rawDataModules(ver) / 8)
  const numShort = numBlocks - (raw % numBlocks)
  const shortLen = Math.floor(raw / numBlocks)
  const div = rsDivisor(eccLen)
  const blocks: number[][] = []
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1))
    k += dat.length
    const ecc = rsRemainder(dat, div)
    if (i < numShort) dat.push(0)
    blocks.push(dat.concat(ecc))
  }
  const codewords: number[] = []
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((b, j) => { if (i !== shortLen - eccLen || j >= numShort) codewords.push(b[i]) })
  }

  // Function patterns
  const size = ver * 4 + 17
  const mod: boolean[][] = Array.from({ length: size }, () => new Array(size).fill(false))
  const fn: boolean[][] = Array.from({ length: size }, () => new Array(size).fill(false))
  const setFn = (x: number, y: number, dark: boolean) => { mod[y][x] = dark; fn[y][x] = true }
  for (let i = 0; i < size; i++) { setFn(6, i, i % 2 === 0); setFn(i, 6, i % 2 === 0) }
  const finder = (x: number, y: number) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const xx = x + dx, yy = y + dy
      if (xx >= 0 && xx < size && yy >= 0 && yy < size) { const d = Math.max(Math.abs(dx), Math.abs(dy)); setFn(xx, yy, d !== 2 && d !== 4) }
    }
  }
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4)
  if (ver > 1) {
    const n = Math.floor(ver / 7) + 2
    const step = Math.floor((ver * 8 + n * 3 + 5) / (n * 4 - 4)) * 2
    const pos = [6]
    for (let p = size - 7; pos.length < n; p -= step) pos.splice(1, 0, p)
    for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) setFn(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
    }
  }
  const formatBits = (mask: number) => {
    const d = (0 << 3) | mask // ECC level M = 0b00
    let rem = d
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
    const bits = ((d << 10) | rem) ^ 0x5412
    for (let i = 0; i <= 5; i++) setFn(8, i, bit(bits, i))
    setFn(8, 7, bit(bits, 6)); setFn(8, 8, bit(bits, 7)); setFn(7, 8, bit(bits, 8))
    for (let i = 9; i < 15; i++) setFn(14 - i, 8, bit(bits, i))
    for (let i = 0; i < 8; i++) setFn(size - 1 - i, 8, bit(bits, i))
    for (let i = 8; i < 15; i++) setFn(8, size - 15 + i, bit(bits, i))
    setFn(8, size - 8, true)
  }
  formatBits(0)
  if (ver >= 7) {
    let rem = ver
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    const bits = (ver << 12) | rem
    for (let i = 0; i < 18; i++) { const a = size - 11 + (i % 3), b = Math.floor(i / 3); setFn(a, b, bit(bits, i)); setFn(b, a, bit(bits, i)) }
  }

  // Codeword placement (zigzag)
  let i = 0
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j
      const up = ((right + 1) & 2) === 0
      const y = up ? size - 1 - vert : vert
      if (!fn[y][x] && i < codewords.length * 8) { mod[y][x] = bit(codewords[i >>> 3], 7 - (i & 7)); i++ }
    }
  }

  const maskFn = [
    (x: number, y: number) => (x + y) % 2 === 0,
    (_x: number, y: number) => y % 2 === 0,
    (x: number) => x % 3 === 0,
    (x: number, y: number) => (x + y) % 3 === 0,
    (x: number, y: number) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x: number, y: number) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x: number, y: number) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x: number, y: number) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ]
  const applyMask = (m: number) => {
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && maskFn[m](x, y)) mod[y][x] = !mod[y][x]
  }

  let best = 0
  let bestScore = Infinity
  for (let m = 0; m < 8; m++) {
    applyMask(m)
    formatBits(m)
    const s = penalty(mod)
    if (s < bestScore) { bestScore = s; best = m }
    applyMask(m) // undo (XOR)
  }
  applyMask(best)
  formatBits(best)
  return mod
}

function penalty(m: boolean[][]): number {
  const n = m.length
  let score = 0
  const lines: boolean[][] = []
  for (let y = 0; y < n; y++) lines.push(m[y])
  for (let x = 0; x < n; x++) lines.push(m.map((row) => row[x]))
  const pattern = [true, false, true, true, true, false, true]
  for (const line of lines) {
    let run = 1
    for (let i = 1; i <= n; i++) {
      if (i < n && line[i] === line[i - 1]) run++
      else { if (run >= 5) score += 3 + (run - 5); run = 1 }
    }
    for (let i = 0; i + 7 <= n; i++) {
      if (!pattern.every((p, k) => line[i + k] === p)) continue
      const lightBefore = i >= 4 && [1, 2, 3, 4].every((k) => !line[i - k])
      const lightAfter = i + 11 <= n && [7, 8, 9, 10].every((k) => !line[i + k])
      if (lightBefore || lightAfter) score += 40
    }
  }
  let dark = 0
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
    if (m[y][x]) dark++
    if (x + 1 < n && y + 1 < n && m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) score += 3
  }
  const total = n * n
  score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10
  return score
}

/** SVG path data for the dark modules, offset by a 4-module quiet zone. */
export function qrPath(m: boolean[][]): { d: string; size: number } {
  const q = 4
  let d = ''
  m.forEach((row, y) => row.forEach((dark, x) => { if (dark) d += `M${x + q} ${y + q}h1v1h-1z` }))
  return { d, size: m.length + q * 2 }
}
