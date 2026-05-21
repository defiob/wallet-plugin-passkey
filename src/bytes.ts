/**
 * varuint32 LEB128-style encoding (low 7 bits per byte, high bit =
 * continuation). Matches @wharfkit/antelope's ABI length prefix used for
 * strings and dynamic byte arrays.
 */
export function encodeVaruint32(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new Error('varuint32 out of range')
  }
  const out: number[] = []
  let v = n >>> 0
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80)
    v >>>= 7
  }
  out.push(v & 0x7f)
  return new Uint8Array(out)
}

export function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((s, a) => s + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrs) {
    out.set(a, off)
    off += a.length
  }
  return out
}

export function bytesToHex(buf: Uint8Array): string {
  let s = ''
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i].toString(16)
    s += b.length === 1 ? '0' + b : b
  }
  return s
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) throw new Error('hex string must have even length')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16)
  }
  return out
}

/**
 * Strict-equal compare for two Uint8Arrays. Used to match a recovered
 * compressed P-256 point against a known one.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
