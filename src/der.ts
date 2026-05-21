/**
 * Parse a DER-encoded ECDSA signature into raw 32-byte r, s components.
 *
 * Format: SEQUENCE { INTEGER r, INTEGER s }
 *   0x30 <total-len> 0x02 <r-len> <r-bytes> 0x02 <s-len> <s-bytes>
 *
 * WebAuthn P-256 signatures fit in the short DER length form (<128 bytes
 * total, no long-form length encoding). Chrome occasionally omits the
 * leading zero on r or s, so we left-pad to exactly 32 bytes. DER encoders
 * also prepend 0x00 when the high bit of the first content byte is set
 * (to disambiguate from a negative two's-complement integer); we strip
 * that single leading zero before padding.
 */
export function parseDerSignature(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  if (der.length < 8) throw new Error('DER signature too short')
  let p = 0
  if (der[p++] !== 0x30) throw new Error('DER: expected SEQUENCE tag')
  const seqLen = der[p++]
  if (seqLen + 2 !== der.length) {
    /* Long-form length encoding would have the high bit of seqLen set.
     * P-256 sigs never need that — bail out rather than silently
     * mis-parse a malformed input. */
    throw new Error('DER: unexpected length encoding')
  }

  const readInt = (): Uint8Array => {
    if (der[p++] !== 0x02) throw new Error('DER: expected INTEGER tag')
    const len = der[p++]
    const start = p
    const end = p + len
    p = end
    /* Strip a single leading 0x00 added for sign disambiguation. */
    if (der[start] === 0x00 && end - start > 1) {
      return der.slice(start + 1, end)
    }
    return der.slice(start, end)
  }

  const rRaw = readInt()
  const sRaw = readInt()
  if (p !== der.length) throw new Error('DER: trailing bytes after signature')

  return { r: leftPad32(rRaw), s: leftPad32(sRaw) }
}

function leftPad32(buf: Uint8Array): Uint8Array {
  if (buf.length === 32) return buf
  if (buf.length > 32) throw new Error('DER: integer larger than 32 bytes')
  const out = new Uint8Array(32)
  out.set(buf, 32 - buf.length)
  return out
}
