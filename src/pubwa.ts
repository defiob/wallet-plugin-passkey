import { Bytes, KeyType, PublicKey } from '@wharfkit/antelope'

import { encodeVaruint32 } from './bytes'

/**
 * Build the on-chain Antelope WA public key from a compressed P-256
 * point plus the WebAuthn metadata embedded in WA keys.
 *
 *   data = compressed(33) | userPresenceByte(1) | varuint32(rpId.len) | rpId(utf8)
 *
 * Returns the canonical `PUB_WA_…` string that the chain stores.
 */
export function encodePubWA(
  compressed: Uint8Array,
  userPresenceByte: number,
  rpId: string,
): string {
  if (compressed.length !== 33) {
    throw new Error('compressed P-256 point must be 33 bytes')
  }
  const rpIdBytes = new TextEncoder().encode(rpId)
  const lenPrefix = encodeVaruint32(rpIdBytes.length)
  const data = new Uint8Array(33 + 1 + lenPrefix.length + rpIdBytes.length)
  data.set(compressed, 0)
  data[33] = userPresenceByte
  data.set(lenPrefix, 34)
  data.set(rpIdBytes, 34 + lenPrefix.length)
  return new PublicKey(KeyType.WA, Bytes.from(data)).toString()
}

/**
 * Extract just the 33-byte compressed point from an existing PUB_WA_… string.
 * Used during sign() to compare against recovered candidates.
 */
export function compressedFromPubWA(pubwa: string): Uint8Array {
  const pk = PublicKey.from(pubwa)
  if (pk.type !== KeyType.WA) {
    throw new Error('not a PUB_WA_ key: ' + pubwa)
  }
  return pk.data.array.slice(0, 33)
}
