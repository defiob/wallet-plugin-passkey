import { p256 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha2.js'

export type RecoveryId = 0 | 1 | 2 | 3

/**
 * Recover candidate 33-byte compressed P-256 public keys that could have
 * produced the given (r, s) signature over `message`.
 *
 * ECDSA recovery yields up to 4 candidates indexed by recid ∈ {0,1,2,3}.
 * recid 2/3 only apply when the nonce-point x-coordinate satisfied
 * r + n < p — vanishingly rare but a valid P-256/WebAuthn signature can
 * land there, so we try all four to avoid spuriously rejecting them.
 *
 * `message` is the WebAuthn signing input (authData || sha256(clientDataJSON)).
 * @noble's recoverPublicKey expects a message hash, so we sha256 the input.
 */
export function recoverP256Candidates(
  message: Uint8Array,
  r: Uint8Array,
  s: Uint8Array,
): { recid: RecoveryId; compressed: Uint8Array }[] {
  const msgHash = sha256(message)
  const compact = new Uint8Array(64)
  compact.set(r, 0)
  compact.set(s, 32)

  const out: { recid: RecoveryId; compressed: Uint8Array }[] = []
  for (const recid of [0, 1, 2, 3] as const) {
    try {
      const sig = p256.Signature.fromCompact(compact).addRecoveryBit(recid)
      const pubkey = sig.recoverPublicKey(msgHash)
      out.push({ recid, compressed: pubkey.toRawBytes(true) })
    } catch {
      /* Most recid values yield no valid point — skip. */
    }
  }
  return out
}

/**
 * Bigint comparison of an s value against curve order / 2.
 * EOS / Antelope canonicalises signatures to low-s; when s > n/2 we negate
 * (s' = n - s) and flip the recid bit.
 *
 * P-256 n (RFC 5639 prime256v1):
 *   0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
 */
const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')
const P256_N_HALF = P256_N >> BigInt(1)

function bytesToBig(b: Uint8Array): bigint {
  let v = BigInt(0)
  for (let i = 0; i < b.length; i++) v = (v << BigInt(8)) | BigInt(b[i])
  return v
}

function bigToBytes(v: bigint): Uint8Array {
  const out = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & BigInt(0xff))
    v >>= BigInt(8)
  }
  return out
}

/**
 * If s > n/2, return the low-s equivalent and a flag indicating recid
 * should be flipped. Otherwise return s unchanged.
 */
export function canonicaliseLowS(s: Uint8Array): { s: Uint8Array; flipRecid: boolean } {
  const sBig = bytesToBig(s)
  if (sBig <= P256_N_HALF) return { s, flipRecid: false }
  const sLow = P256_N - sBig
  return { s: bigToBytes(sLow), flipRecid: true }
}
