import { Bytes, KeyType, Signature, Transaction } from '@wharfkit/antelope'
import type {
  ResolvedSigningRequest,
  TransactContext,
  WalletPluginSignResponse,
} from '@wharfkit/session'
import { sha256 } from '@noble/hashes/sha2.js'

import { bytesEqual, concatBytes, encodeVaruint32, hexToBytes } from './bytes'
import { parseDerSignature } from './der'
import { compressedFromPubWA } from './pubwa'
import { canonicaliseLowS, recoverP256Candidates, type RecoveryId } from './recover'

export interface SignParams {
  credentialID: string
  publicKey: string
}

export async function performSign(
  resolved: ResolvedSigningRequest,
  context: TransactContext,
  params: SignParams,
): Promise<WalletPluginSignResponse> {
  if (typeof window === 'undefined') {
    throw new Error('Passkey sign can only run in the browser')
  }
  if (!navigator.credentials?.get) {
    throw new Error('This browser does not support WebAuthn')
  }

  const rpId = window.location.hostname

  /* Compute the same signing digest the chain will validate. signingDigest
   * takes the chain ID and returns the SHA-256 of (chain_id || serialized
   * transaction || 32 zero bytes for context-free data). */
  const tx = Transaction.from(resolved.transaction)
  const digest = tx.signingDigest(context.chain.id).array

  const credId = hexToBytes(params.credentialID)

  let cred: PublicKeyCredential | null
  try {
    cred = (await navigator.credentials.get({
      publicKey: {
        /* The TS lib types narrow BufferSource to disallow
         * SharedArrayBuffer-backed Uint8Array; `.array` from
         * @wharfkit/antelope returns the broader ArrayBufferLike form
         * so we cast — the runtime value is always a plain
         * ArrayBuffer-backed Uint8Array in practice. */
        challenge: digest as BufferSource,
        rpId,
        allowCredentials: [{ id: credId as BufferSource, type: 'public-key' }],
        userVerification: 'required',
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null
  } catch (err) {
    throw normalizeAuthError(err)
  }
  if (!cred) throw new Error('Passkey signing cancelled')

  const response = cred.response as AuthenticatorAssertionResponse
  const authData = new Uint8Array(response.authenticatorData)
  const clientDataJSON = new Uint8Array(response.clientDataJSON)
  const sigDer = new Uint8Array(response.signature)

  /* The WebAuthn signature is computed over authData || sha256(clientDataJSON).
   * We need this exact same input to (a) recover the recid by matching the
   * resulting pubkey against the registered one, and (b) include authData
   * and clientDataJSON in the on-chain WA Signature so producers can
   * re-verify. */
  const cdjHash = sha256(clientDataJSON)
  const signingInput = concatBytes(authData, cdjHash)

  const { r, s: sRaw } = parseDerSignature(sigDer)

  /* Determine recid by matching recovered candidates against the known
   * public key. Without this match, the chain's signature verification
   * would fail because recid is part of the WA Signature byte layout. */
  const expectedCompressed = compressedFromPubWA(params.publicKey)
  const candidates = recoverP256Candidates(signingInput, r, sRaw)
  const matched = candidates.find((c) => bytesEqual(c.compressed, expectedCompressed))
  if (!matched) {
    throw new Error('Signature did not recover to the registered passkey public key')
  }
  let recid = matched.recid

  /* Canonicalise to low-s: chains require s ≤ n/2 to prevent signature
   * malleability. Negating s flips the y-parity of the recovered point,
   * which is encoded in bit 0 of recid (0↔1, 2↔3). Bit 1 (the r+n branch)
   * is independent of s and stays put. */
  const { s, flipRecid } = canonicaliseLowS(sRaw)
  if (flipRecid) recid = (recid ^ 1) as RecoveryId

  /* Antelope WA Signature byte layout:
   *   recid + 31     (1 byte) — offset into the WA recid range
   *   r              (32 bytes, big-endian)
   *   s              (32 bytes, big-endian)
   *   varuint32(authData.length) + authData
   *   varuint32(clientDataJSON.length) + clientDataJSON
   *
   * Matches what cleos webauthn signatures and the Antelope reference
   * verifier produce. */
  const sigBytes = concatBytes(
    new Uint8Array([recid + 31]),
    r,
    s,
    encodeVaruint32(authData.length),
    authData,
    encodeVaruint32(clientDataJSON.length),
    clientDataJSON,
  )
  const signature = new Signature(KeyType.WA, Bytes.from(sigBytes))

  return { signatures: [signature] }
}

function normalizeAuthError(err: unknown): Error {
  const e = err as { name?: string; message?: string }
  if (e?.name === 'NotAllowedError') {
    return new Error('Passkey prompt cancelled or timed out')
  }
  if (e?.message) return new Error(e.message)
  return new Error('Passkey signing failed')
}
