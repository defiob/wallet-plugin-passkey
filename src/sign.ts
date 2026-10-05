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

  const getAssertion = async (allowCredentials: PublicKeyCredentialDescriptor[]) =>
    (await navigator.credentials.get({
      publicKey: {
        /* The TS lib types narrow BufferSource to disallow
         * SharedArrayBuffer-backed Uint8Array; `.array` from
         * @wharfkit/antelope returns the broader ArrayBufferLike form
         * so we cast — the runtime value is always a plain
         * ArrayBuffer-backed Uint8Array in practice. */
        challenge: digest as BufferSource,
        rpId,
        allowCredentials,
        userVerification: 'required',
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null

  let cred: PublicKeyCredential | null
  try {
    cred = await getAssertion([{ id: credId as BufferSource, type: 'public-key' }])
  } catch (err) {
    /* Some Android credential providers (seen: Xiaomi's password manager
     * on Chrome) fail targeted requests — Chrome reports "An unknown error
     * occurred while talking to the credential manager" — while the
     * discoverable form, the one login uses, works. Retry that way unless
     * the user cancelled, then make sure they picked the logged-in passkey. */
    if ((err as { name?: string })?.name === 'NotAllowedError') throw normalizeAuthError(err)
    try {
      cred = await getAssertion([])
    } catch (retryErr) {
      throw normalizeAuthError(retryErr)
    }
    if (cred && !bytesEqual(new Uint8Array(cred.rawId), credId)) {
      throw new Error('A different passkey was chosen — pick the one you logged in with')
    }
  }
  if (!cred) throw new Error('Passkey signing cancelled')

  const response = cred.response as AuthenticatorAssertionResponse
  const authData = new Uint8Array(response.authenticatorData)
  const clientDataJSON = new Uint8Array(response.clientDataJSON)
  const sigDer = new Uint8Array(response.signature)

  /* The chain checks clientDataJSON.challenge against the signing digest.
   * A buggy provider can echo a stale challenge (the same Xiaomi manager
   * does on targeted requests), so fail here with a readable error instead
   * of an opaque on-chain signature rejection. */
  if (!challengeMatches(clientDataJSON, digest)) {
    throw new Error('The passkey provider signed the wrong challenge — try again, or switch the passkey provider to Google Password Manager')
  }

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

function challengeMatches(clientDataJSON: Uint8Array, digest: Uint8Array): boolean {
  try {
    const { challenge } = JSON.parse(new TextDecoder().decode(clientDataJSON)) as { challenge?: string }
    return challenge === base64url(digest)
  } catch {
    return false
  }
}

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function normalizeAuthError(err: unknown): Error {
  const e = err as { name?: string; message?: string }
  if (e?.name === 'NotAllowedError') {
    return new Error('Passkey prompt cancelled or timed out')
  }
  /* Keep the DOMException name (NotReadableError, UnknownError, …) —
   * the messages alone are too vague to tell failures apart. */
  if (e?.message) return new Error(e.name ? `${e.name}: ${e.message}` : e.message)
  return new Error('Passkey signing failed')
}
