import { Name, PermissionLevel } from '@wharfkit/antelope'
import type { LoginContext, WalletPluginLoginResponse } from '@wharfkit/session'
import { sha256 } from '@noble/hashes/sha2.js'

import { parseAuthData } from './auth-data'
import { bytesToHex, concatBytes } from './bytes'
import { parseDerSignature } from './der'
import { reverseLookup } from './lookup'
import { encodePubWA } from './pubwa'
import { recoverP256Candidates } from './recover'

/**
 * Result of the login flow. The first three fields satisfy the
 * WharfKit WalletPluginLoginResponse contract; credentialID and
 * publicKey are extras the plugin persists in `data` so subsequent
 * sign() calls don't need a fresh reverse-lookup.
 */
export interface LoginResult extends WalletPluginLoginResponse {
  credentialID: string
  publicKey: string
}

export async function performLogin(
  context: LoginContext,
  reverseLookupUrl: string,
): Promise<LoginResult> {
  if (typeof window === 'undefined') {
    throw new Error('Passkey login can only run in the browser')
  }
  if (!window.PublicKeyCredential || !navigator.credentials?.get) {
    throw new Error('This browser does not support WebAuthn')
  }
  if (!window.isSecureContext) {
    throw new Error('Passkeys require HTTPS (or localhost)')
  }

  const rpId = window.location.hostname
  validateRpId(rpId)

  /* SessionKit guarantees context.chain is set when requiresChainSelect
   * is true, but guard anyway for clearer error messages. */
  if (!context.chain) {
    throw new Error('No chain selected — pick a chain before connecting Passkey')
  }

  /* The challenge value doesn't matter at all — we just need a fresh
   * signature whose recoverable public key we can test against the
   * reverse-lookup endpoint. */
  const challenge = crypto.getRandomValues(new Uint8Array(32))

  let cred: PublicKeyCredential | null
  try {
    cred = (await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId,
        allowCredentials: [],
        userVerification: 'required',
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null
  } catch (err) {
    throw normalizeAuthError(err)
  }
  if (!cred) throw new Error('Passkey login cancelled')

  const response = cred.response as AuthenticatorAssertionResponse
  const authData = new Uint8Array(response.authenticatorData)
  const clientDataJSON = new Uint8Array(response.clientDataJSON)
  const sigDer = new Uint8Array(response.signature)
  const credentialID = bytesToHex(new Uint8Array(cred.rawId))

  /* Signing input the assertion signature was produced over
   * (per WebAuthn §6.3.3): authData || sha256(clientDataJSON). */
  const cdjHash = sha256(clientDataJSON)
  const signingInput = concatBytes(authData, cdjHash)

  const { r, s } = parseDerSignature(sigDer)
  const candidates = recoverP256Candidates(signingInput, r, s)
  if (candidates.length === 0) {
    throw new Error('Could not recover any public key from passkey signature')
  }

  const { userPresenceByte } = parseAuthData(authData)

  /* The PUB_WA_ string bakes in a user-presence byte that reflects the
   * policy at registration time. A UV-required assertion always sets the
   * UV flag, so parseAuthData returns 0x02 (user-verified) here — but the
   * same passkey may have been registered with 0x01 (present-only); a UV
   * assertion still satisfies that looser policy. To avoid spurious
   * "not registered" errors, probe both encodings for each candidate. */
  const presenceBytes: number[] =
    userPresenceByte === 0x02 ? [0x02, 0x01] : [userPresenceByte]

  /* For each recovered candidate, build the PUB_WA_ string that WOULD
   * match this passkey if it were registered on chain, then ask the
   * lookup endpoint. The matching candidate is the real public key. */
  const matches: { pubkey: string; accounts: { account: string; permission: string }[] }[] = []
  for (const c of candidates) {
    for (const pb of presenceBytes) {
      const pubkey = encodePubWA(c.compressed, pb, rpId)
      const res = await reverseLookup(reverseLookupUrl, pubkey)
      if (res.accounts.length > 0) {
        matches.push({ pubkey, accounts: res.accounts })
        break
      }
    }
  }

  if (matches.length === 0) {
    throw new Error(
      'Passkey not registered on chain. Add it to your account at /wallet → Permissions first.',
    )
  }
  /* In the vanishingly rare case both recid candidates have on-chain
   * hits, pick the first — they'd be cryptographically distinct keys
   * but practically only one was ever registered. */
  const chosen = matches[0]
  let picked: { account: string; permission: string }
  if (chosen.accounts.length === 1) {
    picked = chosen.accounts[0]
  } else {
    /* Multiple (account, permission) entries share this passkey. Prefer
     * 'active' as the most likely daily driver; otherwise the first.
     * A real multi-select picker is a future improvement — the
     * UserInterface.prompt API only offers display elements, not
     * structured input. */
    picked = chosen.accounts.find((a) => a.permission === 'active') ?? chosen.accounts[0]
    try {
      context.ui?.status?.(
        `Passkey is registered on ${chosen.accounts.length} accounts; logging in as ${picked.account}@${picked.permission}.`,
      )
    } catch {
      /* status() may not be implemented on all UIs — ignore. */
    }
  }

  return {
    chain: context.chain.id,
    permissionLevel: PermissionLevel.from({
      actor: Name.from(picked.account),
      permission: Name.from(picked.permission),
    }),
    credentialID,
    publicKey: chosen.pubkey,
  }
}

function validateRpId(host: string): void {
  if (host === 'localhost') return
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    throw new Error(
      `WebAuthn rejects IP hosts as RP ID ("${host}"). Open the app at http://localhost:<port> instead.`,
    )
  }
  if (host.startsWith('[') || host.includes(':')) {
    throw new Error(`WebAuthn rejects IPv6 hosts as RP ID ("${host}").`)
  }
}

function normalizeAuthError(err: unknown): Error {
  const e = err as { name?: string; message?: string }
  if (e?.name === 'NotAllowedError') {
    return new Error('Passkey prompt cancelled or timed out')
  }
  if (e?.message) return new Error(e.message)
  return new Error('Passkey login failed')
}
