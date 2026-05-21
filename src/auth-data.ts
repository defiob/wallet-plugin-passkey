/**
 * WebAuthn authenticator data layout (W3C WebAuthn §6.1):
 *   rpIdHash(32) | flags(1) | counter(4) | [AT? attestedCredentialData] | [ED? extensions]
 *
 * For our purposes we only need the flags byte. Flags bits:
 *   bit 0 (0x01) UP — user presence
 *   bit 2 (0x04) UV — user verified
 *
 * The Antelope WA public-key data layout encodes a single "user presence"
 * byte that mirrors this, with values:
 *   0x02  user verified
 *   0x01  user present only
 *   0x00  neither (shouldn't happen with userVerification: 'required'
 *         but we keep the fallback so re-encoding stays consistent with
 *         what Anchor / cleos produce for the same authenticator)
 */
export interface AuthDataInfo {
  flags: number
  userPresenceByte: number
}

export function parseAuthData(authData: Uint8Array): AuthDataInfo {
  if (authData.length < 37) throw new Error('authData too short')
  const flags = authData[32]
  let userPresenceByte = 0x00
  if (flags & 0x04) userPresenceByte = 0x02
  else if (flags & 0x01) userPresenceByte = 0x01
  return { flags, userPresenceByte }
}
