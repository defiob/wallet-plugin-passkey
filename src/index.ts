import {
  AbstractWalletPlugin,
  type LoginContext,
  type ResolvedSigningRequest,
  type TransactContext,
  type WalletPlugin,
  type WalletPluginConfig,
  type WalletPluginLoginResponse,
  type WalletPluginSignResponse,
  WalletPluginMetadata,
} from '@wharfkit/session'

import { performLogin } from './login'
import { performSign } from './sign'

export interface WalletPluginPasskeyOptions {
  /**
   * Reverse-lookup endpoint base URL. The plugin appends the candidate
   * `PUB_WA_…` string directly (with a separating slash if missing).
   * Must respond with JSON of shape:
   *   { accounts: [{account, permission}], pubkey, recursive }
   *
   * Default: `https://state.eoseyes.com/v2/key/`
   */
  reverseLookupUrl?: string
}

const DEFAULT_LOOKUP_URL = 'https://state.eoseyes.com/v2/key/'

interface PasskeyPluginData {
  credentialID?: string
  publicKey?: string
}

/**
 * WharfKit wallet plugin that signs Antelope transactions with a
 * WebAuthn passkey registered on chain.
 *
 *  - login(): uses ECDSA public-key recovery + a reverse-lookup endpoint
 *    to determine which `account@permission` the device's passkey is
 *    bound to, without prompting the user for an account name.
 *
 *  - sign(): treats the transaction signing digest as the WebAuthn
 *    challenge, derives the recid from the registered public key, and
 *    assembles a canonical Antelope WA Signature.
 */
export class WalletPluginPasskey extends AbstractWalletPlugin implements WalletPlugin {
  readonly config: WalletPluginConfig = {
    requiresChainSelect: true,
    requiresPermissionSelect: false,
    requiresPermissionEntry: false,
  }

  readonly metadata: WalletPluginMetadata = WalletPluginMetadata.from({
    name: 'Passkey',
    description: 'Sign with a device passkey registered on chain (PUB_WA_).',
    homepage: 'https://github.com/defiob/wallet-plugin-passkey',
  })

  private readonly reverseLookupUrl: string

  constructor(options: WalletPluginPasskeyOptions = {}) {
    super()
    this.reverseLookupUrl = options.reverseLookupUrl ?? DEFAULT_LOOKUP_URL
  }

  get id(): string {
    return 'passkey'
  }

  async login(context: LoginContext): Promise<WalletPluginLoginResponse> {
    const result = await performLogin(context, this.reverseLookupUrl)
    /* Persist credentialID + public key so sign() can issue a targeted
     * navigator.credentials.get() (skipping the system picker) and
     * recover the recid for the WA Signature byte stream. The base
     * class's serialize() will round-trip these fields through
     * SessionKit storage so restoring a session re-uses them. */
    this.data = {
      ...this.data,
      credentialID: result.credentialID,
      publicKey: result.publicKey,
    }
    return {
      chain: result.chain,
      permissionLevel: result.permissionLevel,
    }
  }

  async sign(
    resolved: ResolvedSigningRequest,
    context: TransactContext,
  ): Promise<WalletPluginSignResponse> {
    const data = this.data as PasskeyPluginData
    if (!data.credentialID || !data.publicKey) {
      throw new Error('Passkey plugin has no stored credential — please log in again')
    }
    return performSign(resolved, context, {
      credentialID: data.credentialID,
      publicKey: data.publicKey,
    })
  }
}

export default WalletPluginPasskey
