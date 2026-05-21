# @defiob/wallet-plugin-passkey

A [WharfKit](https://wharfkit.com) wallet plugin that signs Antelope
(EOS / Vaulta / Telos / WAX / Jungle / …) transactions with a **WebAuthn
passkey** —  a `PUB_WA_…` public key registered in the user's on-chain
permission authority.

- **No private keys to back up.** The signing material is whatever the
  user's device already gates with their biometric (Touch ID, Windows
  Hello, security key, phone passkey via QR).
- **No backend account database.** Login uses ECDSA public-key recovery
  + a single reverse-lookup call to find which account the passkey
  belongs to. The user picks "Passkey" in the wallet picker, taps their
  fingerprint, and they're in.
- **Plain WharfKit citizen.** Drop it into `SessionKit({ walletPlugins })`
  and every `session.transact(...)` call automatically supports passkey
  signing. No changes to dApp panels.

## Install

```bash
pnpm add @defiob/wallet-plugin-passkey
# or: npm install @defiob/wallet-plugin-passkey
```

Peer dep: `@wharfkit/session ^1.6.0`.

## Usage

```ts
import { SessionKit } from '@wharfkit/session'
import { WebRenderer } from '@wharfkit/web-renderer'
import { WalletPluginPasskey } from '@defiob/wallet-plugin-passkey'

const kit = new SessionKit({
  appName: 'myapp',
  chains: [{ id: '...', url: 'https://...' }],
  ui: new WebRenderer(),
  walletPlugins: [
    new WalletPluginPasskey(),
    // ...your other wallet plugins
  ],
})
```

### Options

```ts
new WalletPluginPasskey({
  /**
   * Reverse-lookup endpoint base URL. The plugin appends the candidate
   * PUB_WA_ string directly. Must respond with JSON of shape:
   *   { accounts: [{account, permission}], pubkey, recursive }
   *
   * Default: 'https://state.eoseyes.com/v2/key/'
   */
  reverseLookupUrl: 'https://your.lookup.host/v2/key/',
})
```

If you operate your own chain or want to point at a different aggregator,
override `reverseLookupUrl`. Empty `accounts` is treated as "not bound on
chain".

## Registering a passkey before first use

A passkey only becomes usable once its `PUB_WA_…` is added to a permission
on chain. This plugin **signs with** an existing passkey; it doesn't add
new ones. The flow is typically:

1. User connects to the dApp with their existing wallet (Anchor, Metahub,
   …).
2. dApp lets them create a passkey via `navigator.credentials.create()`
   and derives the corresponding `PUB_WA_…`.
3. dApp builds an `eosio::updateauth` action adding that key to their
   permission, signed by their existing wallet.
4. Once on chain, this plugin's login() can find it.

For a reference implementation of step 2–3 see the EOSEyes
`/wallet → Permissions` panel.

## How it works

### Login

WebAuthn's `navigator.credentials.get()` returns a signature but not the
public key. To find the public key without asking the user to type an
account name, the plugin runs ECDSA recovery and a reverse lookup:

1. Browser prompts the user to pick a passkey on the device (random
   challenge, no `allowCredentials` filter).
2. Parse the assertion's DER signature into raw `(r, s)`; build the
   signing input `authData || sha256(clientDataJSON)`.
3. ECDSA recovery yields **two candidate** P-256 public keys.
4. For each candidate, encode the canonical `PUB_WA_…` string (compressed
   point + UP/UV byte from authData flags + current `rpId`), then call
   `reverseLookupUrl`.
5. The candidate whose `PUB_WA_…` returns non-empty `accounts` is the
   real public key.
6. If exactly one account → auto-bind. If multiple → prefer `@active`,
   fall back to the first.
7. Persist `credentialID` + `publicKey` + `permissionLevel` so subsequent
   `sign()` calls don't need another lookup.

### Sign

1. Build the Antelope transaction's signing digest:
   `Transaction.signingDigest(chainId)`.
2. WebAuthn `navigator.credentials.get()` with that 32-byte digest as the
   challenge and the stored `credentialID` in `allowCredentials`.
3. Parse the DER signature, recover the recid by matching candidates
   against the stored public key, low-S normalise (`s = n - s; recid ^=
   1` when `s > n/2`).
4. Assemble the on-chain WA Signature bytes:

   ```
   recid + 31              (1 byte)
   r                       (32 bytes, big-endian)
   s                       (32 bytes, big-endian)
   varuint32(authData.len) | authData
   varuint32(cdj.len)      | clientDataJSON
   ```

5. Return `{ signatures: [Signature(KeyType.WA, bytes)] }`.

## Caveats

- **Secure context required.** Browsers only allow WebAuthn over
  `https://*` and `http://localhost`. Raw IP literals (including
  `127.0.0.1`) are rejected by browsers, and Antelope's chain-side
  verifier additionally requires `clientDataJSON.origin` to begin with
  `https://` — so even `http://localhost` will fail when the signature
  reaches the chain. For local development, run your dev server on
  `https://localhost` (e.g. `next dev --experimental-https`).
- **`PUB_WA_…` is origin-scoped.** The string embeds the `rpId` (current
  hostname). A passkey registered at `example.com` produces a different
  `PUB_WA_…` than the same key would at `example.org`. Passkeys created
  on different origins are not interchangeable on chain.
- **Login UI for multi-account passkeys is minimal.** If the same passkey
  is registered on more than one `(account, permission)`, this plugin
  currently picks the `@active` permission or the first match and
  surfaces a `context.ui.status()` message. A first-class picker waits on
  WharfKit's UserInterface protocol gaining a structured choice prompt.

## Build

```bash
pnpm install
pnpm build        # → lib/wallet-plugin-passkey.{js,mjs,d.ts}
pnpm typecheck
```

Build tool: [tsup](https://tsup.egoist.dev). Output formats: CJS + ESM,
matching the layout of official `@wharfkit/wallet-plugin-*` packages.

## License

BSD-3-Clause. © 2026 defiob.
